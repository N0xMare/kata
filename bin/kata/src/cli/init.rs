//! Project-local bootstrap for `kata init`.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kata_core::ConfigManager;
use kata_op_contract::OpError;
use kata_op_contract::requests::AuthorRequest;
use kata_op_contract::responses::AuthorResponse;

use crate::cli::{DELEGATED_SCOPE, normalize_relative_path};

const STARTER_WORKFLOW_NAME: &str = "std.software_factory.kata_self_improve";
const STARTER_WORKFLOW_FILE: &str = "std.software_factory.kata_self_improve.star";
const STARTER_PREFLIGHT_NAME: &str = "std.software_factory.kata_self_improve_preflight";
const STARTER_PREFLIGHT_FILE: &str = "std.software_factory.kata_self_improve_preflight.star";

/// Self-contained hello starter. Unlike the factory packs above, this workflow
/// `load()`s nothing from the bundled stdlib — it is a single deterministic
/// shell stage built entirely from the always-available `stage()`/`workflow()`
/// globals. It therefore compiles and runs on a freshly initialized directory
/// even when the bundled workflow packs
/// (`workflows/{std,kata-factory,examples}` / `share/kata/*`) are not installed
/// next to the binary. `kata doctor` compiles
/// it as the always-green starter preflight so a fresh `kata init` is GREEN
/// without depending on the bundled factory stdlib.
const HELLO_WORKFLOW_NAME: &str = "std.hello";
const HELLO_WORKFLOW_FILE: &str = "std.hello.star";
const HELLO_WORKFLOW: &str = r#"# std.hello — self-contained hello starter emitted by `kata init`.
#
# A single deterministic shell stage that needs NO bundled stdlib (no
# `load("kata/factory.star", ...)` or `load("kata/std.star", ...)`), so it
# compiles and runs on a freshly initialized directory even before the bundled
# workflow packs are installed next to the binary. `kata doctor` compiles this
# as its always-green starter preflight; the factory packs alongside it are the
# richer, bundled-stdlib-backed starters.

hello = stage(
    id = "hello",
    run = """
printf '{"greeting":"hello from kata"}\\n'
""",
    agent = "shell",
    outputs = {
        "greeting": "string",
    },
    progress_visibility = "summary",
)

workflow(
    "std.hello",
    description = "Self-contained hello starter: one shell stage, no bundled stdlib required.",
    root = [
        hello,
    ],
)
"#;
const STARTER_WORKFLOW: &str = r#"# Project-local Kata-on-Kata factory starter.
#
# This shadows the bundled std.software_factory.kata_self_improve pack so each
# repo can tune the goal while still reusing Kata's workflow stdlib. The
# generated kata.toml defines `default` as the model-backed agent and `shell`
# as the deterministic command runner.

load("kata/factory.star", "software_factory_workflow")

software_factory_workflow(
    name = "std.software_factory.kata_self_improve",
    description = "Project-local durable software-factory starter.",
    goal = "Improve this repository toward the product docs, roadmap, and validation criteria.",
    product_docs = [
        ".kata/product/objective.md",
        ".kata/product/validation.md",
        ".kata/product/steering.md",
    ],
    roadmap_docs = [],
    source_roots = [
        ".",
    ],
    validation_commands = [
        "kata check std.software_factory.kata_self_improve",
        "kata build std.software_factory.kata_self_improve",
        "git diff --check",
    ],
    worker_agent = "default",
    shell_agent = "shell",
)
"#;

const STARTER_PREFLIGHT_WORKFLOW: &str = r#"# Project-local validation-only factory preflight.
#
# This proves the generated factory pack compiles and runs its deterministic
# no-mutation path before a user starts model-backed implementation waves.

load("kata/factory.star", "software_factory_workflow")

software_factory_workflow(
    name = "std.software_factory.kata_self_improve_preflight",
    description = "Project-local validation-only software-factory preflight.",
    goal = "Preflight this project's software factory contract without source mutation.",
    product_docs = [
        ".kata/product/objective.md",
        ".kata/product/validation.md",
        ".kata/product/steering.md",
    ],
    roadmap_docs = [],
    source_roots = [
        ".",
    ],
    validation_commands = [
        "kata check std.software_factory.kata_self_improve",
        "kata build std.software_factory.kata_self_improve",
        "kata check std.software_factory.kata_self_improve_preflight",
        "kata build std.software_factory.kata_self_improve_preflight",
        "git diff --check",
    ],
    worker_agent = "default",
    shell_agent = "shell",
    mode = "validation_only",
)
"#;

const PRODUCT_README: &str = r"# Kata Factory Workspace

This directory is the human-authored product/context surface that the starter
software-factory workflow should read before it plans or edits code.

Files:

- `objective.md`: product objective, scope, and non-goals.
- `validation.md`: concrete criteria the workflow must prove before accepting a
  candidate.
- `steering.md`: operator steering that can be appended into a running factory.

Native memory is authoritative once imported through `kata memory`; files under
`.kata/memory/` are just projections and inbox entries.
";

const PRODUCT_OBJECTIVE: &str = r"# Objective

Build this repository toward a durable autonomous software
factory: a workflow system that can turn product context, tasks, and validation
criteria into high-quality repo changes with minimal human dependency.

Default operating constraints:

- compile every workflow frontend into checked Kata execution IR before run;
- keep runtime authority in Kata's API/SDK, ledger, workspace, and memory state;
- treat human input as optional steering unless a workflow declares a gate;
- require concrete validation evidence before promoting a candidate;
- keep each autonomous implementation wave bounded and reviewable.
";

const PRODUCT_VALIDATION: &str = r"# Validation Criteria

The starter factory should not claim completion unless it can provide concrete
evidence for the relevant criteria:

- `workflow-checks`: `kata check` and `kata build` pass for the workflow pack.
- `bounded-scope`: implementation work is limited to declared owned paths.
- `review-verdict`: review output explicitly approves or identifies required
  changes.
- `validation-evidence`: deterministic commands, tests, or fixtures prove the
  candidate.
- `workspace-safety`: promotion is blocked when required evidence is missing,
  failing, unknown, or insufficient.
";

const PRODUCT_STEERING: &str = r"# Steering

Use this file as a durable scratchpad for operator context that should be
visible to a factory run. Append bounded, actionable updates such as:

- current product priority;
- files or subsystems in or out of scope;
- validation commands that matter for the wave;
- risks the workflow must consider;
- explicit stop, reduce-scope, repair, park, or promote guidance.

Send the latest steering into a running factory with:

```bash
kata factory steer --current --context-file .kata/product/steering.md
```
";

const MEMORY_INBOX_README: &str = r"# Memory Inbox

Drop JSON `MemoryProposal` files here when external tools or humans need to
seed native Kata memory through the file bridge.

Import proposals into the running installed main with:

```bash
kata memory import-inbox --dir .kata/memory/inbox
```

Only `.json` files are imported. Native memory state lives in the API/SDK store;
this directory is not authoritative after import.
";

const MEMORY_OBJECTIVE_PROPOSAL: &str = r#"{
  "proposal_id": "kata-init-objective",
  "object": {
    "id": "kata-init-objective",
    "kind": "objective",
    "status": "active",
    "title": "Project software factory objective",
    "body": {
      "summary": "Drive this repository toward a durable autonomous software factory.",
      "product_context": [
        ".kata/product/objective.md",
        ".kata/product/validation.md"
      ],
      "default_workflow": "std.software_factory.kata_self_improve"
    },
    "tags": [
      "kata-init",
      "software-factory",
      "objective"
    ],
    "provenance": {
      "source_kind": "external_file",
      "source_id": "kata init",
      "path": ".kata/memory/inbox/000-objective.json"
    }
  },
  "source_file": ".kata/memory/inbox/000-objective.json"
}
"#;

const MEMORY_VALIDATION_PROPOSAL: &str = r#"{
  "proposal_id": "kata-init-validation-criteria",
  "object": {
    "id": "kata-init-validation-criteria",
    "kind": "validation_criterion",
    "status": "active",
    "title": "Starter factory validation criteria",
    "body": {
      "criteria": [
        "workflow-checks",
        "bounded-scope",
        "review-verdict",
        "validation-evidence",
        "workspace-safety"
      ],
      "source": ".kata/product/validation.md"
    },
    "tags": [
      "kata-init",
      "software-factory",
      "validation"
    ],
    "provenance": {
      "source_kind": "external_file",
      "source_id": "kata init",
      "path": ".kata/memory/inbox/010-validation-criteria.json"
    }
  },
  "source_file": ".kata/memory/inbox/010-validation-criteria.json"
}
"#;

/// The filesystem outcome of scaffolding a project — every path the
/// non-`--print` init path creates or backs up. Shared by the human `kata init`
/// printer and the contract-facing [`author_for_contract`] binding so both faces
/// perform byte-identical filesystem work; only the human path prints.
///
/// `pub(crate)` for `kata host setup`'s absent-config arm, which performs the
/// same filesystem work rather than re-scaffolding a second way.
pub(crate) struct ScaffoldedProject {
    config: PathBuf,
    data_dir: PathBuf,
    workflows_dir: PathBuf,
    product_dir: PathBuf,
    memory_inbox_dir: PathBuf,
    memory_projection_dir: PathBuf,
    starter_workflows: Vec<PathBuf>,
    starter_files: Vec<PathBuf>,
    backup: Option<PathBuf>,
    /// What [`declare_kata_artifacts_in_gitignore`] did about the paths this
    /// configuration makes kata write into the operator's repository.
    ignore_declaration: IgnoreDeclaration,
}

/// The outcome of declaring kata's own artifact roots to the target repository.
///
/// Three states, because there are three genuinely different things to tell an
/// operator, and collapsing any two of them is how a first run comes to lie.
enum IgnoreDeclaration {
    /// There is no repository to declare anything to, or git declined to answer.
    /// Carries the reason so `next:` can say so instead of pretending.
    NotApplicable(String),
    /// Every root was already ignored. Nothing was written.
    AlreadyDeclared,
    /// These patterns were appended to this `.gitignore`.
    Wrote {
        gitignore: PathBuf,
        patterns: Vec<String>,
    },
}

/// Perform the project scaffolding filesystem work (no stdout side effects):
/// render the config, create the directory tree, write the config + starter
/// workflows + product/memory files, and validate the generated config. The
/// `config` path is assumed already normalized.
pub(crate) fn scaffold_project(config: &Path, force: bool) -> Result<ScaffoldedProject> {
    let config_dir = config.parent().unwrap_or_else(|| Path::new("."));
    let data_dir = config_dir.join("data");
    let workflows_dir = config_dir.join("workflows");
    let product_dir = config_dir.join("product");
    let memory_dir = config_dir.join("memory");
    let memory_inbox_dir = memory_dir.join("inbox");
    let memory_projection_dir = memory_dir.join("projections");
    // Paths in kata.toml are resolved from the config directory. Keep the
    // generated spelling independent of the caller's working directory while
    // creating the corresponding absolute/project-relative directories here.
    let rendered = render_local_config(Path::new("data"))?;

    fs::create_dir_all(config_dir)
        .with_context(|| format!("creating config directory {}", config_dir.display()))?;
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data directory {}", data_dir.display()))?;
    fs::create_dir_all(&workflows_dir)
        .with_context(|| format!("creating workflow directory {}", workflows_dir.display()))?;
    fs::create_dir_all(&product_dir).with_context(|| {
        format!(
            "creating product context directory {}",
            product_dir.display()
        )
    })?;
    fs::create_dir_all(&memory_inbox_dir).with_context(|| {
        format!(
            "creating memory inbox directory {}",
            memory_inbox_dir.display()
        )
    })?;
    fs::create_dir_all(&memory_projection_dir).with_context(|| {
        format!(
            "creating memory projection directory {}",
            memory_projection_dir.display()
        )
    })?;

    let backup = write_config(config, &rendered, force)?;
    let starter_workflows = write_starter_workflows(&workflows_dir)?;
    let starter_files = write_starter_project_files(&product_dir, &memory_inbox_dir)?;
    let snapshot = ConfigManager::load(config)
        .with_context(|| {
            format!(
                "validating generated config with ConfigManager::load({})",
                config.display()
            )
        })?
        .snapshot();
    let ignore_declaration = declare_kata_artifacts_in_gitignore(&snapshot)?;

    Ok(ScaffoldedProject {
        config: config.to_path_buf(),
        data_dir,
        workflows_dir,
        product_dir,
        memory_inbox_dir,
        memory_projection_dir,
        starter_workflows,
        starter_files,
        backup,
        ignore_declaration,
    })
}

/// Declare kata's own artifact roots to the repository this configuration
/// points kata at, by adding the missing `.gitignore` rules.
///
/// # Why init DOES this rather than telling the operator to
///
/// `kata doctor`'s `target_repo_ignore` row fails a fresh `kata init` project.
/// MEASURED against the real binary: `kata init` inside a git
/// repository, then the `kata doctor` that init's own `next:` list routes to,
/// exits 1 on that row — over `.jj/`, `agents/` and `.kata/data/`, the last of
/// which exists only because init chose where to put it, and which init
/// CREATES. A first run that says "now run
/// doctor" and then fails is the worst available outcome, and it is the first
/// thing a new operator sees.
///
/// Four reasons the write is init's job and not the operator's:
///
/// 1. **init already writes into this repository.** `.kata/kata.toml`,
///    `.kata/data/`, `.kata/workflows/`, `.kata/product/`, `.kata/memory/` —
///    seventeen paths on a default run. Four ignore lines NAMING THOSE SAME
///    DIRECTORIES is not a new intrusion; it is the declaration of what was
///    just created.
/// 2. **There is exactly one correct answer.** The roots come from
///    [`repo_local_artifact_paths`], the one enumerable list, keyed on the
///    configured provider; the pattern comes from
///    [`crate::cli::repo_ignore::ignore_pattern`], the same spelling doctor's
///    remedy prints. Nothing here is a judgement call, and a prompt with one
///    correct answer is a chore, not a choice.
/// 3. **Telling was already tried and already failed.** `kata config check`
///    prints this advisory today (`render_vcs_preflight`), and the tree still
///    shipped a first run whose doctor is red. The row exists because a live
///    `gold-loop` run promoted 46 files / 333 insertions of kata's internals
///    into a fixture repository's trunk.
/// 4. **It stays honest.** init does not assert the property — it makes it
///    true and lets `kata doctor` be the verdict, over the same probe
///    (`cli::repo_ignore`) rather than a second opinion.
///
/// # What it will not do
///
/// It APPENDS, never rewrites: an operator's existing rules survive verbatim
/// and in order. It writes only roots git says are NOT already ignored, so a
/// repository that keeps kata's rules in `.git/info/exclude` — correct, and
/// deliberately admitted by the doctor row — gets nothing added and a re-run
/// adds nothing twice. And when there is no repository to ask, or git declines
/// to answer, it writes NOTHING and returns the reason for `next:` to print,
/// because a decline is not permission to guess.
fn declare_kata_artifacts_in_gitignore(
    snapshot: &kata_types::KataConfig,
) -> Result<IgnoreDeclaration> {
    let repo = snapshot.vcs.jj_repo.as_path();
    let roots = kata_workflow::repo_artifacts::repo_local_artifact_paths(
        &snapshot.vcs,
        snapshot.node.data_dir.as_path(),
    );
    if roots.is_empty() {
        return Ok(IgnoreDeclaration::AlreadyDeclared);
    }

    let answers = match crate::cli::repo_ignore::probe_ignored(repo, &roots) {
        Ok(answers) => answers,
        Err(reason) => return Ok(IgnoreDeclaration::NotApplicable(reason)),
    };
    let patterns: Vec<String> = answers
        .iter()
        .filter(|answer| !answer.is_ignored())
        .map(|answer| crate::cli::repo_ignore::ignore_pattern(&answer.root))
        .collect();
    if patterns.is_empty() {
        return Ok(IgnoreDeclaration::AlreadyDeclared);
    }

    let gitignore = repo.join(".gitignore");
    let existing = match fs::read_to_string(&gitignore) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(err).with_context(|| format!("reading {}", gitignore.display()));
        }
    };
    // A file that does not end in a newline would otherwise have kata's first
    // pattern welded onto the operator's last rule.
    let mut block = String::new();
    if !existing.is_empty() && !existing.ends_with('\n') {
        block.push('\n');
    }
    if !existing.is_empty() {
        block.push('\n');
    }
    block.push_str("# kata writes these inside this repository; `kata doctor`'s\n");
    block.push_str("# `target_repo_ignore` row fails without them. Added by `kata init`.\n");
    for pattern in &patterns {
        block.push_str(pattern);
        block.push('\n');
    }
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gitignore)
        .with_context(|| format!("opening {} for append", gitignore.display()))?;
    handle
        .write_all(block.as_bytes())
        .with_context(|| format!("appending kata's artifact roots to {}", gitignore.display()))?;

    Ok(IgnoreDeclaration::Wrote {
        gitignore,
        patterns,
    })
}

/// `Operation::Author` binding: scaffold a project-local Kata config the same
/// way `kata init` does, but return a typed [`AuthorResponse`] and write NOTHING
/// to stdout (the MCP stdio face reserves stdout for JSON-RPC frames). `print`
/// renders the config without touching the filesystem (`created == false`).
pub(crate) fn author_for_contract(req: &AuthorRequest) -> Result<AuthorResponse, OpError> {
    let config = normalize_relative_path(Path::new(&req.config));
    let config_display = config.display().to_string();

    if req.print {
        // Prove the config renders, but do not write it or print it.
        render_local_config(Path::new("data"))
            .map_err(|e| OpError::engine(format!("kata author: rendering config: {e}")))?;
        return Ok(AuthorResponse {
            config: config_display,
            created: false,
        });
    }

    // A clobber without `force` is a state conflict (exit 4), matching the
    // human `kata init` refusal.
    if config.exists() && !req.force {
        return Err(OpError::conflict(format!(
            "{config_display} already exists; pass force=true to replace it \
             or print=true to inspect the generated config"
        )));
    }

    scaffold_project(&config, req.force)
        .map_err(|e| OpError::engine(format!("kata author: {e}")))?;
    Ok(AuthorResponse {
        config: config_display,
        created: true,
    })
}

/// Create a conservative local Kata project config.
pub(crate) fn run_init_cmd(config: PathBuf, force: bool, print: bool) -> Result<()> {
    let config = normalize_relative_path(&config);

    if print {
        let rendered = render_local_config(Path::new("data"))?;
        print!("{rendered}");
        return Ok(());
    }

    let scaffold = scaffold_project(&config, force)?;
    let config_dir = config.parent().unwrap_or_else(|| Path::new("."));

    println!("initialized kata project");
    println!("  config: {}", scaffold.config.display());
    println!("  default agent: nanocode_openai");
    println!("  data: {}", scaffold.data_dir.display());
    println!("  workflows: {}", scaffold.workflows_dir.display());
    println!("  product: {}", scaffold.product_dir.display());
    println!("  memory inbox: {}", scaffold.memory_inbox_dir.display());
    println!(
        "  memory projections: {}",
        scaffold.memory_projection_dir.display()
    );
    for path in &scaffold.starter_workflows {
        println!("  starter workflow: {}", path.display());
    }
    for path in &scaffold.starter_files {
        println!("  starter file: {}", path.display());
    }
    if let Some(backup) = &scaffold.backup {
        println!("  backup: {}", backup.display());
    }
    // Every path init touched is reported, and the .gitignore is a path init
    // touched. An operator who does not want kata's rules in a tracked file
    // needs to be able to see that they are there.
    match &scaffold.ignore_declaration {
        IgnoreDeclaration::Wrote {
            gitignore,
            patterns,
        } => println!(
            "  ignore rules: {} (+{}: {})",
            gitignore.display(),
            patterns.len(),
            patterns.join(" ")
        ),
        // Say what was NOT done and why, rather than leaving an operator to
        // infer from silence that kata declared something it did not. `kata
        // doctor` reports the same non-observation as a `[warn]`.
        IgnoreDeclaration::NotApplicable(reason) => {
            println!("  ignore rules: not declared — {reason}");
        }
        IgnoreDeclaration::AlreadyDeclared => {}
    }
    println!();
    // `kata config check` is where `render_vcs_preflight` states what the first
    // boot does to the surrounding checkout — the generated config sets
    // `jj_repo = ".."`, so the first `kata serve` colocates jj into whatever
    // git repo the project root already is. That notice existed before this
    // line did and reached nobody, because nothing in init's output named the
    // command that prints it.
    println!("next:");
    for step in next_steps(&config, config_dir) {
        println!("  {step}");
    }

    Ok(())
}

/// The `next:` list `kata init` prints, in the order an operator runs it.
fn next_steps(config: &Path, config_dir: &Path) -> Vec<String> {
    vec![
        format!("kata config check --config {}", config.display()),
        format!("kata doctor --config {}", config.display()),
        "kata check --all".to_string(),
        // The self-contained hello starter needs no bundled stdlib — the first
        // thing that works on a fresh host, before the factory packs are installed.
        format!("kata check {HELLO_WORKFLOW_NAME}"),
        format!("kata check {STARTER_PREFLIGHT_NAME}"),
        format!(
            "kata build {STARTER_WORKFLOW_NAME} --out {}/{}.build.json",
            config_dir.display(),
            STARTER_WORKFLOW_NAME
        ),
        // A fresh init declares no node environment and no provider, and
        // `kata serve` refuses each by name (`node_environment_undeclared`, then
        // `oci_provider_undeclared`). `kata host setup` merges the packaged
        // `[node] environment` into the config and writes the provider exports
        // into `.env`.
        // `kata host setup` and `kata serve` run under a delegated cgroup: kata
        // places each container's cgroup inside the one it runs in, and from an
        // undelegated login shell host setup refuses at `cgroup_v2` and serve
        // refuses to boot.
        format!(
            "{DELEGATED_SCOPE} kata host setup --config {} --install-apparmor (declares [node] environment \
             and installs the provider; kata serve refuses node_environment_undeclared \
             and oci_provider_undeclared without it)",
            config.display()
        ),
        // Boot installs `[node] egress_allow`. Without it the factory packs run
        // below are refused `egress_undeclared`: they author `net = "host"` stages
        // whose effective allowlist would be empty.
        format!(
            "edit {}: list the host:port authorities in [node] egress_allow (the factory \
             runs below are refused egress_undeclared while it is absent or empty)",
            config.display()
        ),
        format!("{DELEGATED_SCOPE} kata serve --config {}", config.display()),
        format!("kata doctor --config {} --online", config.display()),
        format!(
            "kata memory import-inbox --dir {}/memory/inbox",
            config_dir.display()
        ),
        format!("kata factory run {STARTER_PREFLIGHT_NAME} --wait --timeout-secs 900"),
        format!(
            "kata factory run {STARTER_WORKFLOW_NAME} --context-file {}/product/objective.md",
            config_dir.display()
        ),
    ]
}

fn write_config(config: &Path, rendered: &str, force: bool) -> Result<Option<PathBuf>> {
    if config.exists() {
        if !force {
            bail!(
                "{} already exists; pass --force to replace it or --print to inspect the generated config",
                config.display()
            );
        }

        let backup = backup_path(config);
        fs::copy(config, &backup).with_context(|| {
            format!(
                "backing up existing config {} to {}",
                config.display(),
                backup.display()
            )
        })?;
        fs::write(config, rendered)
            .with_context(|| format!("writing config {}", config.display()))?;
        return Ok(Some(backup));
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(config)
        .with_context(|| format!("creating config {}", config.display()))?;
    file.write_all(rendered.as_bytes())
        .with_context(|| format!("writing config {}", config.display()))?;
    Ok(None)
}

fn write_starter_workflows(workflows_dir: &Path) -> Result<Vec<PathBuf>> {
    // The self-contained hello starter is ALWAYS emitted: it is the
    // always-green preflight `kata doctor` compiles on a fresh dir and the
    // standalone starter that works before any bundled pack is installed.
    let mut files = vec![write_once(
        &workflows_dir.join(HELLO_WORKFLOW_FILE),
        HELLO_WORKFLOW,
        "hello starter workflow",
    )?];
    files.push(write_once(
        &workflows_dir.join(STARTER_WORKFLOW_FILE),
        STARTER_WORKFLOW,
        "starter workflow",
    )?);
    files.push(write_once(
        &workflows_dir.join(STARTER_PREFLIGHT_FILE),
        STARTER_PREFLIGHT_WORKFLOW,
        "starter preflight workflow",
    )?);
    // Additively seed the curated example starters the install advertises via
    // `workflows/examples/MANIFEST.toml`. When the examples directory is absent
    // (a bin-only copy with no `share/kata/examples`) or the manifest is
    // unparseable, this degrades to a no-op: the embedded hello above already
    // guarantees a standalone, doctor-green starter.
    if let Some(examples_dir) = find_examples_dir() {
        files.extend(seed_example_starters(workflows_dir, &examples_dir));
    }
    Ok(files)
}

/// Copy curated example starters advertised by `workflows/examples/MANIFEST.toml`
/// (a sibling of the bundled workflow roots) into the project workflow dir.
///
/// This is a defensive, best-effort seam: the manifest schema is owned by the
/// example-pack library item, so any missing manifest, parse failure, or
/// missing referenced file degrades to seeding nothing. The embedded
/// [`HELLO_WORKFLOW`] is the guaranteed graceful fallback, so a no-op here
/// still leaves `kata init` standalone and `kata doctor` green.
///
/// `examples_dir` is injected rather than resolved here so the seeding rule is
/// testable against a fixture tree — in particular that it reads the PLURAL
/// `[[starters]]` key (see [`ExampleManifest`]).
fn seed_example_starters(workflows_dir: &Path, examples_dir: &Path) -> Vec<PathBuf> {
    let manifest_path = examples_dir.join("MANIFEST.toml");
    let Ok(raw) = fs::read_to_string(&manifest_path) else {
        return Vec::new();
    };
    let Ok(manifest) = toml::from_str::<ExampleManifest>(&raw) else {
        return Vec::new();
    };

    let mut seeded = Vec::new();
    for starter in manifest.starters {
        // Only seed a bare `<name>.star` file living directly in the examples
        // dir — reject anything with path components (`/`, `..`) so a manifest
        // entry can never write outside the project workflow dir.
        let entry = Path::new(&starter.file);
        let is_bare = entry.file_name() == Some(std::ffi::OsStr::new(&starter.file));
        let is_star = entry
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("star"));
        if !(is_bare && is_star) {
            continue;
        }
        let source = examples_dir.join(&starter.file);
        let Ok(contents) = fs::read_to_string(&source) else {
            continue;
        };
        let dest = workflows_dir.join(&starter.file);
        if let Ok(path) = write_once(&dest, &contents, "example starter workflow") {
            seeded.push(path);
        }
    }
    seeded
}

/// The curated starter subset advertised by `workflows/examples/MANIFEST.toml`.
///
/// The key is **`[[starters]]`, PLURAL** — the field below carries no
/// `#[serde(rename)]`, so a manifest written with the singular `[[starter]]` is
/// valid TOML that parses without error and seeds NOTHING, which is exactly
/// the shape of a silently-green defect;
/// `seed_example_starters_reads_the_plural_starters_key` pins the plural key.
///
/// Tolerant by construction (`#[serde(default)]`): unknown keys are ignored and
/// a missing `[[starters]]` list yields an empty seed set so a schema the
/// example-pack sibling extends later never breaks `kata init`.
#[derive(Debug, Default, serde::Deserialize)]
struct ExampleManifest {
    #[serde(default)]
    starters: Vec<ExampleStarter>,
}

#[derive(Debug, serde::Deserialize)]
struct ExampleStarter {
    /// The example's `.star` file name, relative to the examples directory.
    file: String,
}

/// Resolve the `workflows/examples` directory as a sibling of a bundled
/// workflow root the loader would search. Mirrors the installed
/// (`share/kata/examples`) and dev (`workflows/examples`) sibling layouts.
///
/// The project (`./.kata/workflows`) and user (`$HOME/.kata/workflows`) roots
/// are excluded by path — examples ship only in the bundled tier, so a stray
/// `$HOME/.kata/examples/MANIFEST.toml` must never seed a freshly-`init`ed
/// project. Excluding by path (rather than a fixed `skip(N)`) stays correct
/// whether or not `$HOME` contributes a user root.
fn find_examples_dir() -> Option<PathBuf> {
    use kata_program::library::WorkflowLibrary;
    let project_root = std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join(".kata").join("workflows"));
    let user_root = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".kata").join("workflows"));
    for root in WorkflowLibrary::default_roots().roots() {
        if project_root.as_deref() == Some(root.as_path())
            || user_root.as_deref() == Some(root.as_path())
        {
            continue;
        }
        // A bundled root is `<base>/workflows` (installed: `<base>=share/kata`)
        // or `<repo>/workflows/std`; the examples dir is its `examples`
        // sibling. Try both the root's parent and the root itself as the base.
        // The examples dir is ALSO a resolution root in its own right now, so
        // it appears in this list directly — the parent-based probe still
        // matches it first via its `workflows`/`std` sibling, and either way
        // the returned directory is the same one.
        for base in [root.parent(), Some(root.as_path())].into_iter().flatten() {
            let candidate = base.join("examples");
            if candidate.join("MANIFEST.toml").is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn write_starter_project_files(
    product_dir: &Path,
    memory_inbox_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let files = [
        write_once(
            &product_dir.join("README.md"),
            PRODUCT_README,
            "product README",
        )?,
        write_once(
            &product_dir.join("objective.md"),
            PRODUCT_OBJECTIVE,
            "product objective",
        )?,
        write_once(
            &product_dir.join("validation.md"),
            PRODUCT_VALIDATION,
            "product validation criteria",
        )?,
        write_once(
            &product_dir.join("steering.md"),
            PRODUCT_STEERING,
            "product steering",
        )?,
        write_once(
            &memory_inbox_dir.join("README.md"),
            MEMORY_INBOX_README,
            "memory inbox README",
        )?,
        write_once(
            &memory_inbox_dir.join("000-objective.json"),
            MEMORY_OBJECTIVE_PROPOSAL,
            "memory objective proposal",
        )?,
        write_once(
            &memory_inbox_dir.join("010-validation-criteria.json"),
            MEMORY_VALIDATION_PROPOSAL,
            "memory validation proposal",
        )?,
    ];
    Ok(files.into_iter().collect())
}

fn write_once(path: &Path, contents: &str, label: &str) -> Result<PathBuf> {
    if path.exists() {
        return Ok(path.to_path_buf());
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {label} {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing {label} {}", path.display()))?;
    Ok(path.to_path_buf())
}

/// The `[agents.default]` block `kata init` writes: kata's embedded harness on
/// kata's own ChatGPT login.
///
/// No launch of its own and no vendor closure: the kind fixes the launch, the
/// agent loop runs in the worker, and its capsule holds only the tool host and
/// the model's tool processes. The credential is kata's own
/// login, which `kata login openai` writes; a turn refuses
/// `credential_unavailable` naming that command until it exists.
const NANOCODE_OPENAI_AGENT_BLOCK: &str = "[agents.default]\nadapter = \"nanocode_openai\"\nmodel = \"gpt-6-luna\"\nreasoning_effort = \"medium\"\ncredential = { mode = \"subscription\", source = \"kata_login\" }\n# Log kata in once: `kata login openai` (ChatGPT), or `kata login openai --api-key < key-file`\n# with `mode = \"api_key\"`.\n";

/// The role labels shipped packs select where they split work across model
/// agents: `reviewer` judges a change, `gate` decides a loop or a route.
/// `kata init` declares each as the `[agents.default]` block under its own
/// label, so no shipped pack selects a model label a fresh node lacks
/// (agent-change's header-declared `change-agent` aside; a `net = "host"` pack
/// still needs `[node] egress_allow`), and an operator points one role at
/// another model by editing that one block.
pub(crate) const ROLE_AGENT_LABELS: &[&str] = &["reviewer", "gate"];

/// One `[agents.<label>]` block per [`ROLE_AGENT_LABELS`] entry, each the
/// embedded-harness block `[agents.default]` carries.
fn role_agent_blocks() -> String {
    ROLE_AGENT_LABELS
        .iter()
        .map(|label| {
            NANOCODE_OPENAI_AGENT_BLOCK.replacen(
                "[agents.default]",
                &format!("[agents.{label}]"),
                1,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_local_config(data_dir: &Path) -> Result<String> {
    let cwd = std::env::current_dir().context("resolving current working directory")?;
    let node_id = sanitize_node_id(&cwd);
    let data_dir = toml_string(&path_to_string(data_dir));
    let default_agent = NANOCODE_OPENAI_AGENT_BLOCK;
    let role_agents = role_agent_blocks();

    Ok(format!(
        r#"[node]
id = "{node_id}"
data_dir = "{data_dir}"
# This node runs every stage as a capsule bound to ONE declared Nix
# environment — the shipped `oci` profile is the only execution plane. A
# generated config cannot invent the closure, so `kata init` declares none and
# `kata serve` refuses `node_environment_undeclared` until one exists. Declare
# it as `[node] environment = {{ label = .., system = "x86_64-linux",
# nixpkgs_attribute = .., store_paths = [..], path_prepend = [..],
# integrity_policy = {{ .. }} }}` — the operator guide's `Execution profiles`
# section walks the declaration, and `kata sandbox install-external-provider`
# prints the provider exports the capsule route reads.
#
# A stage authored `net = "host"` reaches exactly the `host:port` authorities
# `[node] egress_allow` names — an absent list is `egress_undeclared` at
# check, which the seeded factory packs' `net = "host"` stages report until
# the operator declares theirs:
# egress_allow = ["static.crates.io:443", "index.crates.io:443"]

[workers]
dispatch_deadline_ms = 30000
assignment_start_deadline_ms = 900000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000
max_workers = 4

# `kata serve` starts one node — a `kata-worker` process beside it, dialing
# `<data_dir>/node.sock` — and starts it again when it ends. Capsules and the
# agent harness run there, never in the main.
[[workers.transports]]
type = "supervised_node"

[api]
bind = "127.0.0.1:8400"

[api.auth]
type = "disabled"

# The model agent a stage selecting no `agent = ".."` runs: kata's embedded
# harness, whose `adapter` names its provider — `nanocode_openai` or
# `nanocode_anthropic`.
{default_agent}
# The role agents shipped packs select by name where they split work:
# `reviewer` judges a change, `gate` decides a loop or route. Each starts as the
# `default` harness; point one at a stronger model by editing its block.
{role_agents}
# The reserved deterministic route `agent = "shell"` stages run under. It takes
# no key, and the label is available even without this block.
[agents.shell]

[vcs]
jj_repo = ".."
# Optional. Unset means "ask this repository which branch is trunk"; kata
# refuses rather than guessing when the repository has no single answer. See
# `kata doctor`'s `trunk_resolution` row.
# trunk = "main"

[telemetry]
enabled = false
log_level = "info"
log_json = false
export = "stdout"
metrics_bind = "127.0.0.1:9400"
otlp_endpoint = ""
"#
    ))
}

fn sanitize_node_id(cwd: &Path) -> String {
    let raw = cwd
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("kata-local");
    let mut out = String::new();
    let mut previous_dash = false;
    for ch in raw.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            Some(ch.to_ascii_lowercase())
        } else if ch == '-' || ch == '_' {
            Some('-')
        } else {
            None
        };
        if let Some(ch) = mapped {
            if ch == '-' {
                if previous_dash {
                    continue;
                }
                previous_dash = true;
            } else {
                previous_dash = false;
            }
            out.push(ch);
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "kata-local".to_string()
    } else {
        trimmed.to_string()
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn toml_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn backup_path(config: &Path) -> PathBuf {
    let now_ms = kata_types::time::now_ms();
    let file_name = config
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("kata.toml");
    config.with_file_name(format!("{file_name}.bak.{now_ms}"))
}

#[cfg(test)]
mod tests {
    use super::{
        NANOCODE_OPENAI_AGENT_BLOCK, ROLE_AGENT_LABELS, render_local_config, sanitize_node_id,
        toml_string,
    };

    /// A fresh init declares no `[node] environment` and no provider, which
    /// `kata serve` refuses, and the factory packs author `net = "host"` stages,
    /// which a node with no `[node] egress_allow` authorities refuses
    /// (`egress_undeclared`); boot is where both are installed. So the printed
    /// list names `kata host setup` and the egress declaration before `kata
    /// serve`, and therefore before either `kata factory run`.
    #[test]
    fn init_names_every_boot_declaration_before_the_node_boots() {
        let steps = super::next_steps(
            std::path::Path::new(".kata/kata.toml"),
            std::path::Path::new(".kata"),
        );
        let position = |needle: &str| {
            steps
                .iter()
                .position(|step| step.contains(needle))
                .unwrap_or_else(|| panic!("no next step mentions `{needle}`: {steps:#?}"))
        };
        let host_setup = position("kata host setup --config");
        let egress = position("[node] egress_allow");
        let serve = position("kata serve --config");
        let first_factory_run = position("kata factory run");
        assert!(
            host_setup < serve && egress < serve && serve < first_factory_run,
            "every declaration a fresh node lacks must precede the boot that installs it, \
             and the boot the factory runs: {steps:#?}"
        );
        // The README's spelling, typed out: both commands refuse from an
        // undelegated login shell.
        for step in [&steps[host_setup], &steps[serve]] {
            assert!(
                step.starts_with("systemd-run --user --scope -p Delegate=yes -- kata "),
                "`kata host setup` and `kata serve` must be printed under a delegated scope: \
                 {step}"
            );
        }
    }

    fn parse_default(block: &str) -> kata_types::config::AgentBackendConfig {
        #[derive(serde::Deserialize)]
        struct Doc {
            #[serde(deserialize_with = "kata_types::config::deserialize_agents")]
            agents: std::collections::BTreeMap<String, kata_types::config::AgentBackendConfig>,
        }
        let doc: Doc = toml::from_str(block).unwrap_or_else(|e| {
            panic!("the generated block must be TOML a config reload accepts: {e}\n{block}")
        });
        doc.agents
            .get("default")
            .cloned()
            .expect("a `default` entry")
    }

    /// **The `[agents.default]` block is D1's: the embedded harness on kata's own
    /// login.** It parses to a `nanocode_openai` entry whose launch the kind
    /// fixes, whose credential is
    /// `subscription` over `kata_login`, and it starts with the two lines `just
    /// first-live-proof` patches.
    #[test]
    fn the_nanocode_openai_block_runs_the_harness_on_kata_login() {
        use kata_types::agent::AdapterKind;
        use kata_types::execution_contract::{CredentialSource, TurnCredentialRef};

        let block = NANOCODE_OPENAI_AGENT_BLOCK;
        assert!(
            block.starts_with("[agents.default]\nadapter = \"nanocode_openai\"\n"),
            "{block}"
        );
        assert!(block.contains("`kata login openai`"), "{block}");
        let entry = parse_default(block);
        assert_eq!(entry.capsule_adapter(), Some("nanocode_openai"));
        assert_eq!(
            entry.capsule_launch(),
            Ok(AdapterKind::NanocodeOpenai),
            "the kind fixes the launch"
        );
        assert_eq!(
            entry.capsule_credential_ref().unwrap(),
            Some(TurnCredentialRef {
                mode: kata_types::metering::CredentialMode::Subscription,
                source: CredentialSource::KataLogin,
            })
        );
    }

    /// **`kata init` writes the embedded harness.** A fresh project gets the
    /// `nanocode_openai` block — under kata's own ChatGPT login, model
    /// `gpt-6-luna` at `reasoning_effort = "medium"` — and names no
    /// `codex_app_server` adapter.
    ///
    /// **Would red if:** the rendered config lost the block, or the block's
    /// model or effort moved.
    #[test]
    fn kata_init_defaults_to_nanocode_openai() {
        let rendered = render_local_config(std::path::Path::new("data")).unwrap();
        assert!(rendered.contains(NANOCODE_OPENAI_AGENT_BLOCK), "{rendered}");
        assert!(!rendered.contains("codex_app_server"), "{rendered}");
        let block: toml::Value =
            toml::from_str(NANOCODE_OPENAI_AGENT_BLOCK).expect("the block is TOML");
        let default = &block["agents"]["default"];
        assert_eq!(default["model"].as_str(), Some("gpt-6-luna"), "{block}");
        assert_eq!(
            default["reasoning_effort"].as_str(),
            Some("medium"),
            "{block}"
        );
    }

    /// **`kata init`'s output loads through the one config door and validates.**
    /// The rendered `kata.toml` parses through `parse_kata_config` — the door
    /// every loader takes — to a harness `[agents.default]` on `nanocode_openai`
    /// and the shell route under `[agents.shell]`, and passes `validate()`.
    ///
    /// **Would red if:** init wrote a key the agents parse refuses (watched: the
    /// `type = "codex"` and `type = "shell"` lines, refused `agent_type_removed`
    /// once the key was removed), or the labels stopped deciding the backends.
    #[test]
    fn kata_init_output_loads_through_the_config_door() {
        let rendered = render_local_config(std::path::Path::new("data")).unwrap();
        let config =
            kata_types::config::parse_kata_config(&rendered, std::path::Path::new("kata.toml"))
                .unwrap_or_else(|error| panic!("`kata init` output loads: {error}\n{rendered}"));
        config
            .validate()
            .unwrap_or_else(|error| panic!("`kata init` output validates: {error}"));
        assert!(
            matches!(
                &config.agents["default"],
                kata_types::config::AgentBackendConfig::Harness { adapter: Some(adapter), .. }
                    if adapter == "nanocode_openai"
            ),
            "{:?}",
            config.agents["default"]
        );
        assert_eq!(
            config.agents["shell"],
            kata_types::config::AgentBackendConfig::Shell {}
        );
    }

    /// **The BYO agent-run surface accepts exactly the model labels `kata init`
    /// declares.** `POST /api/v1/agents/run` admits a label from
    /// `SUPPORTED_AGENT_RUN_LABELS`, and a label runs only where the main
    /// declares its block — so the list is `default` and every
    /// [`ROLE_AGENT_LABELS`] entry, the model agents a fresh node has.
    ///
    /// **Would red if:** the list named a label init never writes (watched: the
    /// vendor-era `["codex", "claude_code"]`, which no fresh node declares).
    #[test]
    fn the_agent_run_labels_are_the_model_labels_kata_init_writes() {
        let written: Vec<&str> = std::iter::once("default")
            .chain(ROLE_AGENT_LABELS.iter().copied())
            .collect();
        assert_eq!(kata_types::agent_run::SUPPORTED_AGENT_RUN_LABELS, written);
    }

    /// **`kata init` declares every role label, as the `default` harness.** A
    /// fresh config carries `[agents.reviewer]` and `[agents.gate]` beside
    /// `[agents.default]`, each the same table, so a pack that splits work by
    /// role selects only labels a fresh node declares.
    ///
    /// **Would red if:** a role block went missing or drifted from `default`.
    #[test]
    fn kata_init_declares_every_role_agent_as_the_default_harness() {
        let rendered = render_local_config(std::path::Path::new("data")).unwrap();
        let config: toml::Value = toml::from_str(&rendered).expect("the config is TOML");
        let agents = config["agents"].as_table().expect("an [agents] table");
        let mut labels: Vec<&str> = agents.keys().map(String::as_str).collect();
        labels.sort_unstable();
        assert_eq!(
            labels,
            ["default", "gate", "reviewer", "shell"],
            "{rendered}"
        );
        for label in ROLE_AGENT_LABELS {
            assert_eq!(agents[*label], agents["default"], "[agents.{label}]");
        }
    }

    /// Every `agent = "<label>"` a shipped pack spells (stage, role, and the
    /// factory's `*_agent` parameters alike) — read as text, so a label inside a
    /// comment counts too.
    fn spelled_agent_labels(source: &str) -> Vec<String> {
        let mut labels = Vec::new();
        let mut rest = source;
        while let Some(at) = rest.find("agent") {
            rest = &rest[at + "agent".len()..];
            let after_eq = rest.trim_start().strip_prefix('=').map(str::trim_start);
            if let Some(quoted) = after_eq.and_then(|value| value.strip_prefix('"'))
                && let Some(end) = quoted.find('"')
            {
                labels.push(quoted[..end].to_owned());
            }
        }
        labels
    }

    /// The labels a shipped pack selects that `kata init` does not write, each
    /// named by the pack's header for the operator to declare, keyed by the
    /// pack's path under `workflows/`.
    const PACK_HEADER_LABELS: &[(&str, &str)] = &[("std/agent-change.star", "change-agent")];

    /// **Every agent label a shipped pack selects is one a fresh node has.** Each
    /// `agent = ".."` under `workflows/**` is `default`, a reserved label
    /// (`shell`, `workspace_effect`), a [`ROLE_AGENT_LABELS`] entry `kata init`
    /// writes, or that pack's own [`PACK_HEADER_LABELS`] entry. Anything else
    /// refuses `adapter_undeclared` on a node `kata init` made.
    ///
    /// **Would red if:** a pack selected a label init never writes and the
    /// allowlist does not name for that pack (watched red on the base packs:
    /// 54 sites, `codex` in factory.star, kata-loop-lite and the examples among
    /// them, `claude`, `codex-spark`, and gatesplit's `codex-gate`).
    #[test]
    fn shipped_packs_select_only_labels_kata_init_writes_or_the_pack_declares() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("workflows/ is readable") {
                let path = entry.expect("a directory entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "star") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workflows");
        let mut packs = Vec::new();
        walk(&root, &mut packs);
        let mut checked = 0_usize;
        let mut refused = Vec::new();
        for pack in &packs {
            let source = std::fs::read_to_string(pack).expect("a pack is readable");
            let relative = pack
                .strip_prefix(&root)
                .expect("a walked pack is under workflows/")
                .to_str()
                .expect("a pack path is UTF-8");
            for label in spelled_agent_labels(&source) {
                checked += 1;
                let written = ["default", "shell", "workspace_effect"].contains(&label.as_str())
                    || ROLE_AGENT_LABELS.contains(&label.as_str())
                    || PACK_HEADER_LABELS.contains(&(relative, label.as_str()));
                if !written {
                    refused.push(format!("{}: agent = \"{label}\"", pack.display()));
                }
            }
        }
        assert!(
            checked > 100,
            "the walk read only {checked} labels: {packs:?}"
        );
        assert!(
            refused.is_empty(),
            "labels no fresh node declares:\n{}",
            refused.join("\n")
        );
    }

    /// **The model id `kata init` writes is one nanocode knows.** The block's `model` parses through nanocode's own
    /// `Model::known` (`nanocode_backend_codex::Model`, re-exported from
    /// `nanocode-types-core`'s `Model::known` at the vendored rev 2ac77424), not
    /// only through its `FromStr`, which maps every other non-empty id to a
    /// `Custom` model and so would hand a misspelt or retired id to the
    /// provider. A nanocode bump that drops or renames the id reds here.
    ///
    /// **Would red if:** the block named an id nanocode's catalog does not hold
    /// (watched: `gpt-6-lune`), or a bump retired `gpt-6-luna`.
    #[test]
    fn the_nanocode_init_model_is_one_nanocode_knows() {
        let block: toml::Value =
            toml::from_str(NANOCODE_OPENAI_AGENT_BLOCK).expect("the block is TOML");
        let model = block["agents"]["default"]["model"]
            .as_str()
            .expect("the block names a model");
        assert!(
            matches!(
                nanocode_backend_codex::Model::known(model),
                Some(nanocode_backend_codex::Model::Luna)
            ),
            "`{model}` is not nanocode's `Luna` in its `Model::known` catalog at the vendored rev"
        );
    }

    /// **RF17: the README's embedded-harness block is the block `kata init`
    /// writes, and it checks.** The `README.md` TOML example that declares
    /// `adapter = "nanocode_openai"` parses to the same `[agents.default]`
    /// table as [`NANOCODE_OPENAI_AGENT_BLOCK`] (adapter, model
    /// `gpt-6-luna`, `reasoning_effort = "medium"`, the `kata_login`
    /// credential), and a config rendered around the README's block passes
    /// `kata config check` (`config_check`), read off the file the README
    /// ships, not a copy.
    ///
    /// **Would red if:** the README's block drifted from what init writes
    /// (watched: the README before this cell, with no `model` and a
    /// `kata_login` `api_key` credential), or stopped parsing as a config.
    #[test]
    fn the_readme_nanocode_block_is_the_init_block_and_checks() {
        let readme = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"),
        )
        .expect("the README is readable");
        let block = readme
            .split("```toml\n")
            .skip(1)
            .filter_map(|rest| rest.split_once("```").map(|(block, _)| block))
            .find(|block| block.contains("adapter = \"nanocode_openai\""))
            .expect("the README carries a nanocode_openai TOML block");
        let block = block
            .lines()
            .map(|line| line.strip_prefix("  ").unwrap_or(line))
            .fold(String::new(), |mut block, line| {
                block.push_str(line);
                block.push('\n');
                block
            });
        let readme_table: toml::Value = toml::from_str(&block).expect("the README block is TOML");
        let init_table: toml::Value =
            toml::from_str(NANOCODE_OPENAI_AGENT_BLOCK).expect("the init block is TOML");
        assert_eq!(
            readme_table["agents"]["default"], init_table["agents"]["default"],
            "the README's block is the one `kata init` writes:\n{block}"
        );
        let dir = tempfile::tempdir().unwrap();
        let rendered = render_local_config(&dir.path().join("data"))
            .unwrap()
            .replace(NANOCODE_OPENAI_AGENT_BLOCK, &block);
        assert!(rendered.contains(&block), "{rendered}");
        let config = dir.path().join("kata.toml");
        std::fs::write(&config, rendered).unwrap();
        crate::cli::config_check::config_check(&config)
            .unwrap_or_else(|error| panic!("the README's block checks: {error:#}"));
    }

    #[test]
    fn sanitize_node_id_keeps_ascii_slug() {
        assert_eq!(
            sanitize_node_id(std::path::Path::new("/tmp/Kata Workspace!!")),
            "kataworkspace"
        );
        assert_eq!(
            sanitize_node_id(std::path::Path::new("/tmp/kata_workspace")),
            "kata-workspace"
        );
    }

    #[test]
    fn toml_string_escapes_quotes_and_backslashes() {
        assert_eq!(toml_string(r#"a\b"c"#), r#"a\\b\"c"#);
    }

    /// The embedded starter templates must compile as native-DSL workflows
    /// against the bundled stdlib. The
    /// templates call `software_factory_workflow(...)` at module scope so
    /// `workflow()` drains during evaluation and the native path engages.
    /// Reverting them to a `def workflow_def(): return ...` wrapper would
    /// leave the builder undrained, fall through to the (removed) dict path,
    /// and fail to compile here.
    #[test]
    fn starter_templates_compile_as_native_workflows() {
        use kata_program::library::WorkflowLibrary;
        use kata_program::preflight::build_starlark_workflow_compiled_artifact;

        // `kata init` seeds NO `execution_profile`, so this node-less
        // compile reads the shipped default — `oci` — the profile the
        // templates' users judge them under.
        let roots = WorkflowLibrary::default_roots().roots().to_vec();
        for (name, file, src) in [
            (
                super::STARTER_WORKFLOW_NAME,
                super::STARTER_WORKFLOW_FILE,
                super::STARTER_WORKFLOW,
            ),
            (
                super::STARTER_PREFLIGHT_NAME,
                super::STARTER_PREFLIGHT_FILE,
                super::STARTER_PREFLIGHT_WORKFLOW,
            ),
        ] {
            let artifact = build_starlark_workflow_compiled_artifact(src, file, &roots)
                .unwrap_or_else(|e| panic!("starter template {file} failed to compile: {e}"));
            assert_eq!(
                artifact.name, name,
                "{file} compiled under an unexpected name"
            );
            assert!(
                artifact.stage_count > 0,
                "{file} compiled to zero stages — native path did not engage",
            );
        }
    }

    /// A landmine, pinned. `ExampleManifest` reads `starters`, PLURAL,
    /// with no `#[serde(rename)]`, and `[[starter]]`, singular, is the spelling
    /// a reader writes by default.
    ///
    /// A manifest written the singular way is valid TOML: it parses without
    /// error, it satisfies the manifest/disk sync test (which scans `file =`
    /// lines regardless of table name), and it seeds NOTHING. That is a defect
    /// that ships green, so it gets a test that can only pass on the plural key.
    #[test]
    fn seed_example_starters_reads_the_plural_starters_key() {
        fn seed_with(table: &str) -> Vec<String> {
            let examples = tempfile::tempdir().expect("examples tmpdir");
            let project = tempfile::tempdir().expect("project tmpdir");
            std::fs::write(examples.path().join("only-example.star"), "# example\n")
                .expect("write example");
            std::fs::write(
                examples.path().join("MANIFEST.toml"),
                format!("[[{table}]]\nfile = \"only-example.star\"\n"),
            )
            .expect("write manifest");

            super::seed_example_starters(project.path(), examples.path())
                .iter()
                .map(|path| {
                    path.file_name()
                        .expect("seeded file name")
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        }

        assert_eq!(
            seed_with("starters"),
            vec!["only-example.star".to_string()],
            "the PLURAL key is the one serde reads — it must seed the named file"
        );
        assert!(
            seed_with("starter").is_empty(),
            "the singular `[[starter]]` key seeds nothing; if this ever starts \
             seeding, the manifest and guard prose must be updated to match"
        );
    }

    /// The shipped `workflows/examples/MANIFEST.toml` actually seeds — the
    /// plural-key test above proves the mechanism, this proves the artifact
    /// uses it, so a manifest that silently loses its `[[starters]]` rows is
    /// caught here rather than by an operator on a fresh `kata init`.
    #[test]
    fn the_shipped_example_manifest_declares_a_starter_subset() {
        let examples = super::find_examples_dir()
            .expect("the examples dir must resolve from a dev-checkout test exe");
        let project = tempfile::tempdir().expect("project tmpdir");
        let seeded = super::seed_example_starters(project.path(), &examples);
        assert!(
            !seeded.is_empty(),
            "the shipped manifest at {} declares no `[[starters]]` rows, so \
             `kata init` seeds nothing from the example pack",
            examples.join("MANIFEST.toml").display()
        );
        for path in &seeded {
            assert!(path.exists(), "seeded starter {} is absent", path.display());
        }
    }
}
