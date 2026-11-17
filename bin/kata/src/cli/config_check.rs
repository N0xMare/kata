//! `kata config check` command and supporting helpers.
//!
//! Validates a kata config file end-to-end (TOML parse +
//! `KataConfig::validate`, then the CHECK's config-only judgement of every
//! harness `[agents.<label>]` block), prints a typed summary, and
//! surfaces a few pre-flight signals operators care about.

use std::path::Path;

use anyhow::{Context, Result};
use kata_core::ConfigManager;
use kata_program::library::WorkflowLibrary;
use kata_types::config::{AgentBackendConfig, ApiAuthConfig, VcsConfig};

use crate::backend_factory::agent_backend_kind;

/// Pretty-print a typed config summary to stdout.
pub(crate) fn print_config_summary_typed(cfg: &kata_types::KataConfig) {
    println!("--- kata config summary (typed) ---");
    println!("node.id       = {}", cfg.node.id);
    println!("node.data_dir = {}", cfg.node.data_dir.display());
    println!("api.bind      = {}", cfg.api.bind);
    println!(
        "workers.transports = {} configured",
        cfg.workers.transports.len()
    );
    println!("agents  = {} defined", cfg.agents.len());
    for line in render_agent_listing(&cfg.agents, "  ") {
        println!("{line}");
    }
    for line in render_vcs_preflight(&cfg.vcs, &cfg.node.data_dir, "") {
        println!("{line}");
    }
    println!("-----------------------------------");
}

/// Model setting for the per-agent summary. Returns the configured
/// model when set; otherwise `<default>` to make explicit that the
/// harness's default applies. `shell` has no model and reports `<n/a>`.
pub(crate) fn agent_backend_model(cfg: &AgentBackendConfig) -> String {
    match cfg {
        AgentBackendConfig::Harness { model, .. } => match model {
            Some(m) => m.clone(),
            None => "<default>".to_string(),
        },
        AgentBackendConfig::Shell { .. } => "<n/a>".to_string(),
    }
}

/// Build the per-agent summary lines printed under the `agents = N
/// defined` header. Each agent gets one line of the form
/// `<indent><name> -> <backend_type> (model: <model>)`, with the
/// resolved-default agent (either an explicit `default` key or the
/// sole entry, mirroring installed-main and scratch selection)
/// flagged `[default]`.
///
/// Iteration is alphabetical because `cfg.agents` is a `BTreeMap`,
/// matching the stable order operators see in any other summary.
///
/// # The no-model-agent advisory
///
/// A config whose only agent is `shell` has NO model-backed agent, and the
/// listing would otherwise be a single `shell -> shell` line carrying a
/// `[default]` marker — accurate (the registry's sole-entry rule really does
/// route unqualified stages there) and easy to read as "models work". The
/// advisory lines below say so plainly: the config states what it can and
/// cannot run, on every `kata config check`,
/// without an operator having to boot first.
#[doc(hidden)]
pub fn render_agent_listing(
    agents: &std::collections::BTreeMap<String, AgentBackendConfig>,
    indent: &str,
) -> Vec<String> {
    if agents.is_empty() {
        return no_model_agent_advisory(indent);
    }
    // Mirror the resolution rule documented in `config/kata.example.toml`:
    // an explicit `default` key wins; otherwise a sole entry is treated
    // as the default. Anything else has no auto-default.
    let default_name: Option<&str> = if agents.contains_key("default") {
        Some("default")
    } else if agents.len() == 1 {
        agents.keys().next().map(String::as_str)
    } else {
        None
    };

    let mut out = Vec::with_capacity(agents.len());
    for (name, backend) in agents {
        let suffix = if Some(name.as_str()) == default_name {
            " [default]"
        } else {
            ""
        };
        out.push(format!(
            "{indent}{name} -> {ty} (model: {model}){suffix}",
            ty = agent_backend_kind(backend),
            model = agent_backend_model(backend),
        ));
    }
    if !agents.values().any(crate::backend_factory::is_model_backed) {
        out.extend(no_model_agent_advisory(indent));
    }
    out
}

/// The plain statement a config with no model-backed `[agents.*]` entry owes
/// its operator. Every line names something they can do or something that will
/// happen; none of it is a warning about a host fact they did not ask for.
fn no_model_agent_advisory(indent: &str) -> Vec<String> {
    vec![
        format!("{indent}NO MODEL-BACKED AGENT IS CONFIGURED."),
        format!(
            "{indent}  RUNS: `agent = \"shell\"` stages, which is the whole `std.hello` starter."
        ),
        format!(
            "{indent}  DOES NOT: any stage selecting a model agent — `kata check --config` \
             refuses it"
        ),
        format!(
            "{indent}  `adapter_undeclared`, and that includes the `std.software_factory.*` \
             starters,"
        ),
        format!("{indent}  whose stages select `agent = \"default\"`."),
        format!("{indent}  FIX: add the `[agents.default]` block `kata init` writes:"),
        format!(
            "{indent}  `adapter = \"nanocode_openai\"`, `credential = {{ mode = \"subscription\", \
             source = \"kata_login\" }}`,"
        ),
        format!("{indent}  then log kata in once with `kata login openai`."),
    ]
}

/// Build VCS preflight lines for `kata config check`.
///
/// jj is the one execution-workspace provider, so the command makes the jj
/// repository path visible before operators boot a daemon that will initialize
/// or mutate a jj repo.
#[doc(hidden)]
pub fn render_vcs_preflight(vcs: &VcsConfig, data_dir: &Path, indent: &str) -> Vec<String> {
    let mut out = Vec::new();
    let jj_exists = vcs.jj_repo.exists();
    let jj_metadata_exists = vcs.jj_repo.join(".jj").is_dir();
    out.push(format!("{indent}vcs.jj_repo = {}", vcs.jj_repo.display()));
    out.push(format!("{indent}vcs.jj_repo.exists = {jj_exists}"));
    out.push(format!("{indent}vcs.jj_repo.has_jj = {jj_metadata_exists}"));
    if vcs.jj_repo.is_relative() {
        out.push(format!(
            "{indent}warning: vcs.jj_repo is relative; it resolves from the daemon launch directory"
        ));
    }
    if !jj_metadata_exists {
        // Say WHAT the initialization does to a directory the operator
        // already owns. "will initialize vcs.jj_repo on first boot" reads
        // as though kata creates something of its own; on a path that
        // already holds a `.git` it does not — `JjBackend::open` calls
        // `Workspace::init_external_git` and imports the repo's HEAD and
        // refs, converting the operator's repository into a COLOCATED jj
        // repo in place. `kata init` writes `jj_repo = ".."`, which
        // resolves to the project root, so the default target of that
        // sentence is the user's own checkout.
        out.push(format!(
            "{indent}warning: native jj provider will initialize vcs.jj_repo on first boot"
        ));
        out.push(format!(
            // kata-spacing: intentional
            "{indent}         if that path already holds a git repo, kata COLOCATES jj into it \
             in place — writing .jj/ and importing the repo's HEAD and refs — and the first \
             execution adds an untracked agents/ tree beside it."
        ));
    }
    // Name WHICH paths kata writes into the operator's repository, derived from
    // the code that CREATES them, and point at the command that VERIFIES the
    // property instead of restating it as advice.
    //
    // The sentence this replaces read "add `.jj/` and `/agents/` to .gitignore
    // if you keep that tree clean", and it lived inside the `!jj_metadata_exists`
    // arm above. Two defects, and the second is the one that cost 46 files: the
    // list was hand-retyped beside the code that creates those paths, and the
    // advice VANISHED the moment `.jj/` existed — so an operator who skipped it
    // on the first boot never saw it again, and nothing anywhere checked. It is
    //
    // It takes `data_dir` because the set is not a function of the backend
    // alone: `kata init` renders `data_dir = "data"` beside the config, so the
    // default project's `operational.db` / `cas/` / `recovery-generations/**` live
    // inside `vcs.jj_repo` too. Naming only the provider's roots understated
    // what kata writes there, and `kata doctor` scored the same short list.
    out.push(format!(
        "{indent}note: kata writes {} inside vcs.jj_repo; `kata doctor` FAILS its \
         `target_repo_ignore` row unless that repository ignores them",
        kata_workflow::repo_artifacts::repo_local_artifact_paths(vcs, data_dir)
            .iter()
            .map(|root| format!("{root}/"))
            .collect::<Vec<_>>()
            .join(" and "),
    ));
    out
}

/// Build the "resolved stdlib roots" lines for `kata config check`.
///
/// Operators need to see WHERE `kata` will look for the workflow
/// standard library before they boot — a fresh-host install that resolves
/// zero workflows is the failure mode this makes visible. Each root is
/// printed with an `[exists]` / `[missing]` marker so the operator can tell
/// at a glance whether the install materialized (e.g. via `just package`).
/// If EVERY root is missing, a loud `WARNING` line names the degrade so it
/// cannot be missed in the summary.
#[doc(hidden)]
pub fn render_stdlib_roots(library: &WorkflowLibrary, indent: &str) -> Vec<String> {
    let roots = library.roots();
    let mut out = Vec::with_capacity(roots.len() + 2);
    out.push(format!(
        "{indent}workflow stdlib roots = {} configured",
        roots.len()
    ));
    for root in roots {
        let marker = if root.is_dir() { "exists" } else { "missing" };
        out.push(format!("{indent}  [{marker}] {}", root.display()));
    }
    if let Some(warning) = kata_program::library::no_roots_present_warning(roots) {
        out.push(format!("{indent}  WARNING: {warning}"));
    }
    out
}

/// Validate a config file and print a short summary on success.
///
/// `ConfigManager::load` both deserialises the TOML into `KataConfig` and
/// runs `KataConfig::validate`, so any failure along either path
/// (missing required field, invalid `api.bind` socket address, empty
/// `workers.transports`, a removed `in_process` transport, …) surfaces as a
/// `KataError::Validation` or `KataError::Config` that bubbles up through
/// `with_context` into the anyhow error chain. The happy-path message
/// therefore genuinely means "parsed AND validated", not just "it was
/// valid TOML".
///
/// Every declared capsule-capable agent block is then judged by
/// [`unservable_agent_blocks`] — the CHECK's own config-only doors. That is a
/// different refused set from validation: such a config LOADS, and boot installs
/// the block unchanged; it is the stages selecting the block that are refused,
/// at check and at admission. So the summary still says "parsed and validated
/// OK", and the command then fails naming every unservable block, its door and
/// that consequence — never "config validation failed".
#[doc(hidden)]
pub fn config_check(path: &std::path::Path) -> Result<()> {
    let config_mgr = ConfigManager::load(path)
        .with_context(|| format!("config validation failed for {}", path.display()))?;
    let cfg = config_mgr.snapshot();
    let unservable = unservable_agent_blocks(&cfg);
    println!("config {} parsed and validated OK", path.display());
    println!("  node.id       = {}", cfg.node.id);
    println!("  node.data_dir = {}", cfg.node.data_dir.display());
    println!("  api.bind      = {}", cfg.api.bind);
    println!("  api.auth      = {}", api_auth_label(&cfg.api.auth));
    println!(
        "  workers.transports = {} configured",
        cfg.workers.transports.len()
    );
    println!("  workers.max_workers = {}", cfg.workers.max_workers);
    // `workers.max_workers` and `runtime.max_concurrent_dispatches` are DIFFERENT
    // units and were routinely conflated because only the first was printed. Print
    // both, adjacent, each labelled with what it actually bounds — and name the
    // thing neither of them bounds, so an operator looking for a running-stage
    // ceiling stops looking here.
    println!(
        "  runtime.max_concurrent_dispatches = {} (concurrent dispatch submissions; NOT running stages)",
        cfg.runtime.max_concurrent_dispatches
    );
    println!(
        "    running stages are bounded per-execution by workflow(max_concurrency=N) in Starlark"
    );

    // Surface resolved agent backends so operators can verify
    // `[agents.<name>]` edits without booting the full system. Header
    // line stays stable (`agents = N defined`) so existing greps keep
    // working; per-agent lines are nested two spaces deeper.
    println!("  agents = {} defined", cfg.agents.len());
    for line in render_agent_listing(&cfg.agents, "    ") {
        println!("{line}");
    }
    for line in render_vcs_preflight(&cfg.vcs, &cfg.node.data_dir, "    ") {
        println!("{line}");
    }

    // Surface the resolved workflow stdlib roots (with existence
    // markers) so operators can confirm a fresh-host install actually
    // materialized the library before booting. Reuses the same
    // `default_roots()` resolution the runtime uses.
    let library = WorkflowLibrary::default_roots();
    for line in render_stdlib_roots(&library, "  ") {
        println!("{line}");
    }

    if unservable.is_empty() {
        return Ok(());
    }
    let blocks = unservable
        .iter()
        .map(|(label, refusal)| format!("`[agents.{label}]`: {refusal}"))
        .collect::<Vec<_>>();
    println!("  unservable agent blocks = {}", blocks.len());
    for block in &blocks {
        println!("    {block}");
    }
    anyhow::bail!(
        "config {} parsed and validated OK, but {} agent block(s) are unservable — every stage \
         that selects one is refused at check and at admission: {}",
        path.display(),
        blocks.len(),
        blocks.join("; ")
    )
}

/// Judge every declared `[agents.<label>]` block by [`judge_agent_block`], under
/// the node facts this config declares — installed through the same funnel `kata
/// check --config` uses — and return each refused block with its refusal, so a
/// block every stage selecting it would be refused is named here, by the same
/// name, before any pack selects it. The refused set is exactly
/// [`judge_agent_block`]'s over every block.
fn unservable_agent_blocks(
    cfg: &kata_types::KataConfig,
) -> Vec<(String, kata_types::error::KataError)> {
    crate::cli::install_node_facts_from_config(cfg);
    cfg.agents
        .iter()
        .filter_map(|(label, agent)| match judge_agent_block(label, agent) {
            Some(Err(refusal)) => Some((label.clone(), refusal)),
            Some(Ok(_)) | None => None,
        })
        .collect()
}

/// The ONE judgement of a declared `[agents.<label>]` block on config alone:
/// the doors the CHECK refuses it under ([`refuse_agent_block`]), under the
/// node facts already installed. `kata config check` and `kata doctor`'s `agent_backends` row both
/// ask it, so the two refuse one block by one name. `None` for a `type =
/// "shell"` block, under any label: it carries no `adapter` field, so it is the
/// deterministic executor's declaration (`KataConfig::validate` holds the
/// reserved `shell` and `workspace_effect` labels to it) or, under another
/// label, a block no agent stage runs under — the CHECK refuses a stage selecting
/// one `adapter_undeclared`. A stage-dependent door (a hard bound, the egress
/// set, an authored `memory_mb`) and a label with no block stay with the CHECK.
///
/// [`refuse_agent_block`]: kata_program::execution_program::refuse_agent_block
pub(crate) fn judge_agent_block(
    label: &str,
    agent: &AgentBackendConfig,
) -> Option<kata_types::error::KataResult<kata_types::agent::AdapterKind>> {
    if agent.is_deterministic() {
        return None;
    }
    let selects = format!("agent `{label}`");
    Some(kata_program::execution_program::refuse_agent_block(
        &selects, label, agent,
    ))
}

fn api_auth_label(auth: &ApiAuthConfig) -> &'static str {
    match auth {
        ApiAuthConfig::SignedToken { .. } => "signed_token",
        ApiAuthConfig::Disabled {} => "disabled",
    }
}
