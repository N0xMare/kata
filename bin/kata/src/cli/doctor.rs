//! Offline first-run project readiness checks for `kata doctor`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kata_client::{HealthSnapshot, KataClient, SystemStatus};
use kata_core::ConfigManager;
use kata_program::execution_program::{VerifierSeverity, VerifierStatus};
use kata_program::library::WorkflowLibrary;
use kata_types::health::SubsystemHealth;
use kata_types::memory::MemoryProposal;
use serde::Serialize;

use crate::cli::{looks_like_path, normalize_relative_path};

const STARTER_WORKFLOW_NAME: &str = "std.software_factory.kata_self_improve";
const STARTER_PREFLIGHT_NAME: &str = "std.software_factory.kata_self_improve_preflight";
const STARTER_WORKFLOW_FILE: &str = "std.software_factory.kata_self_improve.star";
const STARTER_PREFLIGHT_FILE: &str = "std.software_factory.kata_self_improve_preflight.star";
/// The self-contained hello starter `kata init` always emits. It `load()`s
/// nothing from the bundled stdlib, so it must compile on a fresh dir even
/// before the bundled factory packs are installed — this is doctor's
/// always-green starter preflight.
const HELLO_WORKFLOW_NAME: &str = "std.hello";
const HELLO_WORKFLOW_FILE: &str = "std.hello.star";

/// Whether a starter workflow's compile check is a hard readiness gate or an
/// advisory. The self-contained hello starter is always [`Required`]: it needs
/// no bundled stdlib, so a fresh `kata init` must compile it or the install is
/// broken.
///
/// The factory packs are classified *dynamically*. Two facts keep their
/// refusal off the hard gate:
///
/// * absent bundled stdlib ([`bundled_factory_stdlib_present`]): the packs
///   `load("kata/factory.star")`, so a fresh host without the bundled packs
///   installed fails them *expectedly* — [`Optional`], a `[warn]` naming the
///   bundled-pack remedy.
///
/// With the stdlib present they are [`Required`]: a present-but-broken factory
/// pack is a real fault and must hard-`[fail]`, not be green-washed to a
/// warning. A compile refused on a fact this node never declared
/// (`[node] environment`, an adapter, `egress_allow`) is advisory instead —
/// [`UNDECLARED_NODE_FACT_DOORS`] — because the pack may be fine and the
/// declaration is the node's, not the pack's.
///
/// [`Required`]: WorkflowRequirement::Required
/// [`Optional`]: WorkflowRequirement::Optional
/// [`UNDECLARED_NODE_FACT_DOORS`]: UNDECLARED_NODE_FACT_DOORS
#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkflowRequirement {
    Required,
    Optional,
}

/// Run `kata doctor`.
pub(crate) fn run_doctor_cmd(
    api_url: &str,
    config: PathBuf,
    extra_workflows: Vec<String>,
    online: bool,
    format: super::output::OutputFormat,
) -> Result<()> {
    let mut report = doctor_report_with_options(&config, &extra_workflows);
    if online {
        report.checks.extend(online_doctor_checks(api_url));
        report.recompute_status();
    }
    match format {
        super::output::OutputFormat::Json => {
            super::output::emit_record(&report)?;
        }
        super::output::OutputFormat::Human => print!("{}", render_doctor_report(&report)),
    }

    if !report.passed {
        bail!(
            "kata doctor found {} failed check(s); fix them before running factory workflows",
            report.failure_count
        );
    }
    Ok(())
}

/// Build the side-effect-free project readiness report with optional extra
/// workflow checks, its `kata_login` row reading the effective owner's own
/// logins directory.
#[doc(hidden)]
pub fn doctor_report_with_options(config: &Path, extra_workflows: &[String]) -> DoctorReport {
    doctor_report_with_logins_dir(
        config,
        extra_workflows,
        kata_worker::owner_home::kata_logins_dir().map_err(|error| error.to_string()),
    )
}

/// [`doctor_report_with_options`] with kata's logins directory given rather
/// than resolved from the effective owner's account: the seam a cell takes so
/// its `kata_login` row reads a directory it planted, never the owner's own
/// logins.
#[doc(hidden)]
pub fn doctor_report_with_logins_dir(
    config: &Path,
    extra_workflows: &[String],
    logins_dir: std::result::Result<PathBuf, String>,
) -> DoctorReport {
    let config = normalize_relative_path(config);
    let config_dir = config.parent().unwrap_or_else(|| Path::new("."));
    let project_workflow_dir = config_dir.join("workflows");
    let product_dir = config_dir.join("product");
    let memory_inbox_dir = config_dir.join("memory").join("inbox");
    let mut checks = Vec::new();

    push_path_check(
        &mut checks,
        "config_file",
        "config file exists",
        &config,
        PathKind::File,
        MissingSeverity::Fail,
    );

    let loaded = match ConfigManager::load(&config) {
        Ok(manager) => {
            let cfg = manager.snapshot();
            // A doctor run holds the node's whole `[node]`/`[agents]`
            // declaration — judge the checked packs under the profile that
            // config declares rather than the shipped default.
            crate::cli::install_node_facts_from_config(&cfg);
            let mut details = BTreeMap::new();
            details.insert("node_id".to_string(), cfg.node.id.clone());
            details.insert(
                "data_dir".to_string(),
                cfg.node.data_dir.display().to_string(),
            );
            details.insert("api_bind".to_string(), cfg.api.bind.clone());
            details.insert("agents".to_string(), cfg.agents.len().to_string());
            details.insert(
                "worker_transports".to_string(),
                cfg.workers.transports.len().to_string(),
            );
            checks.push(DoctorCheck::pass(
                "config_validation",
                "config parsed and validated",
                details,
            ));
            Some(cfg)
        }
        Err(err) => {
            let mut details = BTreeMap::new();
            details.insert("error".to_string(), err.to_string());
            checks.push(DoctorCheck::fail(
                "config_validation",
                "config failed to parse or validate",
                details,
            ));
            None
        }
    };

    if let Some(cfg) = loaded.as_ref() {
        push_path_check(
            &mut checks,
            "data_dir",
            "configured data directory exists",
            &cfg.node.data_dir,
            PathKind::Dir,
            MissingSeverity::Warn,
        );
        push_oci_attempt_roots_retained_check(&mut checks, &cfg.node.data_dir);
        push_agent_check(&mut checks, cfg);
        push_kata_login_check(&mut checks, cfg, logins_dir);
        push_credential_env_check(&mut checks, cfg, |var| std::env::var_os(var));
        push_agent_backend_reachability_check(&mut checks, cfg);
        push_target_repo_ignore_check(&mut checks, cfg);
        push_trunk_resolution_check(&mut checks, cfg);
        push_commit_identity_check(&mut checks, cfg);
    }

    push_containment_checks(&mut checks);

    push_product_project_path_checks(
        &mut checks,
        &project_workflow_dir,
        &product_dir,
        &memory_inbox_dir,
    );

    let library = workflow_library_for_config_dir(config_dir);
    push_library_check(&mut checks, &library);
    // The self-contained hello starter is the always-green preflight (Required).
    // The factory packs compile on the shipped `oci` profile like any pack —
    // they are Optional (advisory `[warn]`) only when the bundled factory
    // stdlib is genuinely absent — a fresh host without the bundled packs — and
    // Required (hard `[fail]`) when it IS present, so a present-but-broken
    // factory pack still fails honestly rather than being green-washed.
    // CLI-supplied `extra_workflows` are explicit operator asks, so they gate
    // as Required — never weaker than the default.
    let factory_requirement = if bundled_factory_stdlib_present(&library) {
        WorkflowRequirement::Required
    } else {
        WorkflowRequirement::Optional
    };
    let mut workflows = vec![
        (
            HELLO_WORKFLOW_NAME.to_string(),
            WorkflowRequirement::Required,
        ),
        (STARTER_WORKFLOW_NAME.to_string(), factory_requirement),
        (STARTER_PREFLIGHT_NAME.to_string(), factory_requirement),
    ];
    for workflow in extra_workflows {
        if let Some(existing) = workflows.iter_mut().find(|entry| entry.0 == *workflow) {
            // An explicit operator ask must never gate weaker than the default,
            // so upgrade a coinciding built-in entry to Required.
            existing.1 = WorkflowRequirement::Required;
        } else {
            workflows.push((workflow.clone(), WorkflowRequirement::Required));
        }
    }
    for (workflow, requirement) in &workflows {
        push_workflow_check(&mut checks, &library, workflow, *requirement);
    }
    let next_commands = doctor_next_commands(loaded.is_none(), &checks, &config);

    let failure_count = checks
        .iter()
        .filter(|check| check.status == DoctorStatus::Fail)
        .count();
    let warning_count = checks
        .iter()
        .filter(|check| check.status == DoctorStatus::Warn)
        .count();

    DoctorReport {
        summary_kind: "project_doctor",
        config: config.display().to_string(),
        online_checked: false,
        passed: failure_count == 0,
        failure_count,
        warning_count,
        checks,
        next_commands,
    }
}

/// Push the fixed set of product/project/starter/memory readiness checks
/// (extracted verbatim from `doctor_report_with_options`).
fn push_product_project_path_checks(
    checks: &mut Vec<DoctorCheck>,
    project_workflow_dir: &Path,
    product_dir: &Path,
    memory_inbox_dir: &Path,
) {
    push_path_check(
        checks,
        "project_workflow_dir",
        "project workflow override directory exists",
        project_workflow_dir,
        PathKind::Dir,
        MissingSeverity::Fail,
    );
    push_path_check(
        checks,
        "product_objective",
        "product objective context file exists",
        &product_dir.join("objective.md"),
        PathKind::File,
        MissingSeverity::Fail,
    );
    push_path_check(
        checks,
        "product_validation",
        "product validation criteria file exists",
        &product_dir.join("validation.md"),
        PathKind::File,
        MissingSeverity::Fail,
    );
    push_path_check(
        checks,
        "product_steering",
        "product steering file exists",
        &product_dir.join("steering.md"),
        PathKind::File,
        MissingSeverity::Warn,
    );
    push_path_check(
        checks,
        "hello_starter_file",
        "project self-contained hello starter workflow exists",
        &project_workflow_dir.join(HELLO_WORKFLOW_FILE),
        PathKind::File,
        MissingSeverity::Fail,
    );
    push_path_check(
        checks,
        "starter_workflow_file",
        "project starter factory workflow exists",
        &project_workflow_dir.join(STARTER_WORKFLOW_FILE),
        PathKind::File,
        MissingSeverity::Fail,
    );
    push_path_check(
        checks,
        "starter_preflight_file",
        "project starter preflight workflow exists",
        &project_workflow_dir.join(STARTER_PREFLIGHT_FILE),
        PathKind::File,
        MissingSeverity::Fail,
    );

    push_memory_proposal_check(
        checks,
        "memory_objective_proposal",
        &memory_inbox_dir.join("000-objective.json"),
    );
    push_memory_proposal_check(
        checks,
        "memory_validation_proposal",
        &memory_inbox_dir.join("010-validation-criteria.json"),
    );
}

/// Compute the operator's suggested next commands based on whether config
/// loaded and whether any check failed (extracted verbatim from
/// `doctor_report_with_options`).
fn doctor_next_commands(
    config_load_failed: bool,
    checks: &[DoctorCheck],
    config: &Path,
) -> Vec<String> {
    let mut next_commands = Vec::new();
    if config_load_failed
        || checks
            .iter()
            .any(|check| check.status == DoctorStatus::Fail)
    {
        next_commands.push(format!("kata init --config {}", config.display()));
        next_commands.push(format!("kata doctor --config {}", config.display()));
    } else {
        next_commands.push("kata check --all".to_string());
        next_commands.push(format!(
            "{} kata serve --config {}",
            super::DELEGATED_SCOPE,
            config.display()
        ));
        next_commands.push(format!(
            "kata doctor --config {} --online",
            config.display()
        ));
        next_commands.push(format!(
            "kata factory run {STARTER_PREFLIGHT_NAME} --wait --timeout-secs 900"
        ));
    }
    next_commands
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub summary_kind: &'static str,
    pub config: String,
    pub online_checked: bool,
    pub passed: bool,
    pub failure_count: usize,
    pub warning_count: usize,
    pub checks: Vec<DoctorCheck>,
    pub next_commands: Vec<String>,
}

impl DoctorReport {
    fn recompute_status(&mut self) {
        self.online_checked = self
            .checks
            .iter()
            .any(|check| check.name.starts_with("online_"));
        self.failure_count = self
            .checks
            .iter()
            .filter(|check| check.status == DoctorStatus::Fail)
            .count();
        self.warning_count = self
            .checks
            .iter()
            .filter(|check| check.status == DoctorStatus::Warn)
            .count();
        self.passed = self.failure_count == 0;
    }
}

#[derive(Debug, Serialize)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub status: DoctorStatus,
    pub message: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
    /// Lines the human render prints UNDER this row, verbatim.
    ///
    /// The health verdict and the diagnostic are different
    /// outputs. `agent_backends` scores only a declared-and-unreachable backend
    /// but an operator still wants the full inventory — every `[agents.*]`
    /// entry and what its executable resolved to — and `details` could not
    /// serve: [`render_doctor_report`] prints a check's `message` and its
    /// `error` detail and nothing else, so an inventory living only in
    /// `details` would reach `--format json` consumers and no human at all.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostic: Vec<String>,
}

/// Ordered by severity, so a row over several findings reports the worst.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

impl DoctorStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

impl DoctorCheck {
    fn pass(
        name: &'static str,
        message: impl Into<String>,
        details: BTreeMap<String, String>,
    ) -> Self {
        Self {
            name,
            status: DoctorStatus::Pass,
            message: message.into(),
            details,
            diagnostic: Vec::new(),
        }
    }

    fn warn(
        name: &'static str,
        message: impl Into<String>,
        details: BTreeMap<String, String>,
    ) -> Self {
        Self {
            name,
            status: DoctorStatus::Warn,
            message: message.into(),
            details,
            diagnostic: Vec::new(),
        }
    }

    fn fail(
        name: &'static str,
        message: impl Into<String>,
        details: BTreeMap<String, String>,
    ) -> Self {
        Self {
            name,
            status: DoctorStatus::Fail,
            message: message.into(),
            details,
            diagnostic: Vec::new(),
        }
    }

    /// Attach the lines the human render prints under this row. Independent of
    /// the row's status on purpose — an inventory an operator only sees when
    /// something is already broken is not a diagnostic.
    #[must_use]
    fn with_diagnostic(mut self, lines: Vec<String>) -> Self {
        self.diagnostic = lines;
        self
    }
}

#[derive(Clone, Copy)]
enum PathKind {
    File,
    Dir,
}

#[derive(Clone, Copy)]
enum MissingSeverity {
    Warn,
    Fail,
}

fn push_path_check(
    checks: &mut Vec<DoctorCheck>,
    name: &'static str,
    message: &'static str,
    path: &Path,
    kind: PathKind,
    missing: MissingSeverity,
) {
    let exists = match kind {
        PathKind::File => path.is_file(),
        PathKind::Dir => path.is_dir(),
    };
    let mut details = BTreeMap::new();
    details.insert("path".to_string(), path.display().to_string());
    if exists {
        checks.push(DoctorCheck::pass(name, message, details));
        return;
    }

    let expected = match kind {
        PathKind::File => "file",
        PathKind::Dir => "directory",
    };
    details.insert("expected".to_string(), expected.to_string());
    match missing {
        MissingSeverity::Warn => checks.push(DoctorCheck::warn(
            name,
            format!("{message}; missing {expected}"),
            details,
        )),
        MissingSeverity::Fail => checks.push(DoctorCheck::fail(
            name,
            format!("{message}; missing {expected}"),
            details,
        )),
    }
}

/// `oci_attempt_roots_retained` — the capsule route's attempt roots left on disk with no
/// drive holding them: one a drive KEPT because its container's teardown could not be
/// confirmed (`teardown_ambiguous`), and one whose removal FAILED (a mount point beneath
/// it, an immutable entry) — each listed by path with what kept it.
///
/// The first is the one piece of OCI-route residue kata deliberately does not delete:
/// removing it would race a container kata said it cannot account for. The second is
/// residue kata tried to delete and could not. This row is their owner an operator can
/// see. `warn`, never `fail`, and it deletes nothing: the next worker start retries each
/// one (an ambiguous root once no process is left in its container's cgroup), and the
/// remediation is for an operator who wants it sooner or whose root still will not go.
fn push_oci_attempt_roots_retained_check(checks: &mut Vec<DoctorCheck>, data_dir: &Path) {
    use kata_worker::attempt_root::Retention;
    const NAME: &str = "oci_attempt_roots_retained";
    let worker_state = kata_worker::capsule_route::capsule_worker_state(data_dir);
    let mut details = BTreeMap::new();
    details.insert(
        "worker_state".to_string(),
        worker_state.display().to_string(),
    );
    match kata_worker::attempt_root::retained_attempt_roots(&worker_state) {
        Ok(retained) if retained.is_empty() => checks.push(DoctorCheck::pass(
            NAME,
            "no OCI attempt root is retained over an unconfirmed container teardown or a \
             failed removal",
            details,
        )),
        Ok(retained) => {
            let mut named = Vec::with_capacity(retained.len());
            for (path, retention) in &retained {
                let (kept, text) = match retention {
                    Retention::TeardownAmbiguous(outcome) => ("teardown unconfirmed", outcome),
                    Retention::RemovalFailed(error) => ("removal failed", error),
                };
                named.push(format!("{} ({kept})", path.display()));
                details.insert(path.display().to_string(), format!("{kept}: {text}"));
            }
            details.insert(
                "remediation".to_string(),
                "teardown unconfirmed: confirm no process is in the container's `kata.oci.<id>` \
                 cgroup (`systemd-cgls`), then restart the worker (its start sweep removes the \
                 root) or `rm -rf` it; removal failed: clear what the recorded error names (an \
                 unmount, `chattr -i`), then restart the worker or `rm -rf` the root and its \
                 `.REMOVAL_FAILED` file"
                    .to_string(),
            );
            checks.push(DoctorCheck::warn(
                NAME,
                format!(
                    "{} OCI attempt root(s) left on disk: {}",
                    retained.len(),
                    named.join(" ")
                ),
                details,
            ));
        }
        Err(error) => {
            details.insert("error".to_string(), error);
            checks.push(DoctorCheck::warn(
                NAME,
                "the OCI attempt roots could not be scanned for retained roots",
                details,
            ));
        }
    }
}

/// Report what containment this node ACTUALLY has: the rootless-OCI
/// route's prerequisites, as `kata_worker::sandbox_posture::observe` reads them.
///
/// ## It re-derives nothing
///
/// Every row is a posture fact, and every posture fact is read through the
/// SAME fold `kata_worker::oci_runtime::certify_youki` applies — the pinned
/// runtime's bytes, the exact-path AppArmor profile
/// (`kata_worker::oci_runtime::read_apparmor_prerequisite`, the certification's
/// own reader), the runtime's libseccomp witness, and this process's cgroup
/// delegation. Doctor is a RENDERER here; a second derivation would let its
/// answer differ from the worker's admission. So a row is `pass` only where
/// that fold admits: a host the certification refuses — an unrestricted kernel
/// with no installed profile included — warns. The kernel's userns restriction
/// is recorded beside the row and relaxes nothing.
///
/// The one row that is not a certification fact, `containment_env_levers`, is
/// scored by the capsule route admission's own resolver of the provider
/// declaration (`kata_worker::capsule_route::declared_oci_provider`), for the
/// same reason: admission refuses what that row warns about.
///
/// Doctor starts no container. Whether one really STARTS is the certification's
/// functional arm — `kata execution-provider certify oci`, and the worker at
/// capsule-route admission — which is why certification can still refuse a host
/// whose rows all pass.
///
/// ## The exit contract
///
/// [`DoctorStatus::Fail`] is what makes `kata doctor` exit non-zero. Containment
/// reaches it in exactly one case: a DECLARED requirement this node cannot honour
/// — the build's youki pin does not parse, or the pinned path holds bytes the pin
/// does not name. Everything else not available is [`DoctorStatus::Warn`]: a host
/// without the pinned runtime, without the AppArmor profile, or measured from an
/// undelegated shell is a legitimate install that cannot run capsules yet, and
/// `just gate`'s product smoke asserts `failure_count == 0` host-independently.
///
/// ## The known limits
///
/// `known_containment_limits` counts the limits true of the BUILD rather than of
/// the host (`kata_worker::sandbox_posture::KNOWN_LIMITS`, rendered in full by
/// `kata execution-provider inspect`). They are a count plus a pointer rather
/// than a status: every install has them and no operator action clears them.
fn push_containment_checks(checks: &mut Vec<DoctorCheck>) {
    let posture = kata_worker::sandbox_posture::observe();
    for fact in posture.facts() {
        let mut details = fact.details.clone();
        details.insert("state".to_string(), fact.state.label().to_string());
        details.insert(
            "declared_required".to_string(),
            fact.declared_required.to_string(),
        );
        checks.push(DoctorCheck {
            name: fact.name,
            status: containment_status(fact),
            message: fact.evidence.clone(),
            details,
            diagnostic: Vec::new(),
        });
    }

    checks.push(env_levers_check(
        &posture.kill_switches,
        posture.known_limits.len(),
        kata_worker::capsule_route::declared_oci_provider().map(|_| ()),
    ));
}

/// The `containment_env_levers` row: every provider lever, set or not, and
/// whether the declaration they make RESOLVES — `declaration` is
/// `kata_worker::capsule_route::declared_oci_provider`'s answer, the capsule
/// route admission's own first refusals.
///
/// The levers are listed always — an operator whose containment is reshaped by
/// ambient environment must be able to SEE it, and a report listing only the
/// levers that happen to be set cannot be distinguished from one that forgot to
/// look. No lever weakens a fence (`LeverDirection` has no weakening arm since the
/// `KATA_DISABLE_SECCOMP` defeat was superseded).
fn env_levers_check(
    kill_switches: &[kata_worker::sandbox_posture::KillSwitchState],
    known_limits: usize,
    declaration: kata_types::error::KataResult<()>,
) -> DoctorCheck {
    let mut lever_details = BTreeMap::new();
    let mut set_levers: Vec<String> = Vec::new();
    for switch in kill_switches {
        lever_details.insert(
            switch.env.to_string(),
            if switch.set {
                format!("SET ({}) — {}", switch.direction.label(), switch.effect)
            } else {
                format!("unset ({})", switch.default_posture)
            },
        );
        if switch.set {
            set_levers.push(format!("{} ({})", switch.env, switch.direction.label()));
        }
    }
    lever_details.insert(
        "known_containment_limits".to_string(),
        known_limits.to_string(),
    );
    lever_details.insert(
        "detail".to_string(),
        "kata execution-provider inspect oci".to_string(),
    );
    let message = if set_levers.is_empty() {
        "no containment lever is set in this environment".to_string()
    } else {
        format!(
            "{} containment lever(s) SET in this environment: {}",
            set_levers.len(),
            set_levers.join(", ")
        )
    };
    // SCORED by the capsule route's own resolver of the declaration these levers
    // make, so the row passes exactly where a capsule worker started from this
    // environment would get past its provider refusals. A WARN, never a FAIL:
    // a node without a usable provider is a legitimate install that cannot run
    // capsules yet (the contract on `push_containment_checks`).
    match declaration {
        Ok(()) => DoctorCheck::pass(
            "containment_env_levers",
            format!(
                "{message}; the declared OCI provider resolves to its content address in the \
                 declared store"
            ),
            lever_details,
        ),
        Err(refusal) => {
            lever_details.insert("refusal".to_string(), refusal.to_string());
            DoctorCheck::warn(
                "containment_env_levers",
                format!(
                    "{message}; a capsule worker started from this environment would refuse its \
                     provider: {refusal}"
                ),
                lever_details,
            )
        }
    }
}

/// Map a measured containment fact onto doctor's `{pass, warn, fail}`.
///
/// Pure and total, so the exit contract described on
/// [`push_containment_checks`] is pinned by a unit test rather than by prose.
fn containment_status(fact: &kata_worker::sandbox_posture::ContainmentFact) -> DoctorStatus {
    if fact.state == kata_worker::sandbox_posture::ContainmentState::Available {
        DoctorStatus::Pass
    } else if fact.is_declared_refusal() {
        DoctorStatus::Fail
    } else {
        DoctorStatus::Warn
    }
}

/// Does this config declare the agent LABELS the starter workflows select?
///
/// # Why a missing label WARNs where [`push_agent_backend_reachability_check`] fails
///
/// The two rows look alike and score differently, deliberately, and the rule is
/// doctor's own exit contract (see [`push_containment_checks`]): a `[fail]`
/// belongs to a fact a runtime ALREADY hard-errors on.
///
/// A declared-but-unlaunchable backend is such a fact — the `agent_backends`
/// row below FAILs it, because a stage selecting that label is refused at
/// check. A missing LABEL is not the same fact: no `[agents.<label>]` block
/// means no declaration to judge, and `agent = "shell"` stages are unaffected
/// (the reserved label needs no block). The cost lands on exactly the stages
/// that name the missing label — `adapter_undeclared` at check — and nothing
/// else, so this row warns rather than fails.
///
fn push_agent_check(checks: &mut Vec<DoctorCheck>, cfg: &kata_types::KataConfig) {
    let selected = ["default", "shell"];
    let missing = selected
        .iter()
        .filter(|name| !cfg.agents.contains_key(**name))
        .copied()
        .collect::<Vec<_>>();
    let mut details = BTreeMap::new();
    details.insert(
        "selected_by_starters".to_string(),
        selected.into_iter().collect::<Vec<_>>().join(","),
    );
    details.insert(
        "configured".to_string(),
        cfg.agents.keys().cloned().collect::<Vec<_>>().join(","),
    );
    if missing.is_empty() {
        checks.push(DoctorCheck::pass(
            "starter_agents",
            "starter workflow agent labels are configured",
            details,
        ));
        return;
    }

    details.insert("missing".to_string(), missing.join(","));
    let labels = missing.join(", ");
    // The sole-entry fallback is the trap this warning has to name: with
    // `default` gone and exactly one `[agents.*]` entry left, THAT entry becomes
    // what a stage declaring no `agent = "…"` selector resolves to — so an
    // unqualified model stage binds to whatever launch that entry declares.
    let fallback = if !cfg.agents.contains_key("default") && cfg.agents.len() == 1 {
        cfg.agents.keys().next().map_or_else(String::new, |sole| {
            format!(
                " With no `default` and exactly one `[agents.*]` entry, a stage that declares no \
                 `agent = \"…\"` selector resolves to `{sole}` instead — check that no model \
                 stage is relying on an unqualified selector."
            )
        })
    } else {
        String::new()
    };
    checks.push(DoctorCheck::warn(
        "starter_agents",
        format!(
            "the starter workflows select agent label(s) {labels}, which this config does not \
             declare — a stage selecting one is refused `adapter_undeclared` at check. \
             `agent = \"shell\"` stages are unaffected. Add the `[agents.<label>]` block with a \
             capsule `adapter` and its `credential`, or run `std.hello` and any `agent = \"shell\"` \
             workflow as-is.{fallback}"
        ),
        details,
    ));
}

/// kata's own login, for every `[agents.<label>]` declaring
/// `credential.source = "kata_login"` (`kata_login`). Says nothing when no
/// agent declares one.
///
/// Per agent, offline (`kata_agent_nanocode::credential::login_state`: no
/// issuer is contacted and nothing is refreshed), in the owner's logins
/// directory every binary of this uid hands its worker:
///
/// * PASS — the file for the agent's provider and declared `mode` is owner-only
///   in an owner-only directory and holds an API key, or a completed ChatGPT
///   login with a refresh token;
/// * WARN — the operator still has to log in: the file is absent, the ChatGPT
///   store holds no completed login or no refresh token, or
///   `credential_mode_mismatch`: the declared mode's file is absent while the
///   provider's OTHER mode's file is present;
/// * FAIL — a file or directory kata refuses as it stands (not owner-only, or
///   not what kata wrote), an Anthropic subscription (kata holds no Claude
///   login in this build), `kata_login` on an adapter label that names no kind,
///   or a logins directory that cannot be resolved.
///
/// Advisory, like every doctor row: the worker re-judges all of it at
/// dispatch, before the container.
fn push_kata_login_check(
    checks: &mut Vec<DoctorCheck>,
    cfg: &kata_types::KataConfig,
    logins_dir: std::result::Result<PathBuf, String>,
) {
    use kata_agent_nanocode::credential::LoginProvider;

    let declared: Vec<_> = cfg
        .agents
        .iter()
        .filter_map(|(label, agent)| {
            agent
                .capsule_credential()
                .filter(|credential| credential.source == "kata_login")
                .map(|credential| (label, agent, credential))
        })
        .collect();
    if declared.is_empty() {
        return;
    }
    let dir = match logins_dir {
        Ok(dir) => dir,
        Err(error) => {
            checks.push(DoctorCheck::fail(
                "kata_login",
                format!(
                    "kata's logins directory cannot be resolved ({error}); every `kata_login` \
                     turn refuses `credential_unavailable`"
                ),
                BTreeMap::new(),
            ));
            return;
        }
    };
    let mut status = DoctorStatus::Pass;
    let mut lines = Vec::new();
    let mut details = BTreeMap::new();
    details.insert("logins_dir".to_owned(), dir.display().to_string());
    for (label, agent, credential) in declared {
        let kind = agent
            .capsule_adapter()
            .and_then(kata_types::agent::AdapterKind::from_label);
        let harness = kind.map(LoginProvider::of_kind);
        let mode = kata_types::metering::CredentialMode::from_label(&credential.mode);
        let (verdict, line) = match (harness, mode) {
            (None, _) => (
                DoctorStatus::Fail,
                format!(
                    "`kata_login` serves only `nanocode_openai` and `nanocode_anthropic`, and \
                     this block's adapter `{}` names no kind this build carries \
                     (`adapter_unqualified` at check)",
                    agent.capsule_adapter().unwrap_or("<none>")
                ),
            ),
            (Some(_), None) => (
                DoctorStatus::Fail,
                format!(
                    "credential mode `{}` is not `api_key` or `subscription`",
                    credential.mode
                ),
            ),
            (Some(provider), Some(mode)) => kata_login_verdict(&dir, provider, mode),
        };
        status = status.max(verdict);
        details.insert(format!("agent.{label}"), line.clone());
        lines.push(format!("[agents.{label}] {line}"));
    }
    let message = match status {
        DoctorStatus::Pass => "every `kata_login` agent's login is stored, owner-only".to_owned(),
        DoctorStatus::Warn => "a `kata_login` agent still needs its `kata login` (each line \
                               names the command); its turns refuse until then"
            .to_owned(),
        DoctorStatus::Fail => "a `kata_login` agent's login is refused as it stands; its turns \
                               refuse `credential_unavailable` (each line names why)"
            .to_owned(),
    };
    checks.push(
        DoctorCheck {
            name: "kata_login",
            status,
            message,
            details,
            diagnostic: Vec::new(),
        }
        .with_diagnostic(lines),
    );
}

/// One `kata_login` agent's verdict: the state of the file its provider and
/// mode name, read offline. A mode with no file names the door the CHECK
/// judges first, `credential_mode_unsupported`.
fn kata_login_verdict(
    dir: &Path,
    provider: kata_agent_nanocode::credential::LoginProvider,
    mode: kata_types::metering::CredentialMode,
) -> (DoctorStatus, String) {
    use kata_agent_nanocode::credential::{LoginState, login_state};

    let Some(file) = provider.file(mode) else {
        let door = kata_types::execution_contract::CREDENTIAL_MODE_UNSUPPORTED;
        return (
            DoctorStatus::Fail,
            format!(
                "kata holds no `{}` login for {} in this build (`{}` at check; `kata login {} \
                 --api-key` and `mode = \"api_key\"`)",
                mode.as_label(),
                provider.as_label(),
                door,
                provider.as_label()
            ),
        );
    };
    let name = file.file_name();
    match login_state(dir, file) {
        LoginState::ApiKey => (DoctorStatus::Pass, format!("{name}: an API key is stored")),
        LoginState::ChatGpt {
            account_id: Some(account),
            refresh_token: true,
            ..
        } => (
            DoctorStatus::Pass,
            format!("{name}: ChatGPT login for account {account}, refresh token stored"),
        ),
        LoginState::ChatGpt {
            account_id: Some(_),
            refresh_token: false,
            ..
        } => (
            DoctorStatus::Warn,
            format!(
                "{name}: the ChatGPT login holds no refresh token, so kata cannot renew it; run \
                 `{}`",
                file.login_command()
            ),
        ),
        LoginState::ChatGpt {
            account_id: None, ..
        } => (
            DoctorStatus::Warn,
            format!(
                "{name}: no completed ChatGPT login; run `{}`",
                file.login_command()
            ),
        ),
        LoginState::Absent => {
            let held = provider
                .files()
                .into_iter()
                .find(|other| *other != file && login_state(dir, *other) != LoginState::Absent);
            match held {
                Some(other) => (
                    DoctorStatus::Warn,
                    format!(
                        "credential_mode_mismatch: the block declares `mode = \"{}\"`, whose \
                         file {name} is absent, and kata holds a `{}` login ({}); run `{}`, or \
                         declare `mode = \"{}\"`",
                        mode.as_label(),
                        other.mode().as_label(),
                        other.file_name(),
                        file.login_command(),
                        other.mode().as_label()
                    ),
                ),
                None => (
                    DoctorStatus::Warn,
                    format!("{name}: absent; run `{}`", file.login_command()),
                ),
            }
        }
        LoginState::Insecure(reason) => (
            DoctorStatus::Fail,
            format!("{name}: refused, not owner-only: {reason}"),
        ),
        LoginState::Malformed(reason) => (
            DoctorStatus::Fail,
            format!("{name}: refused, not a login kata wrote: {reason}"),
        ),
    }
}

/// Every `[agents.<label>]` declaring `credential.source = "env:<VAR>"`: is
/// `<VAR>` set in THIS process's environment, can a worker carry its value, and
/// can the embedded harness send it? Says nothing when no agent declares one.
///
/// An unset variable is a WARN, never a FAIL: the environment a worker runs
/// with is not doctor's. An installed service reads the snapshot `kata service
/// install` wrote (which refuses an unset variable itself), and an external
/// worker its own; this row answers for a `kata serve` started from this shell.
///
/// The row FAILS naming the agent and the variable, never the value, for
/// exactly the values the worker refuses `credential_unavailable` before the
/// container: one that is not UTF-8 (the harness takes the key as text), and
/// one the worker's own predicate, `HarnessAuth::is_sendable_api_key`, rejects
/// (a byte below 0x20 other than a tab, or 0x7F — a key exported with its
/// trailing newline).
fn push_credential_env_check(
    checks: &mut Vec<DoctorCheck>,
    cfg: &kata_types::KataConfig,
    value_of: impl Fn(&str) -> Option<std::ffi::OsString>,
) {
    let declared: Vec<_> = cfg
        .agents
        .iter()
        .filter_map(|(label, agent)| {
            let credential = agent.capsule_credential()?;
            let var = credential.source.strip_prefix("env:")?;
            Some((label, var))
        })
        .collect();
    if declared.is_empty() {
        return;
    }
    let mut details = BTreeMap::new();
    let mut unset = Vec::new();
    let mut unsendable = Vec::new();
    let lines = declared
        .into_iter()
        .map(|(label, var)| {
            let (state, line) = match value_of(var) {
                None => {
                    unset.push(format!("{label} ({var})"));
                    (
                        "UNSET",
                        format!("[agents.{label}] `{var}` is UNSET in this environment"),
                    )
                }
                Some(value) if value.to_str().is_none() => {
                    unsendable.push(format!("{label} ({var})"));
                    (
                        "NOT UTF-8",
                        format!(
                            "[agents.{label}] `{var}` is set in this environment to a value that \
                             is not UTF-8, which a worker cannot carry"
                        ),
                    )
                }
                Some(value)
                    if !value
                        .to_str()
                        .is_some_and(kata_agent_nanocode::HarnessAuth::is_sendable_api_key) =>
                {
                    unsendable.push(format!("{label} ({var})"));
                    (
                        "UNSENDABLE",
                        format!(
                            "[agents.{label}] `{var}` is set in this environment to a value the \
                             embedded harness cannot send as an HTTP header"
                        ),
                    )
                }
                Some(_) => (
                    "set",
                    format!("[agents.{label}] `{var}` is set in this environment"),
                ),
            };
            details.insert(format!("agent.{label}"), format!("{var} {state}"));
            line
        })
        .collect();
    let check = if !unsendable.is_empty() {
        DoctorCheck::fail(
            "credential_env",
            format!(
                "`env:<VAR>` credential(s) {} hold a value a worker cannot carry: the embedded \
                 harness takes the key as UTF-8 text and sends it as an HTTP header value, \
                 which admits no control character but a tab (a trailing newline, say) — a \
                 worker refuses either `credential_unavailable`; re-export the key as UTF-8 \
                 without the control character",
                unsendable.join(", ")
            ),
            details,
        )
    } else if !unset.is_empty() {
        DoctorCheck::warn(
            "credential_env",
            format!(
                "`env:<VAR>` credential(s) {} are unset in this environment — a worker started \
                 from it refuses `credential_unavailable`. An installed service reads the \
                 environment `kata service install` captured instead",
                unset.join(", ")
            ),
            details,
        )
    } else {
        DoctorCheck::pass(
            "credential_env",
            "every `env:<VAR>` credential's variable is set in this environment",
            details,
        )
    };
    checks.push(check.with_diagnostic(lines));
}

/// Does every declared `[agents.*]` entry pass the CHECK's config-only doors?
///
/// [`push_agent_check`] above compares `cfg.agents`' keys against the two labels
/// the starter workflows select — config against itself. It proves the labels
/// exist and nothing about whether the declared launch behind them is
/// admissible, and its message says "configured" rather than "launchable", so
/// it is honest in isolation. It cannot be the only agent row: a declared entry
/// the CHECK refuses is a refusal waiting for the first stage that selects it,
/// and doctor is where that refusal should be read first.
///
/// The judgement is `kata config check`'s, one function with two callers
/// ([`judge_agent_block`]): every harness block is asked the doors the
/// CHECK refuses it under on config alone — `refuse_agent_block` (the
/// credential's parse and mode; the launch by
/// `AgentBackendConfig::capsule_launch`, the function capsule assembly refuses
/// through; a block with no credential; the declared `env`) — under the node
/// facts its caller installed from this config (a doctor run, and `kata restore --recoverable`'s binding
/// verification, install them first), and a refused block's line carries the
/// refusal, door name first. The shell route under a reserved deterministic
/// label (`shell`, the deterministic executor's; `workspace_effect`, the main's
/// in-process workspace effects') is listed only — the label decides it, and no
/// other label can hold it. The doors that need a stage (a hard bound, the egress set, an
/// authored `memory_mb`) are `kata check`'s, not this row's, and its PASS says
/// so.
///
/// # Why this FAILs, and why that leaves the verdict host-INDEPENDENT
///
/// By doctor's own exit contract (see [`push_containment_checks`]) a route
/// that ALREADY refuses must produce a `[fail]` — and a declared agent the
/// CHECK refuses on config alone does refuse, by name, for every stage that
/// selects it. The verdict stays host-independent because the judgement is pure
/// CONFIG: whether an entry can launch is a question of what the
/// `[agents.<label>]` block and `[node]` declare, never of what this host's
/// `$PATH` holds. An
/// UNDECLARED agent is never probed and never reported; that half is pinned by
/// `doctor_says_nothing_about_an_unlaunchable_agent_no_one_declared`.
///
/// The inventory rides in `diagnostic` (and in `details` under `--format
/// json`) on PASS and FAIL alike: the health verdict and the operator's "what
/// does each entry declare" are different outputs, and only a declared-and-refused
/// entry belongs in the first one.
///
/// [`judge_agent_block`]: super::config_check::judge_agent_block
pub(super) fn push_agent_backend_reachability_check(
    checks: &mut Vec<DoctorCheck>,
    cfg: &kata_types::KataConfig,
) {
    use crate::backend_factory::agent_backend_kind;

    let mut details = BTreeMap::new();
    let mut inventory: Vec<String> = Vec::new();
    let mut unmet: Vec<String> = Vec::new();
    for (label, agent_cfg) in &cfg.agents {
        let kind = agent_backend_kind(agent_cfg);
        // `None` is the shell route, which `KataConfig::validate` holds to the
        // reserved deterministic labels: `shell`, or `workspace_effect`.
        let verdict = match super::config_check::judge_agent_block(label, agent_cfg) {
            None if label == "shell" => format!(
                "{kind}: reserved `shell` label — stages run `sh` inside the node environment"
            ),
            None => format!(
                "{kind}: reserved `{label}` label — the main performs a workspace effect \
                 in-process, and no worker is placed for one"
            ),
            Some(Ok(adapter)) => format!(
                "{kind}: capsule launch declared (adapter `{}`; the kind fixes its launch)",
                adapter.as_label(),
            ),
            Some(Err(refusal)) => {
                unmet.push(label.clone());
                let refusal = match refusal {
                    kata_types::error::KataError::Validation(message) => message,
                    other => other.to_string(),
                };
                format!("{kind}: refused at check — {refusal}")
            }
        };
        inventory.push(format!("[agents.{label}] {verdict}"));
        details.insert(format!("agent.{label}"), verdict);
    }

    if unmet.is_empty() {
        checks.push(
            DoctorCheck::pass(
                "agent_backends",
                "every declared agent block passes the doors the CHECK judges a block by on \
                 config alone (`kata config check`'s judgement); the doors that need a stage are \
                 `kata check`'s",
                details,
            )
            .with_diagnostic(inventory),
        );
        return;
    }

    details.insert("unmet".to_string(), unmet.join(","));
    let labels = unmet.join(", ");
    checks.push(
        DoctorCheck::fail(
            "agent_backends",
            format!(
                "agent backend(s) {labels} are DECLARED in this config but the CHECK refuses \
                 them on config alone, so they cannot launch a capsule — a stage selecting one \
                 is refused at check by the door each line names (`adapter_undeclared`, \
                 `adapter_unqualified`, `credential_mode_unsupported`, `credential_undeclared`, \
                 `capsule_agent_env_*`, ...). Fix the entry as its line says — a capsule \
                 launch is `adapter = \"<kind>\"` (`nanocode_openai`, `nanocode_anthropic`) \
                 on the block, with the `credential` the kind runs under — or delete the block if no stage selects \
                 it; `agent = \"shell\"` \
                 stages need no model agent. Only a backend this config DECLARES is scored \
                 here — an agent named by no `[agents.*]` entry is not a finding"
            ),
            details,
        )
        .with_diagnostic(inventory),
    );
}

/// Prove the operator's target repository IGNORES everything kata materializes
/// inside it (`target_repo_ignore`).
///
/// ## The defect this closes
///
/// kata points its execution-workspace provider at a repository the operator
/// owns — `kata init` writes `jj_repo = ".."`, the project root — and writes its
/// own state into that tree: `.jj/` when `JjBackend::open` colocates or adopts
/// git in place, and `agents/<exec>/` for every candidate workspace. kata
/// REQUIRED those paths to be ignored and verified it
/// nowhere. The requirement was stated twice, both times in prose: kata's own
/// `.gitignore` names `.jj/`, `/agents/` and `.kata/` with a comment describing
/// exactly this case, and `render_vcs_preflight` printed a hand-typed "add
/// `.jj/` and `/agents/` to .gitignore" advisory — which only fires BEFORE first
/// boot, so the operator who skipped it once never saw it again.
///
/// The first live `gold-loop` run promoted **46 files / 333 insertions** of jj
/// internals and candidate-workspace state into a fixture repository's trunk, as
/// new files, and reported `status=completed`.
///
/// ## Why the scored set includes `node.data_dir`
///
/// `repo_local_artifact_roots()` — the roots the PROVIDER writes — does not
/// include `node.data_dir`. `kata init` renders
/// `data_dir = "data"` beside the config, so the default project keeps the node's
/// whole durable state at `<repo>/.kata/data`: `operational.db`, `cas.db` + `cas/`,
/// `memory.db`, `stage_cache.db`, `main.lock`, `recovery-generations/**`.
///
/// MEASURED on a fixture where the operator applied EXACTLY a remedy naming only
/// the provider roots (`/.jj/` and `/agents/`) and a row scoring only those
/// answered `pass`: after one `kata serve`, `jj status` at the repo
/// root listed the entire `.kata/data` tree as `A`dded to the working copy. The
/// row therefore scores `repo_local_artifact_paths(&cfg.vcs, data_dir)`, which
/// composes the config-determined roots onto the provider ones.
///
/// ## Why it asks git rather than reading `.gitignore`
///
/// String-matching the `.gitignore` text answers a different question from the
/// one that matters. `git check-ignore` is the authority git itself consults, so
/// it covers `.git/info/exclude`, `core.excludesFile`, nested per-directory
/// ignore files, and negation — all of which a text scan reports wrongly, in
/// both directions.
///
/// ## Why the probe path has a leaf appended
///
/// MEASURED (git 2.43.0): `git check-ignore .jj` answers **not ignored** in a
/// repository whose `.gitignore` contains `.jj/`, whenever `.jj` does not exist
/// on disk — a directory-only pattern cannot match a path git has no reason to
/// believe is a directory. That is every repository doctor runs against BEFORE
/// first boot, which is doctor's whole audience. Querying
/// `.jj/<leaf>/<leaf>` instead makes the answer independent of what is on disk
/// and models the paths kata really writes. Naming the bare directory would have
/// failed a correctly configured repository: a refused set WIDER than the claim.
///
/// ## Why `fail` and not `warn`
///
/// An un-ignored artifact root is not cosmetic noise in `git status`. A
/// workspace-effect stage that stages the tree sweeps kata's internals into the
/// operator's trunk, silently, as it did on the run above; the damage is
/// committed history in a repository kata does not own, and doctor cannot undo
/// it afterwards. There is no configuration in which an operator wants `.jj/` or
/// `agents/` tracked, and the remedy is one line per root in a file that already
/// exists. A check whose failure mode is irreversible corruption and whose
/// remedy takes ten seconds is a gate, not an advisory.
///
/// The three cases where doctor cannot OBSERVE the property `warn` instead — a
/// repo path that does not exist yet, a directory that is not inside a git
/// repository, and a host with no `git` — because an unobserved property must
/// not be published as a verified one in either direction.
///
/// ## What it deliberately does NOT claim
///
/// Only that FUTURE kata writes under these roots are ignored. A repository that
/// already TRACKS files under `agents/` — because a previous run committed them,
/// or because the operator's own project genuinely owns a directory by that name
/// — still passes if a rule now covers new paths there. That is a different
/// claim with a different remedy (`git rm -r --cached`, or moving kata's repo
/// root), and rolling it in here would make one row's verdict mean two things.
fn push_target_repo_ignore_check(checks: &mut Vec<DoctorCheck>, cfg: &kata_types::KataConfig) {
    let repo = cfg.vcs.jj_repo.as_path();
    // ONE source of truth, shared with the code that CREATES these paths:
    // `kata_workflow::repo_artifacts::repo_local_artifact_roots`, whose names
    // are owned by the code that creates each root — plus the
    // config-determined roots, which is why this asks for the whole config.
    // `node.data_dir` is one: `kata init` renders it beside
    // the config, so the default project keeps `operational.db` / `cas/` /
    // `recovery-generations/**` INSIDE the operator's repository, and a row
    // that skipped it would be green over exactly that.
    let roots = kata_workflow::repo_artifacts::repo_local_artifact_paths(
        &cfg.vcs,
        cfg.node.data_dir.as_path(),
    );

    let mut details = BTreeMap::new();
    details.insert("repo".to_string(), repo.display().to_string());
    details.insert("artifact_roots".to_string(), roots.join(","));

    let unverifiable =
        |checks: &mut Vec<DoctorCheck>, mut details: BTreeMap<String, String>, reason: &str| {
            details.insert("unverified".to_string(), reason.to_string());
            checks.push(DoctorCheck::warn(
                "target_repo_ignore",
                format!(
                    "cannot verify that the target repository {} ignores what kata writes into \
                     it — {reason}. kata materializes {} inside `vcs.jj_repo`; if they are not \
                     ignored there, a landing stage commits kata's internals into that \
                     repository's history. Re-run `kata doctor` once the repository exists",
                    repo.display(),
                    roots
                        .iter()
                        .map(|root| format!("`{root}/`"))
                        .collect::<Vec<_>>()
                        .join(" and "),
                ),
                details,
            ));
        };

    // ONE probe implementation, shared with the command that MAKES this true:
    // `kata init` writes the missing rules through the same answers
    // (`cli::repo_ignore`). A second `git check-ignore` beside this one is how
    // init would come to write rules that do not clear the row it routes at.
    let answers = match crate::cli::repo_ignore::probe_ignored(repo, &roots) {
        Ok(answers) => answers,
        Err(reason) => {
            unverifiable(checks, details, &reason);
            return;
        }
    };

    let mut diagnostic = Vec::with_capacity(roots.len());
    let mut unignored: Vec<&str> = Vec::new();
    for answer in &answers {
        let root = answer.root.as_str();
        match &answer.matched {
            None => {
                unignored.push(root);
                details.insert(format!("root.{root}"), "not_ignored".to_string());
                diagnostic.push(format!("{root}/ — NOT ignored by this repository"));
            }
            Some((source, linenum, pattern)) => {
                details.insert(format!("root.{root}"), format!("{source}:{linenum}"));
                diagnostic.push(format!(
                    "{root}/ — ignored by {source}:{linenum} (`{pattern}`)"
                ));
            }
        }
    }

    if unignored.is_empty() {
        checks.push(
            DoctorCheck::pass(
                "target_repo_ignore",
                "the target repository ignores every path kata writes into it",
                details,
            )
            .with_diagnostic(diagnostic),
        );
        return;
    }

    details.insert("not_ignored".to_string(), unignored.join(","));
    // The remedy is DERIVED from the roots that actually failed, so it can never
    // name a path the check does not refuse, nor miss one it does — and it is
    // spelled by the same `ignore_pattern` `kata init` writes, so the text an
    // operator is told to add is byte-identical to the text init would have.
    let remedy = unignored
        .iter()
        .map(|root| crate::cli::repo_ignore::ignore_pattern(root))
        .collect::<Vec<_>>()
        .join("` and `");
    checks.push(
        DoctorCheck::fail(
            "target_repo_ignore",
            format!(
                "the target repository {} does NOT ignore {}, and kata writes {} there — a \
                 landing stage that stages the tree \
                 commits kata's own internals into that repository's history (measured: 46 \
                 files / 333 insertions promoted to trunk on the first live gold-loop run). Add \
                 `{remedy}` to {}/.gitignore (or .git/info/exclude) and re-run",
                repo.display(),
                unignored
                    .iter()
                    .map(|root| format!("`{root}/`"))
                    .collect::<Vec<_>>()
                    .join(" and "),
                if unignored.len() == 1 { "it" } else { "them" },
                repo.display(),
            ),
            details,
        )
        .with_diagnostic(diagnostic),
    );
}

/// Prove kata can tell which branch is this repository's TRUNK
/// (`trunk_resolution`).
///
/// ## The defect this closes
///
/// kata hard-coded trunk as the literal `"main"` and, when that bookmark was
/// absent, forked the execution workspace from jj's EMPTY ROOT and returned
/// `Ok`. The agent then ran against a tree with none of the repository in it,
/// spent whatever it spends, and the run failed at its LAST stage. Every
/// surface in between — `create_workspace`, `workspace_status`, the recorded
/// identity — reported success, and the identity even claimed
/// `base_ref = "main"` on a repository that had no such branch.
///
/// doctor's entire job is first-run readiness, and it reported PASS for a
/// repository kata could not work on at all.
///
/// ## What it measures, and whose environment
///
/// The DAEMON's, not the invoking shell's. It asks the repository at
/// `vcs.jj_repo` — the path the node will point its provider at — and it reads
/// `vcs.trunk` from the same config the node will boot with. It never consults
/// the process CWD and never consults git `HEAD`: `HEAD` names the branch the
/// operator running `kata doctor` happens to be standing on, which is a fact
/// about the shell, and (measured, git 2.43.0) it also names an UNBORN branch
/// in a repository whose `refs/heads/` is empty.
///
/// It goes through [`observe_trunk_at`] and
/// [`kata_vcs::trunk::resolve_trunk`] — the same observation and the same
/// policy the providers use at run time — so a doctor PASS and a run-time
/// refusal cannot disagree.
///
/// ## Why `fail` and not `warn`
///
/// An unresolvable trunk is not a degraded mode. Every `worktree_isolated`
/// run is refused at submission, when its trunk target is resolved and frozen
/// (`target not resolved: …`), and a schedule records that firing as refused.
/// The remedy is one
/// config key or one `git remote set-head`. Following the `target_repo_ignore`
/// row's shape, the cases doctor cannot OBSERVE — a repo path that does not
/// exist, a directory that is not a git repository, a host with no `git` —
/// `warn` instead, because an unobserved property must not be published as a
/// verified one in either direction.
///
/// [`observe_trunk_at`]: kata_workflow::worktree_isolation::observe_trunk_at
fn push_trunk_resolution_check(checks: &mut Vec<DoctorCheck>, cfg: &kata_types::KataConfig) {
    use kata_workflow::worktree_isolation::observe_trunk_at;

    let repo = cfg.vcs.jj_repo.as_path();
    let mut details = BTreeMap::new();
    details.insert("repo".to_string(), repo.display().to_string());
    details.insert(
        "configured".to_string(),
        cfg.vcs
            .trunk
            .clone()
            .unwrap_or_else(|| "<unset>".to_string()),
    );

    let unverifiable =
        |checks: &mut Vec<DoctorCheck>, mut details: BTreeMap<String, String>, reason: &str| {
            details.insert("unverified".to_string(), reason.to_string());
            checks.push(DoctorCheck::warn(
                "trunk_resolution",
                format!(
                    "cannot verify which branch kata would treat as trunk in {} — {reason}. Every \
                 `worktree_isolated` workflow forks from trunk and lands on it, so an \
                 unresolvable trunk refuses every such run. Re-run `kata doctor` once the \
                 repository exists",
                    repo.display(),
                ),
                details,
            ));
        };

    if !repo.is_dir() {
        unverifiable(
            checks,
            details,
            "`vcs.jj_repo` is not an existing directory, so there is no repository to ask",
        );
        return;
    }

    let observed = observe_trunk_at(repo, cfg.vcs.trunk.clone());
    let candidates = observed.candidates();
    details.insert(
        "branches".to_string(),
        observed.local_branches.len().to_string(),
    );
    details.insert("candidates".to_string(), candidates.len().to_string());
    details.insert(
        "remote_head".to_string(),
        observed
            .remote_head
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    );

    // NO branches AND no configured trunk AND no remote HEAD is
    // indistinguishable from "this is not a git repository" through
    // `for-each-ref` alone, and the two need different messages.
    if observed.local_branches.is_empty()
        && !repo.join(".git").exists()
        && !repo.join(".jj").exists()
    {
        unverifiable(
            checks,
            details,
            "that directory is not a git repository (no `.git`, no `.jj`), so it has no \
             branches to ask about",
        );
        return;
    }

    match kata_vcs::trunk::resolve_trunk(&observed) {
        Ok(kata_vcs::trunk::TrunkResolution::Resolved { name, source }) => {
            details.insert("trunk".to_string(), name.clone());
            details.insert("source".to_string(), source.as_str().to_string());
            checks.push(
                DoctorCheck::pass(
                    "trunk_resolution",
                    format!("kata resolves this repository's trunk as `{name}`"),
                    details,
                )
                .with_diagnostic(vec![format!(
                    "trunk `{name}` resolved from {} ({} branch(es), {} kata did not create)",
                    source.as_str(),
                    observed.local_branches.len(),
                    candidates.len(),
                )]),
            );
        }
        Ok(kata_vcs::trunk::TrunkResolution::NoTrunkYet) => {
            details.insert("trunk".to_string(), "<none>".to_string());
            checks.push(DoctorCheck::warn(
                "trunk_resolution",
                format!(
                    "{} holds no branch kata did not create, so it has no trunk yet. \
                     Nothing can LAND: `promote` refuses until the repository has a trunk; a run \
                     can still START, because the jj provider forks the empty root. Make the \
                     first commit on your trunk branch, or name it \
                     with `vcs.trunk` once it exists",
                    repo.display(),
                ),
                details,
            ));
        }
        Err(err) => {
            details.insert("error".to_string(), err.to_string());
            checks.push(DoctorCheck::fail(
                "trunk_resolution",
                format!(
                    "kata cannot tell which branch is trunk in {}, so every `worktree_isolated` \
                     run is refused at submission (`target not resolved`), and a schedule \
                     records each such firing as refused: {err}",
                    repo.display(),
                ),
                details,
            ));
        }
    }
}

/// Prove kata knows WHO it would commit as in this repository (`commit_identity`).
///
/// ## The defect this refuses
///
/// A `JjBackend::user_settings` that loads exactly one config layer, jj-lib's
/// built-in `config/misc.toml`, sets `user.name` and `user.email` to the empty
/// string, so kata would author commits with jj's EMPTY identity and PUSH them
/// to the operator's forge through `forge_export`. On the git side such a commit
/// carries `JJ_EMPTY_STRING <JJ_EMPTY_STRING>`. A fabricated identity (say
/// `kata <kata@example.invalid>`) would be worse: no empty-identity refusal could
/// ever fire on it.
///
/// doctor's job is first-run readiness, and a PASS for a repository in which
/// every commit kata made would be attributed to nobody is a false green.
///
/// ## What it measures, and whose environment
///
/// The DAEMON's, not the invoking shell's, following the `trunk_resolution`
/// row's precedent for the same reason. It asks about the repository at
/// `vcs.jj_repo` — the path the node will point its provider at — rather than
/// about the process CWD, which is a fact about the operator's terminal. That
/// distinction is not cosmetic here: `git`'s `includeIf "gitdir:…"` gives ONE
/// `~/.gitconfig` different identities per repository, measured, so "who am I"
/// asked in the wrong directory is a different question with a different answer.
///
/// It goes through `kata_vcs::identity::observe_identity_at` and
/// `resolve_commit_identity` — the same observation and the same policy both
/// providers use at run time — so a doctor PASS and a run-time refusal cannot
/// disagree.
///
/// ## Why `fail` and not `warn`
///
/// An unresolvable identity is not a degraded mode. Every `worktree_isolated`
/// workflow refuses at `create_workspace`, before a stage is dispatched. The
/// remedy is one `git config` command, which the message names. As with
/// `target_repo_ignore` and `trunk_resolution`, the case doctor cannot OBSERVE —
/// a repo path that does not exist — `warn`s instead, because an unobserved
/// property must not be published as a verified one in either direction.
fn push_commit_identity_check(checks: &mut Vec<DoctorCheck>, cfg: &kata_types::KataConfig) {
    let repo = cfg.vcs.jj_repo.as_path();
    let mut details = BTreeMap::new();
    details.insert("repo".to_string(), repo.display().to_string());

    if !repo.is_dir() {
        details.insert(
            "unverified".to_string(),
            "`vcs.jj_repo` is not an existing directory".to_string(),
        );
        checks.push(DoctorCheck::warn(
            "commit_identity",
            format!(
                "cannot verify who kata would commit as in {} — `vcs.jj_repo` is not an \
                 existing directory, so there is no repository to ask. Re-run `kata doctor` \
                 once it exists",
                repo.display(),
            ),
            details,
        ));
        return;
    }

    let observed = kata_vcs::identity::observe_identity_at(repo);
    match kata_vcs::identity::resolve_commit_identity(&observed) {
        Ok(identity) => {
            details.insert("author".to_string(), identity.author_line());
            checks.push(
                DoctorCheck::pass(
                    "commit_identity",
                    format!(
                        "kata would commit as `{}` in this repository",
                        identity.author_line()
                    ),
                    details,
                )
                .with_diagnostic(vec![
                    "resolved by asking git — `git -c user.useConfigOnly=true var \
                     GIT_AUTHOR_IDENT` at the repository root, which covers the environment, \
                     the system/global/local config layers and `includeIf`"
                        .to_string(),
                ]),
            );
        }
        Err(err) => {
            details.insert("error".to_string(), err.to_string());
            checks.push(DoctorCheck::fail(
                "commit_identity",
                format!(
                    "kata has no identity to commit as in {}, so every `worktree_isolated` \
                     workflow will refuse at workspace creation: {err}",
                    repo.display(),
                ),
                details,
            ));
        }
    }
}

fn push_memory_proposal_check(checks: &mut Vec<DoctorCheck>, name: &'static str, path: &Path) {
    let mut details = BTreeMap::new();
    details.insert("path".to_string(), path.display().to_string());
    if !path.exists() {
        checks.push(DoctorCheck::warn(
            name,
            "memory inbox proposal is not present",
            details,
        ));
        return;
    }

    match std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))
        .and_then(|raw| {
            serde_json::from_str::<MemoryProposal>(&raw)
                .with_context(|| format!("decoding {}", path.display()))
        }) {
        Ok(proposal) => {
            details.insert(
                "object_id".to_string(),
                proposal
                    .object
                    .id
                    .as_deref()
                    .unwrap_or("<none>")
                    .to_string(),
            );
            details.insert("kind".to_string(), proposal.object.kind.label().to_string());
            details.insert(
                "status".to_string(),
                proposal.object.status.label().to_string(),
            );
            checks.push(DoctorCheck::pass(
                name,
                "memory inbox proposal decodes",
                details,
            ));
        }
        Err(err) => {
            details.insert("error".to_string(), err.to_string());
            checks.push(DoctorCheck::fail(
                name,
                "memory inbox proposal is malformed",
                details,
            ));
        }
    }
}

fn push_library_check(checks: &mut Vec<DoctorCheck>, library: &WorkflowLibrary) {
    let entries = library.list_effective();
    let mut details = BTreeMap::new();
    details.insert("effective_workflows".to_string(), entries.len().to_string());
    details.insert(
        "roots".to_string(),
        library
            .roots()
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    if entries.is_empty() {
        checks.push(DoctorCheck::fail(
            "workflow_library",
            "no effective workflows found in workflow library roots",
            details,
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "workflow_library",
            "workflow library has effective workflows",
            details,
        ));
    }
}

fn push_workflow_check(
    checks: &mut Vec<DoctorCheck>,
    library: &WorkflowLibrary,
    workflow: &str,
    requirement: WorkflowRequirement,
) {
    let mut details = BTreeMap::new();
    details.insert("workflow".to_string(), workflow.to_string());
    let path = match resolve_workflow(library, workflow) {
        Ok(path) => {
            details.insert("path".to_string(), path.display().to_string());
            path
        }
        Err(err) => {
            details.insert("error".to_string(), err.to_string());
            push_workflow_failure(
                checks,
                requirement,
                format!("workflow {workflow} could not be resolved"),
                details,
            );
            return;
        }
    };

    match check_workflow(library, &path) {
        Ok(summary) if summary.error_count == 0 && summary.status != VerifierStatus::Error => {
            details.insert("status".to_string(), format!("{:?}", summary.status));
            details.insert(
                "diagnostic_count".to_string(),
                summary.diagnostic_count.to_string(),
            );
            details.insert(
                "warning_count".to_string(),
                summary.warning_count.to_string(),
            );
            details.insert("stage_count".to_string(), summary.stage_count.to_string());
            details.insert(
                "agent_labels".to_string(),
                summary
                    .agent_labels
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(","),
            );
            if summary.warning_count > 0 {
                checks.push(DoctorCheck::warn(
                    "workflow_check",
                    format!("workflow {workflow} compiles with verifier warnings"),
                    details,
                ));
            } else {
                checks.push(DoctorCheck::pass(
                    "workflow_check",
                    format!("workflow {workflow} compiles to checked execution IR"),
                    details,
                ));
            }
        }
        Ok(summary) => {
            details.insert("status".to_string(), format!("{:?}", summary.status));
            details.insert(
                "diagnostic_count".to_string(),
                summary.diagnostic_count.to_string(),
            );
            details.insert("error_count".to_string(), summary.error_count.to_string());
            details.insert(
                "warning_count".to_string(),
                summary.warning_count.to_string(),
            );
            details.insert(
                "diagnostics".to_string(),
                summary.diagnostic_texts.join("\n"),
            );
            push_workflow_failure(
                checks,
                requirement,
                format!("workflow {workflow} failed checked execution IR verification"),
                details,
            );
        }
        Err(err) => {
            // `{err:#}` renders the whole anyhow CHAIN; `err.to_string()` — what
            // this was — renders only the outermost context, which here is
            // always "failed to compile resolved workflow at <path> into checked
            // execution IR". That names the file and nothing about the defect.
            //
            // A refusal's actionable cause lives in the inner error, which the
            // outermost context alone drops.
            let chain = format!("{err:#}");
            details.insert("error".to_string(), chain.clone());
            // A refusal naming a fact the node's CONFIG never declared is an
            // operator recourse, not pack breakage: `kata init` cannot invent
            // `[node] environment`, an `egress_allow` authority, or a
            // credential — so a generated project always leaves some doors
            // undeclared, and the seeded starters that author `net = "host"`
            // or need a credential refuse there. Doctor ADVISES on those: the pack may be fine, this node
            // just cannot run it yet, and the refusal text already names the
            // declaration to make. A pack refused for its own authoring — a
            // `host` sandbox under `oci`, an unhonoured knob — still fails at
            // its requirement, because declaring a fact cannot fix it.
            if UNDECLARED_NODE_FACT_DOORS
                .iter()
                .any(|door| chain.contains(&format!("{door}:")))
            {
                checks.push(DoctorCheck::warn(
                    "workflow_check",
                    format!(
                        "workflow {workflow} compiles but is refused on facts this node does \
                         not declare"
                    ),
                    details,
                ));
            } else {
                push_workflow_failure(
                    checks,
                    requirement,
                    format!("workflow {workflow} failed to compile"),
                    details,
                );
            }
        }
    }
}

/// What `kata doctor` tells an operator to do about a missing bundled starter.
///
/// It names the whole TRIPLE `share/kata/{workflows,kata-factory,examples}`:
/// `kata_program::library::incomplete_installed_layout_warning` fires at every
/// boot unless all three are uniformly present or uniformly absent, so a remedy
/// naming two of three would leave an operator who followed it literally with
/// `INCOMPLETE installed bundle … MISSING: …/share/kata/examples` forever after.
///
/// `the_optional_starter_remedy_clears_the_warning_it_is_meant_to_clear` holds
/// it to the directories that check actually wants, by BUILDING the tree this
/// string names and asserting the warning goes quiet.
const OPTIONAL_STARTER_REMEDY: &str = "install the bundled workflow packs \
     (share/kata/{workflows,kata-factory,examples} — install all three, a partial bundle \
     warns at boot) or set KATA_STDLIB_DIR; this starter is optional on a fresh init";

/// The refusal doors whose recourse is a declaration in THIS node's config —
/// `[node]` environment/egress facts, `[agents.*]` adapter and credential
/// facts, and the pricing and token-count facts a hard dollar or token bound
/// needs — as each refusal
/// name renders at the head of its `name: <detail>` validation text. A check
/// refused on one of these is advisory in doctor (see `push_workflow_check`'s
/// `Err` arm); every other compile refusal still fails at its requirement.
/// Omitted on purpose: `host_sandbox_unsupported_under_oci`,
/// `per_stage_toolchain_unsupported_under_oci`,
/// and `per_stage_image_unsupported_under_oci` — those refuse pack AUTHORING on
/// this profile, and no `[node]`/`[agents.*]` declaration makes the pack run.
const UNDECLARED_NODE_FACT_DOORS: &[&str] = &[
    "node_environment_undeclared",
    "oci_provider_undeclared",
    "adapter_undeclared",
    "adapter_unqualified",
    "credential_undeclared",
    "egress_undeclared",
    "cost_bound_unenforceable_unpriced_adapter",
    "environment_requirement_unmet",
];

/// Record a workflow compile/resolve failure at the severity its
/// [`WorkflowRequirement`] dictates: a hard `[fail]` for Required starters, an
/// advisory `[warn]` for Optional (bundled-stdlib absent on a fresh host)
/// starters. Each advisory names its own remedy.
fn push_workflow_failure(
    checks: &mut Vec<DoctorCheck>,
    requirement: WorkflowRequirement,
    message: String,
    mut details: BTreeMap<String, String>,
) {
    match requirement {
        WorkflowRequirement::Required => {
            checks.push(DoctorCheck::fail("workflow_check", message, details));
        }
        WorkflowRequirement::Optional => {
            details.insert("remedy".to_string(), OPTIONAL_STARTER_REMEDY.to_string());
            checks.push(DoctorCheck::warn(
                "workflow_check",
                format!("{message} (optional bundled-stdlib starter)"),
                details,
            ));
        }
    }
}

fn online_doctor_checks(api_url: &str) -> Vec<DoctorCheck> {
    let (health, status) = block_on_online_checks(api_url);
    vec![
        online_health_check(api_url, health),
        online_status_check(api_url, status),
    ]
}

fn online_health_check(
    api_url: &str,
    health: std::result::Result<OnlineHealthSummary, String>,
) -> DoctorCheck {
    let mut details = BTreeMap::new();
    details.insert("api_url".to_string(), api_url.to_string());
    match health {
        Ok(health) => {
            details.insert(
                "subsystem_count".to_string(),
                health.subsystem_count.to_string(),
            );
            details.insert("degraded".to_string(), health.degraded.to_string());
            details.insert("unavailable".to_string(), health.unavailable.to_string());
            if health.unavailable > 0 {
                DoctorCheck::fail(
                    "online_health",
                    "online API health is reachable but one or more subsystems are unavailable",
                    details,
                )
            } else if health.degraded > 0 {
                DoctorCheck::warn(
                    "online_health",
                    "online API health is reachable with degraded subsystem(s)",
                    details,
                )
            } else {
                DoctorCheck::pass(
                    "online_health",
                    "online API health is reachable and healthy",
                    details,
                )
            }
        }
        Err(err) => {
            details.insert("error".to_string(), err);
            DoctorCheck::fail("online_health", "online API health check failed", details)
        }
    }
}

fn online_status_check(
    api_url: &str,
    status: std::result::Result<SystemStatus, String>,
) -> DoctorCheck {
    let mut details = BTreeMap::new();
    details.insert("api_url".to_string(), api_url.to_string());
    match status {
        Ok(status) => {
            let node_id = status.node_id;
            let process_mode = status.process_mode;
            details.insert("node_id".to_string(), node_id.clone());
            details.insert("process_mode".to_string(), process_mode.clone());
            if let Some(directory_id) = status.directory_id {
                details.insert("directory_id".to_string(), directory_id);
            }
            if let Some(process_generation) = status.process_generation {
                details.insert("process_generation".to_string(), process_generation);
            }
            details.insert(
                "uptime_seconds".to_string(),
                status.uptime_seconds.to_string(),
            );
            if node_id == "unknown" || process_mode.is_empty() || !status.ready {
                return DoctorCheck::fail(
                    "online_status",
                    "online API status is reachable but reports placeholder identity",
                    details,
                );
            }
            DoctorCheck::pass("online_status", "online API status is reachable", details)
        }
        Err(err) => {
            details.insert("error".to_string(), err);
            DoctorCheck::fail("online_status", "online API status check failed", details)
        }
    }
}

struct OnlineHealthSummary {
    subsystem_count: usize,
    degraded: usize,
    unavailable: usize,
}

fn block_on_online_checks(
    api_url: &str,
) -> (
    std::result::Result<OnlineHealthSummary, String>,
    std::result::Result<SystemStatus, String>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime for online doctor check")
    {
        Ok(runtime) => runtime,
        Err(err) => {
            let error = err.to_string();
            return (Err(error.clone()), Err(error));
        }
    };

    runtime.block_on(async move {
        let client = match KataClient::new_with_env_token(api_url.to_string())
            .context("building the kata API client")
        {
            Ok(client) => client,
            Err(err) => {
                let error = err.to_string();
                return (Err(error.clone()), Err(error));
            }
        };
        let health = client
            .health()
            .await
            .context("GET /health")
            .map(online_health_summary)
            .map_err(|err| err.to_string());
        let status = client
            .system_status()
            .await
            .context("GET /system/status")
            .map_err(|err| err.to_string());
        (health, status)
    })
}

fn online_health_summary(health: HealthSnapshot) -> OnlineHealthSummary {
    let mut degraded = 0;
    let mut unavailable = 0;
    for (_, subsystem) in &health.subsystems {
        match subsystem {
            SubsystemHealth::Healthy => {}
            SubsystemHealth::Degraded { .. } => degraded += 1,
            SubsystemHealth::Unavailable { .. } => unavailable += 1,
        }
    }
    OnlineHealthSummary {
        subsystem_count: health.subsystems.len(),
        degraded,
        unavailable,
    }
}

fn resolve_workflow(library: &WorkflowLibrary, workflow: &str) -> Result<PathBuf> {
    let candidate = Path::new(workflow);
    if candidate.is_file() {
        return Ok(candidate.to_path_buf());
    }
    if looks_like_path(workflow) {
        bail!(
            "workflow path {} could not be read as a file",
            candidate.display()
        );
    }
    library
        .resolve(workflow)
        .with_context(|| format!("workflow {workflow:?} could not be resolved"))
}

#[derive(Debug)]
struct WorkflowCheckSummary {
    status: VerifierStatus,
    diagnostic_count: usize,
    error_count: usize,
    warning_count: usize,
    stage_count: usize,
    agent_labels: BTreeSet<String>,
    /// Every verifier diagnostic as `code: message` — the failure evidence,
    /// not only a count.
    diagnostic_texts: Vec<String>,
}

fn check_workflow(library: &WorkflowLibrary, path: &Path) -> Result<WorkflowCheckSummary> {
    let artifact =
        kata_program::preflight::build_workflow_compiled_artifact_from_file(path, library.roots())
            .with_context(|| {
                format!(
                    "failed to compile resolved workflow at {} into checked execution IR",
                    path.display()
                )
            })?;
    let execution_program = &artifact.execution_program;
    let mut error_count = 0;
    let mut warning_count = 0;
    for diagnostic in &execution_program.verifier.diagnostics {
        match diagnostic.severity {
            VerifierSeverity::Error => error_count += 1,
            VerifierSeverity::Warning => warning_count += 1,
            VerifierSeverity::Info => {}
        }
    }
    let status = execution_program.verifier.status;
    let diagnostic_count = execution_program.verifier.diagnostics.len();
    let agent_labels = artifact.agent_labels.into_iter().collect::<BTreeSet<_>>();
    let diagnostic_texts = execution_program
        .verifier
        .diagnostics
        .iter()
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .collect();

    Ok(WorkflowCheckSummary {
        status,
        diagnostic_count,
        error_count,
        warning_count,
        stage_count: artifact.stage_count,
        agent_labels,
        diagnostic_texts,
    })
}

/// Whether the bundled factory stdlib (`kata/factory.star`) is installed in any
/// of the workflow library roots. The factory starter packs `load()` this
/// module, so its presence is the exact signal that separates a fresh host
/// missing its bundled packs (a factory-pack compile failure is *expected* and
/// advisory) from a fully-installed host whose factory pack is genuinely broken
/// (a compile failure is a real fault and must hard-fail).
fn bundled_factory_stdlib_present(library: &WorkflowLibrary) -> bool {
    library
        .roots()
        .iter()
        .any(|root| root.join("kata").join("factory.star").is_file())
}

pub(super) fn workflow_library_for_config_dir(config_dir: &Path) -> WorkflowLibrary {
    let mut roots = vec![config_dir.join("workflows")];
    for root in WorkflowLibrary::default_roots().roots().iter().skip(1) {
        if !roots.iter().any(|existing| existing == root) {
            roots.push(root.clone());
        }
    }
    WorkflowLibrary::new(roots)
}

fn render_doctor_report(report: &DoctorReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "kata doctor: {} (failures={} warnings={})",
        if report.passed { "pass" } else { "fail" },
        report.failure_count,
        report.warning_count
    );
    let _ = writeln!(out, "config: {}", report.config);
    for check in &report.checks {
        let _ = writeln!(
            out,
            "[{}] {:<28} {}",
            check.status.as_str(),
            check.name,
            check.message
        );
        if let Some(error) = check.details.get("error") {
            let _ = writeln!(out, "      error: {error}");
        }
        for line in &check.diagnostic {
            let _ = writeln!(out, "      {line}");
        }
    }
    if !report.next_commands.is_empty() {
        out.push_str("next:\n");
        for command in &report.next_commands {
            let _ = writeln!(out, "  {command}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config holding exactly `agents`, parsed as `[agents.*]` TOML.
    fn config_with_agents(agents: &str) -> kata_types::KataConfig {
        #[derive(serde::Deserialize)]
        struct Doc {
            #[serde(deserialize_with = "kata_types::config::deserialize_agents")]
            agents: BTreeMap<String, kata_types::config::AgentBackendConfig>,
        }
        let mut cfg: kata_types::KataConfig = toml::from_str(
            "[node]\nid = \"doctor\"\ndata_dir = \"data\"\n\n[workers]\ndispatch_deadline_ms = \
             30000\nassignment_start_deadline_ms = 900000\nheartbeat_interval_ms = \
             10000\nheartbeat_grace_ms = 30000\nmax_workers = 4\n\n[[workers.transports]]\ntype = \
             \"supervised_node\"\n\n[api]\nbind = \
             \"127.0.0.1:8400\"\n\n[api.auth]\ntype = \"disabled\"\n",
        )
        .expect("a minimal config");
        cfg.agents = toml::from_str::<Doc>(agents).expect("the agents").agents;
        cfg
    }

    fn kata_login_row(cfg: &kata_types::KataConfig, dir: &Path) -> Option<DoctorCheck> {
        let mut checks = Vec::new();
        push_kata_login_check(&mut checks, cfg, Ok(dir.to_path_buf()));
        assert!(checks.len() <= 1);
        checks.pop()
    }

    /// **`credential_mode_mismatch` is the declared mode's file absent beside the
    /// provider's other one.** A `nanocode_openai` agent declaring
    /// `mode = "subscription"` over a logins directory holding only an API key
    /// warns `credential_mode_mismatch`, naming both files and the command;
    /// declaring `mode = "api_key"` over the same directory passes; with no file
    /// at all it warns "absent" and no mismatch; a group-readable key fails
    /// naming the path; an Anthropic subscription fails (no Claude login in
    /// this build). A config with no `kata_login` agent gets no row.
    ///
    /// **Would red if:** the row read a file other than the declared mode's, or
    /// scored an operator's pending login as a hard failure.
    #[test]
    fn a_mode_mismatch_reports_credential_mode_mismatch() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let dir = kata_agent_nanocode::credential::logins_dir(home.path());
        let block = |mode: &str, adapter: &str| {
            config_with_agents(&format!(
                "[agents.coder]\nadapter = \"{adapter}\"\ncredential = {{ \
                 mode = \"{mode}\", source = \"kata_login\" }}\n"
            ))
        };
        let subscription = block("subscription", "nanocode_openai");

        let absent = kata_login_row(&subscription, &dir).expect("a row");
        assert_eq!(absent.status, DoctorStatus::Warn, "{absent:?}");
        assert!(
            absent.diagnostic[0].contains("openai-chatgpt.json: absent; run `kata login openai`")
        );
        assert!(!absent.diagnostic[0].contains("credential_mode_mismatch"));

        kata_agent_nanocode::credential::store_api_key(
            &dir,
            kata_agent_nanocode::credential::LoginFile::OpenAiApiKey,
            "sk-doctor",
        )
        .unwrap();
        let mismatch = kata_login_row(&subscription, &dir).expect("a row");
        assert_eq!(mismatch.status, DoctorStatus::Warn, "{mismatch:?}");
        let line = &mismatch.diagnostic[0];
        assert!(
            line.starts_with("[agents.coder] credential_mode_mismatch:"),
            "{line}"
        );
        assert!(
            line.contains("openai-chatgpt.json") && line.contains("openai-api-key"),
            "{line}"
        );
        assert!(line.contains("run `kata login openai`"), "{line}");
        assert!(!format!("{mismatch:?}").contains("sk-doctor"));

        let api_key = kata_login_row(&block("api_key", "nanocode_openai"), &dir).expect("a row");
        assert_eq!(api_key.status, DoctorStatus::Pass, "{api_key:?}");

        let key = dir.join("openai-api-key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
        let insecure = kata_login_row(&block("api_key", "nanocode_openai"), &dir).expect("a row");
        assert_eq!(insecure.status, DoctorStatus::Fail, "{insecure:?}");
        assert!(insecure.diagnostic[0].contains(&key.display().to_string()));

        let claude =
            kata_login_row(&block("subscription", "nanocode_anthropic"), &dir).expect("a row");
        assert_eq!(claude.status, DoctorStatus::Fail, "{claude:?}");

        let none = config_with_agents(
            "[agents.coder]\nadapter = \"nanocode_openai\"\ncredential = { \
             mode = \"api_key\", source = \"env:OPENAI_API_KEY\" }\n",
        );
        assert!(kata_login_row(&none, &dir).is_none());
    }

    /// **Both doctor rows name the door the CHECK refuses `nanocode_anthropic`
    /// under `subscription` by.** The `kata_login` row fails it naming the
    /// recourse and `credential_mode_unsupported`; the `agent_backends` row
    /// fails it naming `credential_mode_unsupported`, and passes the same block
    /// under `api_key`, whose launch the kind fixes.
    ///
    /// **Would red if:** doctor passed a block every run of which the CHECK
    /// refuses, or named a door the CHECK does not judge first.
    #[test]
    fn doctor_names_the_check_door_for_an_anthropic_subscription() {
        let home = tempfile::tempdir().unwrap();
        let dir = kata_agent_nanocode::credential::logins_dir(home.path());
        let block = |mode: &str| {
            config_with_agents(&format!(
                "[agents.coder]\nadapter = \"nanocode_anthropic\"\n\
                 credential = {{ mode = \"{mode}\", source = \"kata_login\" }}\n"
            ))
        };
        let login_names = |door: &str| {
            let login = kata_login_row(&block("subscription"), &dir).expect("a row");
            assert_eq!(login.status, DoctorStatus::Fail, "{login:?}");
            assert!(
                login.diagnostic[0].contains(&format!("(`{door}` at check;"))
                    && login.diagnostic[0].contains("`kata login anthropic --api-key`"),
                "{door}: {login:?}"
            );
        };
        login_names("credential_mode_unsupported");
        let backends = |cfg: &kata_types::KataConfig| {
            let mut checks = Vec::new();
            push_agent_backend_reachability_check(&mut checks, cfg);
            checks.pop().expect("the agent_backends row")
        };
        let refused = backends(&block("subscription"));
        assert_eq!(refused.status, DoctorStatus::Fail, "{refused:?}");
        assert!(
            refused.diagnostic[0].contains("credential_mode_unsupported:")
                && refused.diagnostic[0].contains("`nanocode_anthropic`"),
            "{refused:?}"
        );
        let admitted = backends(&block("api_key"));
        assert_eq!(admitted.status, DoctorStatus::Pass, "{admitted:?}");
        assert!(
            admitted.diagnostic[0]
                .contains("adapter `nanocode_anthropic`; the kind fixes its launch"),
            "{admitted:?}"
        );
    }

    /// **The `agent_backends` row fails a nanocode block that declares no
    /// credential, naming the CHECK's door and the login.** The embedded
    /// harness runs in the worker on the credential its block declares and
    /// nothing else, so every stage selecting such a block is refused
    /// `credential_undeclared` at check; doctor names it first.
    ///
    /// **Would red if:** doctor passed a block the CHECK refuses every stage of.
    #[test]
    fn doctor_names_the_check_door_for_a_nanocode_block_with_no_credential() {
        let backends = |cfg: &kata_types::KataConfig| {
            let mut checks = Vec::new();
            push_agent_backend_reachability_check(&mut checks, cfg);
            checks.pop().expect("the agent_backends row")
        };
        for (adapter, login) in [
            ("nanocode_openai", "`kata login openai`"),
            ("nanocode_anthropic", "`kata login anthropic --api-key`"),
        ] {
            let refused = backends(&config_with_agents(&format!(
                "[agents.coder]\nadapter = \"{adapter}\"\n"
            )));
            assert_eq!(refused.status, DoctorStatus::Fail, "{adapter}: {refused:?}");
            assert!(
                refused.diagnostic[0].contains("credential_undeclared:")
                    && refused.diagnostic[0].contains(&format!("adapter `{adapter}`"))
                    && refused.diagnostic[0].contains(login),
                "{adapter}: {refused:?}"
            );
        }
    }

    /// **The `agent_backends` row fails every harness block `kata
    /// config check` refuses, naming the same door, and passes the blocks it
    /// admits.** Each row is one `[agents.coder]` block the CHECK refuses on
    /// config alone by a door the row did not judge before it asked `kata
    /// config check`'s judgement: an unparseable credential and a declared
    /// `env` collision (a channel kata renders, a secret-shaped name), the node
    /// facts installed from the config first, as a doctor run installs them.
    /// The oracle is the door name each row spells,
    /// not the judgement under test.
    ///
    /// **Would red if:** the row passed a block every stage selecting which the
    /// CHECK refuses (watched: before the row asked `kata config check`'s
    /// judgement, a nanocode block declaring `env.HOME` passed, "every
    /// configured agent declares a launchable capsule").
    #[test]
    fn the_backend_row_fails_every_block_config_check_refuses_by_its_door() {
        let backends = |block: &str| {
            let cfg = config_with_agents(&format!("[agents.coder]\n{block}"));
            crate::cli::install_node_facts_from_config(&cfg);
            let mut checks = Vec::new();
            push_agent_backend_reachability_check(&mut checks, &cfg);
            checks.pop().expect("the agent_backends row")
        };
        let openai_key = "credential = { mode = \"api_key\", source = \"env:OPENAI_API_KEY\" }";
        let openai = "adapter = \"nanocode_openai\"";
        let rows: Vec<(String, &str)> = vec![
            (
                format!("{openai}\n{openai_key}\nenv = {{ HOME = \"/h\" }}"),
                "capsule_agent_env_channel_owned",
            ),
            (
                format!("{openai}\n{openai_key}\nenv = {{ VENDOR_TOKEN = \"x\" }}"),
                "capsule_agent_env_secret_named",
            ),
            (
                format!("{openai}\ncredential = {{ mode = \"bogus\", source = \"kata_login\" }}"),
                "credential_undeclared",
            ),
        ];
        for (block, door) in &rows {
            let row = backends(block);
            assert_eq!(row.status, DoctorStatus::Fail, "{door}: {block:?}: {row:?}");
            assert_eq!(
                row.details.get("unmet").map(String::as_str),
                Some("coder"),
                "{door}: {row:?}"
            );
            assert!(
                row.diagnostic[0].contains(&format!("{door}:")),
                "the line names `{door}` for {block:?}: {row:?}"
            );
        }
        for block in [
            format!("{openai}\n{openai_key}\nenv = {{ TERM = \"dumb\" }}"),
            "adapter = \"nanocode_anthropic\"\ncredential = { mode = \"api_key\", source = \
             \"kata_login\" }\nenv = { TERM = \"dumb\" }"
                .to_owned(),
        ] {
            let row = backends(&block);
            assert_eq!(row.status, DoctorStatus::Pass, "{block:?}: {row:?}");
        }
    }

    /// **The `agent_backends` row lists the shell route under either reserved
    /// deterministic label.** `[agents.shell]` and `[agents.workspace_effect]`
    /// parse to the deterministic executor (the label decides; the block takes no
    /// key), so neither is a capsule launch a stage could be refused for. An empty
    /// block under any other label is a harness entry with no `adapter`, and the
    /// row fails it `adapter_undeclared`. The oracle for the reserved blocks is
    /// the config's own validation.
    ///
    /// **Would red if:** the row failed a reserved label's block (watched: the
    /// `workspace_effect` block failed, "every stage selecting it is refused
    /// `adapter_undeclared`").
    #[test]
    fn the_backend_row_lists_both_reserved_deterministic_labels_and_fails_an_empty_harness_block() {
        let backends = |agents: &str| {
            let cfg = config_with_agents(agents);
            let mut checks = Vec::new();
            push_agent_backend_reachability_check(&mut checks, &cfg);
            (cfg, checks.pop().expect("the agent_backends row"))
        };
        for label in ["shell", "workspace_effect"] {
            let (cfg, row) = backends(&format!("[agents.{label}]\n"));
            cfg.validate()
                .expect("the reserved label's deterministic block validates");
            assert_eq!(row.status, DoctorStatus::Pass, "{label}: {row:?}");
            assert!(
                row.diagnostic[0].contains(&format!("reserved `{label}` label")),
                "{label}: {row:?}"
            );
        }
        let (_, other) = backends("[agents.default]\n");
        assert_eq!(other.status, DoctorStatus::Fail, "{other:?}");
        assert!(
            other.diagnostic[0].contains("adapter_undeclared:"),
            "{other:?}"
        );
    }

    /// **An unset `env:` variable only warns, naming the variable.**
    #[test]
    fn an_unset_env_credential_warns_naming_the_variable() {
        let cfg = config_with_agents(
            "[agents.coder]\nadapter = \"nanocode_openai\"\ncredential = { \
             mode = \"api_key\", source = \"env:DOCTOR_TEST_KEY\" }\n",
        );
        let mut checks = Vec::new();
        push_credential_env_check(&mut checks, &cfg, |_| None);
        assert_eq!(checks[0].status, DoctorStatus::Warn);
        assert!(
            checks[0].message.contains("coder (DOCTOR_TEST_KEY)"),
            "{}",
            checks[0].message
        );
        let mut checks = Vec::new();
        push_credential_env_check(&mut checks, &cfg, |var| {
            (var == "DOCTOR_TEST_KEY").then(|| "sk-test".into())
        });
        assert_eq!(checks[0].status, DoctorStatus::Pass);
    }

    /// **An `env:` key that no HTTP header carries FAILS the row, naming the
    /// variable and never the value.** The expectations are the HTTP
    /// field-value grammar's, written out here, not asked of the predicate: a
    /// trailing newline, a NUL and a DEL are refused, as is a value that is not
    /// UTF-8; a tab, a space, an empty value and a non-ASCII one are sendable.
    /// The rendered row — message, details and diagnostic, serialized — never
    /// holds the value.
    ///
    /// **Would red if:** the row stopped reading the value (it passed every set
    /// variable), or printed the value.
    #[test]
    fn an_unsendable_env_key_fails_naming_the_variable_never_the_value() {
        use std::os::unix::ffi::OsStringExt as _;
        const SECRET: &str = "sk-doctor-0123456789";
        let agents = "[agents.coder]\nadapter = \"nanocode_openai\"\ncredential = { \
                      mode = \"api_key\", source = \"env:DOCTOR_HARNESS_KEY\" }\n";
        let cfg = config_with_agents(agents);
        let row = |harness: std::ffi::OsString| {
            let mut checks = Vec::new();
            push_credential_env_check(&mut checks, &cfg, |var| match var {
                "DOCTOR_HARNESS_KEY" => Some(harness.clone()),
                _ => None,
            });
            checks.pop().expect("the credential_env row")
        };

        for refused in [
            format!("{SECRET}\n"),
            format!("{SECRET}\0end"),
            format!("{SECRET}\u{7f}"),
        ] {
            let check = row(refused.clone().into());
            assert_eq!(check.status, DoctorStatus::Fail, "{refused:?}: {check:?}");
            assert!(
                check.message.contains("coder (DOCTOR_HARNESS_KEY)"),
                "{}",
                check.message
            );
            let rendered = serde_json::to_string(&check).expect("the row serializes");
            assert!(
                !rendered.contains(SECRET),
                "the row prints the key: {rendered}"
            );
        }
        let not_utf8 = std::ffi::OsString::from_vec(b"sk-\xff\xfe".to_vec());
        assert_eq!(row(not_utf8).status, DoctorStatus::Fail);

        for sendable in [
            format!("{SECRET}\tend"),
            format!("{SECRET} end"),
            String::new(),
            format!("{SECRET}\u{e9}"),
        ] {
            let check = row(sendable.clone().into());
            assert_eq!(check.status, DoctorStatus::Pass, "{sendable:?}: {check:?}");
        }
    }

    /// **An `env:` key that is not UTF-8 FAILS the row on both kinds, naming the
    /// agent and variable and never the value.** The worker refuses such a key
    /// `credential_unavailable` for both nanocode kinds (the harness takes the
    /// key as text). The rendered row never holds the value's readable prefix.
    ///
    /// **Would red if:** the row judged UTF-8 on one kind alone, or printed the
    /// value.
    #[test]
    fn a_non_utf8_env_key_fails_on_every_kind_naming_the_variable_never_the_value() {
        use std::os::unix::ffi::OsStringExt as _;
        const PREFIX: &str = "sk-doctor-utf8-0123456789";
        let not_utf8 = || {
            let mut bytes = PREFIX.as_bytes().to_vec();
            bytes.push(0xff);
            std::ffi::OsString::from_vec(bytes)
        };
        let anthropic = "[agents.reviewer]\nadapter = \"nanocode_anthropic\"\n\
                         credential = { mode = \"api_key\", source = \"env:DOCTOR_ANTHROPIC_KEY\" }\n";
        let openai = "[agents.coder]\nadapter = \"nanocode_openai\"\n\
                      credential = { mode = \"api_key\", source = \"env:DOCTOR_HARNESS_KEY\" }\n";
        let row = |agents: &str| {
            let mut checks = Vec::new();
            push_credential_env_check(&mut checks, &config_with_agents(agents), |_| {
                Some(not_utf8())
            });
            checks.pop().expect("the credential_env row")
        };
        for (agents, named) in [
            (anthropic, "reviewer (DOCTOR_ANTHROPIC_KEY)"),
            (openai, "coder (DOCTOR_HARNESS_KEY)"),
        ] {
            let check = row(agents);
            assert_eq!(check.status, DoctorStatus::Fail, "{named}: {check:?}");
            assert!(check.message.contains(named), "{}", check.message);
            let rendered = serde_json::to_string(&check).expect("the row serializes");
            assert!(
                !rendered.contains(PREFIX),
                "the row prints the key: {rendered}"
            );
        }
    }

    /// The containment exit contract: only a DECLARED requirement this node
    /// cannot honour fails; everything else not available warns.
    #[test]
    fn the_containment_exit_contract_fails_only_a_declared_refusal() {
        use kata_worker::sandbox_posture::{ContainmentFact, ContainmentState};
        let fact = |state, declared_required| ContainmentFact {
            name: "containment_runtime",
            state,
            evidence: "observed".to_string(),
            declared_required,
            details: BTreeMap::new(),
        };
        for declared in [false, true] {
            assert_eq!(
                containment_status(&fact(ContainmentState::Available, declared)),
                DoctorStatus::Pass
            );
        }
        for state in [ContainmentState::Degraded, ContainmentState::Unavailable] {
            assert_eq!(containment_status(&fact(state, false)), DoctorStatus::Warn);
            assert_eq!(containment_status(&fact(state, true)), DoctorStatus::Fail);
        }
    }

    /// **The env-levers row scores the provider declaration by the capsule
    /// route's own resolver** (`kata_worker::capsule_route::declared_oci_provider`):
    /// a declaration admission would refuse — none, half of one, malformed, or a
    /// store entry that does not hash to its address — WARNS and carries the
    /// refusal; one that resolves PASSES. Never a FAIL: a node without a usable
    /// provider is a legitimate install that cannot run capsules yet.
    #[test]
    fn the_env_levers_row_warns_a_declaration_admission_refuses() {
        let refusal = "capsule route refused: oci_provider_undeclared: this node declares none";
        let refused = env_levers_check(
            &[],
            3,
            Err(kata_types::error::KataError::Validation(
                refusal.to_string(),
            )),
        );
        assert_eq!(refused.status, DoctorStatus::Warn, "{}", refused.message);
        assert!(
            refused.message.contains("oci_provider_undeclared"),
            "the row names admission's refusal: {}",
            refused.message
        );
        let resolved = env_levers_check(&[], 3, Ok(()));
        assert_eq!(resolved.status, DoctorStatus::Pass, "{}", resolved.message);
    }

    /// **Doctor never PASSes a host the certification refuses for its AppArmor
    /// profile**. An UNRESTRICTED kernel with no installed profile is
    /// refused `profile_file_absent` by `certify_youki`'s fold, and the
    /// `containment_userns` row reads that same fold, so its doctor status is not
    /// `pass`.
    #[test]
    fn a_host_the_certification_refuses_for_its_profile_is_not_a_doctor_pass() {
        use kata_worker::oci_runtime::{InstalledProfileRead, UsernsRestriction};
        let pin = kata_types::youki_pin::YoukiPin::embedded();
        let listed = format!("{} (unconfined)\n", pin.profile_name());
        let folded = kata_worker::oci_runtime::fold_apparmor_prerequisite(
            pin,
            Ok(listed.as_str()),
            "/etc/apparmor.d/youki",
            InstalledProfileRead::Absent,
        );
        assert!(
            folded.is_err(),
            "the certification refuses a profile-less host"
        );
        let fact = kata_worker::sandbox_posture::userns_fact(
            UsernsRestriction::Unrestricted,
            folded.as_ref(),
        );
        assert_ne!(
            containment_status(&fact),
            DoctorStatus::Pass,
            "{}",
            fact.evidence
        );
    }

    /// Parse `share/kata/{a,b,c}` out of the remedy string — the operator reads
    /// this brace list and types it, so the test must read the SAME text rather
    /// than a second hand-kept list beside it.
    fn directories_the_remedy_names(remedy: &str) -> Vec<String> {
        let (_, rest) = remedy
            .split_once("share/kata/{")
            .expect("the remedy names a share/kata brace list");
        let (list, _) = rest.split_once('}').expect("the brace list is closed");
        list.split(',')
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect()
    }

    /// Following `kata doctor`'s advice must CLEAR the boot warning, not cause it.
    ///
    /// A remedy naming the pair `share/kata/{workflows,kata-factory}` is RED
    /// here: `incomplete_installed_layout_warning` is a TRIPLE check, so an
    /// operator who did exactly what doctor said would get `INCOMPLETE installed
    /// bundle … MISSING: …/share/kata/examples` on every subsequent boot.
    ///
    /// This does not compare two strings — it BUILDS the tree the remedy
    /// describes and asks the real check. A remedy that drifts from the check
    /// again fails here however it is worded.
    ///
    /// COUNTERFACTUAL: drop `examples` from `OPTIONAL_STARTER_REMEDY` and the
    /// warning arrives with the tree the remedy just built.
    #[test]
    fn the_optional_starter_remedy_clears_the_warning_it_is_meant_to_clear() {
        let named = directories_the_remedy_names(OPTIONAL_STARTER_REMEDY);
        assert!(
            named.len() > 1,
            "the remedy must name the whole bundle; parsed {named:?}"
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        let exe = tmp.path().join("bin").join("kata");
        std::fs::create_dir_all(exe.parent().expect("bin dir")).expect("create bin");
        let base = tmp.path().join("share").join("kata");
        for dir in &named {
            std::fs::create_dir_all(base.join(dir)).expect("create bundled pack dir");
        }

        assert_eq!(
            kata_program::library::incomplete_installed_layout_warning(Some(&exe), None),
            None,
            "an operator who installs exactly what `kata doctor` names must get a QUIET \
             boot. The remedy names {named:?}; the boot check wants every directory it \
             treats as a resolution root, and remediation that produces the next warning \
             is worse than no remediation."
        );

        // NON-VACUITY: the check is capable of firing on this tree at all.
        let partial = tmp.path().join("partial");
        let partial_exe = partial.join("bin").join("kata");
        std::fs::create_dir_all(partial_exe.parent().expect("bin dir")).expect("create bin");
        std::fs::create_dir_all(partial.join("share").join("kata").join(&named[0]))
            .expect("create one pack dir");
        assert!(
            kata_program::library::incomplete_installed_layout_warning(Some(&partial_exe), None)
                .is_some(),
            "installing only {:?} must still warn — otherwise the assertion above passes \
             because the check never fires, not because the remedy is right",
            named[0]
        );
    }
}
