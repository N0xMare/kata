//! Native per-user service lifecycle for the installed Kata main.
//!
//! Linux uses systemd-user and Apple-silicon macOS 14+ uses a LaunchAgent.
//! Both invoke the same foreground `kata serve` entrypoint. Containers, root
//! daemons, and a Kata-owned supervisor are deliberately outside this module.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::ffi::{OsStr, OsString};
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::attachment::{InstalledDiscoveryLease, InstalledLifecycleOperationLease};
#[cfg(test)]
use crate::authority_file::read_bounded_utf8;
use crate::authority_file::{
    AuthorityFilePolicy, MAX_KATA_BINARY_BYTES, MAX_SERVICE_ENVIRONMENT_BYTES, config_policy,
    digest_bounded_file,
};
use crate::data_dir_lock::inspect_identity;
pub(crate) use crate::owner_only_publication::{
    ExistingOwnerOnlyPublication, OwnerOnlyNoReplacePublication, OwnerOnlyPublicationTemp,
    OwnerOnlyRemoval, OwnerOnlyReplacementPublication, OwnerOnlyRestoration,
    list_publication_names, list_publication_names_with_prefix,
    recover_owner_only_publication_artifacts,
    recover_owner_only_publication_artifacts_with_temporary_links,
};
#[cfg(test)]
pub(crate) use crate::owner_only_publication::{
    capture_owner_only_publication_identity, inject_next_publication_parent_sync_failure,
    inject_next_publication_removal_parent_sync_failure,
    inject_next_replacement_parent_sync_failure, inject_post_publication_quarantine_hook,
    inject_post_replacement_rename_hook, inject_pre_no_replace_rename_hook,
    inject_pre_publication_removal_rename_hook, publication_removal_attempt_counts,
    remove_exact_owner_only_publication, reset_publication_removal_attempt_counts,
};
use crate::owner_only_publication::{ensure_owner_only_directory, ensure_publication_directory};
use anyhow::{Context, Result, bail};
use kata_crypto::blake3_bytes;
use kata_worker::owner_home::effective_owner_home;

const SYSTEMD_UNIT_NAME: &str = "kata.service";
const LAUNCHD_LABEL: &str = "sh.kata.main";
const SYSTEMCTL_PATH: &str = "/usr/bin/systemctl";
const JOURNALCTL_PATH: &str = "/usr/bin/journalctl";
const LAUNCHCTL_PATH: &str = "/bin/launchctl";
const MACOS_LOG_PATH: &str = "/usr/bin/log";
const SERVICE_DEFINITION_FORMAT: &str = "2";
// Opening and recovering Kata's durable stores can legitimately contend with
// an installation or workspace gate on the same host.  The native manager has
// its own process-start semantics; this bound is specifically for verified
// product readiness after that process is live.
const PRODUCT_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const PRODUCT_READY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
const MANAGER_RECHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_SERVICE_DEFINITION_BYTES: u64 = 1024 * 1024;
const MAX_SERVICE_ENVIRONMENT_SNAPSHOTS: usize = 1024;
const MAX_SERVICE_PUBLICATION_ARTIFACTS: usize = 64;
const SERVICE_PUBLICATION_ARTIFACT_PREFIX: &str = ".kata-service.";
const SERVICE_REPLACEMENT_ROLLBACK_PREFIX: &str = ".kata-service.replace-";
const SERVICE_REPLACEMENT_ROLLBACK_SUFFIX: &str = ".rollback";
const MANAGER_ACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const MANAGER_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MANAGER_LOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const SERVICE_STOPPED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
const MANAGER_OUTPUT_BYTES: usize = 256 * 1024;
const MANAGER_LOG_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const CHILD_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundedCommandFailureKind {
    Timeout,
    OutputLimit,
}

#[derive(Debug)]
struct BoundedCommandFailure {
    kind: BoundedCommandFailureKind,
    label: String,
    timeout: std::time::Duration,
    max_output_bytes: usize,
}

impl std::fmt::Display for BoundedCommandFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            BoundedCommandFailureKind::Timeout => write!(
                formatter,
                "{} exceeded its {:?} deadline; killed and reaped its process group",
                self.label, self.timeout
            ),
            BoundedCommandFailureKind::OutputLimit => write!(
                formatter,
                "{} exceeded its {}-byte combined output ceiling; killed and reaped its process group",
                self.label, self.max_output_bytes
            ),
        }
    }
}

impl std::error::Error for BoundedCommandFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServicePlatform {
    SystemdUser,
    LaunchdAppleSilicon,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    Install,
    Start,
    Stop,
    Restart,
    Status,
    Logs,
    Uninstall,
}

/// The installed-manager mutations that may run while the main retains its
/// discovery lease.  Keeping this set distinct from [`ServiceAction`] makes it
/// impossible to route publication mutation or a read-only query through the
/// lifecycle-only apply entrypoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstalledServiceLifecycleAction {
    Start,
    Stop,
    Restart,
}

impl InstalledServiceLifecycleAction {
    const fn service_action(self) -> ServiceAction {
        match self {
            Self::Start => ServiceAction::Start,
            Self::Stop => ServiceAction::Stop,
            Self::Restart => ServiceAction::Restart,
        }
    }
}

/// Compiler-visible authority for installed service publication.
///
/// Install and uninstall must exclude both another lifecycle operation and a
/// running installed main.  The non-cloneable permit borrows both kernel-lock
/// guards, so neither guard can leave the caller's scope before the complete
/// publication state machine returns.
pub(crate) struct InstalledServicePublicationPermit<'a> {
    _lifecycle: &'a InstalledLifecycleOperationLease,
    discovery: &'a InstalledDiscoveryLease,
}

impl<'a> InstalledServicePublicationPermit<'a> {
    pub(crate) fn new(
        lifecycle: &'a InstalledLifecycleOperationLease,
        discovery: &'a InstalledDiscoveryLease,
    ) -> Self {
        Self {
            _lifecycle: lifecycle,
            discovery,
        }
    }

    pub(crate) const fn discovery_lease(&self) -> &'a InstalledDiscoveryLease {
        self.discovery
    }
}

/// Internal execution authority.  Production callers cannot express an
/// applied operation without carrying the corresponding live lease proof.
enum ServiceExecutionAuthority<'a> {
    Preview,
    ReadOnly,
    Lifecycle(&'a InstalledLifecycleOperationLease),
    Publication(InstalledServicePublicationPermit<'a>),
    /// Unit tests exercise injected manager/fault paths without acquiring the
    /// process-global installed-service locks.  This variant does not exist in
    /// any normal or `test-support` build.
    #[cfg(test)]
    TestApplied,
}

impl ServiceExecutionAuthority<'_> {
    fn validate_action(&self, action: ServiceAction) -> Result<()> {
        let valid = match (self, action) {
            (
                Self::Preview,
                ServiceAction::Install
                | ServiceAction::Start
                | ServiceAction::Stop
                | ServiceAction::Restart
                | ServiceAction::Uninstall,
            ) => true,
            (Self::ReadOnly, ServiceAction::Status | ServiceAction::Logs) => true,
            (
                Self::Lifecycle(lease),
                ServiceAction::Start | ServiceAction::Stop | ServiceAction::Restart,
            ) => {
                let _ = lease;
                true
            }
            (Self::Publication(permit), ServiceAction::Install | ServiceAction::Uninstall) => {
                let _ = permit.discovery_lease();
                true
            }
            #[cfg(test)]
            (
                Self::TestApplied,
                ServiceAction::Install
                | ServiceAction::Start
                | ServiceAction::Stop
                | ServiceAction::Restart
                | ServiceAction::Uninstall,
            ) => true,
            _ => false,
        };
        if !valid {
            bail!(
                "service execution authority does not authorize {action:?}; refusing before native-manager or publication access"
            );
        }
        Ok(())
    }

    const fn is_applied(&self) -> bool {
        match self {
            Self::Preview | Self::ReadOnly => false,
            Self::Lifecycle(_) | Self::Publication(_) => true,
            #[cfg(test)]
            Self::TestApplied => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceSpec {
    pub platform: ServicePlatform,
    pub definition_path: PathBuf,
    pub binary: PathBuf,
    pub config: PathBuf,
    pub working_directory: PathBuf,
    pub data_dir: PathBuf,
    pub binary_digest: String,
    pub binary_version: String,
    pub config_digest: String,
    pub environment_digest: String,
    pub data_directory_id: String,
    pub environment: BTreeMap<String, String>,
    pub environment_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicePlan {
    pub action: ServiceAction,
    pub definition_path: PathBuf,
    pub definition: String,
    pub commands: Vec<Vec<String>>,
    pub changed: bool,
    pub environment_path: PathBuf,
    pub environment_directory: PathBuf,
    pub environment_definition: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnedServiceDefinition {
    raw: String,
    environment_definition: String,
    spec: ServiceSpec,
    definition_publication: ExistingOwnerOnlyPublication,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DefinitionAuthority {
    Absent,
    Exact(Box<OwnedServiceDefinition>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagerAuthority {
    Absent,
    ExactMatching,
    ExactRunning,
    ExactMatchingQuiescent,
    /// The manager proves a structurally exact Kata launch at the fixed
    /// target, but has not loaded the current atomic definition commit yet.
    /// Only install may repair this state by running daemon-reload.
    ExactNeedsReload,
    /// Uninstall removed the atomic definition commit, but systemd still
    /// retains the exact stopped Kata launch until daemon-reload converges.
    ExactStaleRemoval,
}

/// The complete identity carried in the native manager's `__service-exec`
/// invocation. The trampoline compares this snapshot with the definition that
/// is current *after* it acquires the per-owner discovery lease. This closes
/// the manager-to-process window in which an install can replace a unit/plist
/// after the manager has read it but before the old trampoline starts.
pub(crate) struct ServiceExecLaunchIdentity<'a> {
    pub definition: &'a Path,
    pub binary: &'a Path,
    pub environment: &'a Path,
    pub config: &'a Path,
    pub working_directory: &'a Path,
    pub binary_digest: &'a str,
    pub config_digest: &'a str,
    pub environment_digest: &'a str,
    pub data_directory: &'a Path,
    pub directory_id: &'a str,
}

impl ServiceSpec {
    /// Build from a config PATH: canonicalize it, digest its bytes, and bind
    /// both through [`Self::new_with_loaded_config_digest`]. Test fixtures
    /// only; `kata service install` digests the bytes it already parsed.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_for_test(
        platform: ServicePlatform,
        binary: &Path,
        config: &Path,
        data_dir: &Path,
        environment: BTreeMap<String, String>,
    ) -> Result<Self> {
        let config = absolute_existing(config, "Kata config")?;
        let config_digest = current_config_digest(&config)?;
        Self::new_with_loaded_config_digest(
            platform,
            binary,
            &config,
            data_dir,
            environment,
            &BTreeSet::new(),
            config_digest,
        )
    }

    /// Build from the digest of the exact config bytes already parsed by the
    /// caller. Service metadata must not bind a second read that can disagree
    /// with the snapshot used to derive data-directory and environment policy.
    pub(crate) fn new_with_loaded_config_digest(
        platform: ServicePlatform,
        binary: &Path,
        config: &Path,
        data_dir: &Path,
        environment: BTreeMap<String, String>,
        declared_environment: &BTreeSet<String>,
        config_digest: String,
    ) -> Result<Self> {
        let binary = absolute_existing(binary, "Kata binary")?;
        // `config` and `config_digest` are one snapshot identity supplied by
        // the caller that parsed the file. Reopening or canonicalizing the
        // path here would let a path replacement pair A's parsed bytes and
        // digest with B's path, producing a service definition that can never
        // pass its own startup check. The caller resolves the path before
        // reading; this constructor deliberately accepts only that
        // already-resolved absolute path without touching the filesystem.
        if !config.is_absolute() {
            bail!(
                "loaded Kata config snapshot path must be absolute: {}",
                config.display()
            );
        }
        let config = config.to_path_buf();
        let working_directory = config
            .parent()
            .expect("canonical config path has a parent")
            .to_path_buf();
        let data_dir = absolute_path(data_dir)?;
        let definition_path = definition_path(platform)?;
        require_utf8_path(&binary, "Kata binary")?;
        require_utf8_path(&config, "Kata config")?;
        require_utf8_path(&working_directory, "Kata service working directory")?;
        require_utf8_path(&data_dir, "Kata data directory")?;
        require_utf8_path(&definition_path, "Kata service definition")?;
        for (key, value) in &environment {
            if !is_allowed_environment_key(key) && !declared_environment.contains(key) {
                bail!(
                    "service environment key {key:?} is not in Kata's bounded allowlist; use config secret references or an operator-managed environment source"
                );
            }
            if value
                .chars()
                .any(|character| character.is_control() && character != '\t')
            {
                bail!(
                    "service environment value for {key:?} contains a forbidden control character"
                );
            }
        }
        let binary_digest = current_binary_digest(&binary)?;
        let environment_definition = serialize_service_environment(&environment)?;
        let environment_digest = blake3_bytes(environment_definition.as_bytes()).to_string();
        let environment_directory = environment_directory(platform)?;
        let environment_path =
            environment_snapshot_path(&environment_directory, &environment_digest)?;
        require_utf8_path(&environment_path, "Kata service environment")?;
        let data_directory_id = inspect_identity(&data_dir)?.map_or_else(
            || "uninitialized".to_string(),
            |identity| identity.directory_id,
        );
        Ok(Self {
            platform,
            definition_path,
            binary,
            config,
            working_directory,
            data_dir,
            binary_digest,
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            config_digest,
            environment_digest,
            data_directory_id,
            environment,
            environment_path,
        })
    }

    #[must_use]
    pub fn render(&self) -> String {
        match self.platform {
            ServicePlatform::SystemdUser => render_systemd(self),
            ServicePlatform::LaunchdAppleSilicon => render_launchd(self),
        }
    }

    pub fn definition_path(&self) -> Result<PathBuf> {
        Ok(self.definition_path.clone())
    }

    pub fn plan(&self, action: ServiceAction) -> Result<ServicePlan> {
        let definition_path = self.definition_path()?;
        if action == ServiceAction::Logs {
            return Ok(logs_plan(
                self.platform,
                definition_path,
                self.environment_path
                    .parent()
                    .expect("service environment snapshot has a parent")
                    .to_path_buf(),
            ));
        }
        let definition = self.render();
        let environment_definition = serialize_service_environment(&self.environment)?;
        let current = inspect_installed_definition(
            self.platform,
            &definition_path,
            self.environment_path
                .parent()
                .expect("service environment snapshot has a parent"),
        )?;
        let changed = match current {
            DefinitionAuthority::Absent => true,
            DefinitionAuthority::Exact(current) => {
                current.raw != definition
                    || current.environment_definition != environment_definition
            }
        };
        let commands = commands_for(self.platform, action, &definition_path);
        Ok(ServicePlan {
            action,
            definition_path,
            definition,
            commands,
            changed,
            environment_path: self.environment_path.clone(),
            environment_directory: self
                .environment_path
                .parent()
                .expect("service environment snapshot has a parent")
                .to_path_buf(),
            environment_definition,
        })
    }
}

/// Plan an operation against the definition already installed for this user.
/// No config parsing is involved: a broken or deleted source config must not
/// prevent stop, inspection, or cleanup of the native service.
pub fn plan_installed(platform: ServicePlatform, action: ServiceAction) -> Result<ServicePlan> {
    if action == ServiceAction::Install {
        bail!("service install requires an explicit config-backed ServiceSpec");
    }
    let definition_path = definition_path(platform)?;
    let environment_directory = environment_directory(platform)?;
    plan_installed_with_paths(platform, action, definition_path, environment_directory)
}

fn plan_installed_with_paths(
    platform: ServicePlatform,
    action: ServiceAction,
    definition_path: PathBuf,
    environment_directory: PathBuf,
) -> Result<ServicePlan> {
    if action == ServiceAction::Logs {
        return Ok(logs_plan(platform, definition_path, environment_directory));
    }
    if matches!(action, ServiceAction::Start | ServiceAction::Restart) {
        require_no_pending_definition_transaction(&definition_path)?;
    }
    let (definition, environment_path) =
        match inspect_installed_definition(platform, &definition_path, &environment_directory)? {
            DefinitionAuthority::Absent => (String::new(), environment_directory.clone()),
            DefinitionAuthority::Exact(owned) => (owned.raw, owned.spec.environment_path),
        };
    if definition.is_empty() && matches!(action, ServiceAction::Start | ServiceAction::Restart) {
        bail!(
            "Kata service is not installed at {}; run `kata service install --config <path> --apply` first",
            definition_path.display()
        );
    }
    Ok(ServicePlan {
        action,
        commands: commands_for(platform, action, &definition_path),
        definition_path,
        definition,
        // Only install compares desired config-derived content. Other actions
        // operate on the installed definition and therefore have no pending
        // definition change to report.
        changed: false,
        environment_path,
        environment_directory,
        environment_definition: String::new(),
    })
}

fn logs_plan(
    platform: ServicePlatform,
    definition_path: PathBuf,
    environment_directory: PathBuf,
) -> ServicePlan {
    ServicePlan {
        action: ServiceAction::Logs,
        commands: commands_for(platform, ServiceAction::Logs, &definition_path),
        definition_path,
        definition: String::new(),
        changed: false,
        environment_path: environment_directory.clone(),
        environment_directory,
        environment_definition: String::new(),
    }
}

/// Refuse a foreign fixed definition or native-manager job before install is
/// allowed to initialize or adopt any data directory.
pub(crate) fn preflight_install(platform: ServicePlatform) -> Result<()> {
    let definition = inspect_installed_definition(
        platform,
        &definition_path(platform)?,
        &environment_directory(platform)?,
    )?;
    let manager = inspect_native_manager(
        platform,
        match &definition {
            DefinitionAuthority::Absent => None,
            DefinitionAuthority::Exact(owned) => Some(owned),
        },
    )?;
    authorize_service_operation(ServiceAction::Install, platform, &definition, manager)
}

pub fn current_platform() -> Result<ServicePlatform> {
    require_non_root_service_owner(nix::unistd::geteuid().as_raw())?;
    require_ambient_owner_home()?;
    #[cfg(target_os = "linux")]
    {
        Ok(ServicePlatform::SystemdUser)
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let output = run_bounded_output(
            &args(&["/usr/bin/sw_vers", "-productVersion"]),
            MANAGER_PROBE_TIMEOUT,
            MANAGER_OUTPUT_BYTES,
            "macOS version probe",
        )?;
        if !output.status.success() {
            bail!("`sw_vers -productVersion` failed with {}", output.status);
        }
        let version =
            String::from_utf8(output.stdout).context("`sw_vers` returned non-UTF-8 output")?;
        let major = version
            .trim()
            .split('.')
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .ok_or_else(|| anyhow::anyhow!("could not parse macOS version {version:?}"))?;
        if major < 14 {
            bail!("Kata requires macOS 14+; detected macOS {version}");
        }
        Ok(ServicePlatform::LaunchdAppleSilicon)
    }
    #[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
    {
        bail!(
            "Kata's first-class macOS service tier is Apple silicon on macOS 14+; Intel macOS is unverified and unsupported"
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("Kata user services currently support only Linux and macOS")
    }
}

/// Inspect an install plan without acquiring or mutating lifecycle authority.
pub(crate) fn preview_install(spec: &ServiceSpec) -> Result<ServicePlan> {
    let plan = spec.plan(ServiceAction::Install)?;
    execute_plan(spec.platform, plan, ServiceExecutionAuthority::Preview)
}

/// Inspect a config-free installed-service mutation without applying it.
pub(crate) fn preview_installed(
    platform: ServicePlatform,
    action: ServiceAction,
) -> Result<ServicePlan> {
    if !matches!(
        action,
        ServiceAction::Start
            | ServiceAction::Stop
            | ServiceAction::Restart
            | ServiceAction::Uninstall
    ) {
        bail!("{action:?} is not an installed-service mutation preview");
    }
    let plan = plan_installed(platform, action)?;
    execute_plan(platform, plan, ServiceExecutionAuthority::Preview)
}

/// Run the native manager's bounded status query without lifecycle authority.
pub(crate) fn status_installed(platform: ServicePlatform) -> Result<ServicePlan> {
    let plan = plan_installed(platform, ServiceAction::Status)?;
    execute_plan(platform, plan, ServiceExecutionAuthority::ReadOnly)
}

/// Run the native manager's bounded log query without lifecycle authority.
pub(crate) fn logs_installed(platform: ServicePlatform) -> Result<ServicePlan> {
    let plan = plan_installed(platform, ServiceAction::Logs)?;
    execute_plan(platform, plan, ServiceExecutionAuthority::ReadOnly)
}

/// Apply start, stop, or restart while borrowing the operation lease for the
/// entire planning, manager mutation, and postcondition-verification path.
pub(crate) fn apply_installed_lifecycle(
    platform: ServicePlatform,
    action: InstalledServiceLifecycleAction,
    lifecycle: &InstalledLifecycleOperationLease,
) -> Result<ServicePlan> {
    let action = action.service_action();
    let plan = plan_installed(platform, action)?;
    execute_plan(
        platform,
        plan,
        ServiceExecutionAuthority::Lifecycle(lifecycle),
    )
}

/// Apply an exact config-backed service publication under both required locks.
pub(crate) fn apply_install(
    spec: &ServiceSpec,
    permit: InstalledServicePublicationPermit<'_>,
) -> Result<ServicePlan> {
    let plan = spec.plan(ServiceAction::Install)?;
    execute_plan(
        spec.platform,
        plan,
        ServiceExecutionAuthority::Publication(permit),
    )
}

/// Remove the exact installed publication under both required locks.
pub(crate) fn apply_uninstall(
    platform: ServicePlatform,
    permit: InstalledServicePublicationPermit<'_>,
) -> Result<ServicePlan> {
    let plan = plan_installed(platform, ServiceAction::Uninstall)?;
    execute_plan(
        platform,
        plan,
        ServiceExecutionAuthority::Publication(permit),
    )
}

fn execute_plan(
    platform: ServicePlatform,
    plan: ServicePlan,
    authority: ServiceExecutionAuthority<'_>,
) -> Result<ServicePlan> {
    execute_plan_with_authority(
        platform,
        plan,
        authority,
        run_command,
        inspect_native_manager,
        verify_stopped,
    )
}

fn execute_plan_with_authority(
    platform: ServicePlatform,
    plan: ServicePlan,
    authority: ServiceExecutionAuthority<'_>,
    mut command_runner: impl FnMut(&[String], ServicePlatform, ServiceAction) -> Result<()>,
    mut manager_inspector: impl FnMut(
        ServicePlatform,
        Option<&OwnedServiceDefinition>,
    ) -> Result<ManagerAuthority>,
    mut stopped_verifier: impl FnMut(ServicePlatform, bool) -> Result<()>,
) -> Result<ServicePlan> {
    let action = plan.action;
    authority.validate_action(action)?;
    let applied = authority.is_applied();
    // See `discovery_quiescent`: a publication permit already owns the
    // per-owner discovery lease, and a same-process re-probe would
    // self-conflict under flock semantics.
    let discovery_owned_by_authority =
        matches!(&authority, ServiceExecutionAuthority::Publication(_));
    if matches!(action, ServiceAction::Start | ServiceAction::Restart) {
        require_no_pending_definition_transaction(&plan.definition_path)?;
    }
    if action == ServiceAction::Logs {
        let expected = commands_for(platform, ServiceAction::Logs, &plan.definition_path);
        if plan.commands != expected {
            bail!("service logs plan does not contain Kata's exact bounded host-log query");
        }
        for command in &plan.commands {
            command_runner(command, platform, action)?;
        }
        return Ok(plan);
    }
    let mutating = !matches!(action, ServiceAction::Status | ServiceAction::Logs);
    let mut restored_replacement = false;
    if applied && matches!(action, ServiceAction::Install | ServiceAction::Uninstall) {
        let parent = plan.definition_path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "service definition has no parent: {}",
                plan.definition_path.display()
            )
        })?;
        match std::fs::symlink_metadata(parent) {
            Ok(_) => {
                restored_replacement = recover_definition_replacement_transaction(
                    &plan.definition_path,
                    (!plan.definition.is_empty()).then_some(plan.definition.as_str()),
                )?;
                recover_owner_only_publication_artifacts(
                    parent,
                    SERVICE_PUBLICATION_ARTIFACT_PREFIX,
                    MAX_SERVICE_DEFINITION_BYTES,
                    MAX_SERVICE_PUBLICATION_ARTIFACTS,
                    "service definition",
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspecting service definition directory {}",
                        parent.display()
                    )
                });
            }
        }
    }
    let mut definition_authority =
        inspect_installed_definition(platform, &plan.definition_path, &plan.environment_directory)?;
    if action != ServiceAction::Install
        && let DefinitionAuthority::Exact(owned) = &definition_authority
        && plan.definition != owned.raw
        && !(action == ServiceAction::Uninstall && restored_replacement)
    {
        bail!("service plan no longer matches the exact installed definition");
    }
    let mut manager_authority = manager_inspector(
        platform,
        match &definition_authority {
            DefinitionAuthority::Absent => None,
            DefinitionAuthority::Exact(owned) => Some(owned),
        },
    )?;
    authorize_service_operation(action, platform, &definition_authority, manager_authority)?;
    if mutating && !applied {
        return Ok(plan);
    }
    if definition_authority == DefinitionAuthority::Absent
        && action == ServiceAction::Uninstall
        && manager_authority == ManagerAuthority::ExactStaleRemoval
    {
        let (current_definition, current_manager) =
            inspect_service_authority(platform, &plan, &mut manager_inspector)?;
        if current_definition != DefinitionAuthority::Absent
            || current_manager != ManagerAuthority::ExactStaleRemoval
        {
            bail!("interrupted service uninstall changed before daemon-reload recovery");
        }
        let reload = plan.commands.get(1).ok_or_else(|| {
            anyhow::anyhow!("interrupted systemd uninstall has no daemon-reload recovery command")
        })?;
        command_runner(reload, platform, action)?;
        if manager_inspector(platform, None)? != ManagerAuthority::Absent {
            bail!("systemd daemon-reload did not clear the stopped removed Kata unit");
        }
        garbage_collect_environment_snapshots(&plan.environment_directory, None)?;
        return Ok(plan);
    }
    if matches!(
        (&definition_authority, action),
        (
            DefinitionAuthority::Absent,
            ServiceAction::Stop
                | ServiceAction::Status
                | ServiceAction::Logs
                | ServiceAction::Uninstall
        )
    ) {
        if action == ServiceAction::Uninstall && applied {
            garbage_collect_environment_snapshots(&plan.environment_directory, None)?;
        }
        return Ok(plan);
    }
    if mutating {
        let (current_definition, current_manager) =
            inspect_service_authority(platform, &plan, &mut manager_inspector)?;
        if current_definition != definition_authority || current_manager != manager_authority {
            bail!(
                "native-service definition or manager identity changed after validation; refusing mutation"
            );
        }
        definition_authority = current_definition;
        manager_authority = current_manager;
    }

    // A prior no-replace publication may have committed the canonical name
    // but failed before its parent-directory sync completed. No durable marker
    // can distinguish that state from a fully synced publication, so every
    // operation that can make the definition effective must converge the exact
    // adopted inode before invoking the manager.
    let definition_sync_context = match action {
        ServiceAction::Install if !plan.changed => {
            Some("converging an existing service definition before install retry")
        }
        ServiceAction::Start | ServiceAction::Restart => {
            Some("converging the installed service definition before manager start")
        }
        _ => None,
    };
    if let (Some(context), DefinitionAuthority::Exact(owned)) =
        (definition_sync_context, &definition_authority)
    {
        owned
            .definition_publication
            .sync_and_revalidate()
            .context(context)?;
    }

    // Refuse launch-input drift before invoking the native manager. Discovering
    // that a different config, secret snapshot, or executable was launched only
    // after the process is active is too late for one-main authority.
    if matches!(action, ServiceAction::Start | ServiceAction::Restart) {
        validate_installed_launch_inputs(&plan)?;
    }
    let prior_process_generation = restart_generation_with(action, |timeout| {
        crate::attachment::connect_verified_attached_main_sync_with_timeout(None, timeout)
            .map(|attached| attached.status)
    })?;

    if action == ServiceAction::Install && plan.changed {
        write_environment_atomically(&plan.environment_path, &plan.environment_definition)?;
        let expected_definition = match &definition_authority {
            DefinitionAuthority::Exact(owned) => Some(&owned.definition_publication),
            DefinitionAuthority::Absent => None,
        };
        write_definition_atomically(&plan.definition_path, &plan.definition, expected_definition)?;
    }

    if action == ServiceAction::Uninstall {
        let owned = match &definition_authority {
            DefinitionAuthority::Exact(owned) => owned.clone(),
            DefinitionAuthority::Absent => unreachable!("true absence returned above"),
        };
        // `run_command` maps only the exact target-absent response to success.
        // Every unknown manager failure must leave the installed publication
        // byte- and inode-identical: removing it could strand a cached/loaded
        // native job with no authoritative definition from which to recover.
        if matches!(
            manager_authority,
            ManagerAuthority::ExactMatching
                | ManagerAuthority::ExactRunning
                | ManagerAuthority::ExactMatchingQuiescent
                | ManagerAuthority::ExactNeedsReload
        ) && let Some(first) = plan.commands.first()
        {
            command_runner(first, platform, action)?;
        }
        stopped_verifier(platform, discovery_owned_by_authority)?;
        let current_definition = inspect_installed_definition(
            platform,
            &plan.definition_path,
            &plan.environment_directory,
        )?;
        if current_definition != DefinitionAuthority::Exact(owned.clone()) {
            bail!("installed service publication changed while stop completed; refusing deletion");
        }
        remove_owned_definition(&owned)?;
        if let Some(reload) = plan.commands.get(1)
            && let Err(reload_error) = command_runner(reload, platform, action)
        {
            return Err(reload_error).context(
                "systemd daemon-reload failed after the service definition absence commit; the canonical definition remains absent and uninstall must be retried to reconcile the stale stopped manager state",
            );
        }
        let final_definition = inspect_installed_definition(
            platform,
            &plan.definition_path,
            &plan.environment_directory,
        )?;
        let final_manager = manager_inspector(platform, None)?;
        if final_definition != DefinitionAuthority::Absent
            || final_manager != ManagerAuthority::Absent
        {
            bail!(
                "service uninstall returned without proving both publication and native manager absent"
            );
        }
        garbage_collect_environment_snapshots(&plan.environment_directory, None)?;
    } else {
        for argv in &plan.commands {
            command_runner(argv, platform, action)?;
        }
    }
    if matches!(action, ServiceAction::Start | ServiceAction::Restart) {
        verify_started(
            platform,
            &plan.definition,
            prior_process_generation.as_deref(),
        )?;
        let (current_definition, current_manager) =
            inspect_service_authority(platform, &plan, &mut manager_inspector)?;
        if !matches!(current_definition, DefinitionAuthority::Exact(_))
            || !manager_satisfies_started(platform, current_manager)
        {
            bail!("started service manager identity is not the exact installed definition");
        }
    }
    if action == ServiceAction::Stop {
        stopped_verifier(platform, discovery_owned_by_authority)?;
        let (current_definition, _) =
            inspect_service_authority(platform, &plan, &mut manager_inspector)?;
        if current_definition != definition_authority {
            bail!("service definition changed while stop completed");
        }
    }
    if action == ServiceAction::Install {
        let (current_definition, current_manager) =
            inspect_service_authority(platform, &plan, &mut manager_inspector)?;
        let DefinitionAuthority::Exact(owned) = current_definition else {
            bail!("service install did not publish an exact Kata-owned definition");
        };
        if owned.raw != plan.definition
            || owned.environment_definition != plan.environment_definition
        {
            bail!("service install publication differs from the requested exact identity");
        }
        let expected_manager = match platform {
            ServicePlatform::SystemdUser => ManagerAuthority::ExactMatchingQuiescent,
            ServicePlatform::LaunchdAppleSilicon => ManagerAuthority::Absent,
        };
        if current_manager != expected_manager {
            bail!("service install did not reach the expected exact manager state");
        }
        garbage_collect_environment_snapshots(
            &plan.environment_directory,
            Some(&owned.spec.environment_path),
        )?;
    }
    Ok(plan)
}

#[cfg(test)]
fn test_execution_authority(
    action: ServiceAction,
    apply: bool,
) -> ServiceExecutionAuthority<'static> {
    if matches!(action, ServiceAction::Status | ServiceAction::Logs) {
        ServiceExecutionAuthority::ReadOnly
    } else if apply {
        ServiceExecutionAuthority::TestApplied
    } else {
        ServiceExecutionAuthority::Preview
    }
}

#[cfg(test)]
fn execute_plan_with(
    platform: ServicePlatform,
    plan: ServicePlan,
    apply: bool,
    command_runner: impl FnMut(&[String], ServicePlatform, ServiceAction) -> Result<()>,
) -> Result<ServicePlan> {
    execute_plan_with_manager_probe(
        platform,
        plan,
        apply,
        command_runner,
        inspect_native_manager,
    )
}

#[cfg(test)]
fn execute_plan_with_manager_probe(
    platform: ServicePlatform,
    plan: ServicePlan,
    apply: bool,
    command_runner: impl FnMut(&[String], ServicePlatform, ServiceAction) -> Result<()>,
    manager_inspector: impl FnMut(
        ServicePlatform,
        Option<&OwnedServiceDefinition>,
    ) -> Result<ManagerAuthority>,
) -> Result<ServicePlan> {
    execute_plan_with_manager_probe_and_stopped_verifier(
        platform,
        plan,
        apply,
        command_runner,
        manager_inspector,
        verify_stopped,
    )
}

#[cfg(test)]
fn execute_plan_with_manager_probe_and_stopped_verifier(
    platform: ServicePlatform,
    plan: ServicePlan,
    apply: bool,
    command_runner: impl FnMut(&[String], ServicePlatform, ServiceAction) -> Result<()>,
    manager_inspector: impl FnMut(
        ServicePlatform,
        Option<&OwnedServiceDefinition>,
    ) -> Result<ManagerAuthority>,
    stopped_verifier: impl FnMut(ServicePlatform, bool) -> Result<()>,
) -> Result<ServicePlan> {
    let authority = test_execution_authority(plan.action, apply);
    execute_plan_with_authority(
        platform,
        plan,
        authority,
        command_runner,
        manager_inspector,
        stopped_verifier,
    )
}

fn authorize_service_operation(
    action: ServiceAction,
    platform: ServicePlatform,
    definition: &DefinitionAuthority,
    manager: ManagerAuthority,
) -> Result<()> {
    if matches!(action, ServiceAction::Start | ServiceAction::Restart)
        && definition == &DefinitionAuthority::Absent
    {
        bail!("Kata service is not installed; run `kata service install --config <path> --apply`");
    }
    if platform == ServicePlatform::LaunchdAppleSilicon
        && action == ServiceAction::Install
        && matches!(
            manager,
            ManagerAuthority::ExactMatching
                | ManagerAuthority::ExactRunning
                | ManagerAuthority::ExactMatchingQuiescent
        )
    {
        bail!(
            "launchd job {LAUNCHD_LABEL} is already loaded; run `kata service stop --apply`, then install, then start so the loaded snapshot and exact definition cannot disagree"
        );
    }
    if platform == ServicePlatform::SystemdUser
        && action == ServiceAction::Install
        && matches!(
            manager,
            ManagerAuthority::ExactMatching | ManagerAuthority::ExactRunning
        )
    {
        bail!(
            "systemd has an active or transitional exact Kata unit; stop it and wait for quiescence before install so a pending automatic restart cannot escape the lifecycle lease"
        );
    }
    if manager == ManagerAuthority::ExactNeedsReload
        && !matches!(action, ServiceAction::Install | ServiceAction::Uninstall)
    {
        bail!(
            "systemd has not loaded the current exact Kata service definition; complete the interrupted lifecycle operation with `kata service install --config <path> --apply` or `kata service uninstall --apply`"
        );
    }
    if manager == ManagerAuthority::ExactStaleRemoval && action != ServiceAction::Uninstall {
        bail!(
            "systemd still retains a stopped Kata service removed from disk; rerun `kata service uninstall --apply` to complete daemon reload"
        );
    }
    Ok(())
}

fn manager_satisfies_started(platform: ServicePlatform, manager: ManagerAuthority) -> bool {
    match platform {
        ServicePlatform::SystemdUser => manager == ManagerAuthority::ExactRunning,
        ServicePlatform::LaunchdAppleSilicon => manager == ManagerAuthority::ExactMatching,
    }
}

fn inspect_service_authority(
    platform: ServicePlatform,
    plan: &ServicePlan,
    manager_inspector: &mut impl FnMut(
        ServicePlatform,
        Option<&OwnedServiceDefinition>,
    ) -> Result<ManagerAuthority>,
) -> Result<(DefinitionAuthority, ManagerAuthority)> {
    let definition =
        inspect_installed_definition(platform, &plan.definition_path, &plan.environment_directory)?;
    let manager = manager_inspector(
        platform,
        match &definition {
            DefinitionAuthority::Absent => None,
            DefinitionAuthority::Exact(owned) => Some(owned),
        },
    )?;
    Ok((definition, manager))
}

fn remove_owned_definition(owned: &OwnedServiceDefinition) -> Result<()> {
    match owned.definition_publication.remove(
        MAX_SERVICE_DEFINITION_BYTES,
        SERVICE_PUBLICATION_ARTIFACT_PREFIX,
        "service definition",
    )? {
        OwnerOnlyRemoval::Removed(_) => Ok(()),
        OwnerOnlyRemoval::RecoveryRequired(error) => Err(error.into()),
    }
}

fn garbage_collect_environment_snapshots(directory: &Path, keep: Option<&Path>) -> Result<()> {
    match std::fs::symlink_metadata(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspecting service environment snapshot directory {}",
                    directory.display()
                )
            });
        }
        Ok(_) => {}
    }

    ensure_owner_only_directory(directory, "service environment snapshot")?;
    recover_environment_snapshot_temporaries(directory)?;
    let names = list_publication_names(
        directory,
        MAX_SERVICE_ENVIRONMENT_SNAPSHOTS,
        "service environment snapshot",
    )?;
    let keep_name = keep.and_then(Path::file_name);
    let mut stale = Vec::new();

    // Validate the complete deletion set before mutating any namespace entry.
    for name in names {
        if keep_name == Some(name.as_os_str()) {
            continue;
        }
        let name_text = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("service environment snapshot name is not UTF-8"))?;
        let Some(digest) = name_text.strip_suffix(".json") else {
            bail!("unexpected file in service environment snapshot directory: {name_text:?}");
        };
        let path = directory.join(&name);
        if environment_snapshot_path(directory, digest)? != path {
            bail!(
                "noncanonical service environment snapshot path {}",
                path.display()
            );
        }
        let publication = ExistingOwnerOnlyPublication::open(
            &path,
            MAX_SERVICE_ENVIRONMENT_BYTES,
            "service environment snapshot",
        )?;
        if blake3_bytes(publication.bytes()?).to_string() != digest {
            bail!(
                "service environment snapshot {} does not match its content address",
                path.display()
            );
        }
        stale.push(path);
    }

    for path in stale {
        match ExistingOwnerOnlyPublication::open(
            &path,
            MAX_SERVICE_ENVIRONMENT_BYTES,
            "service environment snapshot",
        )?
        .remove(
            MAX_SERVICE_ENVIRONMENT_BYTES,
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            "service environment snapshot",
        )? {
            OwnerOnlyRemoval::Removed(_) => {}
            OwnerOnlyRemoval::RecoveryRequired(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn restart_generation_with(
    action: ServiceAction,
    connect_live: impl FnOnce(std::time::Duration) -> Result<kata_client::types::SystemStatus>,
) -> Result<Option<String>> {
    if action != ServiceAction::Restart {
        return Ok(None);
    }
    // The descriptor is discovery convenience, never generation authority.
    // Bind restart to the live status returned by the bounded verified
    // handshake; that handshake also refuses descriptor/live disagreement.
    let status = connect_live(MANAGER_PROBE_TIMEOUT).context(
        "service restart requires a bounded, verified live prior installed main; use `kata service start --apply` when no generation is running",
    )?;
    let generation = status
        .process_generation
        .filter(|generation| !generation.is_empty())
        .ok_or_else(|| anyhow::anyhow!("service restart live prior process generation is empty"))?;
    Ok(Some(generation))
}

fn definition_path(platform: ServicePlatform) -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(match platform {
        ServicePlatform::SystemdUser => home
            .join(".config")
            .join("systemd")
            .join("user")
            .join(SYSTEMD_UNIT_NAME),
        ServicePlatform::LaunchdAppleSilicon => home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LAUNCHD_LABEL}.plist")),
    })
}

fn environment_directory(platform: ServicePlatform) -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(match platform {
        ServicePlatform::SystemdUser => home
            .join(".config")
            .join("kata")
            .join("service-environments"),
        ServicePlatform::LaunchdAppleSilicon => home
            .join("Library")
            .join("Application Support")
            .join("Kata")
            .join("service-environments"),
    })
}

fn environment_snapshot_path(directory: &Path, digest: &str) -> Result<PathBuf> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("service environment snapshot digest is not canonical lowercase hex");
    }
    Ok(directory.join(format!("{digest}.json")))
}

fn commands_for(
    platform: ServicePlatform,
    action: ServiceAction,
    definition: &Path,
) -> Vec<Vec<String>> {
    let path = definition.to_string_lossy().into_owned();
    match platform {
        ServicePlatform::SystemdUser => match action {
            ServiceAction::Install => {
                vec![args(&[SYSTEMCTL_PATH, "--user", "daemon-reload"])]
            }
            ServiceAction::Start => vec![args(&[
                SYSTEMCTL_PATH,
                "--user",
                "enable",
                "--now",
                SYSTEMD_UNIT_NAME,
            ])],
            ServiceAction::Stop => {
                vec![args(&[SYSTEMCTL_PATH, "--user", "stop", SYSTEMD_UNIT_NAME])]
            }
            ServiceAction::Restart => {
                vec![args(&[
                    SYSTEMCTL_PATH,
                    "--user",
                    "restart",
                    SYSTEMD_UNIT_NAME,
                ])]
            }
            ServiceAction::Status => vec![args(&[
                SYSTEMCTL_PATH,
                "--user",
                "status",
                "--no-pager",
                SYSTEMD_UNIT_NAME,
            ])],
            ServiceAction::Logs => vec![args(&[
                JOURNALCTL_PATH,
                "--user",
                "-u",
                SYSTEMD_UNIT_NAME,
                "--no-pager",
                "-n",
                "200",
            ])],
            ServiceAction::Uninstall => vec![
                args(&[
                    SYSTEMCTL_PATH,
                    "--user",
                    "disable",
                    "--now",
                    SYSTEMD_UNIT_NAME,
                ]),
                args(&[SYSTEMCTL_PATH, "--user", "daemon-reload"]),
            ],
        },
        ServicePlatform::LaunchdAppleSilicon => {
            let domain = format!("gui/{}", current_uid());
            match action {
                ServiceAction::Install => Vec::new(),
                ServiceAction::Start => {
                    vec![vec![
                        LAUNCHCTL_PATH.into(),
                        "bootstrap".into(),
                        domain,
                        path,
                    ]]
                }
                ServiceAction::Stop | ServiceAction::Uninstall => vec![args(&[
                    LAUNCHCTL_PATH,
                    "bootout",
                    &format!("gui/{}/{LAUNCHD_LABEL}", current_uid()),
                ])],
                ServiceAction::Restart => vec![
                    args(&[
                        LAUNCHCTL_PATH,
                        "bootout",
                        &format!("gui/{}/{LAUNCHD_LABEL}", current_uid()),
                    ]),
                    vec![LAUNCHCTL_PATH.into(), "bootstrap".into(), domain, path],
                ],
                ServiceAction::Status => vec![args(&[
                    LAUNCHCTL_PATH,
                    "print",
                    &format!("gui/{}/{LAUNCHD_LABEL}", current_uid()),
                ])],
                ServiceAction::Logs => vec![args(&[
                    MACOS_LOG_PATH,
                    "show",
                    "--last",
                    "1h",
                    "--info",
                    "--debug",
                    "--predicate",
                    "subsystem == \"sh.kata.main\" AND category == \"installed-main\"",
                ])],
            }
        }
    }
}

/// `Delegate=yes` is load-bearing: a capsule stage's youki container is bounded by
/// `memory`/`pids` knobs in cgroups the main creates under its own, and systemd owns an
/// undelegated unit's subtree. Measured on systemd 255: without delegation the main's
/// certification passes, but the next re-realization of the unit (`set-property`,
/// `daemon-reload`) empties its `cgroup.subtree_control`, and a running container's
/// `pids.max`/`memory.max` vanish with it; with `Delegate=yes` they survive.
fn render_systemd(spec: &ServiceSpec) -> String {
    let mut out = String::from(
        "[Unit]\nDescription=Kata installed main\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=60s\nStartLimitBurst=5\n\n[Service]\nType=simple\n",
    );
    let command = service_exec_command(spec);
    writeln!(
        &mut out,
        "# X-Kata-Definition-Format={SERVICE_DEFINITION_FORMAT}\n# X-Kata-Definition-Path={}\n# X-Kata-Binary-Digest={}\n# X-Kata-Binary-Version={}\n# X-Kata-Binary-Path={}\n# X-Kata-Config-Digest={}\n# X-Kata-Config-Path={}\n# X-Kata-Service-Environment-Digest={}\n# X-Kata-Service-Environment-Path={}\n# X-Kata-Working-Directory={}\n# X-Kata-Data-Directory-ID={}\n# X-Kata-Data-Directory={}\nWorkingDirectory={}\nExecStart={}\nRestart=on-failure\nRestartSec=2s\nTimeoutStopSec=30s\nKillMode=control-group\nDelegate=yes",
        systemd_quote(&spec.definition_path.to_string_lossy()),
        spec.binary_digest,
        spec.binary_version,
        systemd_quote(&spec.binary.to_string_lossy()),
        spec.config_digest,
        systemd_quote(&spec.config.to_string_lossy()),
        spec.environment_digest,
        systemd_quote(&spec.environment_path.to_string_lossy()),
        systemd_quote(&spec.working_directory.to_string_lossy()),
        spec.data_directory_id,
        systemd_quote(&spec.data_dir.to_string_lossy()),
        systemd_path_value(&spec.working_directory.to_string_lossy()),
        command
            .iter()
            .map(|part| systemd_quote(part))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .expect("writing to a String cannot fail");
    out.push_str("\n[Install]\nWantedBy=default.target\n");
    out
}

fn service_exec_command(spec: &ServiceSpec) -> Vec<String> {
    vec![
        spec.binary.to_string_lossy().into_owned(),
        "__service-exec".to_string(),
        "--definition".to_string(),
        spec.definition_path.to_string_lossy().into_owned(),
        "--environment".to_string(),
        spec.environment_path.to_string_lossy().into_owned(),
        "--config".to_string(),
        spec.config.to_string_lossy().into_owned(),
        "--expected-binary-digest".to_string(),
        spec.binary_digest.clone(),
        "--expected-config-digest".to_string(),
        spec.config_digest.clone(),
        "--expected-environment-digest".to_string(),
        spec.environment_digest.clone(),
        "--expected-data-directory".to_string(),
        spec.data_dir.to_string_lossy().into_owned(),
        "--expected-directory-id".to_string(),
        spec.data_directory_id.clone(),
    ]
}

fn render_launchd(spec: &ServiceSpec) -> String {
    let mut arguments = String::new();
    for value in service_exec_command(spec) {
        writeln!(
            &mut arguments,
            "    <string>{}</string>",
            xml_escape(&value)
        )
        .expect("writing to a String cannot fail");
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n  <key>ProgramArguments</key>\n  <array>\n{arguments}  </array>\n  <key>WorkingDirectory</key><string>{}</string>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n  <key>ThrottleInterval</key><integer>10</integer>\n  <key>ProcessType</key><string>Interactive</string>\n  <key>ExitTimeOut</key><integer>30</integer>\n  <key>KataDefinitionFormat</key><string>{SERVICE_DEFINITION_FORMAT}</string>\n  <key>KataDefinitionPath</key><string>{}</string>\n  <key>KataBinaryDigest</key><string>{}</string>\n  <key>KataBinaryVersion</key><string>{}</string>\n  <key>KataBinaryPath</key><string>{}</string>\n  <key>KataConfigDigest</key><string>{}</string>\n  <key>KataConfigPath</key><string>{}</string>\n  <key>KataServiceEnvironmentDigest</key><string>{}</string>\n  <key>KataServiceEnvironmentPath</key><string>{}</string>\n  <key>KataWorkingDirectory</key><string>{}</string>\n  <key>KataDataDirectoryID</key><string>{}</string>\n  <key>KataDataDirectory</key><string>{}</string>\n</dict>\n</plist>\n",
        xml_escape_path(&spec.working_directory),
        xml_escape_path(&spec.definition_path),
        xml_escape(&spec.binary_digest),
        xml_escape(&spec.binary_version),
        xml_escape_path(&spec.binary),
        xml_escape(&spec.config_digest),
        xml_escape_path(&spec.config),
        xml_escape(&spec.environment_digest),
        xml_escape_path(&spec.environment_path),
        xml_escape_path(&spec.working_directory),
        xml_escape(&spec.data_directory_id),
        xml_escape_path(&spec.data_dir),
    )
}

fn replacement_rollback_expected_identity(name: &str) -> Option<(u64, u64)> {
    let body = name
        .strip_prefix(SERVICE_REPLACEMENT_ROLLBACK_PREFIX)?
        .strip_suffix(SERVICE_REPLACEMENT_ROLLBACK_SUFFIX)?;
    let mut fields = body.splitn(3, '-');
    let device = fields.next()?.parse().ok()?;
    let inode = fields.next()?.parse().ok()?;
    let nonce = fields.next()?;
    (!nonce.is_empty()).then_some((device, inode))
}

fn require_no_pending_definition_transaction(definition_path: &Path) -> Result<()> {
    let parent = definition_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "service definition has no parent: {}",
            definition_path.display()
        )
    })?;
    match std::fs::symlink_metadata(parent) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspecting service definition transaction directory {}",
                    parent.display()
                )
            });
        }
        Ok(_) => {}
    }
    let pending = list_publication_names_with_prefix(
        parent,
        SERVICE_PUBLICATION_ARTIFACT_PREFIX,
        MAX_SERVICE_PUBLICATION_ARTIFACTS,
        "service definition transaction inspection",
    )?
    .len();
    if pending > 0 {
        bail!(
            "service definition transaction recovery is pending at {} ({pending} artifact(s)); run `kata service install --config <path> --apply` or `kata service uninstall --apply` before starting the installed main",
            parent.display()
        );
    }
    Ok(())
}

#[cfg(test)]
fn replacement_rollback_name(
    identity: crate::owner_only_publication::PublicationFileIdentity,
) -> OsString {
    OsString::from(format!(
        "{SERVICE_REPLACEMENT_ROLLBACK_PREFIX}{}-{}-{}{SERVICE_REPLACEMENT_ROLLBACK_SUFFIX}",
        identity.device,
        identity.inode,
        ulid::Ulid::new()
    ))
}

#[cfg(test)]
fn deletion_quarantine_name(
    prefix: &str,
    identity: crate::owner_only_publication::PublicationFileIdentity,
) -> OsString {
    OsString::from(format!(
        "{prefix}delete-{}-{}-{}.quarantine",
        identity.device,
        identity.inode,
        ulid::Ulid::new()
    ))
}

#[cfg(test)]
fn stable_publication_identity(
    identity: crate::owner_only_publication::PublicationFileIdentity,
) -> (u64, u64, u64, u32, u32, u64) {
    (
        identity.device,
        identity.inode,
        identity.bytes,
        identity.uid,
        identity.mode,
        identity.links,
    )
}

/// Recover the one possible interrupted definition replacement transaction.
///
/// Absence of the fixed definition means the old publication was quarantined
/// before the new no-replace commit, so recovery restores it. If the fixed
/// definition already equals this operation's desired bytes, the new commit is
/// durable enough to complete by deleting the validated old rollback. Any
/// other state is ambiguous and both names are preserved.
fn recover_definition_replacement_transaction(
    definition_path: &Path,
    desired_definition: Option<&str>,
) -> Result<bool> {
    let parent_path = definition_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "service definition has no parent: {}",
            definition_path.display()
        )
    })?;
    let rollback_names = list_publication_names_with_prefix(
        parent_path,
        SERVICE_REPLACEMENT_ROLLBACK_PREFIX,
        MAX_SERVICE_PUBLICATION_ARTIFACTS,
        "service definition replacement recovery",
    )?
    .into_iter()
    .filter(|name| {
        name.to_str()
            .is_some_and(|text| text.ends_with(SERVICE_REPLACEMENT_ROLLBACK_SUFFIX))
    })
    .collect::<Vec<_>>();
    if rollback_names.len() > 1 {
        bail!(
            "service definition directory {} contains multiple interrupted replacement rollbacks; refusing ambiguous recovery",
            parent_path.display()
        );
    }
    let Some(rollback_name) = rollback_names.into_iter().next() else {
        return Ok(false);
    };
    let rollback_name_text = rollback_name.to_str().ok_or_else(|| {
        anyhow::anyhow!("service definition replacement rollback name is not UTF-8")
    })?;
    let encoded_identity =
        replacement_rollback_expected_identity(rollback_name_text).ok_or_else(|| {
            anyhow::anyhow!(
                "service definition replacement rollback {} has a noncanonical transaction identity; preserving it",
                parent_path.join(&rollback_name).display()
            )
        })?;
    let rollback_path = parent_path.join(&rollback_name);
    let rollback_publication = ExistingOwnerOnlyPublication::open(
        &rollback_path,
        MAX_SERVICE_DEFINITION_BYTES,
        "service definition replacement rollback",
    )?;
    let identity = rollback_publication.identity();
    if (identity.device, identity.inode) != encoded_identity {
        bail!(
            "service definition replacement rollback {} does not match its captured transaction inode; preserving it",
            rollback_path.display()
        );
    }
    let raw = rollback_publication.read_utf8(
        MAX_SERVICE_DEFINITION_BYTES,
        "service definition replacement rollback",
    )?;
    if definition_format(&raw).as_deref() != Some(SERVICE_DEFINITION_FORMAT)
        || definition_definition_path(&raw).as_deref() != Some(definition_path)
    {
        bail!(
            "service definition replacement rollback {} is not bound to the fixed definition {}; preserving it",
            rollback_path.display(),
            definition_path.display()
        );
    }

    match ExistingOwnerOnlyPublication::open(
        definition_path,
        MAX_SERVICE_DEFINITION_BYTES,
        "service definition",
    ) {
        Err(error) if is_not_found(&error) => {
            match rollback_publication.restore_to(
                definition_path,
                "interrupted service definition replacement",
            )? {
                OwnerOnlyRestoration::Restored => {}
                OwnerOnlyRestoration::RecoveryRequired(error) => return Err(error.into()),
            }
            Ok(true)
        }
        Ok(current_publication) => {
            let current = current_publication
                .read_utf8(MAX_SERVICE_DEFINITION_BYTES, "service definition")
                .with_context(|| {
                    format!(
                        "fixed service definition {} is unsafe while replacement rollback {} remains; preserving both",
                        definition_path.display(),
                        rollback_path.display()
                    )
                })?;
            if desired_definition.is_none_or(|desired| current != desired) {
                bail!(
                    "fixed service definition {} does not equal the desired replacement while rollback {} remains; preserving both",
                    definition_path.display(),
                    rollback_path.display()
                );
            }
            match rollback_publication.remove(
                MAX_SERVICE_DEFINITION_BYTES,
                SERVICE_PUBLICATION_ARTIFACT_PREFIX,
                "committed service definition replacement rollback",
            )? {
                OwnerOnlyRemoval::Removed(_) => {}
                OwnerOnlyRemoval::RecoveryRequired(error) => return Err(error.into()),
            }
            Ok(false)
        }
        Err(error) => Err(error).context(format!(
            "fixed service definition {} is unsafe while replacement rollback {} remains; preserving both",
            definition_path.display(),
            rollback_path.display()
        )),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerOnlyAtomicWriteOutcome {
    Published,
    DestinationExists,
}

fn write_definition_atomically(
    path: &Path,
    text: &str,
    expected: Option<&ExistingOwnerOnlyPublication>,
) -> Result<()> {
    match write_owner_only_atomically(
        path,
        text,
        MAX_SERVICE_DEFINITION_BYTES,
        "service definition",
        expected,
    )? {
        OwnerOnlyAtomicWriteOutcome::Published => Ok(()),
        OwnerOnlyAtomicWriteOutcome::DestinationExists => bail!(
            "service definition {} appeared during no-replace publication; refusing overwrite",
            path.display()
        ),
    }
}

fn write_environment_atomically(path: &Path, text: &str) -> Result<()> {
    ensure_owner_only_environment_directory(path)?;
    recover_environment_snapshot_temporaries(
        path.parent()
            .expect("service environment snapshot has a parent"),
    )?;
    match read_installed_service_environment_utf8(path) {
        Ok(existing) if existing == text => {
            return verify_durable_owner_only_publication_bytes(
                path,
                text,
                MAX_SERVICE_ENVIRONMENT_BYTES,
                "service environment snapshot",
            );
        }
        Ok(_) => bail!(
            "content-addressed service environment snapshot {} exists with different bytes",
            path.display()
        ),
        Err(error) if is_not_found(&error) => {}
        Err(error) => return Err(error),
    }
    match write_owner_only_atomically(
        path,
        text,
        MAX_SERVICE_ENVIRONMENT_BYTES,
        "service environment snapshot",
        None,
    ) {
        Ok(OwnerOnlyAtomicWriteOutcome::Published) => Ok(()),
        Ok(OwnerOnlyAtomicWriteOutcome::DestinationExists) => {
            verify_durable_owner_only_publication_bytes(
                path,
                text,
                MAX_SERVICE_ENVIRONMENT_BYTES,
                "service environment snapshot",
            )
            .and_then(|()| {
                recover_owner_only_publication_artifacts(
                    path.parent()
                        .expect("service environment snapshot has a parent"),
                    SERVICE_PUBLICATION_ARTIFACT_PREFIX,
                    MAX_SERVICE_ENVIRONMENT_BYTES,
                    MAX_SERVICE_PUBLICATION_ARTIFACTS,
                    "service environment snapshot",
                )
            })
        }
        Err(publication_error) => Err(publication_error),
    }
}

pub(crate) fn read_installed_service_environment(path: &Path) -> Result<Vec<u8>> {
    let publication = ExistingOwnerOnlyPublication::open_in_owner_only_directory(
        path,
        MAX_SERVICE_ENVIRONMENT_BYTES,
        "Kata service environment",
    )?;
    publication.bytes().map(<[u8]>::to_vec)
}

fn read_installed_service_environment_utf8(path: &Path) -> Result<String> {
    String::from_utf8(read_installed_service_environment(path)?).with_context(|| {
        format!(
            "Kata service environment {} is not valid UTF-8",
            path.display()
        )
    })
}

fn verify_durable_owner_only_publication_bytes(
    path: &Path,
    expected_bytes: &str,
    max_bytes: u64,
    label: &str,
) -> Result<()> {
    let publication = ExistingOwnerOnlyPublication::open(path, max_bytes, label)?;
    if publication.bytes()? != expected_bytes.as_bytes() {
        bail!(
            "{label} {} does not contain the expected bytes during durable convergence",
            path.display()
        );
    }
    publication.sync_and_revalidate()
}
fn recover_environment_snapshot_temporaries(directory: &Path) -> Result<()> {
    recover_owner_only_publication_artifacts_with_temporary_links(
        directory,
        SERVICE_PUBLICATION_ARTIFACT_PREFIX,
        MAX_SERVICE_ENVIRONMENT_BYTES,
        MAX_SERVICE_PUBLICATION_ARTIFACTS,
        2,
        "service environment snapshot",
    )
}
fn ensure_owner_only_environment_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("service environment has no parent: {}", path.display()))?;
    ensure_owner_only_directory(parent, "service environment")
}
fn create_owner_only_directory_tree(path: &Path) -> Result<()> {
    ensure_publication_directory(path, "service publication")
}
fn write_owner_only_atomically(
    path: &Path,
    text: &str,
    max_bytes: u64,
    label: &str,
    expected: Option<&ExistingOwnerOnlyPublication>,
) -> Result<OwnerOnlyAtomicWriteOutcome> {
    let byte_count = u64::try_from(text.len()).context("service publication size overflow")?;
    if byte_count > max_bytes {
        bail!(
            "{label} for {} is {byte_count} bytes and exceeds the {max_bytes}-byte safety bound",
            path.display()
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} has no parent: {}", path.display()))?;
    create_owner_only_directory_tree(parent)?;
    recover_owner_only_publication_artifacts(
        parent,
        SERVICE_PUBLICATION_ARTIFACT_PREFIX,
        max_bytes,
        MAX_SERVICE_PUBLICATION_ARTIFACTS,
        label,
    )?;
    let mut temporary = OwnerOnlyPublicationTemp::create(
        parent,
        SERVICE_PUBLICATION_ARTIFACT_PREFIX,
        max_bytes,
        label,
    )?;
    let result = (|| {
        temporary
            .file_mut()
            .write_all(text.as_bytes())
            .with_context(|| format!("writing temporary {label} {}", temporary.path().display()))?;
        temporary.sync_contents()?;
        match expected {
            Some(publication) => match temporary.publish_replace(path, publication)? {
                OwnerOnlyReplacementPublication::Published { rollback_cleanup } => {
                    if rollback_cleanup
                        == crate::owner_only_publication::CleanupDisposition::Pending
                    {
                        bail!(
                            "service definition replacement committed but rollback cleanup durability/reconciliation remains pending; refusing native-manager mutation until `kata service install --config <path> --apply` reconciles the transaction"
                        );
                    }
                    Ok(OwnerOnlyAtomicWriteOutcome::Published)
                }
                OwnerOnlyReplacementPublication::RecoveryRequired(error) => Err(error.into()),
            },
            None => match temporary.publish_noreplace(path)? {
                OwnerOnlyNoReplacePublication::Published(publication) => {
                    drop(publication);
                    Ok(OwnerOnlyAtomicWriteOutcome::Published)
                }
                OwnerOnlyNoReplacePublication::RecoveryRequired { publication, error } => {
                    drop(publication);
                    temporary.retain_for_recovery();
                    Err(error.into())
                }
                OwnerOnlyNoReplacePublication::RenamedRecoveryRequired(error) => {
                    temporary.retain_for_recovery();
                    Err(error.into())
                }
                OwnerOnlyNoReplacePublication::DestinationExists => {
                    temporary.cleanup()?;
                    Ok(OwnerOnlyAtomicWriteOutcome::DestinationExists)
                }
            },
        }
    })();
    match result {
        Ok(outcome) => Ok(outcome),
        Err(error) => match temporary.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error).context(format!(
                "{label} publication failed and exact temporary cleanup also failed: {cleanup:#}"
            )),
        },
    }
}

fn serialize_service_environment(environment: &BTreeMap<String, String>) -> Result<String> {
    let definition = serde_json::to_string_pretty(environment)
        .context("serializing owner-only service environment")?;
    let byte_count =
        u64::try_from(definition.len()).context("service environment size overflow")?;
    if byte_count > MAX_SERVICE_ENVIRONMENT_BYTES {
        bail!(
            "serialized service environment is {byte_count} bytes and exceeds the {}-byte safety bound; use config secret references or an operator-managed environment source",
            MAX_SERVICE_ENVIRONMENT_BYTES
        );
    }
    Ok(definition)
}

#[derive(Debug)]
struct CaptureBudget {
    remaining: Mutex<usize>,
    exceeded: AtomicBool,
}

impl CaptureBudget {
    fn new(max_output_bytes: usize) -> Self {
        Self {
            remaining: Mutex::new(max_output_bytes),
            exceeded: AtomicBool::new(false),
        }
    }

    fn claim(&self, requested: usize) -> usize {
        let mut remaining = self
            .remaining
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let allowed = requested.min(*remaining);
        *remaining -= allowed;
        if allowed < requested {
            self.exceeded.store(true, Ordering::Release);
        }
        allowed
    }
}

fn drain_capped_stream(
    mut stream: impl Read,
    budget: Arc<CaptureBudget>,
) -> std::io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(captured);
        }
        let allowed = budget.claim(read);
        captured.extend_from_slice(&chunk[..allowed]);
        if allowed < read {
            return Ok(captured);
        }
    }
}

fn kill_process_group(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let pid = i32::try_from(pid).context("native-manager pid exceeds i32")?;
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    #[cfg(not(unix))]
    let _ = pid;
    Ok(())
}

fn kill_and_reap_process_group(child: &mut std::process::Child) -> Result<()> {
    kill_process_group(child.id())?;
    // The group signal is authoritative on supported Unix hosts. This direct
    // fallback closes the race where the child exits or changes state between
    // `try_wait` and group signalling.
    let _ = child.kill();
    child
        .wait()
        .context("reaping bounded native-manager process")?;
    Ok(())
}

fn run_bounded_output(
    argv: &[String],
    timeout: std::time::Duration,
    max_output_bytes: usize,
    label: &str,
) -> Result<Output> {
    let child = spawn_bounded_command(argv, label)?;
    collect_bounded_output(child, argv, timeout, max_output_bytes, label)
}

fn spawn_bounded_command(argv: &[String], label: &str) -> Result<std::process::Child> {
    let (program, arguments) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty service command"))?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_native_manager_environment(&mut command);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command
        .spawn()
        .with_context(|| format!("running {label} {argv:?}"))
}

fn collect_bounded_output(
    mut child: std::process::Child,
    argv: &[String],
    timeout: std::time::Duration,
    max_output_bytes: usize,
    label: &str,
) -> Result<Output> {
    let process_group = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("{label} stdout pipe was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("{label} stderr pipe was not captured"))?;
    let budget = Arc::new(CaptureBudget::new(max_output_bytes));
    let stdout_budget = Arc::clone(&budget);
    let stderr_budget = Arc::clone(&budget);
    let stdout_reader = std::thread::spawn(move || drain_capped_stream(stdout, stdout_budget));
    let stderr_reader = std::thread::spawn(move || drain_capped_stream(stderr, stderr_budget));
    let deadline = std::time::Instant::now() + timeout;
    let mut failure = None;
    let status = loop {
        if budget.exceeded.load(Ordering::Acquire) {
            failure = Some(BoundedCommandFailureKind::OutputLimit);
            kill_and_reap_process_group(&mut child)?;
            break None;
        }
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("polling {label} {argv:?}"))?
        {
            // A direct child may exit after forking a descendant that inherited
            // either capture pipe. Sweep the dedicated command process group
            // before joining readers or their EOF could remain unbounded.
            kill_process_group(process_group)?;
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            failure = Some(BoundedCommandFailureKind::Timeout);
            kill_and_reap_process_group(&mut child)?;
            break None;
        }
        std::thread::sleep(CHILD_POLL_INTERVAL);
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} stdout capture thread panicked"))?
        .with_context(|| format!("reading bounded stdout from {label}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} stderr capture thread panicked"))?
        .with_context(|| format!("reading bounded stderr from {label}"))?;
    if failure.is_none() && budget.exceeded.load(Ordering::Acquire) {
        failure = Some(BoundedCommandFailureKind::OutputLimit);
    }
    if let Some(kind) = failure {
        return Err(anyhow::Error::new(BoundedCommandFailure {
            kind,
            label: label.to_string(),
            timeout,
            max_output_bytes,
        }));
    }
    Ok(Output {
        status: status.expect("bounded command without failure has an exit status"),
        stdout,
        stderr,
    })
}

fn configure_native_manager_environment(command: &mut Command) {
    // Keep session/bus variables inherited, but make every native-manager
    // diagnostic and property classifier independent of the invoking shell's
    // locale, pager, and color settings.
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .env("PAGER", "cat");
}

fn run_command(argv: &[String], platform: ServicePlatform, action: ServiceAction) -> Result<()> {
    let (timeout, max_output_bytes) = if action == ServiceAction::Logs {
        (MANAGER_LOG_TIMEOUT, MANAGER_LOG_OUTPUT_BYTES)
    } else {
        (MANAGER_ACTION_TIMEOUT, MANAGER_OUTPUT_BYTES)
    };
    let output = run_bounded_output(argv, timeout, max_output_bytes, "service command")?;
    forward_output(&output);
    let needs_launchd_probe = !output.status.success()
        && platform == ServicePlatform::LaunchdAppleSilicon
        && (argv.get(1).is_some_and(|argument| argument == "bootstrap")
            || argv.get(1).is_some_and(|argument| argument == "bootout"));
    let launchd_loaded = needs_launchd_probe
        .then(launchd_service_is_loaded)
        .transpose()?;
    let loaded_after_bootstrap = matches!(launchd_loaded, Some(true))
        && matches!(action, ServiceAction::Start | ServiceAction::Restart)
        && argv.get(1).is_some_and(|argument| argument == "bootstrap");
    let absent_after_bootout = !output.status.success()
        && platform == ServicePlatform::LaunchdAppleSilicon
        && matches!(
            action,
            ServiceAction::Stop | ServiceAction::Restart | ServiceAction::Uninstall
        )
        && argv.get(1).is_some_and(|argument| argument == "bootout")
        && matches!(launchd_loaded, Some(false));
    if !output.status.success()
        && !loaded_after_bootstrap
        && !absent_after_bootout
        && !is_idempotent_manager_result(platform, action, &output)?
    {
        bail!(
            "service command {argv:?} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn verify_started(
    platform: ServicePlatform,
    definition: &str,
    prior_process_generation: Option<&str>,
) -> Result<()> {
    wait_for_product_ready(
        PRODUCT_READY_TIMEOUT,
        PRODUCT_READY_POLL_INTERVAL,
        MANAGER_RECHECK_INTERVAL,
        |remaining| verify_native_manager_running(platform, remaining.min(MANAGER_PROBE_TIMEOUT)),
        |remaining| match crate::attachment::connect_verified_attached_main_sync_with_timeout(
            None,
            remaining.min(std::time::Duration::from_secs(5)),
        ) {
            Ok(attached) => {
                running_identity_mismatch(definition, &attached.status, prior_process_generation)
            }
            Err(error) => Ok(Some(format!("{error:#}"))),
        },
    )
}

fn verify_native_manager_running(
    platform: ServicePlatform,
    timeout: std::time::Duration,
) -> Result<()> {
    match platform {
        ServicePlatform::SystemdUser => {
            let output = run_bounded_output(
                &args(&[
                    SYSTEMCTL_PATH,
                    "--user",
                    "is-active",
                    "--quiet",
                    SYSTEMD_UNIT_NAME,
                ]),
                timeout,
                MANAGER_OUTPUT_BYTES,
                "systemd-user readiness probe",
            )?;
            if !output.status.success() {
                bail!(
                    "systemd-user accepted the start command but {SYSTEMD_UNIT_NAME} did not reach active state ({}); inspect `kata service status` and `kata service logs`",
                    output.status
                );
            }
        }
        ServicePlatform::LaunchdAppleSilicon => {
            if !launchd_service_is_loaded_with_timeout(timeout)? {
                bail!(
                    "launchd accepted the start command but {LAUNCHD_LABEL} is not loaded; inspect `kata service status` and `kata service logs`"
                );
            }
        }
    }
    Ok(())
}

fn verify_stopped(platform: ServicePlatform, discovery_owned_by_caller: bool) -> Result<()> {
    wait_for_service_stopped(
        SERVICE_STOPPED_TIMEOUT,
        PRODUCT_READY_POLL_INTERVAL,
        |remaining| native_manager_is_stopped(platform, remaining.min(MANAGER_PROBE_TIMEOUT)),
        move || discovery_quiescent(discovery_owned_by_caller),
    )
}

/// Discovery-lease quiescence for stopped-state verification.
///
/// Invariant: when the executing authority is a publication permit, that
/// permit already owns the per-owner discovery lease — acquiring it proved no
/// installed main holds discovery. `flock(2)` treats a second descriptor
/// opened by the same process as a conflicting holder, so re-probing the lock
/// here would misread our own authority as a live installed main and wedge
/// every applied uninstall at the stopped-verification timeout. Enforcement:
/// the caller threads `discovery_owned_by_caller` from the execution
/// authority; proof: `discovery_probe_conflicts_with_own_process_lease` and
/// `publication_authority_skips_discovery_probe_on_stop_verification`.
fn discovery_quiescent(discovery_owned_by_caller: bool) -> Result<bool> {
    if discovery_owned_by_caller {
        return Ok(true);
    }
    crate::attachment::InstalledDiscoveryLease::probe_available()
}

fn native_manager_is_stopped(
    platform: ServicePlatform,
    timeout: std::time::Duration,
) -> Result<bool> {
    match platform {
        ServicePlatform::SystemdUser => {
            let output = run_bounded_output(
                &args(&[SYSTEMCTL_PATH, "--user", "is-active", SYSTEMD_UNIT_NAME]),
                timeout,
                MANAGER_OUTPUT_BYTES,
                "systemd-user stopped-state probe",
            )?;
            let lines = manager_output_lines(&output);
            if output.status.success() {
                return Ok(false);
            }
            match lines.as_slice() {
                [state] if ["inactive", "failed", "unknown"].contains(&state.as_str()) => Ok(true),
                [state]
                    if ["active", "activating", "deactivating", "reloading"]
                        .contains(&state.as_str()) =>
                {
                    Ok(false)
                }
                _ => bail!(
                    "could not prove {SYSTEMD_UNIT_NAME} stopped after manager command ({}): {}",
                    output.status,
                    lines.join("\n")
                ),
            }
        }
        ServicePlatform::LaunchdAppleSilicon => {
            Ok(!launchd_service_is_loaded_with_timeout(timeout)?)
        }
    }
}

fn wait_for_service_stopped(
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
    mut manager_stopped: impl FnMut(std::time::Duration) -> Result<bool>,
    mut discovery_available: impl FnMut() -> Result<bool>,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let mut last_state = "native manager still owns the service";
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if manager_stopped(remaining)? {
            if discovery_available()? {
                return Ok(());
            }
            last_state = "installed main still owns the discovery lease";
        }
        std::thread::sleep(
            poll_interval.min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
    bail!(
        "native manager command returned but Kata did not reach verified stopped state within {}s: {last_state}",
        timeout.as_secs()
    )
}

fn wait_for_product_ready(
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
    manager_recheck_interval: std::time::Duration,
    mut verify_manager: impl FnMut(std::time::Duration) -> Result<()>,
    mut verify_product: impl FnMut(std::time::Duration) -> Result<Option<String>>,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let mut next_manager_check = std::time::Instant::now();
    let mut last_error = String::new();
    while std::time::Instant::now() < deadline {
        let now = std::time::Instant::now();
        if now >= next_manager_check {
            verify_manager(deadline.saturating_duration_since(now))?;
            next_manager_check = now + manager_recheck_interval;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match verify_product(remaining)? {
            None => return Ok(()),
            Some(error) => last_error = error,
        }
        std::thread::sleep(poll_interval.min(deadline.saturating_duration_since(now)));
    }
    bail!(
        "native manager started Kata, but verified product readiness was not reached within {}s: {last_error}; inspect `kata service status` and `kata service logs`",
        timeout.as_secs()
    )
}

fn running_identity_mismatch(
    definition: &str,
    status: &kata_client::types::SystemStatus,
    prior_process_generation: Option<&str>,
) -> Result<Option<String>> {
    let required = |value: Option<String>, name: &str| {
        value.ok_or_else(|| {
            anyhow::anyhow!(
                "installed service definition lacks {name} identity; reinstall it before start/restart"
            )
        })
    };
    let expected_directory = required(definition_directory_id(definition), "data-directory")?;
    let expected_binary_digest = required(definition_binary_digest(definition), "binary digest")?;
    let expected_binary_version =
        required(definition_binary_version(definition), "binary version")?;
    let expected_config_digest = required(definition_config_digest(definition), "config digest")?;
    let expected_config_path = definition_config_path(definition).ok_or_else(|| {
        anyhow::anyhow!(
            "installed service definition lacks config path identity; reinstall it before start/restart"
        )
    })?;
    let expected_environment_digest = required(
        definition_environment_digest(definition),
        "environment digest",
    )?;

    let mut mismatches = [
        (
            "directory_id",
            Some(expected_directory.as_str()),
            status.directory_id.as_deref(),
        ),
        (
            "binary_digest",
            Some(expected_binary_digest.as_str()),
            status.loaded_binary_digest.as_deref(),
        ),
        (
            "binary_version",
            Some(expected_binary_version.as_str()),
            status.binary_version.as_deref(),
        ),
        (
            "config_digest",
            Some(expected_config_digest.as_str()),
            status.loaded_config_digest.as_deref(),
        ),
        (
            "config_path",
            expected_config_path.to_str(),
            status.loaded_config_path.as_deref(),
        ),
        (
            "environment_digest",
            Some(expected_environment_digest.as_str()),
            status.loaded_service_environment_digest.as_deref(),
        ),
    ]
    .into_iter()
    .filter(|(_, expected, running)| expected != running)
    .map(|(name, expected, running)| format!("{name}: installed={expected:?}, running={running:?}"))
    .collect::<Vec<_>>();
    if prior_process_generation.is_some()
        && status.process_generation.as_deref() == prior_process_generation
    {
        mismatches.push(format!(
            "process_generation: restart retained prior generation {prior_process_generation:?}"
        ));
    }
    if mismatches.is_empty() {
        Ok(None)
    } else {
        Ok(Some(format!(
            "product-ready main identity does not match installed service definition ({})",
            mismatches.join("; ")
        )))
    }
}

pub fn definition_directory_id(definition: &str) -> Option<String> {
    for line in definition.lines() {
        if let Some(value) = line.trim().strip_prefix("# X-Kata-Data-Directory-ID=") {
            return Some(value.trim().to_string());
        }
    }
    let marker = "<key>KataDataDirectoryID</key><string>";
    let rest = definition.split_once(marker)?.1;
    Some(rest.split_once("</string>")?.0.to_string())
}

/// Return the digest of the config bytes captured when this service definition
/// was installed. This is deliberately read from definition metadata rather
/// than reconstructed from command arguments.
pub fn definition_config_digest(definition: &str) -> Option<String> {
    definition_metadata_value(definition, "# X-Kata-Config-Digest=", "KataConfigDigest")
}

pub fn definition_binary_digest(definition: &str) -> Option<String> {
    definition_metadata_value(definition, "# X-Kata-Binary-Digest=", "KataBinaryDigest")
}

pub fn definition_binary_version(definition: &str) -> Option<String> {
    definition_metadata_value(definition, "# X-Kata-Binary-Version=", "KataBinaryVersion")
}

pub fn definition_binary_path(definition: &str) -> Option<PathBuf> {
    definition_path_metadata_value(definition, "# X-Kata-Binary-Path=", "KataBinaryPath")
}

pub fn definition_definition_path(definition: &str) -> Option<PathBuf> {
    definition_path_metadata_value(
        definition,
        "# X-Kata-Definition-Path=",
        "KataDefinitionPath",
    )
}

/// Return the canonical config path captured in this service definition.
///
/// Older definitions did not carry this explicit field; status reports those
/// as unverifiable and tells the operator to reinstall rather than guessing by
/// parsing native-manager command syntax.
pub fn definition_config_path(definition: &str) -> Option<PathBuf> {
    definition_path_metadata_value(definition, "# X-Kata-Config-Path=", "KataConfigPath")
}

pub fn definition_environment_digest(definition: &str) -> Option<String> {
    definition_metadata_value(
        definition,
        "# X-Kata-Service-Environment-Digest=",
        "KataServiceEnvironmentDigest",
    )
}

pub fn definition_environment_path(definition: &str) -> Option<PathBuf> {
    definition_path_metadata_value(
        definition,
        "# X-Kata-Service-Environment-Path=",
        "KataServiceEnvironmentPath",
    )
}

pub fn definition_working_directory(definition: &str) -> Option<PathBuf> {
    definition_path_metadata_value(
        definition,
        "# X-Kata-Working-Directory=",
        "KataWorkingDirectory",
    )
}

fn definition_format(definition: &str) -> Option<String> {
    definition_metadata_value(
        definition,
        "# X-Kata-Definition-Format=",
        "KataDefinitionFormat",
    )
}

fn inspect_installed_definition(
    platform: ServicePlatform,
    path: &Path,
    environment_directory: &Path,
) -> Result<DefinitionAuthority> {
    let definition_publication = match ExistingOwnerOnlyPublication::open(
        path,
        MAX_SERVICE_DEFINITION_BYTES,
        "service definition",
    ) {
        Ok(publication) => publication,
        // The definition is the single atomic commit. Content-addressed
        // environment snapshots published before it are inert orphans, never
        // a mixed installed state, and are reclaimed by bounded lifecycle GC.
        Err(error) if is_not_found(&error) => return Ok(DefinitionAuthority::Absent),
        Err(error) => {
            return Err(error).context(
                "the fixed native-service definition exists but is not an exact owner-only Kata publication; refusing to overwrite or operate on it",
            );
        }
    };
    let raw = definition_publication
        .read_utf8(MAX_SERVICE_DEFINITION_BYTES, "service definition")
        .context("reading the descriptor-retained native-service definition")?;
    let owned = parse_owned_service_definition(
        platform,
        path,
        environment_directory,
        raw,
        definition_publication,
    )
    .context(
            "the fixed native-service definition is not an exact Kata-owned publication; refusing to overwrite or operate on it",
        )?;
    Ok(DefinitionAuthority::Exact(Box::new(owned)))
}

fn parse_owned_service_definition(
    platform: ServicePlatform,
    path: &Path,
    environment_directory: &Path,
    raw: String,
    definition_publication: ExistingOwnerOnlyPublication,
) -> Result<OwnedServiceDefinition> {
    for (field, systemd_prefix, launchd_key) in [
        (
            "definition format",
            "# X-Kata-Definition-Format=",
            "KataDefinitionFormat",
        ),
        (
            "definition path",
            "# X-Kata-Definition-Path=",
            "KataDefinitionPath",
        ),
        ("binary path", "# X-Kata-Binary-Path=", "KataBinaryPath"),
        (
            "binary digest",
            "# X-Kata-Binary-Digest=",
            "KataBinaryDigest",
        ),
        (
            "binary version",
            "# X-Kata-Binary-Version=",
            "KataBinaryVersion",
        ),
        ("config path", "# X-Kata-Config-Path=", "KataConfigPath"),
        (
            "config digest",
            "# X-Kata-Config-Digest=",
            "KataConfigDigest",
        ),
        (
            "environment path",
            "# X-Kata-Service-Environment-Path=",
            "KataServiceEnvironmentPath",
        ),
        (
            "environment digest",
            "# X-Kata-Service-Environment-Digest=",
            "KataServiceEnvironmentDigest",
        ),
        (
            "working directory",
            "# X-Kata-Working-Directory=",
            "KataWorkingDirectory",
        ),
        (
            "data-directory path",
            "# X-Kata-Data-Directory=",
            "KataDataDirectory",
        ),
        (
            "data-directory id",
            "# X-Kata-Data-Directory-ID=",
            "KataDataDirectoryID",
        ),
    ] {
        let occurrences = definition_metadata_occurrences(&raw, systemd_prefix, launchd_key);
        if occurrences != 1 {
            bail!(
                "{field} metadata occurs {occurrences} times; an owned Kata definition requires exactly one occurrence"
            );
        }
    }
    if definition_format(&raw).as_deref() != Some(SERVICE_DEFINITION_FORMAT) {
        bail!(
            "unsupported or missing Kata service-definition format; expected {SERVICE_DEFINITION_FORMAT}. Stop that service with the Kata binary that installed it, remove its unit/plist, then run `kata service install --config <path> --apply`"
        );
    }
    let required_path = |value: Option<PathBuf>, field: &str| -> Result<PathBuf> {
        let value = value.ok_or_else(|| anyhow::anyhow!("missing {field}"))?;
        if !value.is_absolute() {
            bail!("{field} must be absolute: {}", value.display());
        }
        Ok(value)
    };
    let required_value = |value: Option<String>, field: &str| -> Result<String> {
        let value = value.ok_or_else(|| anyhow::anyhow!("missing {field}"))?;
        if value.is_empty() || value.chars().any(char::is_control) {
            bail!("{field} is empty or contains control characters");
        }
        Ok(value)
    };
    let definition_path = required_path(definition_definition_path(&raw), "definition path")?;
    if definition_path != path {
        bail!(
            "definition metadata names {}, expected fixed path {}",
            definition_path.display(),
            path.display()
        );
    }
    let environment_path = required_path(
        definition_environment_path(&raw),
        "service environment path",
    )?;
    let environment_digest = required_value(
        definition_environment_digest(&raw),
        "service environment digest",
    )?;
    let expected_environment_path =
        environment_snapshot_path(environment_directory, &environment_digest)?;
    if environment_path != expected_environment_path {
        bail!(
            "definition environment metadata names {}, expected content-addressed path {}",
            environment_path.display(),
            expected_environment_path.display()
        );
    }
    let binary = required_path(definition_binary_path(&raw), "binary path")?;
    let config = required_path(definition_config_path(&raw), "config path")?;
    let working_directory = required_path(
        definition_working_directory(&raw),
        "service working directory",
    )?;
    if config.parent() != Some(working_directory.as_path()) {
        bail!(
            "service working directory {} is not the config parent {}",
            working_directory.display(),
            config.display()
        );
    }
    let data_dir = required_path(definition_data_dir(&raw), "data-directory path")?;
    let binary_digest = required_value(definition_binary_digest(&raw), "binary digest")?;
    let config_digest = required_value(definition_config_digest(&raw), "config digest")?;
    for (field, digest) in [
        ("binary digest", &binary_digest),
        ("config digest", &config_digest),
        ("service environment digest", &environment_digest),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("{field} is not canonical lowercase 256-bit hexadecimal text");
        }
    }
    let binary_version = required_value(definition_binary_version(&raw), "binary version")?;
    let data_directory_id =
        required_value(definition_directory_id(&raw), "data-directory identity")?;
    if data_directory_id == "uninitialized" {
        bail!("an installed service definition cannot retain an uninitialized directory identity");
    }

    let environment_definition = read_installed_service_environment_utf8(&environment_path)?;
    if blake3_bytes(environment_definition.as_bytes()).to_string() != environment_digest {
        bail!(
            "owner-only service environment {} does not match the definition digest",
            environment_path.display()
        );
    }
    let environment: BTreeMap<String, String> = serde_json::from_str(&environment_definition)
        .with_context(|| {
            format!(
                "parsing owner-only service environment {}",
                environment_path.display()
            )
        })?;
    if serialize_service_environment(&environment)? != environment_definition {
        bail!(
            "owner-only service environment {} is not in Kata's canonical format",
            environment_path.display()
        );
    }
    let spec = ServiceSpec {
        platform,
        definition_path,
        binary,
        config,
        working_directory,
        data_dir,
        binary_digest,
        binary_version,
        config_digest,
        environment_digest,
        data_directory_id,
        environment,
        environment_path,
    };
    if spec.render() != raw {
        bail!(
            "installed service definition contains noncanonical, extra, or platform-mismatched content"
        );
    }
    Ok(OwnedServiceDefinition {
        raw,
        environment_definition,
        spec,
        definition_publication,
    })
}

/// Prove that the launch snapshot supplied by systemd/launchd still names the
/// definition installed for this owner. The caller must already hold the
/// stable per-owner discovery lease, which excludes Kata's install/uninstall
/// paths while this descriptor-bound read and comparison run.
pub(crate) fn validate_current_service_exec_definition(
    launch: &ServiceExecLaunchIdentity<'_>,
) -> Result<()> {
    validate_service_exec_definition_at(launch.definition, launch)
}

fn validate_service_exec_definition_at(
    path: &Path,
    launch: &ServiceExecLaunchIdentity<'_>,
) -> Result<()> {
    require_no_pending_definition_transaction(path)?;
    let definition_publication = ExistingOwnerOnlyPublication::open(
        path,
        MAX_SERVICE_DEFINITION_BYTES,
        "service definition",
    )?;
    let definition =
        definition_publication.read_utf8(MAX_SERVICE_DEFINITION_BYTES, "service definition")?;
    let platform = if definition.starts_with("[Unit]\n") {
        ServicePlatform::SystemdUser
    } else if definition.starts_with("<?xml version=") {
        ServicePlatform::LaunchdAppleSilicon
    } else {
        bail!("installed service definition has no supported canonical platform format");
    };
    parse_owned_service_definition(
        platform,
        path,
        launch
            .environment
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installed service environment path has no parent"))?,
        definition.clone(),
        definition_publication,
    )?;
    let mut mismatches = Vec::new();
    for (field, systemd_prefix, launchd_key) in [
        (
            "definition path",
            "# X-Kata-Definition-Path=",
            "KataDefinitionPath",
        ),
        ("binary path", "# X-Kata-Binary-Path=", "KataBinaryPath"),
        (
            "environment path",
            "# X-Kata-Service-Environment-Path=",
            "KataServiceEnvironmentPath",
        ),
        ("config path", "# X-Kata-Config-Path=", "KataConfigPath"),
        (
            "working directory",
            "# X-Kata-Working-Directory=",
            "KataWorkingDirectory",
        ),
        (
            "binary digest",
            "# X-Kata-Binary-Digest=",
            "KataBinaryDigest",
        ),
        (
            "config digest",
            "# X-Kata-Config-Digest=",
            "KataConfigDigest",
        ),
        (
            "environment digest",
            "# X-Kata-Service-Environment-Digest=",
            "KataServiceEnvironmentDigest",
        ),
        (
            "data-directory path",
            "# X-Kata-Data-Directory=",
            "KataDataDirectory",
        ),
        (
            "data-directory id",
            "# X-Kata-Data-Directory-ID=",
            "KataDataDirectoryID",
        ),
    ] {
        let occurrences = definition_metadata_occurrences(&definition, systemd_prefix, launchd_key);
        if occurrences != 1 {
            mismatches.push(format!(
                "{field}: installed metadata occurs {occurrences} times, expected exactly once"
            ));
        }
    }
    compare_launch_path(
        &mut mismatches,
        "definition path",
        definition_definition_path(&definition),
        launch.definition,
    );
    compare_launch_path(
        &mut mismatches,
        "binary path",
        definition_binary_path(&definition),
        launch.binary,
    );
    compare_launch_path(
        &mut mismatches,
        "environment path",
        definition_environment_path(&definition),
        launch.environment,
    );
    compare_launch_path(
        &mut mismatches,
        "config path",
        definition_config_path(&definition),
        launch.config,
    );
    compare_launch_path(
        &mut mismatches,
        "working directory",
        definition_working_directory(&definition),
        launch.working_directory,
    );
    compare_launch_value(
        &mut mismatches,
        "binary digest",
        definition_binary_digest(&definition),
        launch.binary_digest,
    );
    compare_launch_value(
        &mut mismatches,
        "config digest",
        definition_config_digest(&definition),
        launch.config_digest,
    );
    compare_launch_value(
        &mut mismatches,
        "environment digest",
        definition_environment_digest(&definition),
        launch.environment_digest,
    );
    compare_launch_path(
        &mut mismatches,
        "data-directory path",
        definition_data_dir(&definition),
        launch.data_directory,
    );
    compare_launch_value(
        &mut mismatches,
        "data-directory id",
        definition_directory_id(&definition),
        launch.directory_id,
    );
    if mismatches.is_empty() {
        Ok(())
    } else {
        bail!(
            "native service manager launched a stale or unverifiable Kata definition while {} is current ({}); refusing startup so the installed definition remains authoritative",
            path.display(),
            mismatches.join("; ")
        )
    }
}

fn definition_metadata_occurrences(
    definition: &str,
    systemd_prefix: &str,
    launchd_key: &str,
) -> usize {
    let systemd = definition
        .lines()
        .filter(|line| line.trim().starts_with(systemd_prefix))
        .count();
    let launchd_marker = format!("<key>{launchd_key}</key><string>");
    systemd + definition.match_indices(&launchd_marker).count()
}

fn compare_launch_path(
    mismatches: &mut Vec<String>,
    field: &str,
    installed: Option<PathBuf>,
    launched: &Path,
) {
    match installed {
        Some(installed) if installed == launched => {}
        Some(installed) => mismatches.push(format!(
            "{field}: launched={}, installed={}",
            launched.display(),
            installed.display()
        )),
        None => mismatches.push(format!("{field}: installed metadata missing")),
    }
}

fn compare_launch_value(
    mismatches: &mut Vec<String>,
    field: &str,
    installed: Option<String>,
    launched: &str,
) {
    match installed {
        Some(installed) if installed == launched => {}
        Some(installed) => mismatches.push(format!(
            "{field}: launched={launched:?}, installed={installed:?}"
        )),
        None => mismatches.push(format!("{field}: installed metadata missing")),
    }
}

#[cfg(test)]
fn read_owner_only_service_definition(path: &Path) -> Result<String> {
    read_bounded_utf8(
        path,
        AuthorityFilePolicy::owner_only(
            "installed service definition",
            MAX_SERVICE_DEFINITION_BYTES,
        ),
    )
}

/// Digest the config bytes currently present at `path` with the same algorithm
/// used when rendering the installed definition.
pub fn current_config_digest(path: &Path) -> Result<String> {
    digest_bounded_file(path, config_policy())
}

pub fn current_binary_digest(path: &Path) -> Result<String> {
    digest_bounded_file(
        path,
        AuthorityFilePolicy::bounded("installed Kata binary", MAX_KATA_BINARY_BYTES),
    )
}

pub fn current_environment_digest(path: &Path) -> Result<String> {
    Ok(blake3_bytes(&read_installed_service_environment(path)?).to_string())
}

fn validate_installed_launch_inputs(plan: &ServicePlan) -> Result<()> {
    let definition = &plan.definition;
    let data_dir = definition_data_dir(definition).ok_or_else(|| {
        anyhow::anyhow!("installed service definition lacks data-directory path; reinstall it")
    })?;
    if std::fs::symlink_metadata(&data_dir)
        .with_context(|| {
            format!(
                "inspecting installed service data directory {}",
                data_dir.display()
            )
        })?
        .file_type()
        .is_symlink()
    {
        bail!(
            "installed Kata data directory {} became a symlink; refusing start/restart before native-manager mutation",
            data_dir.display()
        );
    }
    let expected_directory_id = definition_directory_id(definition).ok_or_else(|| {
        anyhow::anyhow!("installed service definition lacks data-directory identity; reinstall it")
    })?;
    let current_identity = inspect_identity(&data_dir)?.ok_or_else(|| {
        anyhow::anyhow!(
            "installed Kata data directory {} is missing its immutable identity; refusing start/restart before native-manager mutation",
            data_dir.display()
        )
    })?;
    if current_identity.mode != crate::data_dir_lock::MainMode::Installed {
        bail!(
            "installed Kata data directory {} has {:?} identity; refusing start/restart before native-manager mutation",
            data_dir.display(),
            current_identity.mode
        );
    }
    if current_identity.directory_id != expected_directory_id {
        bail!(
            "installed Kata data directory {} identity changed (installed {}, current {}); refuse start/restart and reinstall with the intended config",
            data_dir.display(),
            expected_directory_id,
            current_identity.directory_id
        );
    }
    let binary = definition_binary_path(definition).ok_or_else(|| {
        anyhow::anyhow!("installed service definition lacks binary path identity; reinstall it")
    })?;
    let expected_binary = definition_binary_digest(definition).ok_or_else(|| {
        anyhow::anyhow!("installed service definition lacks binary digest identity; reinstall it")
    })?;
    let current_binary = current_binary_digest(&binary)?;
    if current_binary != expected_binary {
        bail!(
            "installed Kata binary {} changed since service installation (installed digest {}, current digest {}); stop the service, run `kata service install --config <path> --apply`, then start it",
            binary.display(),
            expected_binary,
            current_binary
        );
    }

    let config = definition_config_path(definition).ok_or_else(|| {
        anyhow::anyhow!("installed service definition lacks config path identity; reinstall it")
    })?;
    let expected_config = definition_config_digest(definition).ok_or_else(|| {
        anyhow::anyhow!("installed service definition lacks config digest identity; reinstall it")
    })?;
    let current_config = current_config_digest(&config)?;
    if current_config != expected_config {
        bail!(
            "installed Kata config {} changed since service installation (installed digest {}, current digest {}); stop the service, run `kata service install --config {} --apply`, then start it",
            config.display(),
            expected_config,
            current_config,
            config.display()
        );
    }

    let expected_environment = definition_environment_digest(definition).ok_or_else(|| {
        anyhow::anyhow!(
            "installed service definition lacks environment digest identity; reinstall it"
        )
    })?;
    let current_environment = current_environment_digest(&plan.environment_path)?;
    if current_environment != expected_environment {
        bail!(
            "owner-only Kata service environment {} changed since service installation (installed digest {}, current digest {}); stop the service, run `kata service install --config {} --apply`, then start it",
            plan.environment_path.display(),
            expected_environment,
            current_environment,
            config.display()
        );
    }
    Ok(())
}

pub fn definition_data_dir(definition: &str) -> Option<PathBuf> {
    definition_path_metadata_value(definition, "# X-Kata-Data-Directory=", "KataDataDirectory")
}

fn definition_metadata_value(
    definition: &str,
    systemd_prefix: &str,
    launchd_key: &str,
) -> Option<String> {
    for line in definition.lines() {
        if let Some(value) = line.trim().strip_prefix(systemd_prefix) {
            return Some(value.trim().to_string());
        }
    }
    let marker = format!("<key>{launchd_key}</key><string>");
    let rest = definition.split_once(&marker)?.1;
    let encoded = rest.split_once("</string>")?.0;
    Some(xml_unescape(encoded))
}

fn definition_path_metadata_value(
    definition: &str,
    systemd_prefix: &str,
    launchd_key: &str,
) -> Option<PathBuf> {
    for line in definition.lines() {
        if let Some(value) = line.trim().strip_prefix(systemd_prefix) {
            let decoded = serde_json::from_str::<String>(value.trim())
                .unwrap_or_else(|_| value.trim().trim_matches('"').to_string())
                .replace("%%", "%");
            return Some(PathBuf::from(decoded));
        }
    }
    definition_metadata_value(definition, systemd_prefix, launchd_key).map(PathBuf::from)
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
}

fn inspect_native_manager(
    platform: ServicePlatform,
    owned: Option<&OwnedServiceDefinition>,
) -> Result<ManagerAuthority> {
    match platform {
        ServicePlatform::SystemdUser => {
            let output = run_bounded_output(
                &args(&[
                    SYSTEMCTL_PATH,
                    "--user",
                    "show",
                    "--all",
                    "--no-pager",
                    "--property=Id,Names,LoadState,ActiveState,SubState,MainPID,ControlPID,FragmentPath,DropInPaths,NeedDaemonReload,ExecStart,WorkingDirectory",
                    SYSTEMD_UNIT_NAME,
                ]),
                MANAGER_PROBE_TIMEOUT,
                MANAGER_OUTPUT_BYTES,
                "systemd-user service identity probe",
            )?;
            classify_systemd_manager(
                &output,
                owned,
                &definition_path(ServicePlatform::SystemdUser)?,
                &environment_directory(ServicePlatform::SystemdUser)?,
            )
        }
        ServicePlatform::LaunchdAppleSilicon => {
            let uid = current_uid();
            let output = run_bounded_output(
                &[
                    LAUNCHCTL_PATH.to_string(),
                    "print".to_string(),
                    format!("gui/{uid}/{LAUNCHD_LABEL}"),
                ],
                MANAGER_PROBE_TIMEOUT,
                MANAGER_OUTPUT_BYTES,
                "launchd service identity probe",
            )?;
            classify_launchd_manager(&output, &uid, owned)
        }
    }
}

fn parse_systemd_properties(output: &Output) -> Result<BTreeMap<String, String>> {
    if !output.status.success() {
        bail!(
            "systemd-user identity probe failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = std::str::from_utf8(&output.stdout)
        .context("systemd-user identity probe returned non-UTF-8 output")?;
    let allowed = BTreeSet::from([
        "Id",
        "Names",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "FragmentPath",
        "DropInPaths",
        "NeedDaemonReload",
        "ExecStart",
        "WorkingDirectory",
    ]);
    let mut properties = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("malformed systemd property line {line:?}"))?;
        if !allowed.contains(key) {
            bail!("unexpected systemd identity property {key:?}");
        }
        if properties
            .insert(key.to_string(), value.to_string())
            .is_some()
        {
            bail!("duplicate systemd identity property {key:?}");
        }
    }
    for required in [
        "Id",
        "Names",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "FragmentPath",
        "DropInPaths",
        "NeedDaemonReload",
        "WorkingDirectory",
    ] {
        if !properties.contains_key(required) {
            bail!("systemd identity probe omitted required property {required}");
        }
    }
    Ok(properties)
}

fn classify_systemd_manager(
    output: &Output,
    owned: Option<&OwnedServiceDefinition>,
    fixed_definition: &Path,
    fixed_environment_directory: &Path,
) -> Result<ManagerAuthority> {
    let properties = parse_systemd_properties(output)?;
    if properties.get("Id").map(String::as_str) != Some(SYSTEMD_UNIT_NAME)
        || properties.get("Names").map(String::as_str) != Some(SYSTEMD_UNIT_NAME)
    {
        bail!("systemd resolved the fixed Kata target to a different unit identity");
    }
    match properties.get("LoadState").map(String::as_str) {
        Some("not-found") => {
            for property in [
                "FragmentPath",
                "DropInPaths",
                "WorkingDirectory",
                "ExecStart",
            ] {
                if properties
                    .get(property)
                    .is_some_and(|value| !value.is_empty())
                {
                    bail!(
                        "systemd reported {SYSTEMD_UNIT_NAME} absent but retained nonempty {property} identity"
                    );
                }
            }
            require_safe_systemd_reload_state(&properties)?;
            match properties.get("NeedDaemonReload").map(String::as_str) {
                Some("no") => Ok(ManagerAuthority::Absent),
                Some("yes") if owned.is_some() => Ok(ManagerAuthority::ExactNeedsReload),
                _ => bail!("systemd absent-state reload identity is unknown"),
            }
        }
        Some("loaded") => {
            let expected_definition = owned.map_or_else(
                || fixed_definition.to_path_buf(),
                |owned| owned.spec.definition_path.clone(),
            );
            if properties.get("FragmentPath").map(Path::new) != Some(expected_definition.as_path())
            {
                bail!(
                    "systemd effective FragmentPath does not match the exact Kata-owned definition"
                );
            }
            if properties
                .get("DropInPaths")
                .is_some_and(|value| !value.is_empty())
            {
                bail!(
                    "systemd effective unit has drop-ins; refusing because they can override Kata's checked launch contract"
                );
            }
            let (path, argv) = parse_systemd_exec_start(
                properties
                    .get("ExecStart")
                    .map(String::as_str)
                    .unwrap_or_default(),
            )?;
            if properties.get("NeedDaemonReload").map(String::as_str) == Some("yes") {
                require_safe_systemd_reload_state(&properties)?;
                validate_stale_systemd_kata_launch(
                    &path,
                    &argv,
                    properties
                        .get("WorkingDirectory")
                        .map(String::as_str)
                        .unwrap_or_default(),
                    owned,
                    fixed_definition,
                    fixed_environment_directory,
                )?;
                return Ok(if owned.is_some() {
                    ManagerAuthority::ExactNeedsReload
                } else {
                    ManagerAuthority::ExactStaleRemoval
                });
            }
            let owned = owned.ok_or_else(|| {
                anyhow::anyhow!(
                    "systemd has a loaded {SYSTEMD_UNIT_NAME} object but no exact Kata-owned definition exists at the fixed path"
                )
            })?;
            if properties.get("NeedDaemonReload").map(String::as_str) != Some("no") {
                bail!("systemd effective unit reload state is unknown");
            }
            if properties.get("WorkingDirectory").map(Path::new)
                != Some(owned.spec.working_directory.as_path())
            {
                bail!("systemd effective WorkingDirectory differs from the owned definition");
            }
            let expected = service_exec_command(&owned.spec);
            if path != owned.spec.binary || argv != expected {
                bail!(
                    "systemd effective ExecStart differs from the exact Kata-owned launch identity"
                );
            }
            Ok(if systemd_state_is_quiescent(&properties) {
                ManagerAuthority::ExactMatchingQuiescent
            } else if systemd_state_is_running(&properties) {
                ManagerAuthority::ExactRunning
            } else {
                ManagerAuthority::ExactMatching
            })
        }
        Some(state) => bail!(
            "systemd LoadState {state:?} is neither exactly loaded nor exactly absent; refusing native-service operation"
        ),
        None => bail!("systemd identity probe omitted LoadState"),
    }
}

fn require_safe_systemd_reload_state(properties: &BTreeMap<String, String>) -> Result<()> {
    if !systemd_state_is_quiescent(properties) {
        bail!(
            "systemd reload recovery requires inactive/failed state with no main or control process"
        );
    }
    Ok(())
}

fn systemd_state_is_quiescent(properties: &BTreeMap<String, String>) -> bool {
    matches!(
        properties.get("ActiveState").map(String::as_str),
        Some("inactive" | "failed")
    ) && matches!(
        properties.get("SubState").map(String::as_str),
        Some("dead" | "failed")
    ) && properties.get("MainPID").map(String::as_str) == Some("0")
        && properties.get("ControlPID").map(String::as_str) == Some("0")
}

fn systemd_state_is_running(properties: &BTreeMap<String, String>) -> bool {
    properties.get("ActiveState").map(String::as_str) == Some("active")
        && properties.get("SubState").map(String::as_str) == Some("running")
        && properties
            .get("MainPID")
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|pid| pid > 0)
        && properties.get("ControlPID").map(String::as_str) == Some("0")
}

fn validate_stale_systemd_kata_launch(
    binary: &Path,
    argv: &[String],
    working_directory: &str,
    current: Option<&OwnedServiceDefinition>,
    fixed_definition: &Path,
    fixed_environment_directory: &Path,
) -> Result<()> {
    if argv.len() != 18 || argv.first().map(Path::new) != Some(binary) {
        bail!("stale systemd ExecStart is not a structurally exact Kata trampoline command");
    }
    let expected_flags = [
        (1, "__service-exec"),
        (2, "--definition"),
        (4, "--environment"),
        (6, "--config"),
        (8, "--expected-binary-digest"),
        (10, "--expected-config-digest"),
        (12, "--expected-environment-digest"),
        (14, "--expected-data-directory"),
        (16, "--expected-directory-id"),
    ];
    if expected_flags
        .iter()
        .any(|(index, expected)| argv.get(*index).map(String::as_str) != Some(*expected))
    {
        bail!("stale systemd ExecStart is not a structurally exact Kata trampoline command");
    }
    let expected_definition = current.map_or_else(
        || fixed_definition.to_path_buf(),
        |current| current.spec.definition_path.clone(),
    );
    if Path::new(&argv[3]) != expected_definition {
        bail!("stale systemd ExecStart does not target Kata's fixed definition path");
    }
    let config = Path::new(&argv[7]);
    if !binary.is_absolute()
        || !config.is_absolute()
        || config.parent() != Some(Path::new(working_directory))
        || !Path::new(&argv[15]).is_absolute()
        || argv[17].is_empty()
    {
        bail!(
            "stale systemd ExecStart contains invalid absolute-path or directory identity fields"
        );
    }
    for digest in [&argv[9], &argv[11], &argv[13]] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("stale systemd ExecStart contains a noncanonical digest");
        }
    }
    let environment_directory = current.map_or_else(
        || fixed_environment_directory.to_path_buf(),
        |current| {
            current
                .spec
                .environment_path
                .parent()
                .expect("owned environment snapshot has a parent")
                .to_path_buf()
        },
    );
    let expected_environment = environment_snapshot_path(&environment_directory, &argv[13])?;
    if Path::new(&argv[5]) != expected_environment {
        bail!(
            "stale systemd ExecStart environment is not content-addressed under Kata's owner-only snapshot directory"
        );
    }
    let environment = read_installed_service_environment_utf8(&expected_environment)?;
    if blake3_bytes(environment.as_bytes()).to_string() != argv[13] {
        bail!("stale systemd ExecStart environment snapshot digest does not match");
    }
    let parsed_environment: BTreeMap<String, String> = serde_json::from_str(&environment)
        .context("parsing stale systemd Kata environment snapshot")?;
    if serialize_service_environment(&parsed_environment)? != environment {
        bail!("stale systemd ExecStart environment snapshot is not canonical");
    }
    if current_binary_digest(binary)? != argv[9] {
        bail!("stale systemd ExecStart binary digest no longer matches its executable");
    }
    if current_config_digest(config)? != argv[11] {
        bail!("stale systemd ExecStart config digest no longer matches its config");
    }
    let data_directory = Path::new(&argv[15]);
    let identity = inspect_identity(data_directory)?
        .ok_or_else(|| anyhow::anyhow!("stale systemd ExecStart data directory has no identity"))?;
    if identity.mode != crate::data_dir_lock::MainMode::Installed
        || identity.directory_id != argv[17]
    {
        bail!("stale systemd ExecStart data-directory identity no longer matches");
    }
    Ok(())
}

fn parse_systemd_exec_start(value: &str) -> Result<(PathBuf, Vec<String>)> {
    let rendered = value.trim();
    if !rendered.starts_with('{')
        || !rendered.ends_with('}')
        || rendered.matches('{').count() != 1
        || rendered.matches('}').count() != 1
    {
        bail!("systemd ExecStart is not exactly one complete command");
    }
    let fields = rendered[1..rendered.len() - 1]
        .split(';')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let expected_keys = [
        "path",
        "argv[]",
        "ignore_errors",
        "start_time",
        "stop_time",
        "pid",
        "code",
        "status",
    ];
    if fields.len() != expected_keys.len() {
        bail!("systemd ExecStart field cardinality drifted");
    }
    let mut values = BTreeMap::new();
    for (field, expected_key) in fields.into_iter().zip(expected_keys) {
        let (key, raw) = field
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("malformed systemd ExecStart field {field:?}"))?;
        if key.trim() != expected_key || raw.trim().is_empty() {
            bail!("systemd ExecStart field order or shape drifted at {expected_key}");
        }
        values.insert(key.trim(), raw.trim());
    }
    if values.get("ignore_errors").copied() != Some("no") {
        bail!("systemd ExecStart must have ignore_errors=no");
    }
    let path_words = split_systemd_show_words(values["path"])?;
    let argv = split_systemd_show_words(values["argv[]"])?;
    if path_words.len() != 1 || argv.is_empty() || argv.first() != path_words.first() {
        bail!("systemd ExecStart path and argv identity disagree");
    }
    let path = PathBuf::from(&path_words[0]);
    if !path.is_absolute() {
        bail!("systemd ExecStart program path is not absolute");
    }
    Ok((path, argv))
}

fn split_systemd_show_words(value: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        match quote {
            Some(delimiter) if character == delimiter => quote = None,
            None if character == '\'' || character == '"' => quote = Some(character),
            None if character.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if escaped || quote.is_some() {
        bail!("systemd ExecStart contains unfinished quoting or escaping");
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

fn classify_launchd_manager(
    output: &Output,
    uid: &str,
    owned: Option<&OwnedServiceDefinition>,
) -> Result<ManagerAuthority> {
    if !output.status.success() {
        return classify_launchd_print_result(output, uid).and_then(|loaded| {
            if loaded {
                bail!("launchd loaded-state classifier contradicted command status");
            }
            Ok(ManagerAuthority::Absent)
        });
    }
    let owned = owned.ok_or_else(|| {
        anyhow::anyhow!(
            "launchd has a loaded {LAUNCHD_LABEL} object but no exact Kata-owned definition exists at the fixed path"
        )
    })?;
    let text = std::str::from_utf8(&output.stdout)
        .context("launchd identity probe returned non-UTF-8 output")?;
    let exact_line_value = |prefix: &str| -> Result<String> {
        let values = text
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix(prefix).map(str::to_string))
            .collect::<Vec<_>>();
        if values.len() != 1 || values[0].is_empty() {
            bail!("launchd identity output did not contain exactly one {prefix:?} line");
        }
        Ok(values[0].clone())
    };
    if Path::new(&exact_line_value("path = ")?) != owned.spec.definition_path {
        bail!("launchd loaded plist path differs from the exact Kata-owned definition");
    }
    if Path::new(&exact_line_value("program = ")?) != owned.spec.binary {
        bail!("launchd loaded program differs from the exact Kata-owned definition");
    }
    let lines = text.lines().map(str::trim).collect::<Vec<_>>();
    let starts = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == "arguments = {").then_some(index))
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        bail!("launchd identity output did not contain exactly one arguments block");
    }
    let start = starts[0] + 1;
    let end = lines[start..]
        .iter()
        .position(|line| *line == "}")
        .map(|offset| start + offset)
        .ok_or_else(|| anyhow::anyhow!("launchd arguments block is unterminated"))?;
    let arguments = lines[start..end]
        .iter()
        .map(|line| (*line).to_string())
        .collect::<Vec<_>>();
    if arguments != service_exec_command(&owned.spec) {
        bail!("launchd loaded arguments differ from the exact Kata-owned definition");
    }
    Ok(ManagerAuthority::ExactMatching)
}

fn launchd_service_is_loaded() -> Result<bool> {
    launchd_service_is_loaded_with_timeout(MANAGER_PROBE_TIMEOUT)
}

fn launchd_service_is_loaded_with_timeout(timeout: std::time::Duration) -> Result<bool> {
    let uid = current_uid();
    let output = run_bounded_output(
        &[
            LAUNCHCTL_PATH.to_string(),
            "print".to_string(),
            format!("gui/{uid}/{LAUNCHD_LABEL}"),
        ],
        timeout,
        MANAGER_OUTPUT_BYTES,
        "launchd loaded-state probe",
    )?;
    classify_launchd_print_result(&output, &uid)
}

fn classify_launchd_print_result(output: &Output, uid: &str) -> Result<bool> {
    if output.status.success() {
        return Ok(true);
    }
    let lines = manager_output_lines(output);
    let absent_prefix = format!("could not find service \"{LAUNCHD_LABEL}\"");
    let domain_absent = format!("{absent_prefix} in domain for user gui: {uid}");
    let label_absent = lines == [absent_prefix.as_str()]
        || lines == [domain_absent.as_str()]
        || lines == ["bad request.", domain_absent.as_str()];
    if label_absent {
        Ok(false)
    } else {
        bail!(
            "could not determine whether launchd job {LAUNCHD_LABEL} is loaded ({}): {}",
            output.status,
            lines.join("\n")
        )
    }
}

fn manager_output_lines(output: &Output) -> Vec<String> {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .lines()
    .map(str::trim)
    .filter(|line| !line.is_empty())
    .map(str::to_ascii_lowercase)
    .collect()
}

fn forward_output(output: &Output) {
    if !output.stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
}

fn is_idempotent_manager_result(
    platform: ServicePlatform,
    action: ServiceAction,
    output: &Output,
) -> Result<bool> {
    if action == ServiceAction::Status {
        if platform == ServicePlatform::LaunchdAppleSilicon {
            return classify_launchd_print_result(output, &current_uid()).map(|loaded| !loaded);
        }
        // systemd uses non-zero for inactive/absent. Bind every accepted form
        // to Kata's exact unit so a bus/domain/other-unit error cannot masquerade
        // as a harmless stopped state.
        let lines = manager_output_lines(output);
        if lines == ["unit kata.service could not be found."]
            || lines == ["unit kata.service could not be found"]
        {
            return Ok(true);
        }
        let header_names_unit = lines.first().is_some_and(|line| {
            line.split_whitespace()
                .any(|word| word == SYSTEMD_UNIT_NAME)
        });
        let has_typed_state = lines.iter().any(|line| {
            let line = line.trim_start_matches(['○', '●', '×', ' ']);
            [
                "active: failed",
                "active: activating",
                "active: deactivating",
                "active: inactive (dead)",
            ]
            .iter()
            .any(|state| line.starts_with(state))
        });
        return Ok(header_names_unit && has_typed_state);
    }
    let lines = manager_output_lines(output);
    Ok(match (platform, action) {
        (ServicePlatform::SystemdUser, ServiceAction::Stop | ServiceAction::Uninstall) => {
            lines.len() == 1
                && [
                    "unit kata.service not loaded.",
                    "unit kata.service not loaded",
                    "unit kata.service not found.",
                    "unit kata.service not found",
                    "failed to stop kata.service: unit kata.service not loaded.",
                    "failed to disable unit: unit file kata.service does not exist.",
                    "unit file kata.service does not exist.",
                    "unit kata.service does not exist.",
                ]
                .contains(&lines[0].as_str())
        }
        _ => false,
    })
}

fn absolute_existing(path: &Path, label: &str) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("resolving {label} {}", path.display()))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving current directory")?
            .join(path)
    };
    if absolute.exists() {
        absolute
            .canonicalize()
            .with_context(|| format!("resolving data directory {}", absolute.display()))
    } else {
        Ok(lexically_normalize(&absolute))
    }
}

fn lexically_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn home_dir() -> Result<PathBuf> {
    Ok(effective_owner_home()?)
}

pub(crate) fn require_unprivileged_service_owner() -> Result<()> {
    require_non_root_service_owner(nix::unistd::geteuid().as_raw())
}

pub(crate) fn require_ambient_owner_home() -> Result<()> {
    let owner_home = effective_owner_home()?;
    require_matching_home(&owner_home, std::env::var_os("HOME").as_deref())
}

fn require_matching_home(owner_home: &Path, ambient: Option<&std::ffi::OsStr>) -> Result<()> {
    let ambient = ambient.ok_or_else(|| {
        anyhow::anyhow!(
            "HOME is unset; installed-main config path expansion must use the effective owner's account home {}",
            owner_home.display()
        )
    })?;
    let ambient = Path::new(ambient);
    if ambient != owner_home {
        bail!(
            "HOME {} does not match the effective owner's account home {}; refusing installed-main config parsing because tilde-expanded paths would diverge across service startup",
            ambient.display(),
            owner_home.display()
        );
    }
    Ok(())
}

fn require_non_root_service_owner(uid: u32) -> Result<()> {
    if uid == 0 {
        bail!(
            "Kata's installed main is a per-user service and refuses effective uid 0; run it as the intended non-root owner"
        );
    }
    Ok(())
}

fn current_uid() -> String {
    nix::unistd::geteuid().as_raw().to_string()
}

fn require_utf8_path(path: &Path, label: &str) -> Result<()> {
    let Some(text) = path.to_str() else {
        bail!(
            "{label} {} is not valid UTF-8 and cannot be represented exactly in a systemd unit or launchd plist",
            path.display()
        );
    };
    if text.chars().any(|character| {
        !is_xml_10_character(character)
            || character.is_ascii_control()
            || matches!(character, ';' | '{' | '}' | '\\' | '\'' | '"')
    }) {
        bail!(
            "{label} {} contains control or native-manager syntax that Kata cannot round-trip exactly",
            path.display()
        );
    }
    Ok(())
}

fn is_xml_10_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
        || ('\u{20}'..='\u{D7FF}').contains(&character)
        || ('\u{E000}'..='\u{FFFD}').contains(&character)
        || ('\u{10000}'..='\u{10FFFF}').contains(&character)
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            || cause.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT)
    })
}

fn is_allowed_environment_key(key: &str) -> bool {
    matches!(
        key,
        "HOME"
            | "PATH"
            | "XDG_RUNTIME_DIR"
            | "XDG_STATE_HOME"
            | "RUST_LOG"
            | "SSL_CERT_FILE"
            | "SSL_CERT_DIR"
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "NO_PROXY"
            | "KATA_API_TOKEN"
            | "KATA_LOG"
            | "KATA_RERUN_REPEATABILITY"
            | "KATA_STDLIB_DIR"
    ) || kata_worker::NODE_PROVIDER_ENV_KEYS.contains(&key)
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn systemd_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
            .replace('%', "%%")
    )
}

/// Render a path-valued systemd directive. Unlike `ExecStart=`, directives
/// such as `WorkingDirectory=` do not use command-line quote removal, so a
/// double-quoted path is interpreted literally. Encode unsafe bytes with the
/// unit-file escape syntax and neutralize `%` specifiers instead.
fn systemd_path_value(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'_' | b'-' | b'.' => {
                rendered.push(char::from(byte));
            }
            b'%' => rendered.push_str("%%"),
            _ => write!(&mut rendered, "\\x{byte:02x}").expect("writing to a String cannot fail"),
        }
    }
    rendered
}

fn xml_escape_path(path: &Path) -> String {
    xml_escape(&path.to_string_lossy())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt};
    use std::os::unix::process::ExitStatusExt;

    use tempfile::TempDir as RawTempDir;

    use super::*;

    struct TempDir(RawTempDir);

    impl TempDir {
        fn new() -> std::io::Result<Self> {
            let directory = RawTempDir::new()?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            Ok(Self(directory))
        }

        fn path(&self) -> &Path {
            self.0.path()
        }
    }

    fn write_test_definition(path: &Path, text: &str) -> Result<()> {
        let expected = ExistingOwnerOnlyPublication::open(
            path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test service definition",
        )
        .ok();
        write_definition_atomically(path, text, expected.as_ref())
    }

    fn failed_output(stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(5 << 8),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn applied_service_entrypoint_signatures_require_typed_authority() {
        let _: for<'lease> fn(
            ServicePlatform,
            InstalledServiceLifecycleAction,
            &'lease InstalledLifecycleOperationLease,
        ) -> Result<ServicePlan> = apply_installed_lifecycle;
        let _: for<'spec, 'lease> fn(
            &'spec ServiceSpec,
            InstalledServicePublicationPermit<'lease>,
        ) -> Result<ServicePlan> = apply_install;
        let _: for<'lease> fn(
            ServicePlatform,
            InstalledServicePublicationPermit<'lease>,
        ) -> Result<ServicePlan> = apply_uninstall;
    }

    #[test]
    fn mismatched_service_authority_refuses_before_manager_or_publication_access() {
        let plan = |action| ServicePlan {
            action,
            definition_path: PathBuf::from("/must-not-be-inspected/kata.service"),
            definition: String::new(),
            commands: Vec::new(),
            changed: false,
            environment_path: PathBuf::from("/must-not-be-inspected/environment"),
            environment_directory: PathBuf::from("/must-not-be-inspected"),
            environment_definition: String::new(),
        };
        let refuse = |plan, authority| {
            execute_plan_with_authority(
                ServicePlatform::SystemdUser,
                plan,
                authority,
                |_, _, _| panic!("authority mismatch reached native manager"),
                |_, _| panic!("authority mismatch inspected native manager"),
                |_, _| panic!("authority mismatch ran stopped verification"),
            )
            .expect_err("mismatched authority must fail closed")
        };

        let root = TempDir::new().unwrap();
        let lifecycle = InstalledLifecycleOperationLease::acquire_at_for_test(
            &root.path().join("authority/lifecycle-operation.lock"),
        )
        .unwrap();
        let lifecycle_error = refuse(
            plan(ServiceAction::Install),
            ServiceExecutionAuthority::Lifecycle(&lifecycle),
        );
        assert!(
            format!("{lifecycle_error:#}").contains("does not authorize Install"),
            "{lifecycle_error:#}"
        );

        let discovery = InstalledDiscoveryLease::acquire_at_for_test(
            &root.path().join("authority/discovery.lock"),
        )
        .unwrap();
        let permit = InstalledServicePublicationPermit::new(&lifecycle, &discovery);
        let publication_error = refuse(
            plan(ServiceAction::Start),
            ServiceExecutionAuthority::Publication(permit),
        );
        assert!(
            format!("{publication_error:#}").contains("does not authorize Start"),
            "{publication_error:#}"
        );
    }

    #[test]
    fn manager_absence_is_idempotent_but_unrelated_failures_are_not() {
        assert!(
            is_idempotent_manager_result(
                ServicePlatform::SystemdUser,
                ServiceAction::Stop,
                &failed_output("Unit kata.service not loaded.")
            )
            .unwrap()
        );
        assert!(
            !is_idempotent_manager_result(
                ServicePlatform::SystemdUser,
                ServiceAction::Start,
                &failed_output("permission denied")
            )
            .unwrap()
        );
        assert!(
            is_idempotent_manager_result(
                ServicePlatform::SystemdUser,
                ServiceAction::Status,
                &failed_output("kata.service - Kata\nActive: failed (Result: exit-code)")
            )
            .unwrap()
        );
        assert!(
            is_idempotent_manager_result(
                ServicePlatform::SystemdUser,
                ServiceAction::Status,
                &failed_output("kata.service - Kata\nActive: activating (auto-restart)")
            )
            .unwrap()
        );
        assert!(
            !is_idempotent_manager_result(
                ServicePlatform::SystemdUser,
                ServiceAction::Status,
                &failed_output("Failed to connect to bus: permission denied")
            )
            .unwrap()
        );
        assert!(
            !is_idempotent_manager_result(
                ServicePlatform::SystemdUser,
                ServiceAction::Status,
                &failed_output("other.service: Active: failed")
            )
            .unwrap()
        );
        assert!(
            !is_idempotent_manager_result(
                ServicePlatform::SystemdUser,
                ServiceAction::Stop,
                &failed_output("Failed to connect to bus: Unit kata.service not loaded.")
            )
            .unwrap()
        );
    }

    #[test]
    fn launchd_absence_classifier_binds_the_exact_label_and_gui_uid() {
        let uid = current_uid();
        assert!(
            !classify_launchd_print_result(
                &failed_output(&format!(
                    "Could not find service \"{LAUNCHD_LABEL}\" in domain for user gui: {uid}"
                )),
                &uid,
            )
            .unwrap()
        );
        for unrelated in [
            "GUI domain not found",
            "Could not find service \"other.label\"",
            "Operation not permitted",
            "No such process",
            "Could not find service \"sh.kata.main\"\nGUI domain not found",
            "Could not find service \"sh.kata.main\" in domain for user gui: 501\nOperation not permitted",
        ] {
            let error = classify_launchd_print_result(&failed_output(unrelated), &uid)
                .expect_err("unknown launchd failure must not prove absence");
            assert!(
                format!("{error:#}").contains("could not determine whether launchd job"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn service_manager_commands_use_platform_absolute_binaries() {
        let definition = Path::new("/tmp/sh.kata.main.plist");
        for action in [
            ServiceAction::Install,
            ServiceAction::Start,
            ServiceAction::Stop,
            ServiceAction::Restart,
            ServiceAction::Status,
            ServiceAction::Logs,
            ServiceAction::Uninstall,
        ] {
            for command in commands_for(ServicePlatform::SystemdUser, action, definition) {
                assert!(
                    command[0] == SYSTEMCTL_PATH || command[0] == JOURNALCTL_PATH,
                    "{command:?}"
                );
            }
            for command in commands_for(ServicePlatform::LaunchdAppleSilicon, action, definition) {
                assert!(
                    command[0] == LAUNCHCTL_PATH || command[0] == MACOS_LOG_PATH,
                    "{command:?}"
                );
            }
        }
    }

    #[test]
    fn logs_run_after_definition_is_absent_or_corrupt_without_manager_probe() {
        for corrupt in [false, true] {
            let temp = TempDir::new().unwrap();
            let definition = temp.path().join("kata.service");
            let environment_directory = temp.path().join("service-environments");
            if corrupt {
                std::fs::write(&definition, b"not a Kata service definition").unwrap();
            }
            let plan = plan_installed_with_paths(
                ServicePlatform::SystemdUser,
                ServiceAction::Logs,
                definition.clone(),
                environment_directory,
            )
            .expect("fixed host-log query must not inspect the definition");
            let calls = Cell::new(0_usize);
            execute_plan_with_manager_probe_and_stopped_verifier(
                ServicePlatform::SystemdUser,
                plan,
                true,
                |command, _, action| {
                    assert_eq!(action, ServiceAction::Logs);
                    assert_eq!(
                        command,
                        args(&[
                            JOURNALCTL_PATH,
                            "--user",
                            "-u",
                            SYSTEMD_UNIT_NAME,
                            "--no-pager",
                            "-n",
                            "200",
                        ])
                    );
                    calls.set(calls.get() + 1);
                    Ok(())
                },
                |_, _| panic!("logs must not inspect native-manager authority"),
                |_, _| panic!("logs must not run stopped-main verification"),
            )
            .unwrap();
            assert_eq!(calls.get(), 1);
            assert_eq!(definition.exists(), corrupt);
        }
    }

    #[test]
    fn logs_refuse_a_noncanonical_command_plan() {
        let temp = TempDir::new().unwrap();
        let mut plan = logs_plan(
            ServicePlatform::LaunchdAppleSilicon,
            temp.path().join("sh.kata.main.plist"),
            temp.path().join("service-environments"),
        );
        plan.commands = vec![args(&["/usr/bin/true"])];
        let error = execute_plan_with_manager_probe_and_stopped_verifier(
            ServicePlatform::LaunchdAppleSilicon,
            plan,
            true,
            |_, _, _| panic!("counterfeit log command must not run"),
            |_, _| panic!("logs must not inspect native-manager authority"),
            |_, _| panic!("logs must not run stopped-main verification"),
        )
        .expect_err("logs must stay bound to the fixed bounded host query");
        assert!(format!("{error:#}").contains("exact bounded host-log query"));
    }

    #[test]
    fn native_manager_environment_is_deterministic_without_clearing_session_bus() {
        let mut command = Command::new("/usr/bin/true");
        command.env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/owner/session-bus");
        configure_native_manager_environment(&mut command);
        let environment = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(environment.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(environment.get("LANG").map(String::as_str), Some("C"));
        assert_eq!(
            environment.get("SYSTEMD_COLORS").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            environment.get("SYSTEMD_PAGER").map(String::as_str),
            Some("cat")
        );
        assert_eq!(environment.get("PAGER").map(String::as_str), Some("cat"));
        assert_eq!(
            environment
                .get("DBUS_SESSION_BUS_ADDRESS")
                .map(String::as_str),
            Some("unix:path=/owner/session-bus")
        );
    }

    #[test]
    fn publication_parent_must_be_owner_controlled_but_may_be_0755() {
        let temp = TempDir::new().unwrap();
        let parent = temp.path().join("definitions");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let first = parent.join("kata.service");
        write_test_definition(&first, "owned").unwrap();
        assert_eq!(std::fs::read_to_string(first).unwrap(), "owned");

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let error = write_test_definition(&parent.join("foreign.service"), "unsafe")
            .expect_err("group/world-writable publication parent must fail closed");
        assert!(format!("{error:#}").contains("not group/world writable"));
    }

    #[test]
    fn native_manager_path_grammar_rejects_unroundtrippable_syntax() {
        require_utf8_path(
            Path::new("/owner/Application Support/kata%main"),
            "safe path",
        )
        .unwrap();
        for value in [
            "/owner/kata\nmain",
            "/owner/kata;main",
            "/owner/kata{main}",
            "/owner/kata\\main",
            "/owner/kata\"main",
            "/owner/kata'main",
        ] {
            let error = require_utf8_path(Path::new(value), "test path")
                .expect_err("unsupported native-manager grammar must fail before publication");
            assert!(format!("{error:#}").contains("cannot round-trip exactly"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_manager_runner_times_out_and_reaps_its_process_group() {
        assert_manager_timeout_reaps_ready_descendant("");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_manager_runner_times_out_without_fixture_readiness() {
        let started = std::time::Instant::now();
        let error = run_bounded_output(
            &args(&["/bin/sh", "-c", "exec sleep 30"]),
            std::time::Duration::from_millis(200),
            4096,
            "hanging manager before any readiness signal",
        )
        .expect_err("the production runner must not wait for fixture readiness");
        assert_eq!(
            error.downcast_ref::<BoundedCommandFailure>().unwrap().kind,
            BoundedCommandFailureKind::Timeout
        );
        // Generous on purpose (it includes `sh` start-up on a loaded host); still far
        // under the child's `sleep 30`, which is what waiting on it would cost.
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_manager_timeout_fixture_waits_for_slow_pid_publication() {
        assert_manager_timeout_reaps_ready_descendant("sleep 0.3;");
    }

    #[cfg(unix)]
    fn assert_manager_timeout_reaps_ready_descendant(before_pid: &str) {
        let temp = TempDir::new().unwrap();
        let descendant_pid = temp.path().join("descendant.pid");
        let script = format!(
            "sleep 30 & pid=$!; {{ {before_pid} echo $pid; }} > {}; wait",
            descendant_pid.display()
        );
        let argv = ["/bin/sh".to_string(), "-c".to_string(), script];
        let mut child = spawn_bounded_command(&argv, "hanging fake manager").unwrap();
        // Establish the descendant before testing the 200 ms collection budget.
        // Publication can be interrupted between shell redirection and echo;
        // an empty file is not readiness and host scheduling is not an oracle.
        let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let pid = loop {
            if let Some(pid) = std::fs::read_to_string(&descendant_pid)
                .ok()
                .and_then(|value| value.trim().parse::<i32>().ok())
                .filter(|pid| *pid > 0)
            {
                break pid;
            }
            if std::time::Instant::now() >= ready_deadline {
                kill_and_reap_process_group(&mut child).unwrap();
                panic!("fake manager did not publish its descendant PID");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let started = std::time::Instant::now();
        let error = collect_bounded_output(
            child,
            &argv,
            std::time::Duration::from_millis(200),
            4096,
            "hanging fake manager",
        )
        .expect_err("a hung manager must reach an internal deadline");
        let typed = error
            .downcast_ref::<BoundedCommandFailure>()
            .expect("timeout remains a typed failure");
        assert_eq!(typed.kind, BoundedCommandFailureKind::Timeout);
        // Generous on purpose for a loaded host; still far under the descendant's
        // `sleep 30`, which is what joining its inherited pipe would cost.
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
                Err(nix::errno::Errno::ESRCH) => break,
                _ if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => {
                    panic!("manager descendant {pid} survived process-group reap: {result:?}")
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_manager_runner_kills_output_flood_at_combined_ceiling() {
        let started = std::time::Instant::now();
        let error = run_bounded_output(
            &args(&["/bin/sh", "-c", "while :; do printf '0123456789'; done"]),
            std::time::Duration::from_secs(30),
            1024,
            "oversized fake manager",
        )
        .expect_err("unbounded manager output must be terminated");
        let typed = error
            .downcast_ref::<BoundedCommandFailure>()
            .expect("output overflow remains a typed failure");
        assert_eq!(typed.kind, BoundedCommandFailureKind::OutputLimit);
        // Generous on purpose for `sh` start-up on a loaded host; still under the
        // 30 s deadline, so the ceiling, not the deadline, ended the flood.
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_manager_runner_sweeps_pipe_inheriting_descendant_after_parent_exit() {
        let temp = TempDir::new().unwrap();
        let descendant_pid = temp.path().join("descendant.pid");
        let script = format!("sleep 30 & echo $! > {}; exit 0", descendant_pid.display());
        let started = std::time::Instant::now();
        let output = run_bounded_output(
            &["/bin/sh".to_string(), "-c".to_string(), script],
            std::time::Duration::from_secs(20),
            4096,
            "forking fake manager",
        )
        .expect("direct-child success must not join an inherited pipe forever");
        assert!(output.status.success());
        // Generous on purpose for `sh` start-up on a loaded host; still under the
        // 20 s deadline and the descendant's `sleep 30`, either of which joining
        // the inherited pipe would have waited out.
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        let pid = std::fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
                Err(nix::errno::Errno::ESRCH) => break,
                _ if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => panic!("pipe-inheriting descendant {pid} survived sweep: {result:?}"),
            }
        }
    }

    #[test]
    fn product_readiness_budget_survives_contended_durable_store_open() {
        assert_eq!(
            PRODUCT_READY_TIMEOUT,
            std::time::Duration::from_secs(120),
            "installed-main startup observed durable-store contention beyond the old 20s bound"
        );
    }

    #[test]
    fn restart_cannot_erase_an_unverifiable_prior_generation() {
        let calls = Cell::new(0);
        let error = restart_generation_with(ServiceAction::Restart, |timeout| {
            assert_eq!(timeout, MANAGER_PROBE_TIMEOUT);
            calls.set(calls.get() + 1);
            anyhow::bail!("descriptor/live generation mismatch")
        })
        .expect_err("restart must not silently downgrade new-generation proof");
        let message = format!("{error:#}");
        assert!(message.contains("verified live prior"), "{message}");
        assert!(
            message.contains("descriptor/live generation mismatch"),
            "{message}"
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            restart_generation_with(ServiceAction::Start, |_| {
                panic!("start does not read a prior generation")
            })
            .unwrap(),
            None
        );

        let mut live = running_status_for(&drift_fixture().1);
        live.process_generation = Some("verified-live-generation".to_string());
        assert_eq!(
            restart_generation_with(ServiceAction::Restart, |_| Ok(live)).unwrap(),
            Some("verified-live-generation".to_string())
        );
    }

    #[test]
    fn stopped_verification_waits_for_manager_and_discovery_quiescence() {
        let manager_checks = Cell::new(0);
        let discovery_checks = Cell::new(0);
        wait_for_service_stopped(
            std::time::Duration::from_secs(1),
            std::time::Duration::ZERO,
            |_| {
                manager_checks.set(manager_checks.get() + 1);
                Ok(manager_checks.get() >= 2)
            },
            || {
                discovery_checks.set(discovery_checks.get() + 1);
                Ok(discovery_checks.get() >= 2)
            },
        )
        .expect("stop completes only after both boundaries are quiescent");
        assert!(manager_checks.get() >= 3);
        assert_eq!(discovery_checks.get(), 2);
    }

    #[test]
    fn product_readiness_wait_returns_immediately_when_manager_dies() {
        let manager_checks = Cell::new(0);
        let product_checks = Cell::new(0);
        let started = std::time::Instant::now();
        let error = wait_for_product_ready(
            PRODUCT_READY_TIMEOUT,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            |_| {
                manager_checks.set(manager_checks.get() + 1);
                anyhow::bail!("manager entered failed state")
            },
            |_| {
                product_checks.set(product_checks.get() + 1);
                Ok(Some("not ready".to_string()))
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("manager entered failed state"));
        assert_eq!(manager_checks.get(), 1);
        assert_eq!(product_checks.get(), 0);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn product_readiness_wait_accepts_only_verified_product_identity() {
        let product_checks = Cell::new(0);
        wait_for_product_ready(
            PRODUCT_READY_TIMEOUT,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            |_| Ok(()),
            |_| {
                product_checks.set(product_checks.get() + 1);
                Ok((product_checks.get() < 3).then(|| "identity not ready".to_string()))
            },
        )
        .unwrap();
        assert_eq!(product_checks.get(), 3);
    }

    #[test]
    fn product_readiness_timeout_remains_actionable() {
        let error = wait_for_product_ready(
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            |_| Ok(()),
            |_| Ok(Some("attachment unavailable".to_string())),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("verified product readiness"));
        assert!(message.contains("within 0s"));
        assert!(message.contains("kata service status"));
        assert!(message.contains("kata service logs"));
    }

    #[test]
    fn systemd_path_values_are_unquoted_and_escape_spaces_and_specifiers() {
        assert_eq!(
            systemd_path_value("/tmp/Kata Config/%i"),
            "/tmp/Kata\\x20Config/%%i"
        );
    }

    #[test]
    fn atomic_definition_is_owner_only_and_fully_published() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("nested").join("kata.service");
        write_test_definition(&path, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_test_definition(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        assert!(
            std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
    }

    #[test]
    fn definition_replacement_refuses_a_new_inode_and_cleans_its_temporary() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("kata.service");
        write_test_definition(&path, "definition-a").unwrap();
        let expected = ExistingOwnerOnlyPublication::open(
            &path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();

        let replacement = temp.path().join("replacement");
        std::fs::write(&replacement, "definition-b").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let error = write_definition_atomically(&path, "definition-c", Some(&expected))
            .expect_err("a replacement inode must never be overwritten");
        assert!(format!("{error:#}").contains("changed after descriptor adoption"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "definition-b");
        assert!(
            std::fs::read_dir(temp.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(SERVICE_PUBLICATION_ARTIFACT_PREFIX)
            }),
            "failed replacement must clean its adopted temporary"
        );
    }

    #[test]
    fn definition_no_replace_refuses_a_destination_that_appears_during_publication() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("kata.service");
        let hook_path = path.clone();
        inject_pre_no_replace_rename_hook(move || {
            std::fs::write(&hook_path, "competing-definition").unwrap();
            std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        });

        let error = write_definition_atomically(&path, "desired-definition", None)
            .expect_err("service definitions never converge through destination-exists");
        assert!(
            format!("{error:#}").contains("appeared during no-replace publication"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "competing-definition"
        );
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
            Path::new(&entry.unwrap().file_name()).extension() != Some(OsStr::new("tmp"))
        }));
    }

    #[test]
    fn replacement_parent_rebinding_preserves_new_and_rollback_in_retained_parent() {
        let root = TempDir::new().unwrap();
        let canonical_parent = root.path().join("publications");
        let moved_parent = root.path().join("moved-publications");
        std::fs::create_dir(&canonical_parent).unwrap();
        std::fs::set_permissions(&canonical_parent, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let destination = canonical_parent.join("kata.service");
        write_test_definition(&destination, "old-definition").unwrap();
        let expected = ExistingOwnerOnlyPublication::open(
            &destination,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        let expected_identity = expected.identity();
        let mut temporary = OwnerOnlyPublicationTemp::create(
            &canonical_parent,
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        temporary
            .file_mut()
            .write_all(b"desired-definition")
            .unwrap();
        temporary.sync_contents().unwrap();

        let hook_canonical_parent = canonical_parent.clone();
        let hook_moved_parent = moved_parent.clone();
        inject_post_replacement_rename_hook(move || {
            std::fs::rename(&hook_canonical_parent, &hook_moved_parent).unwrap();
            std::fs::create_dir(&hook_canonical_parent).unwrap();
            std::fs::set_permissions(
                &hook_canonical_parent,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            write_test_definition(
                &hook_canonical_parent.join("sentinel"),
                "replacement-parent-sentinel",
            )
            .unwrap();
        });

        let error = match temporary.publish_replace(&destination, &expected).unwrap() {
            OwnerOnlyReplacementPublication::RecoveryRequired(error) => error,
            OwnerOnlyReplacementPublication::Published { .. } => {
                panic!("a replacement committed outside the canonical parent cannot succeed")
            }
        };
        assert!(
            format!("{error:#}").contains("canonical directory binding changed"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read_to_string(canonical_parent.join("sentinel")).unwrap(),
            "replacement-parent-sentinel"
        );
        assert!(!destination.exists());
        assert_eq!(
            std::fs::read_to_string(moved_parent.join("kata.service")).unwrap(),
            "desired-definition"
        );
        let rollbacks = std::fs::read_dir(&moved_parent)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.path().extension() == Some(OsStr::new("rollback")))
            .collect::<Vec<_>>();
        assert_eq!(rollbacks.len(), 1, "the exact prior rollback remains");
        assert_eq!(
            std::fs::read_to_string(rollbacks[0].path()).unwrap(),
            "old-definition"
        );
        assert_eq!(
            stable_publication_identity(
                capture_owner_only_publication_identity(
                    &rollbacks[0].path(),
                    MAX_SERVICE_DEFINITION_BYTES,
                    "test definition rollback",
                )
                .unwrap()
            ),
            stable_publication_identity(expected_identity)
        );
    }

    #[test]
    fn definition_replacement_parent_sync_failure_is_truthful_and_recoverable() {
        let (_temp, mut spec, plan) = drift_fixture();
        spec.binary_version = "replacement-version".to_string();
        let desired = spec.render();
        assert_ne!(desired, plan.definition);
        let expected = ExistingOwnerOnlyPublication::open(
            &plan.definition_path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        let expected_identity = expected.identity();
        inject_next_replacement_parent_sync_failure(|| {});

        let error = write_definition_atomically(&plan.definition_path, &desired, Some(&expected))
            .expect_err("failed replacement parent sync cannot report a durable commit");
        assert!(
            format!("{error:#}")
                .contains("injected replacement service definition parent-directory sync failure"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&plan.definition_path).unwrap(),
            desired,
            "the committed fixed publication remains available to exact recovery"
        );
        let rollbacks = std::fs::read_dir(plan.definition_path.parent().unwrap())
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.path().extension() == Some(OsStr::new("rollback")))
            .collect::<Vec<_>>();
        assert_eq!(rollbacks.len(), 1, "the exact prior rollback remains");
        let rollback = rollbacks[0].path();
        assert_eq!(std::fs::read_to_string(&rollback).unwrap(), plan.definition);
        assert_eq!(
            stable_publication_identity(
                capture_owner_only_publication_identity(
                    &rollback,
                    MAX_SERVICE_DEFINITION_BYTES,
                    "test definition rollback",
                )
                .unwrap()
            ),
            stable_publication_identity(expected_identity),
            "the rollback retains the exact prior publication inode"
        );

        let start_error = plan_installed_with_paths(
            ServicePlatform::LaunchdAppleSilicon,
            ServiceAction::Start,
            plan.definition_path.clone(),
            plan.environment_directory.clone(),
        )
        .expect_err("a preserved replacement rollback must block launchd start planning");
        assert!(
            format!("{start_error:#}").contains("transaction recovery is pending"),
            "{start_error:#}"
        );
        let launch = ServiceExecLaunchIdentity {
            definition: &spec.definition_path,
            binary: &spec.binary,
            environment: &spec.environment_path,
            config: &spec.config,
            working_directory: &spec.working_directory,
            binary_digest: &spec.binary_digest,
            config_digest: &spec.config_digest,
            environment_digest: &spec.environment_digest,
            data_directory: &spec.data_dir,
            directory_id: &spec.data_directory_id,
        };
        let exec_error = validate_current_service_exec_definition(&launch)
            .expect_err("the native trampoline must refuse a pending replacement rollback");
        assert!(
            format!("{exec_error:#}").contains("transaction recovery is pending"),
            "{exec_error:#}"
        );

        assert!(
            !recover_definition_replacement_transaction(&plan.definition_path, Some(&desired),)
                .unwrap(),
            "desired fixed bytes allow recovery to finish the replacement"
        );
        assert!(!rollback.exists());
        assert_eq!(
            std::fs::read_to_string(&plan.definition_path).unwrap(),
            desired
        );
    }

    #[test]
    fn unrelated_shared_directory_entries_do_not_block_start_or_trampoline() {
        let (_temp, spec, plan) = drift_fixture();
        let parent = plan.definition_path.parent().unwrap();
        for index in 0..96 {
            std::fs::write(
                parent.join(format!("unrelated-manager-entry-{index}")),
                b"x",
            )
            .unwrap();
        }

        let planned = plan_installed_with_paths(
            ServicePlatform::SystemdUser,
            ServiceAction::Start,
            plan.definition_path.clone(),
            plan.environment_directory.clone(),
        )
        .expect("unrelated manager files are not Kata recovery transactions");
        assert_eq!(planned.definition, plan.definition);

        let launch = ServiceExecLaunchIdentity {
            definition: &spec.definition_path,
            binary: &spec.binary,
            environment: &spec.environment_path,
            config: &spec.config,
            working_directory: &spec.working_directory,
            binary_digest: &spec.binary_digest,
            config_digest: &spec.config_digest,
            environment_digest: &spec.environment_digest,
            data_directory: &spec.data_dir,
            directory_id: &spec.data_directory_id,
        };
        validate_current_service_exec_definition(&launch)
            .expect("the native trampoline ignores unrelated manager files");
    }

    #[test]
    fn replacement_recovery_bounds_matching_artifacts_not_unrelated_siblings() {
        let (_temp, _spec, plan) = drift_fixture();
        let parent = plan.definition_path.parent().unwrap();
        for index in 0..=4096 {
            std::fs::write(
                parent.join(format!("unrelated-recovery-entry-{index}")),
                b"x",
            )
            .unwrap();
        }

        assert!(
            !recover_definition_replacement_transaction(
                &plan.definition_path,
                Some(&plan.definition),
            )
            .expect("unrelated shared-directory entries do not consume the rollback bound")
        );
    }

    #[test]
    fn replacement_cleanup_pending_blocks_manager_and_retry_reconciles() {
        let (temp, mut spec, _plan) = drift_fixture();
        spec.binary_version = "replacement-cleanup-version".to_string();
        let plan = spec.plan(ServiceAction::Install).unwrap();
        assert!(plan.changed);
        let desired = plan.definition.clone();
        let parent = plan.definition_path.parent().unwrap().to_path_buf();
        let alias = temp.path().join("rollback-hardlink-alias");
        let hook_parent = parent.clone();
        let hook_alias = alias.clone();
        inject_post_replacement_rename_hook(move || {
            let rollback = std::fs::read_dir(&hook_parent)
                .unwrap()
                .map(Result::unwrap)
                .find(|entry| entry.path().extension() == Some(OsStr::new("rollback")))
                .expect("replacement created its rollback")
                .path();
            std::fs::hard_link(rollback, hook_alias).unwrap();
        });

        let manager_calls = Cell::new(0usize);
        let error = execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            plan,
            true,
            |_, _, _| {
                manager_calls.set(manager_calls.get() + 1);
                Ok(())
            },
            |_, _| Ok(ManagerAuthority::ExactMatchingQuiescent),
        )
        .expect_err("deferred rollback cleanup must block manager mutation");
        assert!(
            format!("{error:#}")
                .contains("rollback cleanup durability/reconciliation remains pending"),
            "{error:#}"
        );
        assert_eq!(manager_calls.get(), 0);
        assert_eq!(
            std::fs::read_to_string(&spec.definition_path).unwrap(),
            desired
        );
        assert!(alias.exists());
        assert_eq!(
            std::fs::read_dir(&parent)
                .unwrap()
                .map(Result::unwrap)
                .filter(|entry| entry.path().extension() == Some(OsStr::new("rollback")))
                .count(),
            1
        );

        std::fs::remove_file(&alias).unwrap();
        let retry = spec.plan(ServiceAction::Install).unwrap();
        assert!(!retry.changed);
        execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            retry,
            true,
            |_, _, _| {
                manager_calls.set(manager_calls.get() + 1);
                Ok(())
            },
            |_, _| Ok(ManagerAuthority::ExactMatchingQuiescent),
        )
        .expect("a later applied install reconciles the exact rollback and converges");
        assert_eq!(manager_calls.get(), 1);
        assert_eq!(
            std::fs::read_dir(&parent)
                .unwrap()
                .map(Result::unwrap)
                .filter(|entry| entry.path().extension() == Some(OsStr::new("rollback")))
                .count(),
            0
        );
    }

    #[test]
    fn interrupted_definition_replacement_restores_old_when_fixed_name_is_absent() {
        let (_temp, _owned, plan) = owned_fixture();
        let old_identity = capture_owner_only_publication_identity(
            &plan.definition_path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        let rollback = plan
            .definition_path
            .parent()
            .unwrap()
            .join(replacement_rollback_name(old_identity));
        std::fs::rename(&plan.definition_path, &rollback).unwrap();

        assert!(
            recover_definition_replacement_transaction(
                &plan.definition_path,
                Some(&plan.definition)
            )
            .unwrap(),
            "absence must restore the exact prior definition"
        );
        assert!(!rollback.exists());
        assert_eq!(
            stable_publication_identity(
                capture_owner_only_publication_identity(
                    &plan.definition_path,
                    MAX_SERVICE_DEFINITION_BYTES,
                    "test definition",
                )
                .unwrap()
            ),
            stable_publication_identity(old_identity)
        );
    }

    #[test]
    fn interrupted_definition_replacement_completes_only_for_desired_fixed_bytes() {
        let (_temp, _owned, plan) = owned_fixture();
        let old_identity = capture_owner_only_publication_identity(
            &plan.definition_path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        let rollback = plan
            .definition_path
            .parent()
            .unwrap()
            .join(replacement_rollback_name(old_identity));
        std::fs::rename(&plan.definition_path, &rollback).unwrap();
        write_test_definition(&plan.definition_path, &plan.definition).unwrap();

        assert!(
            !recover_definition_replacement_transaction(
                &plan.definition_path,
                Some(&plan.definition)
            )
            .unwrap()
        );
        assert!(!rollback.exists());

        let second_identity = capture_owner_only_publication_identity(
            &plan.definition_path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        let second_rollback = plan
            .definition_path
            .parent()
            .unwrap()
            .join(replacement_rollback_name(second_identity));
        std::fs::rename(&plan.definition_path, &second_rollback).unwrap();
        write_test_definition(&plan.definition_path, "different owner-only bytes").unwrap();
        let error = recover_definition_replacement_transaction(
            &plan.definition_path,
            Some(&plan.definition),
        )
        .expect_err("non-desired fixed bytes must preserve both publications");
        assert!(format!("{error:#}").contains("preserving both"));
        assert!(second_rollback.exists());
        assert_eq!(
            std::fs::read_to_string(&plan.definition_path).unwrap(),
            "different owner-only bytes"
        );
    }

    #[test]
    fn quarantine_removal_never_unlinks_a_replacement_inode() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("kata.service");
        write_test_definition(&path, "definition-a").unwrap();
        let expected = capture_owner_only_publication_identity(
            &path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();

        let replacement = temp.path().join("replacement");
        std::fs::write(&replacement, "definition-b").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let error = remove_exact_owner_only_publication(
            &path,
            expected,
            MAX_SERVICE_DEFINITION_BYTES,
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            "test definition",
        )
        .expect_err("a replacement inode must be restored, not deleted");
        assert!(format!("{error:#}").contains("refusing deletion"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "definition-b");
    }

    #[test]
    fn conflict_quarantine_is_never_deleted_by_recovery() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("kata.service");
        let replacement_b = temp.path().join("replacement-b");
        let replacement_c = temp.path().join("replacement-c");
        write_test_definition(&path, "definition-a").unwrap();
        write_test_definition(&replacement_b, "definition-b").unwrap();
        write_test_definition(&replacement_c, "definition-c").unwrap();
        let expected = capture_owner_only_publication_identity(
            &path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();

        let hook_path = path.clone();
        inject_pre_publication_removal_rename_hook(move || {
            std::fs::rename(&replacement_b, &hook_path)
                .expect("replacement B wins after the exact inode is held");
        });
        let hook_path = path.clone();
        inject_post_publication_quarantine_hook(move || {
            std::fs::rename(&replacement_c, &hook_path)
                .expect("replacement C wins while B is quarantined");
        });

        let error = remove_exact_owner_only_publication(
            &path,
            expected,
            MAX_SERVICE_DEFINITION_BYTES,
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            "test definition",
        )
        .expect_err("foreign B must be preserved when C prevents its restore");
        assert!(format!("{error:#}").contains("preserved it"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "definition-c");
        let quarantine = std::fs::read_dir(temp.path())
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.path().extension() == Some(OsStr::new("quarantine")))
            .expect("replacement B remains in a typed quarantine")
            .path();
        assert_eq!(
            std::fs::read_to_string(&quarantine).unwrap(),
            "definition-b"
        );

        let error = recover_owner_only_publication_artifacts(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            MAX_SERVICE_PUBLICATION_ARTIFACTS,
            "test definition",
        )
        .expect_err("recovery must fail closed on a foreign conflict quarantine");
        assert!(format!("{error:#}").contains("preserving the conflict"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "definition-c");
        assert_eq!(
            std::fs::read_to_string(&quarantine).unwrap(),
            "definition-b"
        );
    }

    #[test]
    fn conflict_quarantine_counts_toward_recovery_ceiling_before_mutation() {
        let temp = TempDir::new().unwrap();
        let encoded_source = temp.path().join("encoded-source");
        let conflict_source = temp.path().join("conflict-source");
        write_test_definition(&encoded_source, "encoded-publication").unwrap();
        write_test_definition(&conflict_source, "conflicting-publication").unwrap();
        let encoded_identity = capture_owner_only_publication_identity(
            &encoded_source,
            MAX_SERVICE_DEFINITION_BYTES,
            "test encoded publication",
        )
        .unwrap();
        let quarantine = temp.path().join(deletion_quarantine_name(
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            encoded_identity,
        ));
        std::fs::remove_file(encoded_source).unwrap();
        std::fs::rename(conflict_source, &quarantine).unwrap();

        let error = recover_owner_only_publication_artifacts(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            0,
            "test definition",
        )
        .expect_err("a conflict quarantine must count toward the recovery ceiling");
        assert!(
            format!("{error:#}").contains("recovery ceiling"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&quarantine).unwrap(),
            "conflicting-publication",
            "ceiling refusal occurs before inspecting or mutating the conflict"
        );

        let error = recover_owner_only_publication_artifacts(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            MAX_SERVICE_PUBLICATION_ARTIFACTS,
            "test definition",
        )
        .expect_err("normal recovery must identify and preserve the conflict");
        assert!(format!("{error:#}").contains("preserving the conflict"));
        assert_eq!(
            std::fs::read_to_string(&quarantine).unwrap(),
            "conflicting-publication"
        );
    }

    #[test]
    fn matching_cleanup_quarantine_is_recovered_by_encoded_identity() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("publication");
        write_test_definition(&source, "definition-a").unwrap();
        let identity = capture_owner_only_publication_identity(
            &source,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        let quarantine = temp.path().join(deletion_quarantine_name(
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            identity,
        ));
        std::fs::rename(&source, &quarantine).unwrap();

        recover_owner_only_publication_artifacts(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            MAX_SERVICE_PUBLICATION_ARTIFACTS,
            "test definition",
        )
        .unwrap();
        assert!(!quarantine.exists());
    }

    #[test]
    fn destination_withdraw_sync_failure_leaves_recoverable_retired_artifact() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("kata.service");
        let mut temporary = OwnerOnlyPublicationTemp::create(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        temporary.file_mut().write_all(b"definition-a").unwrap();
        temporary.sync_contents().unwrap();
        let publication = match temporary.publish_noreplace(&destination).unwrap() {
            OwnerOnlyNoReplacePublication::Published(publication) => publication,
            OwnerOnlyNoReplacePublication::RecoveryRequired { .. } => {
                panic!("fresh test publication unexpectedly requires recovery")
            }
            OwnerOnlyNoReplacePublication::RenamedRecoveryRequired(_) => {
                panic!("fresh test publication unexpectedly requires renamed recovery")
            }
            OwnerOnlyNoReplacePublication::DestinationExists => {
                panic!("fresh test destination unexpectedly exists")
            }
        };

        reset_publication_removal_attempt_counts();
        inject_next_publication_removal_parent_sync_failure(|| {});
        let error = publication
            .withdraw()
            .expect_err("withdrawal must report the failed durability sync");
        assert!(
            format!("{error:#}")
                .contains("injected test definition removal parent-directory sync failure"),
            "{error:#}"
        );
        assert_eq!(
            publication_removal_attempt_counts(),
            (1, 1),
            "explicit withdrawal performs one pathname transaction and one parent sync attempt"
        );
        assert!(!destination.exists());
        assert!(std::fs::read_dir(temp.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(SERVICE_PUBLICATION_ARTIFACT_PREFIX)
        }));
        recover_owner_only_publication_artifacts(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            MAX_SERVICE_PUBLICATION_ARTIFACTS,
            "test definition",
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[test]
    fn dropping_published_destination_never_mutates_namespace() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("kata.service");
        let mut temporary = OwnerOnlyPublicationTemp::create(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        temporary.file_mut().write_all(b"definition-a").unwrap();
        temporary.sync_contents().unwrap();
        let publication = match temporary.publish_noreplace(&destination).unwrap() {
            OwnerOnlyNoReplacePublication::Published(publication) => publication,
            OwnerOnlyNoReplacePublication::RecoveryRequired { .. } => {
                panic!("fresh test publication unexpectedly requires recovery")
            }
            OwnerOnlyNoReplacePublication::RenamedRecoveryRequired(_) => {
                panic!("fresh test publication unexpectedly requires renamed recovery")
            }
            OwnerOnlyNoReplacePublication::DestinationExists => {
                panic!("fresh test destination unexpectedly exists")
            }
        };

        drop(publication);
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            "definition-a"
        );
        assert!(std::fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(SERVICE_PUBLICATION_ARTIFACT_PREFIX)
        }));
    }

    #[test]
    fn temporary_parent_swap_cleans_through_retained_directory() {
        let root = TempDir::new().unwrap();
        let canonical_parent = root.path().join("publications");
        let moved_parent = root.path().join("moved-publications");
        std::fs::create_dir(&canonical_parent).unwrap();
        std::fs::set_permissions(&canonical_parent, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let mut temporary = OwnerOnlyPublicationTemp::create(
            &canonical_parent,
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            "test definition",
        )
        .unwrap();
        temporary.file_mut().write_all(b"definition-a").unwrap();
        temporary.sync_contents().unwrap();

        std::fs::rename(&canonical_parent, &moved_parent).unwrap();
        std::fs::create_dir(&canonical_parent).unwrap();
        std::fs::set_permissions(&canonical_parent, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let destination = canonical_parent.join("kata.service");
        let error = temporary
            .publish_noreplace(&destination)
            .expect_err("canonical parent replacement must fail publication");
        assert!(format!("{error:#}").contains("changed during publication"));
        temporary.cleanup().unwrap();
        assert_eq!(std::fs::read_dir(&moved_parent).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&canonical_parent).unwrap().count(), 0);
    }

    #[test]
    fn bounded_publication_recovery_removes_only_safe_known_artifacts() {
        let temp = TempDir::new().unwrap();
        let safe = temp.path().join(".kata-service.interrupted.tmp");
        std::fs::write(&safe, "partial").unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o600)).unwrap();
        recover_owner_only_publication_artifacts(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            MAX_SERVICE_PUBLICATION_ARTIFACTS,
            "test definition",
        )
        .unwrap();
        assert!(!safe.exists());

        let unsafe_artifact = temp.path().join(".kata-service.foreign.tmp");
        std::fs::create_dir(&unsafe_artifact).unwrap();
        let error = recover_owner_only_publication_artifacts(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            MAX_SERVICE_PUBLICATION_ARTIFACTS,
            "test definition",
        )
        .expect_err("unsafe matching recovery artifacts must fail closed");
        assert!(format!("{error:#}").contains("not safe to recover"));
        assert!(unsafe_artifact.is_dir());
    }

    #[test]
    fn publication_recovery_ceiling_fails_before_mutation() {
        let temp = TempDir::new().unwrap();
        for index in 0..=MAX_SERVICE_PUBLICATION_ARTIFACTS {
            let path = temp
                .path()
                .join(format!(".kata-service.interrupted-{index}.tmp"));
            std::fs::write(&path, b"partial").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = recover_owner_only_publication_artifacts(
            temp.path(),
            SERVICE_PUBLICATION_ARTIFACT_PREFIX,
            MAX_SERVICE_DEFINITION_BYTES,
            MAX_SERVICE_PUBLICATION_ARTIFACTS,
            "test definition",
        )
        .expect_err("over-ceiling recovery must fail closed");
        assert!(format!("{error:#}").contains("recovery ceiling"));
        assert_eq!(
            std::fs::read_dir(temp.path()).unwrap().count(),
            MAX_SERVICE_PUBLICATION_ARTIFACTS + 1,
            "ceiling refusal must happen before removing any artifact"
        );
    }

    #[test]
    #[cfg(unix)]
    fn owner_only_service_publication_ignores_restrictive_umask() {
        use std::os::unix::fs::MetadataExt as _;

        const CHILD_ROOT: &str = "KATA_SERVICE_PUBLICATION_UMASK_TEST_ROOT";
        if let Some(raw) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(raw);
            let definition = root
                .join("fresh-home")
                .join(".config")
                .join("systemd")
                .join("user")
                .join(SYSTEMD_UNIT_NAME);
            let macos_definition = root
                .join("fresh-macos-home")
                .join("Library")
                .join("LaunchAgents")
                .join(format!("{LAUNCHD_LABEL}.plist"));
            let environment = root
                .join("fresh-home")
                .join(".config")
                .join("kata")
                .join("service-environment.json");
            let macos_environment = root
                .join("fresh-macos-home")
                .join("Library")
                .join("Application Support")
                .join("Kata")
                .join("service-environment.json");
            write_test_definition(&definition, "definition").expect("definition");
            write_test_definition(&macos_definition, "definition").expect("mac definition");
            write_environment_atomically(&environment, "{}").expect("environment");
            write_environment_atomically(&macos_environment, "{}").expect("mac environment");
            assert_eq!(
                definition.metadata().expect("metadata").mode() & 0o7777,
                0o600
            );
            assert_eq!(
                macos_definition.metadata().expect("metadata").mode() & 0o7777,
                0o600
            );
            assert_eq!(
                environment.metadata().expect("metadata").mode() & 0o7777,
                0o600
            );
            assert_eq!(
                environment
                    .parent()
                    .expect("parent")
                    .metadata()
                    .expect("metadata")
                    .mode()
                    & 0o7777,
                0o700
            );
            assert_eq!(
                read_owner_only_service_definition(&definition).unwrap(),
                "definition"
            );
            assert_eq!(
                current_environment_digest(&environment).unwrap(),
                blake3_bytes(b"{}").to_string()
            );
            assert_eq!(
                macos_environment
                    .parent()
                    .expect("parent")
                    .metadata()
                    .expect("metadata")
                    .mode()
                    & 0o7777,
                0o700
            );
            assert_eq!(
                macos_environment.metadata().expect("metadata").mode() & 0o7777,
                0o600
            );
            return;
        }

        let root = TempDir::new().unwrap();
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 0777; exec \"$1\" --exact service::tests::owner_only_service_publication_ignores_restrictive_umask --nocapture")
            .arg("kata-service-umask")
            .arg(std::env::current_exe().unwrap())
            .env(CHILD_ROOT, root.path())
            .output()
            .expect("run restrictive-umask child");
        assert!(
            output.status.success(),
            "restrictive-umask child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn owner_only_definition_reader_refuses_fifo_without_blocking() {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        const CHILD_PATH: &str = "KATA_SERVICE_DEFINITION_FIFO_TEST_PATH";
        if let Some(raw) = std::env::var_os(CHILD_PATH) {
            let path = PathBuf::from(raw);
            let error = read_owner_only_service_definition(&path)
                .expect_err("FIFO service definition must fail closed");
            assert!(
                error.to_string().contains("must be a regular file"),
                "unexpected FIFO refusal: {error:#}"
            );
            return;
        }

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("kata.service");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .expect("FIFO fixture");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("service::tests::owner_only_definition_reader_refuses_fifo_without_blocking")
            .arg("--nocapture")
            .env(CHILD_PATH, &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn FIFO refusal child");
        // Generous on purpose: it wraps a re-exec of the whole kata test binary,
        // which a loaded host starts slowly; a FIFO open that blocks never returns,
        // so any finite bound still catches it.
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll FIFO refusal child") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("terminate blocked FIFO refusal child");
                child.wait().expect("reap blocked FIFO refusal child");
                panic!("opening a FIFO service definition blocked");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "FIFO refusal child failed: {status}");
    }

    #[test]
    fn owner_only_definition_reader_rejects_special_bits_links_and_bad_bytes() {
        let temp = TempDir::new().unwrap();

        let special = temp.path().join("special.service");
        std::fs::write(&special, "definition").unwrap();
        std::fs::set_permissions(&special, std::fs::Permissions::from_mode(0o4600)).unwrap();
        let error = read_owner_only_service_definition(&special)
            .expect_err("special permission bits must fail closed");
        assert!(format!("{error:#}").contains("mode 4600"));

        let linked = temp.path().join("linked.service");
        let alias = temp.path().join("linked-alias.service");
        write_test_definition(&linked, "definition").unwrap();
        std::fs::hard_link(&linked, &alias).unwrap();
        let error = read_owner_only_service_definition(&linked)
            .expect_err("multiply linked definitions must fail closed");
        assert!(format!("{error:#}").contains("exactly one link"));

        let invalid_utf8 = temp.path().join("invalid-utf8.service");
        std::fs::write(&invalid_utf8, [0xff, 0xfe]).unwrap();
        std::fs::set_permissions(&invalid_utf8, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_owner_only_service_definition(&invalid_utf8)
            .expect_err("non-UTF-8 definitions must fail closed");
        assert!(format!("{error:#}").contains("is not UTF-8"));

        let target = temp.path().join("target.service");
        let symlink = temp.path().join("symlink.service");
        write_test_definition(&target, "definition").unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();
        read_owner_only_service_definition(&symlink)
            .expect_err("symlinked definitions must fail closed");

        let oversized = temp.path().join("oversized.service");
        std::fs::write(
            &oversized,
            vec![b'x'; usize::try_from(MAX_SERVICE_DEFINITION_BYTES).unwrap() + 1],
        )
        .unwrap();
        std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_owner_only_service_definition(&oversized)
            .expect_err("oversized definitions must fail closed");
        assert!(format!("{error:#}").contains("safety bound"));
    }

    #[test]
    fn installed_plan_routes_definition_fifo_through_bounded_reader() {
        let temp = TempDir::new().unwrap();
        let definition = temp.path().join("kata.service");
        nix::unistd::mkfifo(&definition, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let environment = temp.path().join("environment.json");
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = plan_installed_with_paths(
                ServicePlatform::SystemdUser,
                ServiceAction::Status,
                definition,
                environment,
            )
            .map(|_| ())
            .map_err(|error| format!("{error:#}"));
            tx.send(result).unwrap();
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("installed status must not block opening a FIFO definition");
        worker.join().unwrap();
        let error = result.expect_err("FIFO definition must fail closed");
        assert!(error.contains("regular file"), "{error}");
    }

    #[test]
    fn launchd_install_refuses_a_loaded_manager_snapshot_before_publication() {
        let temp = TempDir::new().unwrap();
        let definition_path = temp.path().join("sh.kata.main.plist");
        let environment_path = temp.path().join("kata").join("service-environment.json");
        let plan = ServicePlan {
            action: ServiceAction::Install,
            definition_path: definition_path.clone(),
            definition: "new plist".to_string(),
            commands: Vec::new(),
            changed: true,
            environment_path: environment_path.clone(),
            environment_directory: environment_path.parent().unwrap().to_path_buf(),
            environment_definition: "{}".to_string(),
        };
        let calls = Cell::new(0);
        let error = execute_plan_with_manager_probe(
            ServicePlatform::LaunchdAppleSilicon,
            plan,
            true,
            |_, _, _| {
                calls.set(calls.get() + 1);
                Ok(())
            },
            |_, _| Ok(ManagerAuthority::ExactMatching),
        )
        .expect_err("install must not strand old launchd ProgramArguments");
        let message = format!("{error:#}");
        assert!(message.contains("already loaded"), "{message}");
        assert!(message.contains("stop --apply"), "{message}");
        assert!(message.contains("then install"), "{message}");
        assert!(message.contains("then start"), "{message}");
        assert_eq!(calls.get(), 0);
        assert!(!definition_path.exists());
        assert!(!environment_path.exists());
    }

    #[test]
    fn launchd_install_fails_closed_when_loaded_state_cannot_be_proved() {
        let temp = TempDir::new().unwrap();
        let definition_path = temp.path().join("sh.kata.main.plist");
        let environment_path = temp.path().join("kata").join("service-environment.json");
        let plan = ServicePlan {
            action: ServiceAction::Install,
            definition_path: definition_path.clone(),
            definition: "new plist".to_string(),
            commands: Vec::new(),
            changed: true,
            environment_path: environment_path.clone(),
            environment_directory: environment_path.parent().unwrap().to_path_buf(),
            environment_definition: "{}".to_string(),
        };
        let error = execute_plan_with_manager_probe(
            ServicePlatform::LaunchdAppleSilicon,
            plan,
            true,
            |_, _, _| Ok(()),
            |_, _| anyhow::bail!("launchd probe unavailable"),
        )
        .expect_err("an unavailable manager probe must not be interpreted as unloaded");
        assert!(
            format!("{error:#}").contains("launchd probe unavailable"),
            "{error:#}"
        );
        assert!(!definition_path.exists());
        assert!(!environment_path.exists());
    }

    #[test]
    fn unchanged_install_preserves_definition_and_environment_inodes() {
        use std::os::unix::fs::MetadataExt as _;

        let (_temp, _spec, mut plan) = drift_fixture();
        plan.action = ServiceAction::Install;
        plan.commands.clear();
        plan.changed = false;
        plan.environment_definition = std::fs::read_to_string(&plan.environment_path).unwrap();
        let definition_path = plan.definition_path.clone();
        let environment_path = plan.environment_path.clone();
        let definition_inode = std::fs::metadata(&definition_path).unwrap().ino();
        let environment_inode = std::fs::metadata(&environment_path).unwrap().ino();
        execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            plan,
            true,
            |_, _, _| Ok(()),
            |_, _| Ok(ManagerAuthority::ExactMatchingQuiescent),
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(definition_path).unwrap().ino(),
            definition_inode
        );
        assert_eq!(
            std::fs::metadata(environment_path).unwrap().ino(),
            environment_inode
        );
    }

    #[test]
    fn unchanged_install_retry_resyncs_definition_before_manager_mutation() {
        let (_temp, _spec, mut plan) = drift_fixture();
        std::fs::remove_file(&plan.definition_path).unwrap();
        inject_next_publication_parent_sync_failure(|| {});
        let first_error =
            write_definition_atomically(&plan.definition_path, &plan.definition, None)
                .expect_err("initial definition publication sync must fail truthfully");
        assert!(
            format!("{first_error:#}")
                .contains("injected service definition parent-directory sync failure")
        );
        assert!(plan.definition_path.exists());

        plan.action = ServiceAction::Install;
        plan.changed = false;
        plan.commands.clear();
        plan.environment_definition = std::fs::read_to_string(&plan.environment_path).unwrap();
        inject_next_publication_parent_sync_failure(|| {});
        let retry_error = execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            plan.clone(),
            true,
            |_, _, _| panic!("manager mutation must wait for definition durability convergence"),
            |_, _| Ok(ManagerAuthority::ExactMatchingQuiescent),
        )
        .expect_err("the unchanged retry must exercise the existing-definition sync boundary");
        assert!(
            format!("{retry_error:#}")
                .contains("converging an existing service definition before install retry"),
            "{retry_error:#}"
        );

        execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            plan,
            true,
            |_, _, _| Ok(()),
            |_, _| Ok(ManagerAuthority::ExactMatchingQuiescent),
        )
        .expect("a later identical retry converges after the sync succeeds");
    }

    #[test]
    fn start_and_restart_converge_definition_durability_before_manager_mutation() {
        for action in [ServiceAction::Start, ServiceAction::Restart] {
            let (_temp, _spec, mut plan) = drift_fixture();
            std::fs::remove_file(&plan.definition_path).unwrap();
            inject_next_publication_parent_sync_failure(|| {});
            let first_error =
                write_definition_atomically(&plan.definition_path, &plan.definition, None)
                    .expect_err("initial no-replace sync must fail truthfully");
            assert!(
                format!("{first_error:#}")
                    .contains("injected service definition parent-directory sync failure")
            );
            assert!(plan.definition_path.exists());

            plan.action = action;
            inject_next_publication_parent_sync_failure(|| {});
            let manager_calls = Cell::new(0usize);
            let retry_error = execute_plan_with_manager_probe(
                ServicePlatform::SystemdUser,
                plan.clone(),
                true,
                |_, _, _| {
                    manager_calls.set(manager_calls.get() + 1);
                    Ok(())
                },
                |_, _| Ok(ManagerAuthority::ExactMatchingQuiescent),
            )
            .expect_err("Start and Restart must exercise the definition sync boundary");
            assert!(
                format!("{retry_error:#}")
                    .contains("converging the installed service definition before manager start"),
                "{retry_error:#}"
            );
            assert_eq!(manager_calls.get(), 0);

            if action == ServiceAction::Start {
                let reached = execute_plan_with_manager_probe(
                    ServicePlatform::SystemdUser,
                    plan,
                    true,
                    |_, _, _| {
                        manager_calls.set(manager_calls.get() + 1);
                        anyhow::bail!("manager reached after durable convergence")
                    },
                    |_, _| Ok(ManagerAuthority::ExactMatchingQuiescent),
                )
                .expect_err("the sentinel manager failure stops the test after convergence");
                assert!(
                    format!("{reached:#}").contains("manager reached after durable convergence"),
                    "{reached:#}"
                );
                assert_eq!(manager_calls.get(), 1);
            }
        }
    }

    #[test]
    fn installed_environment_refuses_a_rebound_directory_before_manager_mutation() {
        use std::os::unix::fs::symlink;

        let (temp, _spec, plan) = drift_fixture();
        let moved = temp.path().join("moved-service-environments");
        std::fs::rename(&plan.environment_directory, &moved).unwrap();
        symlink(&moved, &plan.environment_directory).unwrap();
        let expected =
            std::fs::read(moved.join(plan.environment_path.file_name().unwrap())).unwrap();

        let error = execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            plan.clone(),
            true,
            |_, _, _| panic!("manager must not run with a rebound environment directory"),
            |_, _| panic!("manager authority must not be inspected before environment refusal"),
        )
        .expect_err("an intermediate environment symlink must fail closed");
        assert!(
            format!("{error:#}").contains("without following symlinks"),
            "{error:#}"
        );
        assert!(current_environment_digest(&plan.environment_path).is_err());
        assert_eq!(
            std::fs::read(moved.join(plan.environment_path.file_name().unwrap())).unwrap(),
            expected,
            "refusal must not mutate the symlink target"
        );
    }

    #[test]
    fn uninstall_unknown_manager_failure_preserves_installed_publication() {
        use std::os::unix::fs::MetadataExt as _;

        let (_temp, _spec, mut plan) = drift_fixture();
        plan.action = ServiceAction::Uninstall;
        plan.commands = vec![
            args(&[
                SYSTEMCTL_PATH,
                "--user",
                "disable",
                "--now",
                SYSTEMD_UNIT_NAME,
            ]),
            args(&[SYSTEMCTL_PATH, "--user", "daemon-reload"]),
        ];
        let definition_path = plan.definition_path.clone();
        let environment_path = plan.environment_path.clone();
        let definition_inode = std::fs::metadata(&definition_path).unwrap().ino();
        let environment_inode = std::fs::metadata(&environment_path).unwrap().ino();
        let installed_definition = plan.definition.clone();
        let calls = Cell::new(0);
        let error = execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            plan,
            true,
            |_, _, _| {
                calls.set(calls.get() + 1);
                anyhow::bail!("manager bus unavailable")
            },
            |_, _| Ok(ManagerAuthority::ExactMatching),
        )
        .expect_err("unknown manager failure must abort uninstall before publication mutation");
        assert!(format!("{error:#}").contains("manager bus unavailable"));
        assert_eq!(calls.get(), 1, "daemon-reload must not run after failure");
        assert_eq!(
            std::fs::read_to_string(&definition_path).unwrap(),
            installed_definition
        );
        assert_eq!(
            blake3_bytes(&std::fs::read(&environment_path).unwrap()).to_string(),
            definition_environment_digest(&installed_definition).unwrap()
        );
        assert_eq!(
            std::fs::metadata(definition_path).unwrap().ino(),
            definition_inode
        );
        assert_eq!(
            std::fs::metadata(environment_path).unwrap().ino(),
            environment_inode
        );
    }

    #[test]
    fn oversized_service_environment_is_rejected_before_publication() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("kata");
        let config = temp.path().join("kata.toml");
        std::fs::write(&binary, b"kata-binary").unwrap();
        std::fs::write(&config, b"[node]\n").unwrap();
        let environment_path = temp.path().join("service-environment.json");
        let definition_path = temp.path().join("kata.service");
        let environment = BTreeMap::from([(
            "RUST_LOG".to_string(),
            "x".repeat(usize::try_from(MAX_SERVICE_ENVIRONMENT_BYTES).unwrap()),
        )]);
        let error = ServiceSpec::new_with_loaded_config_digest(
            ServicePlatform::SystemdUser,
            &binary,
            &config,
            &temp.path().join("data"),
            environment,
            &BTreeSet::new(),
            "config-digest".to_string(),
        )
        .expect_err("an environment larger than the reader bound must not be publishable");
        let message = format!("{error:#}");
        assert!(
            message.contains("serialized service environment"),
            "{message}"
        );
        assert!(message.contains("safety bound"), "{message}");
        assert!(!definition_path.exists());
        assert!(!environment_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn service_definition_rejects_non_utf8_paths_instead_of_aliasing_them() {
        use std::os::unix::ffi::OsStringExt as _;

        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("kata");
        let config = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"kata-\xff.toml".to_vec()));
        std::fs::write(&binary, b"binary").unwrap();
        std::fs::write(&config, b"[node]\n").unwrap();
        let error = ServiceSpec::new_for_test(
            ServicePlatform::SystemdUser,
            &binary,
            &config,
            &temp.path().join("data"),
            BTreeMap::new(),
        )
        .expect_err("lossy service paths must never be rendered");
        assert!(
            format!("{error:#}").contains("not valid UTF-8"),
            "{error:#}"
        );
    }

    #[test]
    fn service_definition_rejects_xml_forbidden_path_characters() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("kata");
        let config = temp.path().join("kata-\u{1}.toml");
        std::fs::write(&binary, b"binary").unwrap();
        std::fs::write(&config, b"[node]\n").unwrap();
        let error = ServiceSpec::new_for_test(
            ServicePlatform::LaunchdAppleSilicon,
            &binary,
            &config,
            &temp.path().join("data"),
            BTreeMap::new(),
        )
        .expect_err("a path that cannot form valid XML must not publish a plist");
        let message = format!("{error:#}");
        assert!(message.contains("cannot round-trip exactly"), "{message}");
    }

    #[test]
    fn native_per_user_service_refuses_root_authority() {
        let error = require_non_root_service_owner(0)
            .expect_err("the per-user service must not become a root daemon");
        assert!(format!("{error:#}").contains("refuses effective uid 0"));
        require_non_root_service_owner(1).expect("a non-root owner is admissible");
    }

    #[test]
    fn native_service_paths_ignore_forged_ambient_home() {
        const CHILD: &str = "KATA_TEST_EFFECTIVE_OWNER_HOME_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let expected = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
                .unwrap()
                .expect("effective account")
                .dir;
            assert_eq!(home_dir().unwrap(), expected);
            assert_eq!(
                definition_path(ServicePlatform::SystemdUser).unwrap(),
                expected.join(".config/systemd/user/kata.service")
            );
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("service::tests::native_service_paths_ignore_forged_ambient_home")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env("HOME", "/tmp/kata-forged-owner-home")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "forged-HOME child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn installed_main_rejects_home_that_would_split_tilde_paths() {
        let owner = Path::new("/owner/home");
        require_matching_home(owner, Some(std::ffi::OsStr::new("/owner/home"))).unwrap();
        let error =
            require_matching_home(owner, Some(std::ffi::OsStr::new("/tmp/forged-owner-home")))
                .expect_err("forged HOME must fail before installed config parsing");
        let message = format!("{error:#}");
        assert!(message.contains("tilde-expanded paths"), "{message}");
        assert!(message.contains("/owner/home"), "{message}");
        assert!(message.contains("/tmp/forged-owner-home"), "{message}");
    }

    #[test]
    fn trampoline_refuses_manager_snapshot_replaced_before_lease_acquisition() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("kata");
        let config_a = temp.path().join("a").join("kata.toml");
        let config_b = temp.path().join("b").join("kata.toml");
        let data_dir = temp.path().join("data");
        std::fs::write(&binary, b"kata-binary").unwrap();
        std::fs::create_dir_all(config_a.parent().unwrap()).unwrap();
        std::fs::create_dir_all(config_b.parent().unwrap()).unwrap();
        std::fs::write(&config_a, b"[node]\n").unwrap();
        std::fs::write(&config_b, b"[node]\n").unwrap();
        drop(
            crate::data_dir_lock::DataDirLock::acquire(
                &data_dir,
                crate::data_dir_lock::MainMode::Installed,
                None,
            )
            .unwrap(),
        );
        let environment = BTreeMap::from([("RUST_LOG".to_string(), "kata=info".to_string())]);

        for platform in [
            ServicePlatform::SystemdUser,
            ServicePlatform::LaunchdAppleSilicon,
        ] {
            let mut spec_a = ServiceSpec::new_for_test(
                platform,
                &binary,
                &config_a,
                &data_dir,
                environment.clone(),
            )
            .unwrap();
            let mut spec_b = ServiceSpec::new_for_test(
                platform,
                &binary,
                &config_b,
                &data_dir,
                environment.clone(),
            )
            .unwrap();
            assert_eq!(spec_a.config_digest, spec_b.config_digest);
            assert_eq!(spec_a.environment_digest, spec_b.environment_digest);

            let definition_path = temp.path().join(format!("{platform:?}.definition"));
            spec_a.definition_path.clone_from(&definition_path);
            spec_b.definition_path.clone_from(&definition_path);
            let environment_directory = temp.path().join(format!("{platform:?}.environments"));
            let environment_path =
                environment_snapshot_path(&environment_directory, &spec_a.environment_digest)
                    .unwrap();
            spec_a.environment_path.clone_from(&environment_path);
            spec_b.environment_path.clone_from(&environment_path);
            write_environment_atomically(
                &environment_path,
                &serialize_service_environment(&spec_a.environment).unwrap(),
            )
            .unwrap();
            write_test_definition(&definition_path, &spec_a.render()).unwrap();
            let launch_a = ServiceExecLaunchIdentity {
                definition: &definition_path,
                binary: &spec_a.binary,
                environment: &spec_a.environment_path,
                config: &spec_a.config,
                working_directory: &spec_a.working_directory,
                binary_digest: &spec_a.binary_digest,
                config_digest: &spec_a.config_digest,
                environment_digest: &spec_a.environment_digest,
                data_directory: &spec_a.data_dir,
                directory_id: &spec_a.data_directory_id,
            };
            validate_current_service_exec_definition(&launch_a)
                .expect("the exact current manager snapshot validates");

            // Model: the manager captured A, then install published B under
            // the lease, then the old A trampoline acquired that lease.
            write_test_definition(&definition_path, &spec_b.render()).unwrap();
            let error = validate_current_service_exec_definition(&launch_a)
                .expect_err("a manager snapshot older than the installed definition must fail");
            let message = format!("{error:#}");
            assert!(message.contains("stale or unverifiable"), "{message}");
            assert!(message.contains("config path"), "{message}");
            assert!(
                message.contains(&config_a.display().to_string()),
                "{message}"
            );
            assert!(
                message.contains(&config_b.display().to_string()),
                "{message}"
            );

            let duplicate = match platform {
                ServicePlatform::SystemdUser => format!(
                    "{}# X-Kata-Config-Path={}\n",
                    spec_b.render(),
                    systemd_quote(&spec_b.config.to_string_lossy())
                ),
                ServicePlatform::LaunchdAppleSilicon => {
                    let mut definition = spec_b.render();
                    let root_end = definition.rfind("</dict>").unwrap();
                    definition.insert_str(
                        root_end,
                        &format!(
                            "  <key>KataConfigPath</key><string>{}</string>\n",
                            xml_escape_path(&spec_b.config)
                        ),
                    );
                    definition
                }
            };
            write_test_definition(&definition_path, &duplicate).unwrap();
            let launch_b = ServiceExecLaunchIdentity {
                definition: &definition_path,
                binary: &spec_b.binary,
                environment: &spec_b.environment_path,
                config: &spec_b.config,
                working_directory: &spec_b.working_directory,
                binary_digest: &spec_b.binary_digest,
                config_digest: &spec_b.config_digest,
                environment_digest: &spec_b.environment_digest,
                data_directory: &spec_b.data_dir,
                directory_id: &spec_b.data_directory_id,
            };
            let error = validate_service_exec_definition_at(&definition_path, &launch_b)
                .expect_err("ambiguous duplicate launch metadata must fail closed");
            assert!(
                format!("{error:#}").contains("config path metadata occurs 2 times"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn install_refuses_definition_permission_drift_as_foreign() {
        let temp = TempDir::new().unwrap();
        let definition_path = temp.path().join("kata.service");
        let environment_path = temp.path().join("service-environment.json");
        let definition = "same definition bytes";
        let environment = "{}";
        write_test_definition(&definition_path, definition).unwrap();
        std::fs::set_permissions(&definition_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let plan = ServicePlan {
            action: ServiceAction::Install,
            definition_path: definition_path.clone(),
            definition: definition.to_string(),
            commands: Vec::new(),
            changed: true,
            environment_directory: environment_path.parent().unwrap().to_path_buf(),
            environment_path,
            environment_definition: environment.to_string(),
        };
        let error = execute_plan_with(ServicePlatform::SystemdUser, plan, true, |_, _, _| Ok(()))
            .expect_err("permission drift at the fixed definition is foreign, not repairable");
        assert!(format!("{error:#}").contains("mode 644"), "{error:#}");
        assert_eq!(
            std::fs::metadata(&definition_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    fn drift_fixture() -> (TempDir, ServiceSpec, ServicePlan) {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("kata");
        let config = temp.path().join("kata.toml");
        std::fs::write(&binary, b"kata-binary-v1").unwrap();
        std::fs::write(&config, b"[node]\n").unwrap();
        let data_dir = temp.path().join("data");
        drop(
            crate::data_dir_lock::DataDirLock::acquire(
                &data_dir,
                crate::data_dir_lock::MainMode::Installed,
                None,
            )
            .unwrap(),
        );
        let mut environment = BTreeMap::new();
        environment.insert("RUST_LOG".to_string(), "kata=info".to_string());
        let mut spec = ServiceSpec::new_for_test(
            ServicePlatform::SystemdUser,
            &binary,
            &config,
            &data_dir,
            environment,
        )
        .unwrap();
        spec.definition_path = temp.path().join("kata.service");
        let environment_directory = temp.path().join("service-environments");
        spec.environment_path =
            environment_snapshot_path(&environment_directory, &spec.environment_digest).unwrap();
        let environment_path = spec.environment_path.clone();
        write_environment_atomically(
            &environment_path,
            &serde_json::to_string_pretty(&spec.environment).unwrap(),
        )
        .unwrap();
        write_test_definition(&spec.definition_path, &spec.render()).unwrap();
        let plan = ServicePlan {
            action: ServiceAction::Start,
            definition_path: spec.definition_path.clone(),
            definition: spec.render(),
            commands: vec![args(&["manager-must-not-run"])],
            changed: false,
            environment_directory,
            environment_path,
            environment_definition: String::new(),
        };
        (temp, spec, plan)
    }

    #[test]
    fn publication_authority_skips_discovery_probe_on_stop_verification() {
        let (_temp, _owned, mut plan) = owned_fixture();
        plan.action = ServiceAction::Uninstall;
        plan.commands = vec![
            args(&[
                SYSTEMCTL_PATH,
                "--user",
                "disable",
                "--now",
                SYSTEMD_UNIT_NAME,
            ]),
            args(&[SYSTEMCTL_PATH, "--user", "daemon-reload"]),
        ];
        let root = TempDir::new().unwrap();
        let lifecycle = InstalledLifecycleOperationLease::acquire_at_for_test(
            &root.path().join("authority/lifecycle-operation.lock"),
        )
        .unwrap();
        let discovery = InstalledDiscoveryLease::acquire_at_for_test(
            &root.path().join("authority/discovery.lock"),
        )
        .unwrap();
        let permit = InstalledServicePublicationPermit::new(&lifecycle, &discovery);
        let reload_ran = Cell::new(false);
        let observed_discovery_owned = Cell::new(None);
        execute_plan_with_authority(
            ServicePlatform::SystemdUser,
            plan.clone(),
            ServiceExecutionAuthority::Publication(permit),
            |argv, _, _| {
                if argv == plan.commands[1] {
                    reload_ran.set(true);
                }
                Ok(())
            },
            |_, _| {
                Ok(if reload_ran.get() {
                    ManagerAuthority::Absent
                } else {
                    ManagerAuthority::ExactMatchingQuiescent
                })
            },
            |_, discovery_owned| {
                observed_discovery_owned.set(Some(discovery_owned));
                Ok(())
            },
        )
        .unwrap();
        // The publication permit already owns the per-owner discovery lease;
        // re-probing it from this same process would self-conflict under
        // flock semantics and wedge every applied uninstall
        // (attachment::discovery_probe_conflicts_with_own_process_lease pins
        // the kernel-side reason).
        assert_eq!(
            observed_discovery_owned.get(),
            Some(true),
            "publication authority must report discovery ownership to the stopped verifier"
        );
    }

    fn owned_fixture() -> (TempDir, OwnedServiceDefinition, ServicePlan) {
        let (temp, _spec, plan) = drift_fixture();
        let definition_publication = ExistingOwnerOnlyPublication::open(
            &plan.definition_path,
            MAX_SERVICE_DEFINITION_BYTES,
            "test service definition",
        )
        .unwrap();
        let owned = parse_owned_service_definition(
            ServicePlatform::SystemdUser,
            &plan.definition_path,
            &plan.environment_directory,
            plan.definition.clone(),
            definition_publication,
        )
        .unwrap();
        (temp, owned, plan)
    }

    fn successful_output(stdout: String) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: stdout.into_bytes(),
            stderr: Vec::new(),
        }
    }

    fn systemd_identity_output(
        owned: &OwnedServiceDefinition,
        need_reload: &str,
        active: &str,
        sub: &str,
        main_pid: &str,
        control_pid: &str,
    ) -> Output {
        let command = service_exec_command(&owned.spec);
        successful_output(format!(
            "Id={SYSTEMD_UNIT_NAME}\nNames={SYSTEMD_UNIT_NAME}\nLoadState=loaded\nActiveState={active}\nSubState={sub}\nMainPID={main_pid}\nControlPID={control_pid}\nFragmentPath={}\nDropInPaths=\nNeedDaemonReload={need_reload}\nExecStart={{ path={} ; argv[]={}; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}\nWorkingDirectory={}\n",
            owned.spec.definition_path.display(),
            owned.spec.binary.display(),
            command.join(" "),
            owned.spec.working_directory.display(),
        ))
    }

    #[test]
    fn systemd_reload_recovery_requires_every_quiescence_property() {
        let (_temp, owned, plan) = owned_fixture();
        let exact = classify_systemd_manager(
            &systemd_identity_output(&owned, "no", "active", "running", "42", "0"),
            Some(&owned),
            &plan.definition_path,
            &plan.environment_directory,
        )
        .unwrap();
        assert_eq!(exact, ManagerAuthority::ExactRunning);

        let recovery = classify_systemd_manager(
            &systemd_identity_output(&owned, "yes", "inactive", "dead", "0", "0"),
            Some(&owned),
            &plan.definition_path,
            &plan.environment_directory,
        )
        .unwrap();
        assert_eq!(recovery, ManagerAuthority::ExactNeedsReload);
        let stale_removal = classify_systemd_manager(
            &systemd_identity_output(&owned, "yes", "inactive", "dead", "0", "0"),
            None,
            &plan.definition_path,
            &plan.environment_directory,
        )
        .unwrap();
        assert_eq!(stale_removal, ManagerAuthority::ExactStaleRemoval);

        let mut drop_in = systemd_identity_output(&owned, "no", "inactive", "dead", "0", "0");
        drop_in.stdout = String::from_utf8(drop_in.stdout)
            .unwrap()
            .replace("DropInPaths=\n", "DropInPaths=/tmp/foreign.conf\n")
            .into_bytes();
        assert!(
            format!(
                "{:#}",
                classify_systemd_manager(
                    &drop_in,
                    Some(&owned),
                    &plan.definition_path,
                    &plan.environment_directory,
                )
                .unwrap_err()
            )
            .contains("drop-ins")
        );
        let mut ignored_exec = systemd_identity_output(&owned, "no", "inactive", "dead", "0", "0");
        ignored_exec.stdout = String::from_utf8(ignored_exec.stdout)
            .unwrap()
            .replace("ignore_errors=no", "ignore_errors=yes")
            .into_bytes();
        assert!(
            format!(
                "{:#}",
                classify_systemd_manager(
                    &ignored_exec,
                    Some(&owned),
                    &plan.definition_path,
                    &plan.environment_directory,
                )
                .unwrap_err()
            )
            .contains("ignore_errors=no")
        );

        for (active, sub, main, control) in [
            ("active", "dead", "0", "0"),
            ("inactive", "running", "0", "0"),
            ("inactive", "dead", "1", "0"),
            ("inactive", "dead", "0", "1"),
        ] {
            let error = classify_systemd_manager(
                &systemd_identity_output(&owned, "yes", active, sub, main, control),
                Some(&owned),
                &plan.definition_path,
                &plan.environment_directory,
            )
            .expect_err("each non-quiescent property must independently refuse reload recovery");
            assert!(format!("{error:#}").contains("requires inactive/failed"));
        }

        let definition = DefinitionAuthority::Exact(Box::new(owned));
        for manager in [
            ManagerAuthority::ExactRunning,
            ManagerAuthority::ExactMatching,
        ] {
            let error = authorize_service_operation(
                ServiceAction::Install,
                ServicePlatform::SystemdUser,
                &definition,
                manager,
            )
            .expect_err("active or auto-restart-transition units must not race install");
            assert!(format!("{error:#}").contains("pending automatic restart"));
        }
        authorize_service_operation(
            ServiceAction::Install,
            ServicePlatform::SystemdUser,
            &definition,
            ManagerAuthority::ExactMatchingQuiescent,
        )
        .unwrap();
        assert!(manager_satisfies_started(
            ServicePlatform::SystemdUser,
            ManagerAuthority::ExactRunning
        ));
        assert!(!manager_satisfies_started(
            ServicePlatform::SystemdUser,
            ManagerAuthority::ExactMatching
        ));
        assert!(!manager_satisfies_started(
            ServicePlatform::SystemdUser,
            ManagerAuthority::ExactMatchingQuiescent
        ));
    }

    #[test]
    fn launchd_manager_requires_exact_path_program_and_arguments_shape() {
        let (_temp, mut owned, _plan) = owned_fixture();
        owned.spec.platform = ServicePlatform::LaunchdAppleSilicon;
        let arguments = service_exec_command(&owned.spec).join("\n");
        let exact = successful_output(format!(
            "path = {}\nprogram = {}\narguments = {{\n{arguments}\n}}\n",
            owned.spec.definition_path.display(),
            owned.spec.binary.display(),
        ));
        assert_eq!(
            classify_launchd_manager(&exact, "501", Some(&owned)).unwrap(),
            ManagerAuthority::ExactMatching
        );

        let mut duplicate = exact;
        duplicate
            .stdout
            .extend_from_slice(format!("program = {}\n", owned.spec.binary.display()).as_bytes());
        let error = classify_launchd_manager(&duplicate, "501", Some(&owned))
            .expect_err("duplicate launchd identity fields must fail closed");
        assert!(format!("{error:#}").contains("exactly one \"program = \" line"));
    }

    #[test]
    fn existing_environment_requires_successful_parent_sync() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("service-environments");
        let definition = "{}";
        let digest = blake3_bytes(definition.as_bytes()).to_string();
        let target = environment_snapshot_path(&directory, &digest).unwrap();
        write_environment_atomically(&target, definition).unwrap();

        inject_next_publication_parent_sync_failure(|| {});
        let error = write_environment_atomically(&target, definition)
            .expect_err("equal bytes without a successful parent sync are not convergence");
        assert!(format!("{error:#}").contains("parent-directory sync failure"));
        write_environment_atomically(&target, definition)
            .expect("a later exact durable retry converges");
    }

    #[test]
    fn environment_post_rename_failure_preserves_recognizable_canonical_for_reconciliation() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("service-environments");
        let definition = "{}";
        let digest = blake3_bytes(definition.as_bytes()).to_string();
        let target = environment_snapshot_path(&directory, &digest).unwrap();
        ensure_owner_only_environment_directory(&target).unwrap();
        inject_next_publication_parent_sync_failure(|| {});

        let error = write_environment_atomically(&target, definition)
            .expect_err("a post-rename failure is not destination-exists convergence");
        assert!(format!("{error:#}").contains("parent-directory sync failure"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), definition);
        write_environment_atomically(&target, definition)
            .expect("a later exact durable reconciliation succeeds");
    }

    #[test]
    fn environment_post_rename_replacement_requires_explicit_reconciliation() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("service-environments");
        let definition = "{}";
        let digest = blake3_bytes(definition.as_bytes()).to_string();
        let target = environment_snapshot_path(&directory, &digest).unwrap();
        ensure_owner_only_environment_directory(&target).unwrap();
        let replacement = directory.join("same-bytes-replacement");
        std::fs::write(&replacement, definition).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hook_target = target.clone();
        inject_next_publication_parent_sync_failure(move || {
            std::fs::rename(&replacement, &hook_target)
                .expect("replace the just-published inode with identical desired bytes");
        });

        let error = write_environment_atomically(&target, definition)
            .expect_err("visible desired bytes cannot convert a post-rename failure into success");
        let message = format!("{error:#}");
        assert!(
            message.contains("parent-directory sync failure"),
            "{message}"
        );
        assert!(message.contains("requires reconciliation"), "{message}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            definition,
            "exact cleanup preserves the replacement inode despite matching bytes"
        );
        assert!(std::fs::read_dir(&directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(SERVICE_PUBLICATION_ARTIFACT_PREFIX)
        }));

        write_environment_atomically(&target, definition)
            .expect("a later independent durable-convergence attempt may succeed");
    }

    #[test]
    fn environment_destination_exists_convergence_requires_parent_sync() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("service-environments");
        let definition = "{}";
        let digest = blake3_bytes(definition.as_bytes()).to_string();
        let target = environment_snapshot_path(&directory, &digest).unwrap();
        ensure_owner_only_environment_directory(&target).unwrap();
        let hook_target = target.clone();
        inject_pre_no_replace_rename_hook(move || {
            std::fs::write(&hook_target, definition).unwrap();
            std::fs::set_permissions(&hook_target, std::fs::Permissions::from_mode(0o600)).unwrap();
        });
        inject_next_publication_parent_sync_failure(|| {});

        let error = write_environment_atomically(&target, definition)
            .expect_err("destination-exists convergence must durably sync its parent");
        assert!(format!("{error:#}").contains("parent-directory sync failure"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), definition);
        assert!(std::fs::read_dir(&directory).unwrap().all(|entry| {
            Path::new(&entry.unwrap().file_name()).extension() != Some(OsStr::new("tmp"))
        }));
        write_environment_atomically(&target, definition)
            .expect("retry durably accepts the exact content-addressed snapshot");
    }

    #[test]
    fn interrupted_environment_link_is_recovered_idempotently() {
        use std::os::unix::fs::MetadataExt as _;

        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("service-environments");
        let definition = "{}";
        let digest = blake3_bytes(definition.as_bytes()).to_string();
        let target = environment_snapshot_path(&directory, &digest).unwrap();
        ensure_owner_only_environment_directory(&target).unwrap();
        let temporary = directory.join(".kata-service.interrupted.tmp");
        std::fs::write(&temporary, definition).unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&temporary, &target).unwrap();
        assert_eq!(std::fs::metadata(&target).unwrap().nlink(), 2);

        write_environment_atomically(&target, definition).unwrap();
        assert!(!temporary.exists());
        assert_eq!(std::fs::metadata(&target).unwrap().nlink(), 1);
        assert_eq!(std::fs::read_to_string(target).unwrap(), definition);
    }

    #[test]
    fn environment_snapshot_without_definition_is_absent_and_retryable() {
        let temp = TempDir::new().unwrap();
        let definition_path = temp.path().join("kata.service");
        let directory = temp.path().join("service-environments");
        let environment = "{}";
        let digest = blake3_bytes(environment.as_bytes()).to_string();
        let snapshot = environment_snapshot_path(&directory, &digest).unwrap();
        write_environment_atomically(&snapshot, environment).unwrap();
        assert_eq!(
            inspect_installed_definition(
                ServicePlatform::SystemdUser,
                &definition_path,
                &directory,
            )
            .unwrap(),
            DefinitionAuthority::Absent
        );
        write_environment_atomically(&snapshot, environment).unwrap();
    }

    #[test]
    fn interrupted_install_retries_daemon_reload_without_republishing() {
        let (_temp, _owned, mut plan) = owned_fixture();
        plan.action = ServiceAction::Install;
        plan.commands = vec![args(&[SYSTEMCTL_PATH, "--user", "daemon-reload"])];
        plan.changed = false;
        plan.environment_definition = std::fs::read_to_string(&plan.environment_path).unwrap();
        let definition_inode = std::fs::metadata(&plan.definition_path).unwrap();
        let probes = Cell::new(0usize);
        let commands = Cell::new(0usize);
        execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            plan.clone(),
            true,
            |argv, _, _| {
                assert_eq!(argv, plan.commands[0]);
                commands.set(commands.get() + 1);
                Ok(())
            },
            |_, _| {
                let probe = probes.get();
                probes.set(probe + 1);
                Ok(if probe < 2 {
                    ManagerAuthority::ExactNeedsReload
                } else {
                    ManagerAuthority::ExactMatchingQuiescent
                })
            },
        )
        .unwrap();
        assert_eq!(commands.get(), 1);
        assert_eq!(
            std::fs::metadata(&plan.definition_path).unwrap().ino(),
            definition_inode.ino()
        );
    }

    #[test]
    fn interrupted_uninstall_with_stale_manager_converges_from_absent_definition() {
        let (_temp, _owned, mut plan) = owned_fixture();
        std::fs::remove_file(&plan.definition_path).unwrap();
        plan.action = ServiceAction::Uninstall;
        plan.definition.clear();
        plan.commands = vec![
            args(&[
                SYSTEMCTL_PATH,
                "--user",
                "disable",
                "--now",
                SYSTEMD_UNIT_NAME,
            ]),
            args(&[SYSTEMCTL_PATH, "--user", "daemon-reload"]),
        ];
        let probes = Cell::new(0usize);
        let commands = Cell::new(0usize);
        execute_plan_with_manager_probe(
            ServicePlatform::SystemdUser,
            plan.clone(),
            true,
            |argv, _, _| {
                assert_eq!(argv, plan.commands[1]);
                commands.set(commands.get() + 1);
                Ok(())
            },
            |_, _| {
                let probe = probes.get();
                probes.set(probe + 1);
                Ok(if probe < 2 {
                    ManagerAuthority::ExactStaleRemoval
                } else {
                    ManagerAuthority::Absent
                })
            },
        )
        .unwrap();
        assert_eq!(commands.get(), 1);
        assert!(!plan.environment_path.exists());
    }

    #[test]
    fn uninstall_reload_failure_preserves_committed_absence_and_retry_converges() {
        let (_temp, _owned, mut plan) = owned_fixture();
        plan.action = ServiceAction::Uninstall;
        plan.commands = vec![
            args(&[
                SYSTEMCTL_PATH,
                "--user",
                "disable",
                "--now",
                SYSTEMD_UNIT_NAME,
            ]),
            args(&[SYSTEMCTL_PATH, "--user", "daemon-reload"]),
        ];
        let commands = Cell::new(0usize);
        let error = execute_plan_with_manager_probe_and_stopped_verifier(
            ServicePlatform::SystemdUser,
            plan.clone(),
            true,
            |_, _, _| {
                let index = commands.get();
                commands.set(index + 1);
                if index == 1 {
                    anyhow::bail!("manager bus dropped during daemon-reload");
                }
                Ok(())
            },
            |_, _| Ok(ManagerAuthority::ExactMatchingQuiescent),
            |_, _| Ok(()),
        )
        .expect_err("second-command daemon-reload failure must be recoverable");
        assert!(format!("{error:#}").contains("definition absence commit"));
        assert!(!plan.definition_path.exists());
        assert!(plan.environment_path.exists());

        let probes = Cell::new(0usize);
        let retry_commands = Cell::new(0usize);
        execute_plan_with_manager_probe_and_stopped_verifier(
            ServicePlatform::SystemdUser,
            plan.clone(),
            true,
            |argv, _, _| {
                assert_eq!(argv, plan.commands[1]);
                retry_commands.set(retry_commands.get() + 1);
                Ok(())
            },
            |_, _| {
                let probe = probes.get();
                probes.set(probe + 1);
                Ok(if probe < 2 {
                    ManagerAuthority::ExactStaleRemoval
                } else {
                    ManagerAuthority::Absent
                })
            },
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(retry_commands.get(), 1, "retry runs daemon-reload only");
        assert!(!plan.definition_path.exists());
        assert!(!plan.environment_path.exists());
    }

    #[test]
    fn systemd_definition_bounds_permanent_start_failure_retries() {
        let (_temp, spec, _plan) = drift_fixture();
        let definition = spec.render();
        assert!(definition.contains("StartLimitIntervalSec=60s"));
        assert!(definition.contains("StartLimitBurst=5"));
        assert!(definition.contains("Restart=on-failure"));
        assert!(definition.contains("RestartSec=2s"));
    }

    #[test]
    fn launchd_definition_makes_failure_retry_throttle_explicit() {
        let (_temp, spec, _plan) = drift_fixture();
        let definition = render_launchd(&spec);
        assert!(definition.contains("<key>KeepAlive</key>"));
        assert!(definition.contains("<key>SuccessfulExit</key><false/>"));
        assert!(definition.contains("<key>ThrottleInterval</key><integer>10</integer>"));
        assert!(!definition.contains("StandardOutPath"));
        assert!(!definition.contains("StandardErrorPath"));
        let logs = commands_for(
            ServicePlatform::LaunchdAppleSilicon,
            ServiceAction::Logs,
            &spec.definition_path,
        );
        assert_eq!(
            logs,
            [args(&[
                MACOS_LOG_PATH,
                "show",
                "--last",
                "1h",
                "--info",
                "--debug",
                "--predicate",
                "subsystem == \"sh.kata.main\" AND category == \"installed-main\"",
            ])]
        );
    }

    fn assert_drift_refuses_before_manager(plan: ServicePlan, expected: &str) {
        let calls = Cell::new(0usize);
        let error = execute_plan_with(ServicePlatform::SystemdUser, plan, true, |_, _, _| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(calls.get(), 0, "native manager must not run on drift");
    }

    #[test]
    fn config_drift_refuses_start_before_manager_mutation() {
        let (_temp, spec, plan) = drift_fixture();
        std::fs::write(&spec.config, b"[node]\nid = \"changed\"\n").unwrap();
        assert_drift_refuses_before_manager(plan, "config");
    }

    #[test]
    fn environment_drift_refuses_start_before_manager_mutation() {
        let (_temp, _spec, plan) = drift_fixture();
        write_test_definition(&plan.environment_path, "{\"RUST_LOG\":\"debug\"}").unwrap();
        assert_drift_refuses_before_manager(plan, "environment");
    }

    #[test]
    fn same_path_binary_replacement_refuses_restart_before_manager_mutation() {
        let (_temp, spec, mut plan) = drift_fixture();
        plan.action = ServiceAction::Restart;
        std::fs::write(&spec.binary, b"kata-binary-v2").unwrap();
        assert_drift_refuses_before_manager(plan, "binary");
    }

    #[test]
    fn replaced_data_directory_identity_refuses_before_manager_mutation() {
        let (_temp, spec, plan) = drift_fixture();
        std::fs::write(
            spec.data_dir.join("main-identity.json"),
            br#"{"directory_id":"wrong-directory","format_generation":7,"mode":"installed"}"#,
        )
        .unwrap();
        assert_drift_refuses_before_manager(plan, "identity changed");
    }

    #[test]
    fn wrong_data_directory_mode_refuses_before_manager_mutation() {
        let (_temp, spec, plan) = drift_fixture();
        let installed = crate::data_dir_lock::inspect_identity(&spec.data_dir)
            .unwrap()
            .unwrap();
        std::fs::write(
            spec.data_dir.join("main-identity.json"),
            serde_json::to_vec(&crate::data_dir_lock::DataDirIdentity {
                directory_id: spec.data_directory_id.clone(),
                format_generation: installed.format_generation,
                mode: crate::data_dir_lock::MainMode::Scratch,
            })
            .unwrap(),
        )
        .unwrap();
        assert_drift_refuses_before_manager(plan, "Scratch identity");
    }

    #[cfg(unix)]
    #[test]
    fn data_directory_symlink_refuses_before_manager_mutation() {
        use std::os::unix::fs::symlink;

        let (temp, spec, plan) = drift_fixture();
        let real = temp.path().join("moved-data");
        std::fs::rename(&spec.data_dir, &real).unwrap();
        symlink(&real, &spec.data_dir).unwrap();
        assert_drift_refuses_before_manager(plan, "became a symlink");
    }

    #[test]
    fn loaded_config_digest_is_not_re_read_by_service_spec() {
        let temp = TempDir::new().unwrap();
        let binary = temp.path().join("kata");
        let config = temp.path().join("kata.toml");
        std::fs::write(&binary, b"binary").unwrap();
        std::fs::write(&config, b"second read must not win").unwrap();
        let parsed_digest = blake3_bytes(b"exact parsed bytes").to_string();
        let spec = ServiceSpec::new_with_loaded_config_digest(
            ServicePlatform::SystemdUser,
            &binary,
            &config,
            &temp.path().join("data"),
            BTreeMap::new(),
            &BTreeSet::new(),
            parsed_digest.clone(),
        )
        .unwrap();
        assert_eq!(spec.config_digest, parsed_digest);
    }

    fn running_status_for(spec: &ServiceSpec) -> kata_client::types::SystemStatus {
        serde_json::from_value(serde_json::json!({
            "node_id": "main",
            "process_mode": "installed",
            "directory_id": spec.data_directory_id,
            "process_generation": "generation",
            "attachment_protocol_version": 1,
            "binary_version": spec.binary_version,
            "loaded_binary_digest": spec.binary_digest,
            "control_endpoint": "http://127.0.0.1:8400",
            "loaded_config_digest": spec.config_digest,
            "loaded_config_path": spec.config,
            "loaded_service_environment_digest": spec.environment_digest,
            "recovery_state": "ready",
            "ready": true,
            "uptime_seconds": 1
        }))
        .unwrap()
    }

    #[test]
    fn product_ready_identity_requires_every_loaded_service_input() {
        for platform in [
            ServicePlatform::SystemdUser,
            ServicePlatform::LaunchdAppleSilicon,
        ] {
            let (_temp, mut spec, _plan) = drift_fixture();
            spec.platform = platform;
            let definition = spec.render();
            let exact = running_status_for(&spec);
            assert_eq!(
                running_identity_mismatch(&definition, &exact, None).unwrap(),
                None
            );

            let mut stale = running_status_for(&spec);
            stale.loaded_config_digest = Some("stale-config".to_string());
            let mismatch = running_identity_mismatch(&definition, &stale, None)
                .unwrap()
                .expect("stale already-active process must not satisfy start");
            assert!(mismatch.contains("config_digest"), "{mismatch}");

            let mut stale = running_status_for(&spec);
            stale.loaded_service_environment_digest = Some("stale-environment".to_string());
            let mismatch = running_identity_mismatch(&definition, &stale, None)
                .unwrap()
                .expect("stale already-active environment must not satisfy start");
            assert!(mismatch.contains("environment_digest"), "{mismatch}");

            let mut stale = running_status_for(&spec);
            stale.loaded_binary_digest = Some("stale-binary".to_string());
            let mismatch = running_identity_mismatch(&definition, &stale, None)
                .unwrap()
                .expect("stale already-active binary must not satisfy start");
            assert!(mismatch.contains("binary_digest"), "{mismatch}");

            let stale_generation =
                running_identity_mismatch(&definition, &exact, exact.process_generation.as_deref())
                    .unwrap()
                    .expect("restart must observe a new process generation");
            assert!(
                stale_generation.contains("process_generation"),
                "{stale_generation}"
            );
        }
    }
}
