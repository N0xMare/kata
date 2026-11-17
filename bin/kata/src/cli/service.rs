use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use kata_core::ConfigManager;
use kata_types::config::{ApiAuthConfig, KataConfig, WorkerTransportConfig};
use kata_types::execution_contract::credential_env_refusal;
use kata_types::metering::CredentialMode;

use crate::attachment::{
    InstalledDiscoveryLease, InstalledLifecycleOperationLease, SERVICE_DISCOVERY_LEASE_FD_ENV,
};
#[cfg(test)]
use crate::authority_file::MAX_SERVICE_ENVIRONMENT_BYTES;
use crate::authority_file::{
    SERVICE_CONFIG_SNAPSHOT_FD_ENV, config_policy, open_digest_snapshot, prepare_exec_handoff,
};
#[cfg(test)]
use crate::data_dir_lock::DataDirLock;
use crate::data_dir_lock::{
    InstalledDataDirLock, MainMode, inspect_identity, inspect_lock_metadata,
    resolve_config_data_dir,
};
use crate::service::{
    InstalledServiceLifecycleAction, InstalledServicePublicationPermit, ServiceAction,
    ServiceExecLaunchIdentity, ServicePlan, ServiceSpec, apply_install, apply_installed_lifecycle,
    apply_uninstall, current_platform, logs_installed, preflight_install, preview_install,
    preview_installed, require_unprivileged_service_owner, status_installed,
    validate_current_service_exec_definition,
};
use kata_worker::owner_home::effective_owner_home;

use super::types::ServiceCmd;

pub(super) const SERVICE_ENVIRONMENT_DIGEST_ENV: &str = "KATA_SERVICE_ENVIRONMENT_DIGEST";
pub(super) const SERVICE_EXPECTED_BINARY_DIGEST_ENV: &str = "KATA_SERVICE_EXPECTED_BINARY_DIGEST";
pub(super) const SERVICE_EXPECTED_CONFIG_DIGEST_ENV: &str = "KATA_SERVICE_EXPECTED_CONFIG_DIGEST";
pub(super) const SERVICE_EXPECTED_DATA_DIRECTORY_ENV: &str = "KATA_SERVICE_EXPECTED_DATA_DIRECTORY";
pub(super) const SERVICE_EXPECTED_DIRECTORY_ID_ENV: &str = "KATA_SERVICE_EXPECTED_DIRECTORY_ID";

macro_rules! define_service_exec_handoff_keys {
    ($($variant:ident => ($name:expr, $identity:literal)),+ $(,)?) => {
        /// Complete typed inventory for the one-shot native-service exec
        /// handoff. The producer, validator, consumer, and scrubber all iterate
        /// this same set; adding a key here makes the value match exhaustive and
        /// automatically adds the key to descendant scrubbing.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum ServiceExecHandoffKey {
            $($variant),+
        }

        impl ServiceExecHandoffKey {
            pub(super) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(super) const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name),+
                }
            }

            pub(super) const fn is_identity(self) -> bool {
                match self {
                    $(Self::$variant => $identity),+
                }
            }
        }
    };
}

define_service_exec_handoff_keys! {
    EnvironmentDigest => (SERVICE_ENVIRONMENT_DIGEST_ENV, true),
    ExpectedBinaryDigest => (SERVICE_EXPECTED_BINARY_DIGEST_ENV, true),
    ExpectedConfigDigest => (SERVICE_EXPECTED_CONFIG_DIGEST_ENV, true),
    ExpectedDataDirectory => (SERVICE_EXPECTED_DATA_DIRECTORY_ENV, true),
    ExpectedDirectoryId => (SERVICE_EXPECTED_DIRECTORY_ID_ENV, true),
    DiscoveryLeaseDescriptor => (SERVICE_DISCOVERY_LEASE_FD_ENV, false),
    ConfigSnapshotDescriptor => (SERVICE_CONFIG_SNAPSHOT_FD_ENV, false),
}

/// Values for [`ServiceExecHandoffKey::ALL`]. The exhaustive [`Self::value`]
/// match makes a new producer key a compile error until its value is supplied.
struct ServiceExecHandoffLaunchEnvironment {
    environment_digest: std::ffi::OsString,
    binary_digest: std::ffi::OsString,
    config_digest: std::ffi::OsString,
    data_directory: std::ffi::OsString,
    directory_id: std::ffi::OsString,
    discovery_descriptor: std::ffi::OsString,
    config_descriptor: std::ffi::OsString,
}

impl ServiceExecHandoffLaunchEnvironment {
    fn new(
        environment_digest: &str,
        binary_digest: &str,
        config_digest: &str,
        data_directory: &std::path::Path,
        directory_id: &str,
        discovery_descriptor: i32,
        config_descriptor: i32,
    ) -> Self {
        Self {
            environment_digest: environment_digest.into(),
            binary_digest: binary_digest.into(),
            config_digest: config_digest.into(),
            data_directory: data_directory.as_os_str().to_owned(),
            directory_id: directory_id.into(),
            discovery_descriptor: discovery_descriptor.to_string().into(),
            config_descriptor: config_descriptor.to_string().into(),
        }
    }

    fn value(&self, key: ServiceExecHandoffKey) -> &std::ffi::OsStr {
        match key {
            ServiceExecHandoffKey::EnvironmentDigest => &self.environment_digest,
            ServiceExecHandoffKey::ExpectedBinaryDigest => &self.binary_digest,
            ServiceExecHandoffKey::ExpectedConfigDigest => &self.config_digest,
            ServiceExecHandoffKey::ExpectedDataDirectory => &self.data_directory,
            ServiceExecHandoffKey::ExpectedDirectoryId => &self.directory_id,
            ServiceExecHandoffKey::DiscoveryLeaseDescriptor => &self.discovery_descriptor,
            ServiceExecHandoffKey::ConfigSnapshotDescriptor => &self.config_descriptor,
        }
    }

    fn apply_to(&self, command: &mut std::process::Command) {
        for key in ServiceExecHandoffKey::ALL {
            command.env(key.name(), self.value(*key));
        }
    }
}

/// Load the owner-only environment snapshot and replace this trampoline with
/// the ordinary `kata serve` process. Values never appear in the unit/plist or
/// process argument vector; `service install --apply` refreshes the snapshot.
pub(crate) fn run_service_exec(
    definition: PathBuf,
    environment: PathBuf,
    config: PathBuf,
    expected_binary_digest: String,
    expected_config_digest: String,
    expected_environment_digest: String,
    expected_data_directory: PathBuf,
    expected_directory_id: String,
) -> Result<()> {
    require_unprivileged_service_owner()?;
    #[cfg(unix)]
    {
        with_installed_startup_lease(|lease| {
            use std::os::unix::process::CommandExt as _;

            // The manager may have snapshotted this argv before the lease was
            // available. Re-read the current definition under the lease and
            // reject every stale launch-bound field before reading its files.
            let binary = std::env::current_exe().context("resolving Kata service executable")?;
            let working_directory =
                std::env::current_dir().context("resolving Kata service working directory")?;
            validate_current_service_exec_definition(&ServiceExecLaunchIdentity {
                definition: &definition,
                binary: &binary,
                environment: &environment,
                config: &config,
                working_directory: &working_directory,
                binary_digest: &expected_binary_digest,
                config_digest: &expected_config_digest,
                environment_digest: &expected_environment_digest,
                data_directory: &expected_data_directory,
                directory_id: &expected_directory_id,
            })?;

            // This descriptor crosses exec without an unlock window and is
            // adopted before `serve` reads the config.
            let identity = validate_service_exec_inputs(
                &binary,
                &config,
                &environment,
                &expected_binary_digest,
                &expected_config_digest,
                &expected_environment_digest,
            )?;
            let discovery_descriptor = lease.prepare_service_exec_handoff()?;
            let config_descriptor =
                prepare_exec_handoff(&identity.config_snapshot, "installed config snapshot")?;
            let handoff = ServiceExecHandoffLaunchEnvironment::new(
                &identity.environment_digest,
                &identity.binary_digest,
                &expected_config_digest,
                &expected_data_directory,
                &expected_directory_id,
                discovery_descriptor,
                config_descriptor,
            );
            let mut command = std::process::Command::new(binary);
            command.env_clear().envs(&identity.environment);
            // Apply the complete typed handoff after the snapshot so
            // operator-provided keys cannot spoof its identity or descriptors.
            // ConfigManager checks the digest of the exact bytes it parses,
            // closing the path-replacement window.
            handoff.apply_to(&mut command);
            let error = command.arg("serve").arg("--config").arg(config).exec();
            Err(error).context("execing installed Kata main from service trampoline")
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (
            definition,
            environment,
            config,
            expected_binary_digest,
            expected_config_digest,
            expected_environment_digest,
            expected_data_directory,
            expected_directory_id,
        );
        anyhow::bail!("Kata native service execution currently requires Linux or macOS")
    }
}

fn with_installed_startup_lease<T>(
    operation: impl FnOnce(&InstalledDiscoveryLease) -> Result<T>,
) -> Result<T> {
    with_installed_startup_lease_using(InstalledDiscoveryLease::acquire, operation)
}

fn with_installed_startup_lease_using<L, T>(
    acquire: impl FnOnce() -> Result<L>,
    operation: impl FnOnce(&L) -> Result<T>,
) -> Result<T> {
    let lease = acquire().context(
        "failed to acquire the per-owner discovery lease before reading installed service inputs",
    )?;
    operation(&lease)
}

#[derive(Debug)]
struct ValidatedServiceExecInputs {
    environment: BTreeMap<String, String>,
    binary_digest: String,
    environment_digest: String,
    config_snapshot: std::fs::File,
}

fn validate_service_exec_inputs(
    binary: &std::path::Path,
    config: &std::path::Path,
    environment: &std::path::Path,
    expected_binary_digest: &str,
    expected_config_digest: &str,
    expected_environment_digest: &str,
) -> Result<ValidatedServiceExecInputs> {
    let binary_digest = crate::service::current_binary_digest(binary)?;
    require_expected_digest("binary", expected_binary_digest, &binary_digest)?;
    let (config_snapshot, config_digest) = open_digest_snapshot(config, config_policy())?;
    require_expected_digest("config", expected_config_digest, &config_digest)?;

    let bytes = crate::service::read_installed_service_environment(environment)?;
    let environment_digest = kata_crypto::blake3_bytes(&bytes).to_string();
    require_expected_digest(
        "owner-only environment",
        expected_environment_digest,
        &environment_digest,
    )?;
    let values: BTreeMap<String, String> = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing owner-only service environment {}",
            environment.display()
        )
    })?;
    for key in values.keys() {
        if key.is_empty()
            || !key.bytes().enumerate().all(|(index, byte)| {
                byte == b'_'
                    || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
            })
        {
            anyhow::bail!("service environment contains invalid key {key:?}");
        }
    }
    Ok(ValidatedServiceExecInputs {
        environment: values,
        binary_digest,
        environment_digest,
        config_snapshot,
    })
}

fn require_expected_digest(kind: &str, expected: &str, current: &str) -> Result<()> {
    if expected != current {
        anyhow::bail!(
            "installed Kata service {kind} identity drifted (installed digest {expected}, current digest {current}); stop the service, run `kata service install --config <path> --apply`, then start it"
        );
    }
    Ok(())
}

pub(crate) fn run_service_cmd(command: ServiceCmd) -> Result<()> {
    let platform = current_platform()?;
    match command {
        ServiceCmd::Install {
            config,
            apply: true,
        } => {
            // Acquire in the global order before loading or planning. The
            // combined permit is then consumed only after install-time data
            // directory initialization has borrowed the same two guards.
            let lifecycle = acquire_lifecycle_operation_lease("install")?;
            let discovery = acquire_service_mutation_lease("install")?;
            let permit = InstalledServicePublicationPermit::new(&lifecycle, &discovery);
            let mut spec = load_spec(config, platform, &process_environment)?;
            let identity = ensure_service_data_dir_identity_after_preflight(
                platform,
                &permit,
                &spec.data_dir,
            )?;
            // The installed definition binds the identity created above, not
            // the pre-install "uninitialized" preview state. Do not reload
            // config here: one install owns exactly the snapshot used to
            // select and initialize this directory.
            spec.data_directory_id = identity.directory_id;
            finish_service_command(apply_install(&spec, permit)?, true);
        }
        ServiceCmd::Install {
            config,
            apply: false,
        } => {
            let spec = load_spec(config, platform, &process_environment)?;
            finish_service_command(preview_install(&spec)?, false);
        }
        ServiceCmd::Start { apply: true } => {
            let lifecycle = acquire_lifecycle_operation_lease("start")?;
            finish_service_command(
                apply_installed_lifecycle(
                    platform,
                    InstalledServiceLifecycleAction::Start,
                    &lifecycle,
                )?,
                true,
            );
        }
        ServiceCmd::Start { apply: false } => {
            finish_service_command(preview_installed(platform, ServiceAction::Start)?, false);
        }
        ServiceCmd::Stop { apply: true } => {
            let lifecycle = acquire_lifecycle_operation_lease("stop")?;
            finish_service_command(
                apply_installed_lifecycle(
                    platform,
                    InstalledServiceLifecycleAction::Stop,
                    &lifecycle,
                )?,
                true,
            );
        }
        ServiceCmd::Stop { apply: false } => {
            finish_service_command(preview_installed(platform, ServiceAction::Stop)?, false);
        }
        ServiceCmd::Restart { apply: true } => {
            let lifecycle = acquire_lifecycle_operation_lease("restart")?;
            finish_service_command(
                apply_installed_lifecycle(
                    platform,
                    InstalledServiceLifecycleAction::Restart,
                    &lifecycle,
                )?,
                true,
            );
        }
        ServiceCmd::Restart { apply: false } => {
            finish_service_command(preview_installed(platform, ServiceAction::Restart)?, false);
        }
        ServiceCmd::Status => finish_service_command(status_installed(platform)?, true),
        ServiceCmd::Logs => finish_service_command(logs_installed(platform)?, true),
        ServiceCmd::Uninstall { apply: true } => {
            let lifecycle = acquire_lifecycle_operation_lease("uninstall")?;
            let discovery = acquire_service_mutation_lease("uninstall")?;
            let permit = InstalledServicePublicationPermit::new(&lifecycle, &discovery);
            finish_service_command(apply_uninstall(platform, permit)?, true);
        }
        ServiceCmd::Uninstall { apply: false } => finish_service_command(
            preview_installed(platform, ServiceAction::Uninstall)?,
            false,
        ),
    }
    Ok(())
}

fn finish_service_command(plan: ServicePlan, applied: bool) {
    print_plan(&plan, applied);
    if plan.action == ServiceAction::Status {
        print_product_status(&plan);
    }
}

fn ensure_service_data_dir_identity_after_preflight(
    platform: crate::service::ServicePlatform,
    permit: &InstalledServicePublicationPermit<'_>,
    data_dir: &std::path::Path,
) -> Result<crate::data_dir_lock::DataDirIdentity> {
    ensure_service_data_dir_identity_after_preflight_with(
        || preflight_install(platform),
        || ensure_service_data_dir_identity(permit, data_dir),
    )
}

fn ensure_service_data_dir_identity_after_preflight_with<T>(
    preflight: impl FnOnce() -> Result<()>,
    initialize: impl FnOnce() -> Result<T>,
) -> Result<T> {
    // The fixed definition and native-manager target are authority. Prove
    // them exact under both lifecycle leases before config-driven data-dir
    // initialization can mutate any project state.
    preflight()?;
    initialize()
}

fn acquire_lifecycle_operation_lease(
    action_name: &'static str,
) -> Result<InstalledLifecycleOperationLease> {
    acquire_lifecycle_operation_lease_with(action_name, InstalledLifecycleOperationLease::acquire)
}

fn acquire_lifecycle_operation_lease_with<T>(
    action_name: &'static str,
    acquire: impl FnOnce() -> Result<T>,
) -> Result<T> {
    acquire().with_context(|| {
        format!("service {action_name} could not serialize against another lifecycle operation")
    })
}

fn acquire_service_mutation_lease(action_name: &'static str) -> Result<InstalledDiscoveryLease> {
    acquire_service_mutation_lease_with(action_name, InstalledDiscoveryLease::acquire)
}

fn acquire_service_mutation_lease_with<T>(
    action_name: &'static str,
    acquire: impl FnOnce() -> Result<T>,
) -> Result<T> {
    acquire()
        .with_context(|| {
            format!(
                "service {action_name} requires the installed main to be stopped and its per-owner discovery lease to be safe and free"
            )
        })
}

fn ensure_service_data_dir_identity(
    permit: &InstalledServicePublicationPermit<'_>,
    data_dir: &std::path::Path,
) -> Result<crate::data_dir_lock::DataDirIdentity> {
    if let Some(identity) = inspect_identity(data_dir)? {
        if identity.mode != MainMode::Installed {
            anyhow::bail!(
                "service installation refuses {:?} data-directory identity at {}",
                identity.mode,
                data_dir.display()
            );
        }
        return Ok(identity);
    }
    let discovery_lease = permit.discovery_lease();
    let guard = InstalledDataDirLock::acquire(discovery_lease, data_dir, None)
        .context("service install could not initialize installed-main identity")?;
    let identity = guard.identity().clone();
    drop(guard);
    Ok(identity)
}

fn print_product_status(plan: &ServicePlan) {
    let expected = crate::service::definition_directory_id(&plan.definition);
    let data_dir = crate::service::definition_data_dir(&plan.definition);
    print_binary_status(&plan.definition);
    print_config_status(&plan.definition);
    print_environment_status(plan);
    print_data_directory_status(&plan.definition);
    if let Some(data_dir) = data_dir.as_ref() {
        let lock_path = data_dir.join("main.lock");
        match inspect_lock_metadata(data_dir) {
            Ok(Some(metadata)) => println!(
                "  lock_metadata: pid={} directory_id={} generation={} mode={:?}",
                metadata.pid, metadata.directory_id, metadata.process_generation, metadata.mode
            ),
            Ok(None) => println!(
                "  lock_metadata: unavailable at {} (kernel lock, not this file, is authority)",
                lock_path.display()
            ),
            Err(error) => println!(
                "  lock_metadata: unsafe or unreadable at {} ({error:#}; kernel lock, not this file, is authority)",
                lock_path.display()
            ),
        }
    }
    match crate::attachment::connect_verified_attached_main_sync(None) {
        Ok(attached) => {
            println!("  product: ready");
            println!("  endpoint: {}", attached.endpoint);
            println!("  process_mode: {}", attached.status.process_mode);
            println!(
                "  binary_version: {}",
                attached
                    .status
                    .binary_version
                    .as_deref()
                    .unwrap_or("unknown")
            );
            println!(
                "  running_binary_digest: {}",
                attached
                    .status
                    .loaded_binary_digest
                    .as_deref()
                    .unwrap_or("unknown")
            );
            match running_binary_matches_definition(
                &plan.definition,
                attached.status.loaded_binary_digest.as_deref(),
            ) {
                Some(true) => println!("  running_binary_digest_drift: none"),
                Some(false) => {
                    println!("  running_binary_digest_drift: detected");
                    println!(
                        "  running_binary_digest_next_action: run `kata service restart --apply` to load the installed executable"
                    );
                }
                None => {
                    println!("  running_binary_digest_drift: unverifiable");
                    println!(
                        "  running_binary_digest_next_action: stop the service, reinstall its definition, then start it"
                    );
                }
            }
            match (
                crate::service::definition_binary_version(&plan.definition),
                attached.status.binary_version.as_deref(),
            ) {
                (Some(installed), Some(running)) if installed == running => {
                    println!("  running_binary_version_drift: none");
                }
                (Some(installed), Some(running)) => {
                    println!(
                        "  running_binary_version_drift: detected (installed={installed}, running={running})"
                    );
                    println!(
                        "  running_binary_next_action: stop the service, reinstall the intended Kata binary and definition, then start it"
                    );
                }
                _ => println!("  running_binary_version_drift: unverifiable"),
            }
            println!(
                "  control_endpoint: {}",
                attached
                    .status
                    .control_endpoint
                    .as_deref()
                    .unwrap_or("unknown")
            );
            println!(
                "  running_config_digest: {}",
                attached
                    .status
                    .loaded_config_digest
                    .as_deref()
                    .unwrap_or("unknown")
            );
            println!(
                "  running_config_path: {}",
                attached
                    .status
                    .loaded_config_path
                    .as_deref()
                    .unwrap_or("unknown")
            );
            match running_config_matches_definition(
                &plan.definition,
                attached.status.loaded_config_digest.as_deref(),
                attached.status.loaded_config_path.as_deref(),
            ) {
                Some(true) => println!("  running_config_drift: none"),
                Some(false) => {
                    println!("  running_config_drift: detected");
                    println!(
                        "  running_config_next_action: run `kata service restart --apply` to load the installed config"
                    );
                }
                _ => {
                    println!("  running_config_drift: unverifiable");
                    println!(
                        "  running_config_next_action: stop the service, reinstall its definition, then start it"
                    );
                }
            }
            println!(
                "  running_service_environment_digest: {}",
                attached
                    .status
                    .loaded_service_environment_digest
                    .as_deref()
                    .unwrap_or("unknown")
            );
            match running_environment_matches_definition(
                &plan.definition,
                attached.status.loaded_service_environment_digest.as_deref(),
            ) {
                Some(true) => {
                    println!("  running_service_environment_drift: none");
                }
                Some(false) => {
                    println!("  running_service_environment_drift: detected");
                    println!(
                        "  running_service_environment_next_action: run `kata service restart --apply` to load the installed environment"
                    );
                }
                _ => {
                    println!("  running_service_environment_drift: unverifiable");
                    println!(
                        "  running_service_environment_next_action: stop the service, reinstall its definition, then start it"
                    );
                }
            }
            println!(
                "  directory_id: {}",
                attached.status.directory_id.as_deref().unwrap_or("unknown")
            );
            println!(
                "  process_generation: {}",
                attached
                    .status
                    .process_generation
                    .as_deref()
                    .unwrap_or("unknown")
            );
            println!("  recovery_state: {}", attached.status.recovery_state);
            if let Some(action) = attached.status.next_action {
                println!("  next_action: {action}");
            } else {
                println!("  next_action: none");
            }
            if expected.as_deref() != attached.status.directory_id.as_deref() {
                println!(
                    "  definition_mismatch: expected directory_id={:?}; next_action: stop and reinstall the service with the intended config",
                    expected
                );
            }
        }
        Err(error) => {
            println!("  product: not-ready");
            println!(
                "  expected_directory_id: {}",
                expected.as_deref().unwrap_or("unknown")
            );
            println!("  attachment: {error:#}");
            println!(
                "  next_action: inspect `kata service logs`; then run `kata service start --apply` or reinstall the definition"
            );
        }
    }
}

fn print_binary_status(definition: &str) {
    let path = crate::service::definition_binary_path(definition);
    let installed = crate::service::definition_binary_digest(definition);
    println!(
        "  binary_path: {}",
        path.as_ref()
            .map_or_else(|| "unknown".to_string(), |path| path.display().to_string())
    );
    println!(
        "  installed_binary_digest: {}",
        installed.as_deref().unwrap_or("unknown")
    );
    let (Some(path), Some(installed)) = (path, installed) else {
        println!("  current_binary_digest: unknown");
        println!("  binary_drift: unverifiable");
        println!("  binary_next_action: stop the service, reinstall its definition, then start it");
        return;
    };
    match crate::service::current_binary_digest(&path) {
        Ok(current) if current == installed => {
            println!("  current_binary_digest: {current}");
            println!("  binary_drift: none");
        }
        Ok(current) => {
            println!("  current_binary_digest: {current}");
            println!("  binary_drift: detected");
            println!(
                "  binary_next_action: stop the service, reinstall the intended Kata binary, run `kata service install --config <path> --apply`, then start it"
            );
        }
        Err(error) => {
            println!("  current_binary_digest: unavailable ({error:#})");
            println!("  binary_drift: unverifiable");
        }
    }
}

fn running_config_matches_definition(
    definition: &str,
    running_digest: Option<&str>,
    running_path: Option<&str>,
) -> Option<bool> {
    let installed_digest = crate::service::definition_config_digest(definition)?;
    let installed_path = crate::service::definition_config_path(definition)?;
    Some(
        running_digest == Some(installed_digest.as_str())
            && running_path.is_some_and(|path| installed_path == std::path::Path::new(path)),
    )
}

fn running_binary_matches_definition(
    definition: &str,
    running_digest: Option<&str>,
) -> Option<bool> {
    let installed = crate::service::definition_binary_digest(definition)?;
    Some(running_digest == Some(installed.as_str()))
}

fn running_environment_matches_definition(
    definition: &str,
    running_digest: Option<&str>,
) -> Option<bool> {
    let installed = crate::service::definition_environment_digest(definition)?;
    Some(running_digest == Some(installed.as_str()))
}

fn print_environment_status(plan: &ServicePlan) {
    let installed = crate::service::definition_environment_digest(&plan.definition);
    let current = crate::service::current_environment_digest(&plan.environment_path);
    println!(
        "  service_environment_path: {}",
        plan.environment_path.display()
    );
    println!(
        "  installed_service_environment_digest: {}",
        installed.as_deref().unwrap_or("unknown")
    );
    match (installed, current) {
        (Some(installed), Ok(current)) if installed == current => {
            println!("  current_service_environment_digest: {current}");
            println!("  service_environment_drift: none");
        }
        (Some(_), Ok(current)) => {
            println!("  current_service_environment_digest: {current}");
            println!("  service_environment_drift: detected");
            println!(
                "  service_environment_next_action: stop the service, run `kata service install --config <path> --apply`, then start it"
            );
        }
        (_, Err(error)) => {
            println!("  current_service_environment_digest: unavailable ({error:#})");
            println!("  service_environment_drift: unverifiable");
            println!(
                "  service_environment_next_action: stop the service, reinstall its definition to restore the owner-only environment snapshot, then start it"
            );
        }
        (None, Ok(current)) => {
            println!("  current_service_environment_digest: {current}");
            println!("  service_environment_drift: unverifiable");
            println!(
                "  service_environment_next_action: stop the service, reinstall its definition to add environment identity metadata, then start it"
            );
        }
    }
}

fn data_directory_identity_mismatch(definition: &str) -> Result<Option<String>> {
    let path = crate::service::definition_data_dir(definition).ok_or_else(|| {
        anyhow::anyhow!("installed service definition has no data-directory path identity")
    })?;
    let expected = crate::service::definition_directory_id(definition).ok_or_else(|| {
        anyhow::anyhow!("installed service definition has no data-directory ID identity")
    })?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Some(format!(
                "installed path {} is missing (expected directory_id={expected})",
                path.display()
            )));
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspecting installed service data directory {}",
                    path.display()
                )
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Ok(Some(format!(
            "installed path {} is now a symlink (expected directory_id={expected})",
            path.display()
        )));
    }
    let Some(current) = inspect_identity(&path)? else {
        return Ok(Some(format!(
            "installed path {} has no immutable identity (expected directory_id={expected})",
            path.display()
        )));
    };
    if current.mode != MainMode::Installed || current.directory_id != expected {
        return Ok(Some(format!(
            "installed path {} expected directory_id={expected}, mode=Installed; current directory_id={}, mode={:?}",
            path.display(),
            current.directory_id,
            current.mode
        )));
    }
    Ok(None)
}

fn print_data_directory_status(definition: &str) {
    println!(
        "  data_directory_path: {}",
        crate::service::definition_data_dir(definition)
            .map_or_else(|| "unknown".to_string(), |path| path.display().to_string())
    );
    println!(
        "  installed_directory_id: {}",
        crate::service::definition_directory_id(definition)
            .as_deref()
            .unwrap_or("unknown")
    );
    match data_directory_identity_mismatch(definition) {
        Ok(None) => println!("  data_directory_identity_drift: none"),
        Ok(Some(mismatch)) => {
            println!("  data_directory_identity_drift: detected ({mismatch})");
            println!(
                "  data_directory_identity_next_action: preserve the drifted directory offline and reinstall the service with the intended config and data directory; do not copy or relabel its identity, or start against the drifted path"
            );
        }
        Err(error) => {
            println!("  data_directory_identity_drift: unverifiable ({error:#})");
            println!(
                "  data_directory_identity_next_action: inspect the data-directory path and permissions before start/restart"
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DefinitionConfigState {
    InSync {
        path: PathBuf,
        digest: String,
    },
    Drifted {
        path: PathBuf,
        installed_digest: String,
        current_digest: String,
    },
    Unreadable {
        path: PathBuf,
        installed_digest: String,
        error: String,
    },
    MissingMetadata {
        installed_digest: Option<String>,
        path: Option<PathBuf>,
    },
}

fn inspect_definition_config(definition: &str) -> DefinitionConfigState {
    let installed_digest = crate::service::definition_config_digest(definition);
    let path = crate::service::definition_config_path(definition);
    let (installed_digest, path) = match (installed_digest, path) {
        (Some(installed_digest), Some(path)) => (installed_digest, path),
        (installed_digest, path) => {
            return DefinitionConfigState::MissingMetadata {
                installed_digest,
                path,
            };
        }
    };
    match crate::service::current_config_digest(&path) {
        Ok(current_digest) if current_digest == installed_digest => DefinitionConfigState::InSync {
            path,
            digest: installed_digest,
        },
        Ok(current_digest) => DefinitionConfigState::Drifted {
            path,
            installed_digest,
            current_digest,
        },
        Err(error) => DefinitionConfigState::Unreadable {
            path,
            installed_digest,
            error: format!("{error:#}"),
        },
    }
}

fn print_config_status(definition: &str) {
    match inspect_definition_config(definition) {
        DefinitionConfigState::InSync { path, digest } => {
            println!("  config_path: {}", path.display());
            println!("  installed_config_digest: {digest}");
            println!("  current_config_digest: {digest}");
            println!("  config_drift: none");
        }
        DefinitionConfigState::Drifted {
            path,
            installed_digest,
            current_digest,
        } => {
            println!("  config_path: {}", path.display());
            println!("  installed_config_digest: {installed_digest}");
            println!("  current_config_digest: {current_digest}");
            println!("  config_drift: detected");
            println!(
                "  config_next_action: stop the service, run `kata service install --config {} --apply`, then start it",
                path.display()
            );
        }
        DefinitionConfigState::Unreadable {
            path,
            installed_digest,
            error,
        } => {
            println!("  config_path: {}", path.display());
            println!("  installed_config_digest: {installed_digest}");
            println!("  current_config_digest: unavailable ({error})");
            println!("  config_drift: unverifiable");
            println!(
                "  config_next_action: restore {}, or reinstall the service with the intended config",
                path.display()
            );
        }
        DefinitionConfigState::MissingMetadata {
            installed_digest,
            path,
        } => {
            println!(
                "  config_path: {}",
                path.as_ref()
                    .map_or_else(|| "unknown".to_string(), |path| path.display().to_string())
            );
            println!(
                "  installed_config_digest: {}",
                installed_digest.as_deref().unwrap_or("unknown")
            );
            println!("  current_config_digest: unknown");
            println!("  config_drift: unverifiable");
            println!(
                "  config_next_action: stop the service, reinstall with `kata service install --config <path> --apply`, then start it"
            );
        }
    }
}

/// Where the install reads the variables it snapshots: the installing process's
/// own environment in production (`.env` already loaded, as for any ordinary CLI
/// process), a fixture in a cell. The raw value: [`snapshot_text`] refuses one
/// that is not UTF-8 by its name.
type InstallEnvironment<'a> = &'a dyn Fn(&str) -> Option<std::ffi::OsString>;

/// The installing process's environment.
fn process_environment(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key)
}

/// `key`'s value in the installing environment as the snapshot holds it, text:
/// `None` when it is unset, and a refusal naming `key` (never the value) when it
/// is set to a value that is not UTF-8 — the snapshot cannot carry it, and
/// reading it as unset would send the operator after the wrong mistake.
fn snapshot_text(key: &str, env: InstallEnvironment<'_>) -> Result<Option<String>> {
    env(key)
        .map(|value| {
            value.into_string().map_err(|_| {
                anyhow::anyhow!(
                    "service environment variable {key:?} is set to a value that is not UTF-8 \
                     in the installing environment; the service's environment snapshot holds \
                     text, so re-export it as UTF-8"
                )
            })
        })
        .transpose()
}

fn load_spec(
    supplied_config_path: PathBuf,
    platform: crate::service::ServicePlatform,
    env: InstallEnvironment<'_>,
) -> Result<ServiceSpec> {
    let manager = ConfigManager::load(&supplied_config_path)
        .with_context(|| format!("loading service config {}", supplied_config_path.display()))?;
    service_spec_from_loaded_manager(&manager, platform, env)
}

fn service_spec_from_loaded_manager(
    manager: &ConfigManager,
    platform: crate::service::ServicePlatform,
    env: InstallEnvironment<'_>,
) -> Result<ServiceSpec> {
    // ConfigManager binds this canonical path to the exact bytes it parsed.
    // Preserve that pair. Re-resolving the caller's path—or canonicalizing
    // this one again—would allow an atomic symlink/path replacement to combine
    // A's digest and policy with B's path in the installed definition.
    let config_path = manager.path().to_path_buf();
    let config_digest = manager
        .initial_content_digest()
        .expect("ConfigManager::load records the digest of the exact parsed bytes")
        .to_string();
    let config = manager.snapshot();
    let data_dir = resolve_config_data_dir(&config_path, &config.node.data_dir)?;
    if inspect_identity(&data_dir)?.is_some_and(|identity| identity.mode == MainMode::Scratch) {
        anyhow::bail!(
            "service installation refuses scratch data directory {}; choose the installed-main directory",
            data_dir.display()
        );
    }
    let binary = std::env::current_exe().context("resolving installed Kata binary")?;
    let (environment, declared_environment) = service_environment(&config, env)?;
    ServiceSpec::new_with_loaded_config_digest(
        platform,
        &binary,
        &config_path,
        &data_dir,
        environment,
        &declared_environment,
        config_digest,
    )
}

fn service_environment(
    config: &KataConfig,
    env: InstallEnvironment<'_>,
) -> Result<(BTreeMap<String, String>, BTreeSet<String>)> {
    const KEYS: &[&str] = &[
        "PATH",
        "XDG_RUNTIME_DIR",
        "XDG_STATE_HOME",
        "RUST_LOG",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "KATA_LOG",
        "KATA_RERUN_REPEATABILITY",
        "KATA_STDLIB_DIR",
    ];
    let mut environment = BTreeMap::new();
    for key in KEYS {
        if let Some(value) = snapshot_text(key, env)? {
            environment.insert((*key).to_string(), value);
        }
    }
    let owner_home = effective_owner_home()?
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("effective Kata owner account home is not Unicode"))?;
    environment.insert("HOME".to_string(), owner_home);
    let mut declared = BTreeSet::new();
    if let ApiAuthConfig::SignedToken {
        verifying_key_env: Some(key),
        ..
    } = &config.api.auth
    {
        inherit_required(
            key,
            "api.auth.verifying_key_env",
            env,
            &mut environment,
            &mut declared,
        )?;
    }
    // The node's provider declaration: the supervised node learns its
    // containment provider ONLY from these keys (it inherits the main's
    // environment), and `kata host setup` writes
    // them to the project `.env`, which the service never reads. Each is copied
    // when the installing process has it; a blank value is absent, the
    // worker's own reading. They are node configuration, not a credential, so
    // they ride the bounded allowlist rather than the config-declared set.
    let mut undeclared_provider_keys = Vec::new();
    for key in kata_worker::NODE_PROVIDER_ENV_KEYS {
        match snapshot_text(key, env)?.filter(|value| !value.trim().is_empty()) {
            Some(value) => {
                environment.insert(key.to_string(), value);
            }
            None => undeclared_provider_keys.push(key),
        }
    }
    // The service runs under exactly this snapshot (the trampoline clears its
    // environment), and the supervised node — a child of the main — lifts an
    // `env:<VAR>` key from the environment it inherits — so an API-key agent's
    // variable is copied here at install time, or the installed main's node
    // could never deliver it. Without a `supervised_node` transport the main
    // starts no node: an external local-socket worker lifts the key from its
    // own environment, so the main's snapshot neither needs nor carries it.
    let supervised_node = config
        .workers
        .transports
        .iter()
        .any(|transport| matches!(transport, WorkerTransportConfig::SupervisedNode {}));
    if !supervised_node {
        return Ok((environment, declared));
    }
    for (label, agent) in &config.agents {
        let Some(credential) = agent.capsule_credential() else {
            continue;
        };
        if CredentialMode::from_label(&credential.mode) != Some(CredentialMode::ApiKey) {
            continue;
        }
        let Some(key) = credential.source.strip_prefix("env:") else {
            continue;
        };
        let source = format!("agents.{label}.credential.source");
        // A name the worker refuses to deliver a credential through — one
        // kata's own plumbing holds (`PATH`, `HOME`, a proxy name) or the
        // worker keeps for its user-manager clients (`XDG_RUNTIME_DIR`).
        if let Some(why) = credential_env_refusal(key) {
            anyhow::bail!("{source} names {key:?}, which no worker delivers: {why}");
        }
        inherit_required(key, &source, env, &mut environment, &mut declared)?;
    }
    // The supervised node admits its capsule route before it enrolls, and
    // every stage runs as a capsule, so a main that starts one with no provider
    // declared fails to start (`oci_provider_undeclared`). Names only — never a
    // value.
    if !undeclared_provider_keys.is_empty() {
        anyhow::bail!(
            "this main starts a supervised node, and the installing environment does not \
             declare {keys}: the containment provider `kata host setup` writes to the project \
             `.env`. The installed service never reads `.env` (it runs under the snapshot this \
             install takes), so its worker could start no capsule. Run `kata host setup` first, \
             then re-run `kata service install` from the project directory, where `.env` loads, \
             or with the keys exported",
            keys = undeclared_provider_keys
                .iter()
                .map(|key| format!("`{key}`"))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    Ok((environment, declared))
}

fn inherit_required(
    key: &str,
    source: &str,
    env: InstallEnvironment<'_>,
    environment: &mut BTreeMap<String, String>,
    declared: &mut BTreeSet<String>,
) -> Result<()> {
    if key.is_empty()
        || !key.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
        })
    {
        anyhow::bail!("{source} names invalid environment variable {key:?}");
    }
    if key.starts_with("KATA_") {
        anyhow::bail!(
            "{source} names reserved Kata runtime environment variable {key:?}; choose a provider- or operator-owned name outside Kata's KATA_ namespace"
        );
    }
    let value = snapshot_text(key, env)
        .with_context(|| {
            format!("required service environment variable {key:?} declared by {source}")
        })?
        .with_context(|| {
            format!("required service environment variable {key:?} declared by {source} is unset")
        })?;
    declared.insert(key.to_string());
    environment.insert(key.to_string(), value);
    Ok(())
}

fn print_plan(plan: &ServicePlan, applied: bool) {
    println!(
        "kata service {:?}: {}",
        plan.action,
        plan_outcome_label(plan.action, applied)
    );
    println!("  definition: {}", plan.definition_path.display());
    if plan.action == ServiceAction::Install {
        println!("  changed: {}", plan.changed);
        println!(
            "  environment: {} (owner-only; refreshed by each install --apply)",
            plan.environment_path.display()
        );
    }
    for command in &plan.commands {
        println!("  command: {}", shell_display(command));
    }
    // The separate owner-only snapshot may contain config-declared provider/API
    // values. The definition binds only its path and digest, but keep preview
    // output stable and avoid suggesting either artifact is a secret display.
    if plan.action == ServiceAction::Install && !applied {
        println!(
            "  definition content: withheld (environment values remain in the owner-only snapshot)"
        );
    }
    if !applied && !matches!(plan.action, ServiceAction::Status | ServiceAction::Logs) {
        println!("Re-run with --apply to make this change.");
    }
    if plan.action == ServiceAction::Uninstall {
        println!("Durable data is never removed by service uninstall.");
    }
}

fn plan_outcome_label(action: ServiceAction, applied: bool) -> &'static str {
    if matches!(action, ServiceAction::Status | ServiceAction::Logs) {
        "observed (read-only)"
    } else if applied {
        "applied"
    } else {
        "preview"
    }
}

fn shell_display(command: &[String]) -> String {
    command
        .iter()
        .map(|part| {
            if part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._/:".contains(&byte))
            {
                part.clone()
            } else {
                format!("{:?}", part)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn owner_only_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("create owner-only service test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make service test directory owner-private");
        directory
    }

    #[test]
    fn typed_service_handoff_inventory_drives_every_produced_key() {
        let values = ServiceExecHandoffLaunchEnvironment::new(
            "environment-digest",
            "binary-digest",
            "config-digest",
            std::path::Path::new("/owner/kata-data"),
            "directory-id",
            71,
            72,
        );
        let mut command = std::process::Command::new("kata");
        values.apply_to(&mut command);
        let produced = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_owned(),
                    value.expect("handoff values are never removals").to_owned(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            produced.len(),
            ServiceExecHandoffKey::ALL.len(),
            "the typed inventory must contain unique produced names"
        );
        let expected = std::collections::BTreeMap::from([
            (
                std::ffi::OsString::from(SERVICE_ENVIRONMENT_DIGEST_ENV),
                std::ffi::OsString::from("environment-digest"),
            ),
            (
                std::ffi::OsString::from(SERVICE_EXPECTED_BINARY_DIGEST_ENV),
                std::ffi::OsString::from("binary-digest"),
            ),
            (
                std::ffi::OsString::from(SERVICE_EXPECTED_CONFIG_DIGEST_ENV),
                std::ffi::OsString::from("config-digest"),
            ),
            (
                std::ffi::OsString::from(SERVICE_EXPECTED_DATA_DIRECTORY_ENV),
                std::ffi::OsString::from("/owner/kata-data"),
            ),
            (
                std::ffi::OsString::from(SERVICE_EXPECTED_DIRECTORY_ID_ENV),
                std::ffi::OsString::from("directory-id"),
            ),
            (
                std::ffi::OsString::from(SERVICE_DISCOVERY_LEASE_FD_ENV),
                std::ffi::OsString::from("71"),
            ),
            (
                std::ffi::OsString::from(SERVICE_CONFIG_SNAPSHOT_FD_ENV),
                std::ffi::OsString::from("72"),
            ),
        ]);
        assert_eq!(produced, expected);
    }

    #[test]
    fn service_trampoline_revalidates_every_bound_input_on_automatic_restart() {
        let temp = owner_only_tempdir();
        let binary = temp.path().join("kata");
        let config = temp.path().join("kata.toml");
        let environment = temp.path().join("service-environment.json");
        std::fs::write(&binary, b"binary-v1").unwrap();
        std::fs::write(&config, b"[node]\n").unwrap();
        std::fs::write(&environment, b"{\"RUST_LOG\":\"info\"}").unwrap();
        std::fs::set_permissions(&environment, std::fs::Permissions::from_mode(0o600)).unwrap();
        let binary_digest = crate::service::current_binary_digest(&binary).unwrap();
        let config_digest = crate::service::current_config_digest(&config).unwrap();
        let environment_digest = crate::service::current_environment_digest(&environment).unwrap();

        validate_service_exec_inputs(
            &binary,
            &config,
            &environment,
            &binary_digest,
            &config_digest,
            &environment_digest,
        )
        .expect("unchanged manager restart inputs validate");

        std::fs::write(&binary, b"binary-v2").unwrap();
        let error = validate_service_exec_inputs(
            &binary,
            &config,
            &environment,
            &binary_digest,
            &config_digest,
            &environment_digest,
        )
        .expect_err("same-path binary replacement must fail in trampoline");
        assert!(format!("{error:#}").contains("binary identity drifted"));
        std::fs::write(&binary, b"binary-v1").unwrap();

        std::fs::write(&config, b"[node]\nid = \"changed\"\n").unwrap();
        let error = validate_service_exec_inputs(
            &binary,
            &config,
            &environment,
            &binary_digest,
            &config_digest,
            &environment_digest,
        )
        .expect_err("config replacement must fail in trampoline");
        assert!(format!("{error:#}").contains("config identity drifted"));
        std::fs::write(&config, b"[node]\n").unwrap();

        std::fs::write(&environment, b"{\"RUST_LOG\":\"debug\"}").unwrap();
        let error = validate_service_exec_inputs(
            &binary,
            &config,
            &environment,
            &binary_digest,
            &config_digest,
            &environment_digest,
        )
        .expect_err("environment replacement must fail in trampoline");
        assert!(format!("{error:#}").contains("environment identity drifted"));
    }

    #[test]
    fn service_trampoline_refuses_environment_fifo_without_blocking() {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        const CHILD_ROOT: &str = "KATA_SERVICE_ENVIRONMENT_FIFO_TEST_ROOT";
        if let Some(raw) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(raw);
            let binary = root.join("kata");
            let config = root.join("kata.toml");
            let environment = root.join("service-environment.json");
            let binary_digest = crate::service::current_binary_digest(&binary).unwrap();
            let config_digest = crate::service::current_config_digest(&config).unwrap();
            let error = validate_service_exec_inputs(
                &binary,
                &config,
                &environment,
                &binary_digest,
                &config_digest,
                "irrelevant-for-a-fifo",
            )
            .expect_err("FIFO environment must fail closed");
            assert!(
                format!("{error:#}")
                    .contains("not an exact owner-only bounded regular file publication"),
                "unexpected FIFO refusal: {error:#}"
            );
            return;
        }

        let temp = owner_only_tempdir();
        std::fs::write(temp.path().join("kata"), b"binary").unwrap();
        std::fs::write(temp.path().join("kata.toml"), b"[node]\n").unwrap();
        nix::unistd::mkfifo(
            &temp.path().join("service-environment.json"),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .expect("FIFO fixture");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "cli::service::tests::service_trampoline_refuses_environment_fifo_without_blocking",
            )
            .arg("--nocapture")
            .env(CHILD_ROOT, temp.path())
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
                panic!("opening a FIFO service environment blocked");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "FIFO refusal child failed: {status}");
    }

    #[test]
    fn service_trampoline_rejects_unsafe_environment_publication_metadata_and_size() {
        let temp = owner_only_tempdir();
        let binary = temp.path().join("kata");
        let config = temp.path().join("kata.toml");
        let environment = temp.path().join("service-environment.json");
        std::fs::write(&binary, b"binary").unwrap();
        std::fs::write(&config, b"[node]\n").unwrap();
        std::fs::write(&environment, b"{}").unwrap();
        let binary_digest = crate::service::current_binary_digest(&binary).unwrap();
        let config_digest = crate::service::current_config_digest(&config).unwrap();

        std::fs::set_permissions(&environment, std::fs::Permissions::from_mode(0o640)).unwrap();
        let error = validate_service_exec_inputs(
            &binary,
            &config,
            &environment,
            &binary_digest,
            &config_digest,
            "irrelevant-for-unsafe-metadata",
        )
        .expect_err("group-readable installed environment must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains("mode 640"), "{message}");
        assert!(message.contains("mode 600"), "{message}");

        std::fs::set_permissions(&environment, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = temp.path().join("service-environment.alias");
        std::fs::hard_link(&environment, &alias).unwrap();
        let error = validate_service_exec_inputs(
            &binary,
            &config,
            &environment,
            &binary_digest,
            &config_digest,
            "irrelevant-for-multiple-links",
        )
        .expect_err("multiply-linked installed environment must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains("links=2"), "{message}");
        assert!(message.contains("links=1..=1"), "{message}");

        std::fs::remove_file(alias).unwrap();
        std::fs::write(
            &environment,
            vec![
                0_u8;
                usize::try_from(MAX_SERVICE_ENVIRONMENT_BYTES + 1)
                    .expect("service environment test bound fits usize")
            ],
        )
        .unwrap();
        let error = validate_service_exec_inputs(
            &binary,
            &config,
            &environment,
            &binary_digest,
            &config_digest,
            "irrelevant-for-oversize",
        )
        .expect_err("oversized installed environment must fail closed");
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!("bytes={}", MAX_SERVICE_ENVIRONMENT_BYTES + 1)),
            "{message}"
        );
        assert!(
            message.contains(&format!("bytes<={MAX_SERVICE_ENVIRONMENT_BYTES}")),
            "{message}"
        );
    }

    #[test]
    fn read_only_service_actions_are_never_labeled_applied() {
        assert_eq!(
            plan_outcome_label(ServiceAction::Status, true),
            "observed (read-only)"
        );
        assert_eq!(
            plan_outcome_label(ServiceAction::Logs, true),
            "observed (read-only)"
        );
        assert_eq!(plan_outcome_label(ServiceAction::Start, false), "preview");
        assert_eq!(plan_outcome_label(ServiceAction::Start, true), "applied");
    }

    #[test]
    fn installed_config_status_proves_sync_and_reports_drift() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("kata config.toml");
        std::fs::write(&path, b"[node]\n").unwrap();
        let installed_digest = crate::service::current_config_digest(&path).unwrap();
        let encoded_path = serde_json::to_string(&path.to_string_lossy()).unwrap();
        let definition = format!(
            "# X-Kata-Config-Digest={installed_digest}\n# X-Kata-Config-Path={encoded_path}\n"
        );

        assert_eq!(
            inspect_definition_config(&definition),
            DefinitionConfigState::InSync {
                path: path.clone(),
                digest: installed_digest.clone(),
            }
        );

        std::fs::write(&path, b"[node]\ndata_dir = \"changed\"\n").unwrap();
        let current_digest = crate::service::current_config_digest(&path).unwrap();
        assert_eq!(
            inspect_definition_config(&definition),
            DefinitionConfigState::Drifted {
                path,
                installed_digest,
                current_digest,
            }
        );
    }

    #[test]
    fn legacy_definition_without_config_path_is_explicitly_unverifiable() {
        assert_eq!(
            inspect_definition_config("# X-Kata-Config-Digest=abc\n"),
            DefinitionConfigState::MissingMetadata {
                installed_digest: Some("abc".to_string()),
                path: None,
            }
        );
    }

    #[test]
    fn running_config_identity_includes_canonical_path_not_only_bytes() {
        let definition =
            "# X-Kata-Config-Digest=same-bytes\n# X-Kata-Config-Path=\"/a/kata.toml\"\n";
        assert_eq!(
            running_config_matches_definition(definition, Some("same-bytes"), Some("/a/kata.toml")),
            Some(true)
        );
        assert_eq!(
            running_config_matches_definition(definition, Some("same-bytes"), Some("/b/kata.toml")),
            Some(false),
            "byte-identical config at a different authority path still requires restart"
        );
    }

    #[test]
    fn running_environment_identity_detects_live_refresh_drift() {
        let definition = "# X-Kata-Service-Environment-Digest=installed\n";
        assert_eq!(
            running_environment_matches_definition(definition, Some("installed")),
            Some(true)
        );
        assert_eq!(
            running_environment_matches_definition(definition, Some("prior-process")),
            Some(false)
        );
    }

    #[test]
    fn running_binary_content_identity_detects_same_version_live_drift() {
        let definition = "# X-Kata-Binary-Digest=installed-content\n";
        assert_eq!(
            running_binary_matches_definition(definition, Some("installed-content")),
            Some(true)
        );
        assert_eq!(
            running_binary_matches_definition(definition, Some("prior-process-content")),
            Some(false),
            "same package version must not conceal different running executable bytes"
        );
        assert_eq!(
            running_binary_matches_definition(definition, None),
            Some(false)
        );
    }

    #[test]
    fn stopped_service_status_detects_data_directory_identity_drift() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        drop(DataDirLock::acquire(&data, MainMode::Installed, None).unwrap());
        let installed = inspect_identity(&data).unwrap().unwrap();
        let encoded_path = serde_json::to_string(&data.to_string_lossy()).unwrap();
        let definition = format!(
            "# X-Kata-Data-Directory-ID={}\n# X-Kata-Data-Directory={}\n",
            installed.directory_id, encoded_path
        );
        assert_eq!(data_directory_identity_mismatch(&definition).unwrap(), None);

        std::fs::write(
            data.join("main-identity.json"),
            serde_json::to_vec(&crate::data_dir_lock::DataDirIdentity {
                directory_id: "replacement-directory".to_string(),
                format_generation: installed.format_generation,
                mode: MainMode::Installed,
            })
            .unwrap(),
        )
        .unwrap();
        let mismatch = data_directory_identity_mismatch(&definition)
            .unwrap()
            .expect("stopped replacement must be reported before start");
        assert!(mismatch.contains("replacement-directory"), "{mismatch}");
        assert!(mismatch.contains(&installed.directory_id), "{mismatch}");
    }

    #[test]
    fn declared_required_environment_must_be_present() {
        let key = format!(
            "PROVIDER_TEST_REQUIRED_ENV_THAT_IS_UNSET_{}",
            std::process::id()
        );
        let error = inherit_required(
            &key,
            "api.auth.verifying_key_env",
            &process_environment,
            &mut BTreeMap::new(),
            &mut BTreeSet::new(),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(&key));
        assert!(message.contains("is unset"), "{message}");
    }

    /// The shipped example's signed-token snippet, enabled as written, is a config
    /// `kata service install` can plan: it loads, and the install's environment
    /// snapshot asks only for the variable's VALUE, never refusing its NAME.
    #[test]
    fn the_example_signed_token_snippet_is_installable() {
        let example = include_str!("../../../../config/kata.example.toml");
        let key_line = example
            .lines()
            .find_map(|line| line.strip_prefix("#   verifying_key_env = "))
            .expect("the example documents a verifying_key_env snippet");
        let key = key_line.trim_matches('"');
        let live = "[api.auth]\ntype = \"disabled\"\n";
        assert_eq!(example.matches(live).count(), 1, "one live auth table");
        let enabled = example.replace(
            live,
            &format!("[api.auth]\ntype = \"signed_token\"\nverifying_key_env = {key_line}\n"),
        );
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("kata.toml");
        std::fs::write(&config_path, enabled).unwrap();
        let config = ConfigManager::load(config_path)
            .expect("the enabled snippet loads")
            .snapshot();
        match (
            service_environment(&config, &with_provider_declared),
            std::env::var(key),
        ) {
            (Ok((environment, declared)), Ok(value)) => {
                assert!(declared.contains(key));
                assert_eq!(environment.get(key), Some(&value));
            }
            (Err(error), Err(_)) => {
                let message = format!("{error:#}");
                assert!(
                    message.contains(key) && message.contains("is unset"),
                    "only the unset value may stop the install: {message}"
                );
            }
            (outcome, value) => panic!(
                "the snapshot must follow the variable's presence: {:?} with {value:?}",
                outcome.map(|_| ())
            ),
        }
    }

    #[test]
    fn installed_service_environment_uses_effective_owner_home() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("kata.toml");
        std::fs::write(
            &config_path,
            "[node]\nid = \"owner-home-test\"\ndata_dir = \"data\"\n\n[workers]\ntransports = [{ type = \"supervised_node\" }]\nmax_workers = 1\ndispatch_deadline_ms = 5000\nheartbeat_interval_ms = 2500\nheartbeat_grace_ms = 10000\n\n[api]\nbind = \"127.0.0.1:8400\"\nauth = { type = \"disabled\" }\n",
        )
        .unwrap();
        let config = ConfigManager::load(config_path).unwrap().snapshot();
        let (environment, _) = service_environment(&config, &with_provider_declared).unwrap();
        let expected = effective_owner_home()
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap();
        assert_eq!(environment.get("HOME"), Some(&expected));
    }

    #[test]
    fn declared_environment_name_is_validated_before_lookup() {
        let error = inherit_required(
            "BAD-NAME",
            "api.auth.verifying_key_env",
            &process_environment,
            &mut BTreeMap::new(),
            &mut BTreeSet::new(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("invalid environment variable"));
    }

    #[test]
    fn declared_environment_cannot_shadow_any_kata_runtime_namespace() {
        for key in [
            "KATA_SERVICE_EXPECTED_CONFIG_DIGEST",
            "KATA_SERVICE_CONFIG_SNAPSHOT_FD",
            "KATA_FAULT_INJECT",
            "KATA_EXTERNAL_EXECUTION_PROVIDER",
        ] {
            let error = inherit_required(
                key,
                "api.auth.verifying_key_env",
                &process_environment,
                &mut BTreeMap::new(),
                &mut BTreeSet::new(),
            )
            .unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("reserved Kata runtime"), "{message}");
            assert!(message.contains("KATA_"), "{message}");
        }
    }

    #[test]
    fn identified_service_data_dir_requires_no_writer_reacquisition() {
        let data = tempfile::tempdir().unwrap();
        let lease_root = tempfile::tempdir().unwrap();
        let lifecycle = InstalledLifecycleOperationLease::acquire_at_for_test(
            &lease_root.path().join("authority/lifecycle-operation.lock"),
        )
        .unwrap();
        let discovery_lease = InstalledDiscoveryLease::acquire_at_for_test(
            &lease_root.path().join("authority/discovery.lock"),
        )
        .unwrap();
        let permit = InstalledServicePublicationPermit::new(&lifecycle, &discovery_lease);
        let live = DataDirLock::acquire(data.path(), MainMode::Installed, None).unwrap();
        let identity = ensure_service_data_dir_identity(&permit, data.path())
            .expect("an existing immutable identity needs no second data-directory writer");
        assert_eq!(identity, *live.identity());
        drop(live);
    }

    #[test]
    fn applied_install_keeps_one_config_snapshot_through_identity_publication() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("kata.toml");
        let first_data = root.path().join("data-a");
        let second_data = root.path().join("data-b");
        let config_for = |data_dir: &str| {
            format!(
                "[node]\nid = \"snapshot-main\"\ndata_dir = \"{data_dir}\"\n\n[workers]\ntransports = [{{ type = \"supervised_node\" }}]\ndispatch_deadline_ms = 5000\nheartbeat_interval_ms = 2500\nheartbeat_grace_ms = 10000\nmax_workers = 4\n\n[api]\nbind = \"127.0.0.1:8400\"\nauth = {{ type = \"disabled\" }}\n"
            )
        };
        std::fs::write(&config, config_for("data-a")).unwrap();
        let first_digest = crate::service::current_config_digest(&config).unwrap();
        let mut spec = load_spec(
            config.clone(),
            crate::service::ServicePlatform::SystemdUser,
            &with_provider_declared,
        )
        .unwrap();
        assert_eq!(spec.data_dir, first_data);

        // Model an atomic operator edit after the install captured its config
        // but before it initializes the selected data-directory identity.
        std::fs::write(&config, config_for("data-b")).unwrap();
        let lifecycle = InstalledLifecycleOperationLease::acquire_at_for_test(
            &root.path().join("authority/lifecycle-operation.lock"),
        )
        .unwrap();
        let discovery_lease = InstalledDiscoveryLease::acquire_at_for_test(
            &root.path().join("authority/discovery.lock"),
        )
        .unwrap();
        let permit = InstalledServicePublicationPermit::new(&lifecycle, &discovery_lease);
        let identity = ensure_service_data_dir_identity(&permit, &spec.data_dir).unwrap();
        spec.data_directory_id.clone_from(&identity.directory_id);

        assert_eq!(spec.config_digest, first_digest);
        assert_eq!(spec.data_dir, first_data);
        assert_eq!(inspect_identity(&first_data).unwrap(), Some(identity));
        assert_eq!(inspect_identity(&second_data).unwrap(), None);
        let definition = spec.render();
        assert_eq!(
            crate::service::definition_data_dir(&definition).as_deref(),
            Some(first_data.as_path())
        );
    }

    #[test]
    #[cfg(unix)]
    fn loaded_service_snapshot_keeps_config_path_and_digest_coupled() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let first_root = root.path().join("first");
        let second_root = root.path().join("second");
        std::fs::create_dir_all(&first_root).unwrap();
        std::fs::create_dir_all(&second_root).unwrap();
        let first = first_root.join("kata.toml");
        let second = second_root.join("kata.toml");
        let retained_first = first_root.join("kata.loaded.toml");
        let config_for = |node: &str, data_dir: &str| {
            format!(
                "[node]\nid = \"{node}\"\ndata_dir = \"{data_dir}\"\n\n[workers]\ntransports = [{{ type = \"supervised_node\" }}]\ndispatch_deadline_ms = 5000\nheartbeat_interval_ms = 2500\nheartbeat_grace_ms = 10000\nmax_workers = 4\n\n[api]\nbind = \"127.0.0.1:8400\"\nauth = {{ type = \"disabled\" }}\n"
            )
        };
        std::fs::write(&first, config_for("snapshot-a", "data-a")).unwrap();
        std::fs::write(&second, config_for("snapshot-b", "data-b")).unwrap();

        let manager = ConfigManager::load(&first).unwrap();
        let first_path = first.canonicalize().unwrap();
        let first_digest = manager.initial_content_digest().unwrap().to_string();
        assert_eq!(manager.path(), first_path);

        // Replace the canonical path after ConfigManager captured A. Service
        // construction must not resolve it again and pair A's parsed
        // policy/digest with B's canonical path.
        std::fs::rename(&first, &retained_first).unwrap();
        symlink(&second, &first).unwrap();
        let spec = service_spec_from_loaded_manager(
            &manager,
            crate::service::ServicePlatform::SystemdUser,
            &with_provider_declared,
        )
        .unwrap();

        assert_eq!(
            first.canonicalize().unwrap(),
            second.canonicalize().unwrap()
        );
        assert_eq!(spec.config, first_path);
        assert_eq!(spec.config_digest, first_digest);
        assert_eq!(spec.data_dir, first_root.join("data-a"));
        let definition = spec.render();
        assert_eq!(
            crate::service::definition_config_path(&definition).as_deref(),
            Some(first_path.as_path())
        );
        assert_eq!(
            crate::service::definition_config_digest(&definition).as_deref(),
            Some(first_digest.as_str())
        );
    }

    #[test]
    fn applied_service_install_and_uninstall_require_the_global_lease() {
        for action_name in ["install", "uninstall"] {
            let error = acquire_service_mutation_lease_with::<()>(action_name, || {
                Err(anyhow::anyhow!("injected held discovery lease"))
            })
            .expect_err("a held discovery lease must refuse service mutation");
            let message = format!("{error:#}");
            assert!(message.contains("requires the installed main to be stopped"));
            assert!(message.contains("injected held discovery lease"));
        }
    }

    #[test]
    fn service_startup_snapshot_remains_serialized_against_install() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("discovery").join("lease.lock");
        let mut snapshot_captured = false;

        with_installed_startup_lease_using(
            || InstalledDiscoveryLease::acquire_at_for_test(&path),
            |_startup_lease| {
                // Model the point after the trampoline has captured the
                // definition-bound binary/config/environment snapshot but
                // before exec/adoption. Install must still be excluded.
                snapshot_captured = true;
                let error = acquire_service_mutation_lease_with("install", || {
                    InstalledDiscoveryLease::acquire_at_for_test(&path)
                })
                .expect_err("install must not publish after startup captured old inputs");
                assert!(
                    format!("{error:#}").contains("already owns per-user discovery"),
                    "unexpected startup/install race refusal: {error:#}"
                );
                Ok(())
            },
        )
        .expect("startup lease operation");
        assert!(snapshot_captured);
        drop(
            InstalledDiscoveryLease::acquire_at_for_test(&path)
                .expect("startup lease releases after the guarded operation"),
        );
    }

    #[test]
    fn applied_service_commands_serialize_before_native_manager_or_publication_mutation() {
        let root = tempfile::tempdir().unwrap();
        let path = root
            .path()
            .join("coordination")
            .join("lifecycle-operation.lock");
        let held = InstalledLifecycleOperationLease::acquire_at_for_test(&path).unwrap();

        for action_name in ["install", "start", "stop", "restart", "uninstall"] {
            let error = acquire_lifecycle_operation_lease_with(action_name, || {
                InstalledLifecycleOperationLease::acquire_at_for_test(&path)
            })
            .expect_err("a concurrent service mutation must fail before manager access");
            let message = format!("{error:#}");
            assert!(message.contains("another lifecycle operation"), "{message}");
            assert!(message.contains("already owns"), "{message}");
        }

        drop(held);
        drop(
            InstalledLifecycleOperationLease::acquire_at_for_test(&path)
                .expect("the operation lease becomes reusable after command completion"),
        );
    }

    #[test]
    fn foreign_manager_preflight_cannot_initialize_a_data_directory() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("must-remain-absent");
        let initialize_calls = std::cell::Cell::new(0usize);
        let error = ensure_service_data_dir_identity_after_preflight_with(
            || anyhow::bail!("foreign fixed native-manager target"),
            || {
                initialize_calls.set(initialize_calls.get() + 1);
                std::fs::create_dir_all(&data_dir)?;
                Ok(())
            },
        )
        .expect_err("foreign manager authority must fail before data-dir mutation");
        assert!(format!("{error:#}").contains("foreign fixed native-manager target"));
        assert_eq!(initialize_calls.get(), 0);
        assert!(!data_dir.exists());
    }

    /// A loadable main config whose `[agents]` table is `agents`, written to
    /// `root/kata.toml`; `node` adds lines to `[node]`.
    fn agent_service_config(root: &std::path::Path, node: &str, agents: &str) -> PathBuf {
        let path = root.join("kata.toml");
        std::fs::write(
            &path,
            format!(
                "[node]\nid = \"agent-key-test\"\ndata_dir = \"data\"\n{node}\n[workers]\ntransports = [{{ type = \"supervised_node\" }}]\nmax_workers = 1\ndispatch_deadline_ms = 5000\nheartbeat_interval_ms = 2500\nheartbeat_grace_ms = 10000\n\n[api]\nbind = \"127.0.0.1:8400\"\nauth = {{ type = \"disabled\" }}\n\n{agents}"
            ),
        )
        .unwrap();
        path
    }

    fn api_key_agent(label: &str, var: &str) -> String {
        format!(
            "[agents.{label}]\nadapter = \"nanocode_openai\"\ncredential = {{ mode = \"api_key\", source = \"env:{var}\" }}\n"
        )
    }

    #[test]
    fn service_install_snapshots_an_api_key_agents_variable() {
        // The workspace denies `unsafe_code`, so the cell cannot `set_var`:
        // it re-runs itself in a child of this test binary whose environment
        // carries the key, and the child is the installing shell.
        const CHILD: &str = "SERVICE_AGENT_KEY_CELL_CHILD";
        const KEY: &str = "SERVICE_AGENT_KEY_CELL_OPENAI_KEY";
        const VALUE: &str = "sk-service-agent-key-cell";
        if std::env::var_os(CHILD).is_some() {
            let root = owner_only_tempdir();
            let config = agent_service_config(root.path(), "", &api_key_agent("coder", KEY));
            let loaded = ConfigManager::load(&config).unwrap().snapshot();
            let (environment, declared) =
                service_environment(&loaded, &with_provider_declared).unwrap();
            assert!(declared.contains(KEY), "{declared:?}");
            assert_eq!(environment.get(KEY).map(String::as_str), Some(VALUE));
            // The install path itself: the spec admits KEY only because it is
            // declared (it is outside the bounded allowlist), carries it in
            // the owner-only snapshot, and keeps it out of the definition.
            let spec = load_spec(
                config,
                crate::service::ServicePlatform::SystemdUser,
                &with_provider_declared,
            )
            .unwrap();
            assert_eq!(spec.environment.get(KEY).map(String::as_str), Some(VALUE));
            assert!(!spec.render().contains(VALUE));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("cli::service::tests::service_install_snapshots_an_api_key_agents_variable")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env(KEY, VALUE)
            .output()
            .expect("spawn the installing-shell child");
        assert!(
            output.status.success(),
            "installing-shell child failed: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the child must run the cell, not filter it away: {}",
            String::from_utf8_lossy(&output.stdout),
        );
    }

    /// **`kata service install` names a non-UTF-8 `<VAR>` as not UTF-8, never as
    /// unset.** In a child of this test binary (the workspace denies
    /// `unsafe_code`, so the cell cannot `set_var`), the installing shell holds
    /// an API-key agent's variable set to bytes that are not UTF-8: the install
    /// refuses naming the variable and saying it is not UTF-8, and neither
    /// stream of the child carries the planted bytes.
    ///
    /// **Would red if:** the install read a non-UTF-8 value as unset (watched:
    /// "is unset or non-Unicode", the reading before this cell).
    #[test]
    fn service_install_names_a_non_utf8_variable_as_not_utf8() {
        use std::os::unix::ffi::OsStrExt;
        const CHILD: &str = "SERVICE_AGENT_KEY_NON_UTF8_CHILD";
        const KEY: &str = "SERVICE_AGENT_KEY_NON_UTF8_KEY";
        const VALUE: &[u8] = b"sk-u23-PLANTED\xff";
        if std::env::var_os(CHILD).is_some() {
            let root = owner_only_tempdir();
            let config = agent_service_config(root.path(), "", &api_key_agent("coder", KEY));
            let error = load_spec(
                config,
                crate::service::ServicePlatform::SystemdUser,
                &with_provider_declared,
            )
            .expect_err("a non-UTF-8 variable is refused");
            println!("refusal: {error:#}");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("cli::service::tests::service_install_names_a_non_utf8_variable_as_not_utf8")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env(KEY, std::ffi::OsStr::from_bytes(VALUE))
            .output()
            .expect("spawn the installing-shell child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "the child ran the cell: {}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
        let refusal = stdout
            .lines()
            .find(|line| line.starts_with("refusal: "))
            .unwrap_or_else(|| panic!("the child printed its refusal: {stdout}"));
        assert!(
            refusal.contains(KEY) && refusal.contains("not UTF-8") && !refusal.contains("unset"),
            "{refusal}"
        );
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !bytes.windows(7).any(|window| window == b"PLANTED"),
                "the child's output holds the planted value"
            );
        }
    }

    #[test]
    fn service_install_refuses_an_api_key_agent_whose_variable_is_unset() {
        let key = format!("SERVICE_AGENT_KEY_CELL_UNSET_{}", std::process::id());
        let root = owner_only_tempdir();
        let config = agent_service_config(root.path(), "", &api_key_agent("coder", &key));
        let error = load_spec(
            config,
            crate::service::ServicePlatform::SystemdUser,
            &with_provider_declared,
        )
        .expect_err("an api_key agent whose variable the installing shell lacks refuses");
        let message = format!("{error:#}");
        assert!(
            message.contains("agents.coder.credential.source"),
            "{message}"
        );
        assert!(message.contains(&key), "{message}");
        assert!(message.contains("is unset"), "{message}");
    }

    /// A main with no `supervised_node` transport starts no node, so no
    /// credential is lifted from its environment: an external local-socket
    /// worker reads its own. The install neither copies an API-key agent's variable nor refuses
    /// while the installing shell lacks it.
    #[test]
    fn service_install_without_a_supervised_node_snapshots_no_agent_key() {
        let key = format!("SERVICE_AGENT_KEY_CELL_EXTERNAL_{}", std::process::id());
        let root = owner_only_tempdir();
        let path = agent_service_config(root.path(), "", &api_key_agent("coder", &key));
        let text = std::fs::read_to_string(&path).unwrap().replace(
            "transports = [{ type = \"supervised_node\" }]",
            "transports = [{ type = \"local_socket\", path = \"worker.sock\" }]",
        );
        std::fs::write(&path, text).unwrap();
        let config = ConfigManager::load(&path).unwrap().snapshot();
        assert!(
            !config
                .workers
                .transports
                .iter()
                .any(|transport| matches!(transport, WorkerTransportConfig::SupervisedNode {})),
            "the cell's config must carry no supervised node"
        );
        let (environment, declared) = service_environment(&config, &process_environment)
            .expect("an external worker's key is not the service's to require");
        assert!(!declared.contains(&key), "{declared:?}");
        assert!(!environment.contains_key(&key), "{environment:?}");
    }

    #[test]
    fn service_install_refuses_an_api_key_variable_it_cannot_snapshot() {
        // `KATA_*` is kata's own runtime namespace; the rest are names the
        // worker refuses to deliver a credential through, so snapshotting one
        // would only overwrite the service's own value of it (`HOME`, `PATH`).
        for (var, expected) in [
            ("KATA_AGENT_KEY_CELL", "reserved Kata runtime"),
            ("BAD-NAME", "not a POSIX environment-variable name"),
            ("HOME", "boundary plumbing owns"),
            ("PATH", "boundary plumbing owns"),
        ] {
            let root = owner_only_tempdir();
            let config = agent_service_config(root.path(), "", &api_key_agent("coder", var));
            let error = load_spec(
                config,
                crate::service::ServicePlatform::SystemdUser,
                &with_provider_declared,
            )
            .expect_err("an undeliverable api_key variable refuses the install");
            let message = format!("{error:#}");
            assert!(
                message.contains("agents.coder.credential.source"),
                "{var}: {message}"
            );
            assert!(message.contains(var), "{var}: {message}");
            assert!(message.contains(expected), "{var}: {message}");
        }
    }

    #[test]
    fn service_install_adds_nothing_for_a_kata_login_agent() {
        let root = owner_only_tempdir();
        let bare = agent_service_config(root.path(), "", "");
        let bare = ConfigManager::load(&bare).unwrap().snapshot();
        // `crossed` pairs `subscription` with an unset `env:` name: no worker
        // lifts that pair, so the install neither copies nor demands it.
        let crossed = format!("SERVICE_AGENT_KEY_CELL_CROSSED_{}", std::process::id());
        let login = owner_only_tempdir();
        let login = agent_service_config(
            login.path(),
            "",
            &format!(
                "[agents.coder]\nadapter = \"nanocode_openai\"\ncredential = {{ mode = \"subscription\", source = \"kata_login\" }}\n\n[agents.crossed]\nadapter = \"nanocode_openai\"\ncredential = {{ mode = \"subscription\", source = \"env:{crossed}\" }}\n"
            ),
        );
        let login = ConfigManager::load(&login).unwrap().snapshot();
        assert!(login.agents["coder"].capsule_credential().is_some());
        assert!(login.agents["crossed"].capsule_credential().is_some());
        assert_eq!(
            service_environment(&login, &with_provider_declared).unwrap(),
            service_environment(&bare, &with_provider_declared).unwrap()
        );
    }

    // The node-configuration keys `kata host setup` writes to `.env`, spelled
    // out rather than read from `kata_worker::NODE_PROVIDER_ENV_KEYS`, so a cell
    // asserts against the names the worker reads, not against the list the
    // install iterates.
    const STORE_KEY: &str = "KATA_EXTERNAL_PROVIDER_STORE";
    const NAME_KEY: &str = "KATA_EXTERNAL_EXECUTION_PROVIDER";
    const ADDRESS_KEY: &str = "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS";
    const STORE_VALUE: &str = "/srv/kata-service-cell/providers";
    const NAME_VALUE: &str = "youki";

    fn address_value(digit: char) -> String {
        format!("store:{}", digit.to_string().repeat(64))
    }

    /// The installing process's environment, plus the provider declaration
    /// `kata host setup` writes — what a shell in a set-up project holds.
    fn with_provider_declared(key: &str) -> Option<std::ffi::OsString> {
        match key {
            STORE_KEY => Some(STORE_VALUE.into()),
            NAME_KEY => Some(NAME_VALUE.into()),
            ADDRESS_KEY => Some(address_value('a').into()),
            _ => std::env::var_os(key),
        }
    }

    /// The installing process's environment with no provider declared.
    fn without_provider_declared(key: &str) -> Option<std::ffi::OsString> {
        match key {
            STORE_KEY | NAME_KEY | ADDRESS_KEY => None,
            _ => std::env::var_os(key),
        }
    }

    fn local_socket_service_config(root: &std::path::Path) -> PathBuf {
        let path = agent_service_config(root, "", "");
        let text = std::fs::read_to_string(&path).unwrap().replace(
            "transports = [{ type = \"supervised_node\" }]",
            "transports = [{ type = \"local_socket\", path = \"worker.sock\" }]",
        );
        std::fs::write(&path, text).unwrap();
        path
    }

    /// The defect this pins: `kata host setup` declares the provider in `.env`,
    /// the installed service never reads `.env`, so the install must carry the
    /// declaration from the installing process into the snapshot — and carry
    /// nothing else from the `KATA_` namespace with it.
    #[test]
    fn service_install_snapshots_the_host_setup_provider_declaration() {
        // The workspace denies `unsafe_code`, so the cell cannot `set_var`: it
        // re-runs itself in a child whose environment is the installing shell.
        const CHILD: &str = "SERVICE_PROVIDER_DECLARATION_CELL_CHILD";
        // Neighbours of the declared names that are not in the set.
        const OUTSIDE: [&str; 2] = [
            "KATA_EXTERNAL_PROVIDER_STORE_SHADOW",
            "KATA_EXTERNAL_EXECUTION_PROVIDER_NAME",
        ];
        if std::env::var_os(CHILD).is_some() {
            let root = owner_only_tempdir();
            let config = agent_service_config(root.path(), "", "");
            let spec = load_spec(
                config,
                crate::service::ServicePlatform::SystemdUser,
                &process_environment,
            )
            .expect("a supervising main whose installing shell declares the provider installs");
            let carried = |key: &str| spec.environment.get(key).map(String::as_str);
            assert_eq!(carried(STORE_KEY), Some(STORE_VALUE));
            assert_eq!(carried(NAME_KEY), Some(NAME_VALUE));
            assert_eq!(carried(ADDRESS_KEY), Some(address_value('b').as_str()));
            for key in OUTSIDE {
                assert_eq!(carried(key), None, "{key} is outside the declared set");
            }
            let kata_keys: BTreeSet<&str> = spec
                .environment
                .keys()
                .map(String::as_str)
                .filter(|key| key.starts_with("KATA_"))
                .collect();
            let admitted: BTreeSet<&str> = [
                "KATA_LOG",
                "KATA_RERUN_REPEATABILITY",
                "KATA_STDLIB_DIR",
                STORE_KEY,
                NAME_KEY,
                ADDRESS_KEY,
            ]
            .into_iter()
            .collect();
            assert!(kata_keys.is_subset(&admitted), "{kata_keys:?}");
            // The values live only in the owner-only snapshot, never the unit.
            let definition = spec.render();
            assert!(!definition.contains(STORE_VALUE), "{definition}");
            assert!(!definition.contains(&address_value('b')), "{definition}");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("cli::service::tests::service_install_snapshots_the_host_setup_provider_declaration")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env(STORE_KEY, STORE_VALUE)
            .env(NAME_KEY, NAME_VALUE)
            .env(ADDRESS_KEY, address_value('b'))
            .env(OUTSIDE[0], "/srv/shadow")
            .env(OUTSIDE[1], "shadow")
            .output()
            .expect("spawn the installing-shell child");
        assert!(
            output.status.success(),
            "installing-shell child failed: {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the child must run the cell, not filter it away: {}",
            String::from_utf8_lossy(&output.stdout),
        );
    }

    /// The declaration is part of the digest-bound snapshot: a re-run of
    /// `kata host setup` that moves the address yields a different snapshot
    /// identity, so the installed definition cannot silently keep the old one.
    #[test]
    fn the_provider_declaration_is_bound_into_the_environment_digest() {
        let root = owner_only_tempdir();
        let manager = ConfigManager::load(agent_service_config(root.path(), "", "")).unwrap();
        let moved = |key: &str| match key {
            ADDRESS_KEY => Some(address_value('c').into()),
            _ => with_provider_declared(key),
        };
        let platform = crate::service::ServicePlatform::SystemdUser;
        let first =
            service_spec_from_loaded_manager(&manager, platform, &with_provider_declared).unwrap();
        let second = service_spec_from_loaded_manager(&manager, platform, &moved).unwrap();
        assert_ne!(first.environment_digest, second.environment_digest);
        assert_ne!(first.render(), second.render());
    }

    #[test]
    fn service_install_refuses_a_supervising_main_without_the_provider_declaration() {
        let root = owner_only_tempdir();
        let config = ConfigManager::load(agent_service_config(root.path(), "", ""))
            .unwrap()
            .snapshot();
        let error = service_environment(&config, &without_provider_declared)
            .expect_err("a supervising main with no provider declared refuses the install");
        let message = format!("{error:#}");
        for key in [STORE_KEY, NAME_KEY, ADDRESS_KEY] {
            assert!(message.contains(&format!("`{key}`")), "{key}: {message}");
        }
        assert!(message.contains("`kata host setup`"), "{message}");
        assert!(message.contains(".env"), "{message}");

        // Half a declaration names exactly the missing half — a blank value
        // is absent — and prints no value it did find.
        let half = |key: &str| match key {
            NAME_KEY => Some("   ".into()),
            ADDRESS_KEY => None,
            _ => with_provider_declared(key),
        };
        let message = format!("{:#}", service_environment(&config, &half).unwrap_err());
        assert!(message.contains(&format!("`{NAME_KEY}`")), "{message}");
        assert!(message.contains(&format!("`{ADDRESS_KEY}`")), "{message}");
        assert!(!message.contains(&format!("`{STORE_KEY}`")), "{message}");
        assert!(!message.contains(STORE_VALUE), "{message}");
    }

    /// A main with no `supervised_node` transport starts no node, so its
    /// install neither requires the declaration nor refuses without it; a
    /// declaration the installing shell does hold is still carried.
    #[test]
    fn service_install_without_a_supervised_node_requires_no_provider_declaration() {
        let root = owner_only_tempdir();
        let config = ConfigManager::load(local_socket_service_config(root.path()))
            .unwrap()
            .snapshot();
        let (environment, _) = service_environment(&config, &without_provider_declared)
            .expect("a main that starts no node installs without a provider");
        for key in [STORE_KEY, NAME_KEY, ADDRESS_KEY] {
            assert!(!environment.contains_key(key), "{key}: {environment:?}");
        }
        let (environment, _) = service_environment(&config, &with_provider_declared).unwrap();
        assert_eq!(
            environment.get(ADDRESS_KEY).map(String::as_str),
            Some(address_value('a').as_str())
        );
    }
}
