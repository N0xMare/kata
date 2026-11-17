//! Foreground installed-main boot path.
//!
//! The installed main is the one durable authority for storage, checked
//! workflows, recovery, policy, and operator APIs. It hosts no worker:
//! execution capacity is the configured local-socket providers — the node it
//! supervises (`type = "supervised_node"`, a `kata-worker` it starts beside
//! itself, `crate::supervised_node`) and `kata-worker` daemons the operator
//! starts.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use kata_core::init_telemetry_with_writer;
use kata_core::{ConfigManager, init_telemetry};
use kata_types::config::{ApiAuthConfig, WorkerTransportConfig};
use tracing::{info, warn};

use crate::attachment::{InstalledAttachment, InstalledDiscoveryLease};
use crate::authority_file::take_inherited_config_snapshot;
use crate::boot;
use crate::data_dir_lock::{InstalledDataDirLock, inspect_identity};
use crate::local_capacity::LocalCapacityRuntime;
use crate::shutdown_journal::{InstalledShutdownJournal, ShutdownPhase};

use super::config_check::print_config_summary_typed;
use super::service::ServiceExecHandoffKey;

/// Boot every installed-main subsystem in one foreground process.
///
/// Boot sequence:
///   1. Acquire or adopt the stable per-owner discovery lease.
///   2. Load and validate config via `kata_core::ConfigManager`.
///   3. Reserve the API listener, then acquire discovery-bound data-directory authority.
///   4. Load pricing from the exact validated config bytes.
///   5. Init telemetry.
///   6. Open durable stores and recover the checked execution authority.
///   7. Establish exactly the configured local-capacity providers: the
///      local-socket listeners, and the supervised node, started and enrolled
///      before readiness.
///   8. Init agent and workflow orchestration subsystems.
///   9. Serve the retained API listener as a readiness prerequisite.
///  10. Hold the runtime open until Ctrl+C.
///
/// Run the installed durable main in the foreground. Service managers invoke
/// this exact entrypoint; supervision never changes runtime semantics.
pub(crate) fn run_installed_main(config: PathBuf) -> Result<()> {
    // Direct foreground starts acquire before config reads. Native-service
    // starts adopt the exact descriptor held continuously by the trampoline
    // before it read definition-bound binary/config/environment inputs.
    let inherited = std::env::var_os(ServiceExecHandoffKey::DiscoveryLeaseDescriptor.name());
    let inherited_config = std::env::var_os(ServiceExecHandoffKey::ConfigSnapshotDescriptor.name());
    // FIRST, before this process opens a descriptor of its own. A
    // `kata serve` inherits whatever its launching shell held — measured, a
    // harness lane lock on fd 9 — and holds it for the daemon's whole life,
    // which is longer than the shell's. The two reserved service-handoff
    // descriptors are the exception and are named by the markers just read.
    // See `crate::inherited_descriptors` for why this is the daemon's job and
    // not the harness's.
    close_descriptors_inherited_by_the_installed_main(
        inherited.as_deref(),
        inherited_config.as_deref(),
    );
    crate::service::require_unprivileged_service_owner()?;
    crate::service::require_ambient_owner_home()?;
    validate_service_handoff_bundle(inherited.as_deref(), inherited_config.as_deref(), |name| {
        std::env::var_os(name)
    })?;
    if let (Some(discovery), Some(config)) = (&inherited, &inherited_config) {
        require_distinct_service_handoff_descriptors(discovery, config)?;
    }
    let discovery_lease = Arc::new(
        InstalledDiscoveryLease::acquire_or_adopt_service_exec_handoff(inherited.as_deref())
            .context("failed to establish the per-owner installed-main discovery lease")?,
    );
    run_local_main(Some(config), discovery_lease, inherited_config)
}

/// Drop every descriptor this daemon inherited and was never given.
///
/// Reports what it closed on stderr, because telemetry is step 5 of the boot
/// sequence and this is step 0: a subscriber does not exist yet, and the whole
/// point of the line is that the leak is otherwise invisible from BOTH ends —
/// the queued run's message names the launching shell's pid, which by then is
/// gone.
///
/// Never fatal. Refusing to start a node because `/proc/self/fd` could not be
/// listed would trade an invisible lock for an unstartable main; the daemon
/// runs, and an operator who then hits the lane-lock symptom has this message's
/// ABSENCE as the tell.
#[cfg(unix)]
fn close_descriptors_inherited_by_the_installed_main(
    discovery: Option<&std::ffi::OsStr>,
    config: Option<&std::ffi::OsStr>,
) {
    use crate::inherited_descriptors::{
        close_inherited_descriptors, inherited_descriptor_report, preserved_descriptors,
    };

    let preserve = match preserved_descriptors(&[discovery, config]) {
        Ok(preserve) => preserve,
        Err(error) => {
            // The handoff bundle is validated a few lines later and will refuse
            // this start with a better message. Closing nothing is the only
            // safe answer while the reserved numbers are unknown.
            eprintln!("kata serve: not closing inherited descriptors — {error:#}");
            return;
        }
    };
    match close_inherited_descriptors(&preserve) {
        Ok(closed) => {
            if let Some(report) = inherited_descriptor_report(&closed) {
                eprintln!("{report}");
            }
        }
        Err(error) => {
            eprintln!("kata serve: could not enumerate inherited descriptors — {error:#}");
        }
    }
}

#[cfg(not(unix))]
fn close_descriptors_inherited_by_the_installed_main(
    _discovery: Option<&std::ffi::OsStr>,
    _config: Option<&std::ffi::OsStr>,
) {
}

fn validate_service_handoff_bundle(
    discovery: Option<&std::ffi::OsStr>,
    config: Option<&std::ffi::OsStr>,
    mut environment: impl FnMut(&str) -> Option<std::ffi::OsString>,
) -> Result<()> {
    match (discovery, config) {
        (Some(_), Some(_)) => {
            for key in ServiceExecHandoffKey::ALL
                .iter()
                .copied()
                .filter(|key| key.is_identity())
            {
                let name = key.name();
                let raw = environment(name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "installed service identity handoff is missing {name}; reinstall the stopped service before starting it"
                    )
                })?;
                let value = raw.to_str().ok_or_else(|| {
                    anyhow::anyhow!("installed service identity handoff {name} is not Unicode")
                })?;
                if value.is_empty() {
                    anyhow::bail!(
                        "installed service identity handoff {name} is empty; reinstall the stopped service before starting it"
                    );
                }
            }
            Ok(())
        }
        (None, None) => {
            if let Some(name) = ServiceExecHandoffKey::ALL
                .iter()
                .copied()
                .filter(|key| key.is_identity())
                .map(ServiceExecHandoffKey::name)
                .find(|name| environment(name).is_some())
            {
                anyhow::bail!(
                    "service-only identity variable {name} is present without descriptor handoff; invoke the installed service through `kata service start --apply` or remove the ambient variable"
                );
            }
            Ok(())
        }
        _ => anyhow::bail!(
            "installed service descriptor handoff is incomplete; reinstall the stopped service before starting it"
        ),
    }
}

fn require_distinct_service_handoff_descriptors(
    discovery: &std::ffi::OsStr,
    config: &std::ffi::OsStr,
) -> Result<()> {
    fn parse(raw: &std::ffi::OsStr, label: &str) -> Result<i32> {
        let text = raw
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("installed {label} descriptor is not Unicode"))?;
        text.parse::<i32>()
            .with_context(|| format!("invalid installed {label} descriptor {text:?}"))
    }

    let discovery = parse(discovery, "discovery lease")?;
    let config = parse(config, "config snapshot")?;
    if discovery == config {
        anyhow::bail!(
            "installed service discovery and config handoffs reuse descriptor {discovery}; refusing to risk releasing authority"
        );
    }
    Ok(())
}

mod service_exec_handoff_boundary {
    use super::ServiceExecHandoffKey;

    /// Unforgeable outside this module: production cannot build its runtime
    /// without crossing the scrub boundary.
    #[must_use]
    pub(super) struct RuntimeEnvironmentReady(());

    /// Cross from validated descriptor handoff into the first runtime action.
    ///
    /// Production initializes telemetry through this continuation; the
    /// regression proof starts a child through the exact same transition.
    /// Neither can run until the complete typed handoff is scrubbed.
    pub(super) fn enter<S, T, E>(
        native_service_handoff: bool,
        mut state: S,
        mut remove: impl FnMut(&mut S, &str),
        first_runtime_action: impl FnOnce(S) -> Result<T, E>,
    ) -> Result<(RuntimeEnvironmentReady, T), E> {
        if native_service_handoff {
            for key in ServiceExecHandoffKey::ALL {
                remove(&mut state, key.name());
            }
        }
        let value = first_runtime_action(state)?;
        Ok((RuntimeEnvironmentReady(()), value))
    }

    /// Consume the private permit to build the real runtime. Deleting or
    /// moving the production boundary below runtime start therefore leaves no
    /// value with which the production call can compile.
    pub(super) fn runtime(
        _ready: RuntimeEnvironmentReady,
    ) -> std::io::Result<crate::runtime_start::Runtime> {
        crate::runtime_start::Runtime::build()
    }
}

#[allow(clippy::too_many_lines, unsafe_code)]
fn run_local_main(
    config: Option<PathBuf>,
    discovery_lease: Arc<InstalledDiscoveryLease>,
    inherited_config: Option<std::ffi::OsString>,
) -> Result<()> {
    let native_service_handoff = inherited_config.is_some();
    let supplied_config =
        config.ok_or_else(|| anyhow::anyhow!("--config is required for `kata serve`"))?;
    let config_path = if inherited_config.is_some() {
        if !supplied_config.is_absolute() {
            anyhow::bail!(
                "native-service config path must be absolute: {}",
                supplied_config.display()
            );
        }
        supplied_config
    } else {
        supplied_config
            .canonicalize()
            .context("resolving installed-main config path")?
    };

    // Step 2 -- config (the discovery lease was established by the entrypoint)
    let config_mgr = match inherited_config.as_deref() {
        Some(descriptor) => {
            let snapshot = take_inherited_config_snapshot(descriptor)?;
            ConfigManager::load_initial_snapshot(config_path.clone(), snapshot)
        }
        None => ConfigManager::load(config_path.clone()),
    }
    .with_context(|| format!("failed to load config at {}", config_path.display()))?;
    let loaded_config_digest = config_mgr
        .initial_content_digest()
        .expect("ConfigManager::load always records the parsed byte digest")
        .to_string();
    if let Ok(expected) = std::env::var(ServiceExecHandoffKey::ExpectedConfigDigest.name())
        && expected != loaded_config_digest
    {
        anyhow::bail!(
            "installed Kata service config changed while starting (installed digest {expected}, parsed digest {loaded_config_digest}); stop the service, run `kata service install --config <path> --apply`, then start it"
        );
    }
    let loaded_config_path = config_mgr.path().to_string_lossy().into_owned();
    let loaded_service_environment_digest =
        std::env::var(ServiceExecHandoffKey::EnvironmentDigest.name()).ok();
    let running_binary = std::env::current_exe().context("resolving running Kata executable")?;
    let loaded_binary_digest = crate::service::current_binary_digest(&running_binary)?;
    validate_running_binary_digest(
        std::env::var(ServiceExecHandoffKey::ExpectedBinaryDigest.name())
            .ok()
            .as_deref(),
        &loaded_binary_digest,
    )?;
    let mut cfg = (*config_mgr.snapshot()).clone();
    let expected_service_data_dir =
        std::env::var_os(ServiceExecHandoffKey::ExpectedDataDirectory.name()).map(PathBuf::from);
    let expected_service_directory_id =
        std::env::var(ServiceExecHandoffKey::ExpectedDirectoryId.name()).ok();
    if let (Some(expected_path), Some(expected_id)) = (
        expected_service_data_dir.as_ref(),
        expected_service_directory_id.as_deref(),
    ) {
        let configured = cfg.node.data_dir.canonicalize().with_context(|| {
            format!(
                "resolving service-configured data directory {}",
                cfg.node.data_dir.display()
            )
        })?;
        let expected = expected_path.canonicalize().with_context(|| {
            format!(
                "resolving service-definition data directory {}",
                expected_path.display()
            )
        })?;
        if configured != expected {
            anyhow::bail!(
                "installed service config selected data directory {}, but the installed definition binds {}; refusing before opening durable stores",
                configured.display(),
                expected.display()
            );
        }
        let identity = inspect_identity(&configured)?.ok_or_else(|| {
            anyhow::anyhow!(
                "installed service data directory {} is missing its immutable identity; refusing before opening durable stores",
                configured.display()
            )
        })?;
        if identity.directory_id != expected_id {
            anyhow::bail!(
                "installed service data-directory identity changed (definition {expected_id}, current {}); refusing before opening durable stores",
                identity.directory_id
            );
        }
    }
    // Reserve once and retain the socket through boot. In particular, :0 is a
    // request to the kernel, not an endpoint clients can use. Resolve only the
    // runtime config; the advertised loaded-config digest still binds the exact
    // parsed source bytes, just as it does for bound data-directory paths.
    let requested_api_bind = cfg.api.bind.clone();
    let api_listener = std::net::TcpListener::bind(&cfg.api.bind)
        .with_context(|| format!("installed API listener is unavailable at {}", cfg.api.bind))?;
    api_listener
        .set_nonblocking(true)
        .context("setting the retained installed API listener nonblocking")?;
    cfg.api.bind = api_listener
        .local_addr()
        .context("reading the retained installed API listener address")?
        .to_string();
    let resolved_self_api_env = resolve_self_api_env(
        &requested_api_bind,
        &cfg.api.bind,
        std::env::var_os("KATA_API_URL").as_deref(),
    );
    let control_endpoint = Some(format!("http://{}", cfg.api.bind));
    let authority_lock = if let Some(expected_id) = expected_service_directory_id.as_deref() {
        InstalledDataDirLock::acquire_expected(
            discovery_lease.as_ref(),
            &cfg.node.data_dir,
            control_endpoint,
            expected_id,
        )
    } else {
        InstalledDataDirLock::acquire(
            discovery_lease.as_ref(),
            &cfg.node.data_dir,
            control_endpoint,
        )
    }
    .with_context(|| {
        format!(
            "failed to acquire installed-main authority for {}",
            cfg.node.data_dir.display()
        )
    })?;
    if let Some(expected_id) = expected_service_directory_id.as_deref()
        && authority_lock.identity().directory_id != expected_id
    {
        anyhow::bail!(
            "installed service data-directory identity changed while acquiring its authority lock (definition {expected_id}, locked {}); refusing before opening durable stores",
            authority_lock.identity().directory_id
        );
    }
    authority_lock
        .bind_config(&mut cfg)
        .context("binding installed-main boot paths to the locked data directory")?;
    let cfg = Arc::new(cfg);
    let attachment_metadata = authority_lock.metadata().clone();

    // Derive pricing from the exact bytes ConfigManager validated. Reopening the
    // path here would let an atomic replacement split runtime pricing identity
    // from the config digest advertised by the installed main.
    kata_worker::pricing::load_overrides_from_snapshot(
        config_mgr
            .initial_content()
            .expect("ConfigManager::load always retains its initial content"),
        config_mgr.path(),
        &loaded_config_digest,
    )
    .context("pricing in the validated installed-main config is invalid")?;

    // The discovery descriptor is now an owned close-on-exec lease, the config
    // descriptor has been consumed and closed, and all identity values have
    // been copied and validated. Enter the runtime only after removing the
    // complete one-shot handoff. This is still synchronous on the process main
    // thread: no telemetry, tokio runtime, config watcher, worker, model,
    // tool, or other child exists yet.
    let (runtime_environment_ready, ()) = service_exec_handoff_boundary::enter(
        native_service_handoff,
        (),
        |(), name| {
            // SAFETY: this continuation is the first runtime action, so no
            // other thread can concurrently inspect or mutate the environment.
            unsafe {
                std::env::remove_var(name);
            }
        },
        |()| -> Result<()> {
            if let Some(endpoint) = resolved_self_api_env {
                // SAFETY: this is the same single-threaded exec boundary as
                // handoff removal above, before telemetry or runtime creation.
                // Both executor and sandbox snapshots must see the retained
                // listener's endpoint, not the caller's unusable self :0.
                // Source config/environment digests remain input provenance.
                unsafe { std::env::set_var("KATA_API_URL", endpoint) };
            }
            // A launchd-managed main writes to Apple's bounded,
            // retention-managed unified log. Foreground execution keeps the
            // ordinary stderr writer. Linux systemd captures stderr in
            // journald, which already owns retention.
            #[cfg(target_os = "macos")]
            if native_service_handoff {
                let writer = crate::macos_unified_log::make_writer()
                    .context("initializing Apple unified logging for the installed Kata service")?;
                init_telemetry_with_writer(&cfg, writer)
                    .context("installing telemetry for the launchd-managed Kata main")?;
            } else {
                init_telemetry(&cfg)
                    .context("installing telemetry for the foreground Kata main")?;
            }
            #[cfg(not(target_os = "macos"))]
            init_telemetry(&cfg).context("installing telemetry for the Kata main")?;
            Ok(())
        },
    )?;

    info!(
        node_id = %cfg.node.id,
        data_dir = %cfg.node.data_dir.display(),
        "loaded kata config for installed main"
    );
    print_config_summary_typed(&cfg);

    // Boot inside the main's tokio runtime.
    let runtime = service_exec_handoff_boundary::runtime(runtime_environment_ready)
        .context("building the main's tokio runtime")?;
    let attachment_discovery_lease = Arc::clone(&discovery_lease);
    let runtime_result = runtime.run(async move {
        // Retain the config watcher for the runtime lifetime. The watcher runs
        // the reload contract itself (`kata_core::apply_reload`): its only
        // proven live consumer is the tracing subscriber's log-level reload
        // handle, and every other changed field is reported restart-required —
        // the main's subsystems intentionally retain the immutable `cfg` boot
        // snapshot, not ConfigManager's ArcSwap handle.
        let _watch_handle = match config_mgr.watch() {
            Ok(h) => Some(h),
            Err(e) => {
                warn!(
                    error = %e,
                    "config watch failed; runtime config hot-reload disabled for this run",
                );
                None
            }
        };

        // The installed main always uses the durable checked-program/ledger
        // authority and performs recovery before publishing readiness.
        let rig = boot::BootRig::boot(Arc::clone(&cfg)).await?;

        // Step 4 -- establish exactly the execution-capacity providers named by
        // config. Every worker is a separate process on a local socket: the
        // supervised node on the main-owned `<data_dir>/node.sock`, and
        // operator-started daemons on each configured `local_socket` path.
        let supervised = cfg
            .workers
            .transports
            .iter()
            .any(|transport| matches!(transport, WorkerTransportConfig::SupervisedNode {}));
        let local_paths = cfg
            .workers
            .transports
            .iter()
            .filter_map(|transport| match transport {
                WorkerTransportConfig::LocalSocket { path } => Some(path.clone()),
                WorkerTransportConfig::SupervisedNode {} => None,
            })
            .collect::<Vec<_>>();
        let node_socket =
            supervised.then(|| crate::supervised_node::socket_path(&cfg.node.data_dir));

        let mut local_capacity = LocalCapacityRuntime::start(
            &local_paths,
            node_socket.as_deref(),
            &cfg.node.data_dir,
            rig.source_main_identity.clone(),
            cfg.workers.max_workers,
            Arc::clone(&rig.supervisor),
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.heartbeat),
            Arc::clone(&rig.recovery_exchange),
        )?;

        // The node runs capsules and the agent harness in its own process: a
        // defect model output reaches ends the node, never this main. Readiness
        // waits for it to enroll, so a ready main has capacity.
        let mut supervised_node = if supervised {
            Some(
                crate::supervised_node::SupervisedNode::start(
                    &cfg,
                    &rig.supervisor,
                    &rig.dispatcher,
                    rig.local_membrane,
                )
                .await
                .context("starting the supervised node")?,
            )
        } else {
            None
        };

        // Step 6 -- workflow orchestrator (ready state, no workflows auto-run).
        info!("workflow orchestrator: ready (submit via API or `kata run <workflow>`)");

        // Step 7 -- fail-closed API listener + installed discovery.
        // Arm termination handling before either the listener or attachment can
        // advertise readiness. Readiness must imply SIGTERM/SIGINT will enter
        // the graceful path; installing inside the later select leaves a race
        // where a service manager can observe ready and hit the default fatal
        // signal disposition before the future is first polled.
        #[cfg(unix)]
        let mut shutdown_diagnostic =
            crate::signal_diag::install().context("failed to install signal_diag handler")?;
        #[cfg(not(unix))]
        let mut shutdown_diagnostic = ();
        let mut api_task = rig.start_api_server(
            tokio::net::TcpListener::from_std(api_listener)
                .context("adopting the retained installed API listener")?,
            "installed",
            &attachment_metadata.directory_id,
            &attachment_metadata.process_generation,
            &loaded_binary_digest,
            &loaded_config_digest,
            &loaded_config_path,
            loaded_service_environment_digest,
        )?;
        let auth_reference = match &cfg.api.auth {
            ApiAuthConfig::SignedToken { .. } => "bearer_token:env:KATA_API_TOKEN",
            ApiAuthConfig::Disabled {} => "none:owner-loopback",
        };
        let installed_attachment = InstalledAttachment::publish(
            attachment_discovery_lease,
            &attachment_metadata,
            auth_reference,
        )
        .context("installed main bound its API but could not publish verified client discovery")?;
        #[cfg(test)]
        if let Some(delay_ms) = std::env::var_os("KATA_TEST_POST_READY_SIGNAL_PAUSE_MS") {
            let delay_ms = delay_ms
                .to_str()
                .expect("KATA_TEST_POST_READY_SIGNAL_PAUSE_MS must be UTF-8")
                .parse::<u64>()
                .expect("KATA_TEST_POST_READY_SIGNAL_PAUSE_MS must be an integer");
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }

        // Step 8 -- hold the runtime until shutdown.
        //
        // Wait on both SIGTERM and SIGINT so a service stop, `just kill-kata`,
        // and interactive Ctrl+C reach the same graceful-shutdown path.
        info!("kata installed main ready; press Ctrl+C to stop the foreground process");
        let mut shutdown_journal;
        tokio::select! {
            shutdown = await_shutdown_signal(&mut shutdown_diagnostic) => {
                shutdown?;
                shutdown_journal = InstalledShutdownJournal::create(
                    &cfg.node.data_dir,
                    &attachment_metadata.process_generation,
                )?;
                // Withdraw readiness and close listener admission before
                // draining workflows. This prevents a new submission from
                // extending the drain while the installed main is stopping.
                rig.close_admission();
                // The node finishes what it holds; none starts after shutdown began.
                if let Some(node) = &supervised_node {
                    node.stop_respawning();
                }
                // Raise the same fence for runs ALREADY driving. `close_admission`
                // stops new authority from being created; this tells a live driver
                // parked on durable work to hand its run back to the durable chain
                // instead of being joined for the full workflow-drain budget in a
                // process that has, one phase later, aborted the very sweep that
                // could have woken it. See `Dispatcher::begin_graceful_shutdown`.
                rig.dispatcher.begin_graceful_shutdown();
                api_task.begin_shutdown();
                shutdown_journal.record(
                    ShutdownPhase::AdmissionClosed,
                    true,
                    "workflow admission closed; API readiness withdrawn and listener shutdown requested",
                )?;
            }
            api_result = api_task.wait() => {
                return match api_result {
                    Ok(()) => Err(anyhow::anyhow!(
                        "installed-main API server exited unexpectedly"
                    )),
                    Err(error) => Err(anyhow::Error::new(error)
                        .context("installed-main API server exited unexpectedly")),
                };
            }
            node_failure = async {
                supervised_node
                    .as_mut()
                    .expect("select guard guarantees a supervised node")
                    .wait_for_failure()
                    .await
            }, if supervised_node.is_some() => {
                return Err(node_failure.context("installed-main supervised node failed"));
            }
            capacity_failure = async {
                local_capacity
                    .as_mut()
                    .expect("select guard guarantees local capacity")
                    .wait_for_failure()
                    .await
            }, if local_capacity.is_some() => {
                return Err(anyhow::anyhow!(
                    "installed-main local capacity exited unexpectedly: {capacity_failure}"
                ));
            }
            fatal_reason = rig.wait_for_executor_fatal() => {
                return Err(anyhow::anyhow!(
                    "installed-main workflow authority failed; restart recovery required: {fatal_reason}"
                ));
            }
        }

        // Stop main-owned producers before taking the workflow-task drain
        // snapshot. In particular, a due schedule must not race the closed
        // admission gate and advance its cursor without creating its run.
        let producers_stopped = rig
            .stop_background_tasks(std::time::Duration::from_secs(3))
            .await;
        if !producers_stopped {
            warn!("main background-task shutdown budget elapsed");
        }
        shutdown_journal.record(
            ShutdownPhase::ProducersStopped,
            producers_stopped,
            "main-owned schedules, sweepers, and producers stopped",
        )?;
        // Graceful shutdown: drain in-flight workflow tasks so a
        // completed / failed run's workspace teardown finishes before the
        // runtime is dropped, then tear down transports to stop the workers.
        let admission_quiescent = rig
            .wait_for_admission_quiescence(std::time::Duration::from_secs(3))
            .await;
        if !admission_quiescent {
            warn!(
                "main admission-drain budget elapsed; unresolved work remains durable for recovery"
            );
        }
        shutdown_journal.record(
            ShutdownPhase::AdmissionQuiescent,
            admission_quiescent,
            "all pre-fence submission/task-registration critical sections quiesced",
        )?;
        let workflows_drained = rig.drain_workflow_tasks().await;
        shutdown_journal.record(
            ShutdownPhase::WorkflowTasksDrained,
            workflows_drained,
            "tracked workflow drivers completed inside the shutdown budget",
        )?;
        let provider_acceptors_stopped = if let Some(runtime) = local_capacity.as_mut() {
            runtime
                .stop_accepting(std::time::Duration::from_secs(6))
                .await
        } else {
            true
        };
        if !provider_acceptors_stopped {
            warn!("local capacity acceptor shutdown budget elapsed");
        }
        shutdown_journal.record(
            ShutdownPhase::ProviderAcceptorsStopped,
            provider_acceptors_stopped,
            "subordinate local-capacity acceptors stopped",
        )?;
        rig.supervisor.shutdown_registered_workers().await;
        // Its connection is closed now, so the node leaves on its own; its
        // subtree is killed after a grace either way.
        let workers_and_descendants_stopped = match supervised_node {
            Some(node) => node.stop().await,
            None => true,
        };
        shutdown_journal.record(
            ShutdownPhase::WorkersAndDescendantsStopped,
            workers_and_descendants_stopped,
            "registered workers and the supervised node stopped and reaped",
        )?;
        let local_capacity_stopped = if let Some(runtime) = local_capacity {
            runtime.shutdown(std::time::Duration::from_secs(6)).await
        } else {
            true
        };
        if !local_capacity_stopped {
            warn!("local capacity reactor shutdown budget elapsed; tasks aborted for recovery");
        }
        shutdown_journal.record(
            ShutdownPhase::LocalCapacityStopped,
            local_capacity_stopped,
            "local-capacity reactors stopped and reaped",
        )?;
        let api_drained = api_task
            .finish_shutdown(std::time::Duration::from_secs(10))
            .await
            .context("installed-main API server failed during graceful shutdown")?;
        if !api_drained {
            warn!("API graceful-shutdown budget elapsed; force-closed remaining connections");
        }
        shutdown_journal.record(
            ShutdownPhase::ApiDrained,
            api_drained,
            "API listener task terminated after draining active connections",
        )?;
        // Shutdown flushes the delivery plane AND the authoritative
        // store, and those two roles live on two files. `rig.ledger.checkpoint()`
        // folds `ledger_events.db` — the DERIVED delivery plane;
        // `execution_lifecycle.db().checkpoint()` folds `operational.db`, the
        // AUTHORITY plane. Delivery first, authority second: the same
        // ordering `SqliteWorkflowStore::checkpoint` states for CAS-before-refs —
        // a crash between the two fsyncs must leave the AUTHORITY plane's flush
        // outstanding rather than the derived one's, because the derived plane is
        // rebuildable from the authority and not the other way round.
        let delivery_checkpoint = rig.ledger.checkpoint();
        let authority_checkpoint = rig.execution_lifecycle.db().checkpoint();
        shutdown_journal.record(
            ShutdownPhase::AuthoritativeLedgerCheckpointed,
            delivery_checkpoint.is_ok() && authority_checkpoint.is_ok(),
            "delivery (ledger_events.db) and authority (operational.db) WAL checkpoints completed",
        )?;
        delivery_checkpoint.context("checkpointing the delivery plane during shutdown")?;
        authority_checkpoint.context("checkpointing the authority chain during shutdown")?;
        let attachment_withdrawn = installed_attachment.withdraw();
        shutdown_journal.record(
            ShutdownPhase::AttachmentRemoved,
            attachment_withdrawn.is_ok(),
            "installed-client discovery descriptor durably removed",
        )?;
        attachment_withdrawn.context("withdrawing installed-main attachment")?;
        // Keep the self-pipe reader alive until the outer scope has synced the
        // final journal phase and released both installed-main authority locks.
        // The raw handler write fd is process-global; dropping its reader any
        // earlier would make a second shutdown signal rely on SIGPIPE policy.
        Ok((shutdown_journal, shutdown_diagnostic))
    });
    let (mut shutdown_journal, _shutdown_diagnostic) = runtime_result?;
    shutdown_journal.record(
        ShutdownPhase::LockReleaseImminent,
        true,
        "all graceful phases are durable; the data-directory lock releases under the still-held per-owner discovery lease",
    )?;
    // Keep the cross-directory installed-main fence until the store-specific
    // authority is gone. The stable discovery inode itself remains in place;
    // dropping the guard releases only its kernel lock.
    drop(authority_lock);
    drop(discovery_lease);
    Ok(())
}

fn validate_running_binary_digest(expected: Option<&str>, actual: &str) -> Result<()> {
    if let Some(expected) = expected
        && expected != actual
    {
        anyhow::bail!(
            "installed Kata executable changed between service validation and exec (installed digest {expected}, running digest {actual}); refusing before opening durable stores"
        );
    }
    Ok(())
}

/// Block until a termination signal arrives, then log the shutdown line.
///
/// Await an already-armed termination source, then log the shutdown line.
///
/// On Unix the diagnostic is installed before API/discovery readiness so a
/// service-manager stop cannot race the default signal disposition. Elsewhere
/// the unit argument keeps the call shape identical and Ctrl+C is armed here.
#[cfg(unix)]
async fn await_shutdown_signal(diag: &mut crate::signal_diag::Diagnostic) -> Result<()> {
    let info = diag
        .await_termination()
        .await
        .context("await_termination on signal_diag")?;
    // Single line that operations triage can copy-paste. Includes signal name
    // plus sender pid / uid / comm / cmdline; WARN survives default filtering.
    tracing::warn!(
        target: "kata.signal_diag",
        signal = info.signal,
        sender_pid = ?info.sender_pid,
        sender_uid = ?info.sender_uid,
        sender_comm = ?info.sender_comm,
        sender_cmdline = ?info.sender_cmdline,
        "{}",
        info.render(),
    );
    info!("received shutdown signal; tearing down");
    Ok(())
}

#[cfg(not(unix))]
async fn await_shutdown_signal((): &mut ()) -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to install Ctrl+C handler")?;
    info!("received shutdown signal; tearing down");
    Ok(())
}

/// Resolve only an explicitly requested local ephemeral self-endpoint. An
/// absent value or a foreign target is operator intent, not ours to replace.
fn resolve_self_api_env(
    requested: &str,
    resolved: &str,
    inherited: Option<&std::ffi::OsStr>,
) -> Option<String> {
    let requested_addr: std::net::SocketAddr = requested.parse().ok()?;
    let resolved_addr: std::net::SocketAddr = resolved.parse().ok()?;
    if !requested_addr.ip().is_loopback()
        || requested_addr.port() != 0
        || resolved_addr.ip() != requested_addr.ip()
        || resolved_addr.port() == 0
        || inherited != Some(std::ffi::OsStr::new(&format!("http://{requested}")))
    {
        return None;
    }
    Some(format!("http://{resolved_addr}"))
}

#[cfg(test)]
mod tests {
    use super::{
        ServiceExecHandoffKey, require_distinct_service_handoff_descriptors,
        service_exec_handoff_boundary, validate_running_binary_digest,
        validate_service_handoff_bundle,
    };

    #[test]
    fn self_api_env_resolves_only_an_exact_loopback_ephemeral_target() {
        use std::ffi::OsStr;
        let resolve = super::resolve_self_api_env;
        assert_eq!(
            resolve(
                "127.0.0.1:0",
                "127.0.0.1:12345",
                Some(OsStr::new("http://127.0.0.1:0"))
            ),
            Some("http://127.0.0.1:12345".to_string())
        );
        assert_eq!(
            resolve("[::1]:0", "[::1]:12345", Some(OsStr::new("http://[::1]:0"))),
            Some("http://[::1]:12345".to_string())
        );
        for inherited in [
            None,
            Some(OsStr::new("http://127.0.0.1:8400")),
            Some(OsStr::new("http://other:0")),
            Some(OsStr::new("http://127.0.0.1:0/")),
        ] {
            assert_eq!(resolve("127.0.0.1:0", "127.0.0.1:12345", inherited), None);
        }
        for (requested, resolved) in [
            ("127.0.0.1:8400", "127.0.0.1:8400"),
            ("0.0.0.0:0", "0.0.0.0:12345"),
            ("127.0.0.1:0", "127.0.0.2:12345"),
            ("127.0.0.1:0", "127.0.0.1:0"),
        ] {
            assert_eq!(
                resolve(
                    requested,
                    resolved,
                    Some(OsStr::new(&format!("http://{requested}")))
                ),
                None
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn self_api_env_does_not_replace_non_unicode_operator_values() {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            super::resolve_self_api_env(
                "127.0.0.1:0",
                "127.0.0.1:12345",
                Some(std::ffi::OsStr::from_bytes(b"http://\xff:0"))
            ),
            None
        );
    }

    #[test]
    fn execed_main_rehashes_binary_instead_of_trusting_trampoline_claim() {
        validate_running_binary_digest(Some("same"), "same").unwrap();
        validate_running_binary_digest(None, "foreground").unwrap();
        let error =
            validate_running_binary_digest(Some("validated-before-exec"), "actually-loaded")
                .expect_err("same-path replacement between validation and exec must fail");
        assert!(format!("{error:#}").contains("changed between service validation and exec"));
    }

    #[test]
    fn service_handoff_descriptors_compare_numeric_identity() {
        require_distinct_service_handoff_descriptors("7".as_ref(), "8".as_ref()).unwrap();
        let error = require_distinct_service_handoff_descriptors("7".as_ref(), "07".as_ref())
            .expect_err("alternate decimal spellings must not alias one descriptor");
        assert!(format!("{error:#}").contains("reuse descriptor 7"));
    }

    #[test]
    fn service_handoff_requires_every_identity_field_and_rejects_ambient_partials() {
        let identity_names = ServiceExecHandoffKey::ALL
            .iter()
            .copied()
            .filter(|key| key.is_identity())
            .map(ServiceExecHandoffKey::name)
            .collect::<Vec<_>>();
        let complete = identity_names
            .iter()
            .copied()
            .map(|name| (name, std::ffi::OsString::from("value")))
            .collect::<std::collections::BTreeMap<_, _>>();
        validate_service_handoff_bundle(Some("7".as_ref()), Some("8".as_ref()), |name| {
            complete.get(name).cloned()
        })
        .expect("complete service identity bundle");
        for missing in &identity_names {
            let error =
                validate_service_handoff_bundle(Some("7".as_ref()), Some("8".as_ref()), |name| {
                    (name != *missing).then(|| std::ffi::OsString::from("value"))
                })
                .expect_err("every service identity field is mandatory");
            assert!(format!("{error:#}").contains(*missing), "{error:#}");
        }
        let error = validate_service_handoff_bundle(None, None, |name| {
            (name == identity_names[0]).then(|| std::ffi::OsString::from("ambient"))
        })
        .expect_err("foreground start must not accept partial ambient service identity");
        assert!(format!("{error:#}").contains(identity_names[0]));
    }

    #[test]
    fn consumed_service_handoff_is_absent_from_descendants_and_native_detection() {
        const CHILD: &str = "KATA_TEST_CONSUMED_SERVICE_HANDOFF_CHILD";
        const PRESERVED: &str = "KATA_API_TOKEN";

        if std::env::var_os(CHILD).is_some() {
            for key in ServiceExecHandoffKey::ALL {
                let name = key.name();
                assert!(
                    std::env::var_os(name).is_none(),
                    "consumed service handoff {name} leaked into a descendant"
                );
            }
            assert_eq!(
                std::env::var_os(PRESERVED).as_deref(),
                Some("preserved-user-value".as_ref()),
                "scrubbing the one-shot handoff must not remove user-facing configuration"
            );
            assert!(
                !super::super::is_raw_native_service_invocation(),
                "a descendant without either descriptor marker must not be classified as a native-service invocation"
            );
            return;
        }

        let mut complete = ServiceExecHandoffKey::ALL
            .iter()
            .copied()
            .enumerate()
            .map(|(index, key)| {
                (
                    key.name(),
                    std::ffi::OsString::from(format!("value-{index}")),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        complete.insert(
            crate::attachment::SERVICE_DISCOVERY_LEASE_FD_ENV,
            "71".into(),
        );
        complete.insert(
            crate::authority_file::SERVICE_CONFIG_SNAPSHOT_FD_ENV,
            "72".into(),
        );
        require_distinct_service_handoff_descriptors(
            complete[crate::attachment::SERVICE_DISCOVERY_LEASE_FD_ENV].as_os_str(),
            complete[crate::authority_file::SERVICE_CONFIG_SNAPSHOT_FD_ENV].as_os_str(),
        )
        .expect("a valid service handoff uses distinct descriptors");
        validate_service_handoff_bundle(
            Some(complete[crate::attachment::SERVICE_DISCOVERY_LEASE_FD_ENV].as_os_str()),
            Some(complete[crate::authority_file::SERVICE_CONFIG_SNAPSHOT_FD_ENV].as_os_str()),
            |name| complete.get(name).cloned(),
        )
        .expect("a complete service handoff remains valid before it is consumed");

        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .arg("--exact")
            .arg(
                "cli::solo::tests::consumed_service_handoff_is_absent_from_descendants_and_native_detection",
            )
            .arg("--nocapture")
            .env_clear()
            .envs(&complete)
            .env(CHILD, "1")
            .env(PRESERVED, "preserved-user-value");
        let (runtime_environment_ready, output) = service_exec_handoff_boundary::enter(
            true,
            child,
            |child, name| {
                child.env_remove(name);
            },
            |mut child| {
                Ok::<_, std::convert::Infallible>(
                    child.output().expect("run descendant handoff probe"),
                )
            },
        )
        .expect("the infallible child continuation must enter the runtime");
        let _runtime = service_exec_handoff_boundary::runtime(runtime_environment_ready)
            .expect("build the runtime once the handoff is scrubbed");
        assert!(
            output.status.success(),
            "descendant handoff probe failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
