//! Worker daemon entry points.
//!
//! The single source of truth for the dedicated `kata-worker run` path.
//!
//! The synchronous [`run_worker_daemon`] builds its own
//! single-threaded tokio runtime. Tests that want to drive the daemon
//! from inside an existing runtime use [`worker_run_loop`] directly.
//!
//! [`provision_worker`] is filesystem-only and shared with
//! `kata-worker provision` so operators get identical behaviour
//! whether they run it through the all-in-one binary or the
//! dedicated one.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use kata_transport::{LocalSocketTransport, WorkerSideTransport};
use kata_types::config::{WorkerNodeConfig, WorkerSharedSecret};
use kata_types::identity::WorkerResource;
use tracing::{error, info, warn};

use crate::worker_loop::worker_loop;

/// Run a worker daemon to completion.
///
/// Loads the worker config + credential from disk, dials the main, sends the
/// mutual credential-possession handshake, and runs the
/// recv/execute/send loop until the connection closes or the
/// process receives SIGINT.
///
/// Synchronous: it builds its own tokio runtime internally, because the
/// caller is typically `fn main` or a clap dispatch that isn't already in
/// an async context.
///
/// `logins_dir` is kata's own logins directory as the binary resolved it
/// ([`crate::owner_home::KataLoginsDir::resolve`]); the daemon's capsule route
/// reads a `kata_login` credential from there. An unresolved one does not stop
/// the daemon: only a `kata_login` turn refuses.
pub fn run_worker_daemon(
    config_path: PathBuf,
    logins_dir: crate::owner_home::KataLoginsDir,
) -> Result<()> {
    // Step 1 -- load worker-specific config.
    let worker_cfg = kata_types::config::load_worker_config(&config_path)
        .with_context(|| format!("failed to load worker config at {}", config_path.display()))?;

    // Minimal telemetry init (no full KataConfig available in worker mode).
    // `try_init` (not `init`) so double-invocation from the `kata` shim
    // doesn't panic when another subscriber has already been installed.
    let _ = tracing_subscriber::fmt::try_init();

    info!(
        home_node_endpoint = %worker_cfg.home_node_endpoint,
        credential_path = %worker_cfg.credential_path.display(),
        capabilities = ?worker_cfg.capabilities,
        "kata worker starting"
    );

    // Load the credential for mutual nonce-bound proofs. Its bytes never
    // cross the transport. The
    // credential file is written by `kata-worker provision` and is
    // 0600, so operators who copied a config from an insecure
    // host will see a permissions-style error here rather than
    // silently leaking their secret.
    let cred = kata_types::config::load_worker_shared_secret(&worker_cfg.credential_path)
        .with_context(|| {
            format!(
                "failed to load worker credential at {}",
                worker_cfg.credential_path.display()
            )
        })?;
    let shared_secret = cred.secret;

    // Step 2 -- build tokio runtime and connect + run.
    let rt = tokio::runtime::Runtime::new().context("failed to build tokio runtime")?;
    rt.block_on(worker_run_loop(worker_cfg, shared_secret, logins_dir))
}

/// The async body of the worker daemon. Exposed `pub` so tests can
/// drive it against an existing runtime without going through
/// [`run_worker_daemon`]'s own `Runtime::new`. Production code
/// normally calls [`run_worker_daemon`].
pub async fn worker_run_loop(
    worker_cfg: WorkerNodeConfig,
    shared_secret: String,
    logins_dir: crate::owner_home::KataLoginsDir,
) -> Result<()> {
    // The LAUNCH-TIME containment report (`sandbox_posture::observe`):
    // the pinned runtime, its userns/AppArmor/seccomp prerequisites and this
    // process's cgroup delegation, read through the certification's own folds.
    //
    // Deliberately BEFORE `connect_main_transport`: a posture the operator can
    // only see after a successful handshake is not a launch-time posture, and a
    // worker that cannot reach its main is exactly when its log is being read.
    //
    // This NEVER fails the boot: the capsule route's admission is what refuses a
    // node that cannot run capsules, by name.
    //
    // The emitter lives in `sandbox_posture`, beside the producer, and is ALSO
    // called from `worker_loop`, the loop every worker runs. The
    // `Once` inside it is
    // what lets this early call and the loop's call coexist: this daemon reports
    // before it dials, and does not repeat itself when the loop starts.
    // The daemon boots no node of its own, but it takes work like one — mark
    // the process installed before the posture is reported so the document
    // reads this worker's facts rather than the node-less deferral.
    kata_types::node_profile::mark_node_installed();
    crate::sandbox_posture::log_containment_posture_once();

    // The CRASH-WINDOW residue of a previous worker. A worker
    // killed between establishing a provider's outer cgroup and dropping it leaves
    // that subtree behind, with its provider and container possibly still inside:
    // nothing else reclaims it, because the next worker's sweep root carries a
    // different pid and never looks there, and an existing one on a REUSED pid is
    // refused rather than adopted. So it is cleared once, here, before this node
    // takes work — and only for a `kata.provider.*` whose pid is gone, because two
    // workers can share one uid and one delegated parent.
    //
    // Like the posture probe above this NEVER fails the boot: residue kata could not
    // remove is a reportable state, and a node that refused to come up over it could
    // not run `exec = "host"` work either.
    let swept = crate::provider_supervisor::sweep_stale_provider_cgroups(
        crate::sandbox_bounds::cgroup_delegation(),
    );
    if !swept.is_empty() {
        warn!(
            count = swept.len(),
            cgroups = ?swept,
            "swept provider cgroup subtrees left by a worker that did not shut down; their \
             processes were killed and the directories removed"
        );
    }

    // The CAPSULE EXECUTION CONTEXT for a standalone daemon,
    // admitted once at start through the MAIN's planes (`main_data_dir`); refused at start,
    // by name, when the key is absent. BEFORE the dial: this certifies the
    // rootless-OCI prerequisite, and ADR-0001's profile is explicit that the
    // answer to an uninstallable containment requirement is refusal before
    // issuance — *"There is no host-process or weaker-sandbox fallback."* — so
    // a node that cannot run capsules says so before it takes a connection
    // slot on its main.
    let capsule_route =
        crate::capsule_route::CapsuleRoute::admit_for_daemon(&worker_cfg, logins_dir)?;
    info!(
        route = %capsule_route.describe(),
        "rootless OCI prerequisite CERTIFIED; this worker runs its stages as capsules"
    );

    // Parse endpoint scheme and connect the appropriate transport.
    let transport = connect_main_transport(&worker_cfg).await?;

    info!("connected to main; starting the capsule worker loop");

    // Main possession is proved before the worker emits its own proof;
    // the final binding covers the full enrolled effect domain.
    let mut worker_info = build_hello_worker_info(&worker_cfg, &capsule_route)?;
    // The worker's durable membrane anchors the enrollment and keeps
    // `kata recovery capture`'s live-worker export door open; under the
    // capsule route it records no stage effects (the attempt's claim on
    // the main is the exactly-once), but the id is the worker's durable
    // identity the domain binds to.
    let store = open_worker_idempotency_store(&worker_cfg)?;
    let membrane_id = store.membrane_id()?;
    worker_info["membrane_id"] = serde_json::to_value(membrane_id)?;

    let kata_transport::enrollment::WorkerEnrollment {
        domain,
        heartbeat_period,
    } = enroll_with_main(transport.as_ref(), &shared_secret, membrane_id, worker_info).await?;
    info!(
        ?heartbeat_period,
        "mutual enrollment and worker effect domain verified"
    );

    // Step 4 -- run the worker loop until the connection closes or a
    // shutdown signal fires. We await BOTH
    // SIGTERM and SIGINT so `just kill-kata` (SIGTERM-based) gets
    // the same graceful path as interactive Ctrl+C.
    let loop_handle = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move {
            if let Err(e) = worker_loop(
                transport,
                capsule_route,
                heartbeat_period,
                (Some(domain), Some(store)),
            )
            .await
            {
                error!("worker loop exited with error: {e}");
            }
        })
    };

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
        let mut sigint =
            signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
        tokio::select! {
            _ = loop_handle => {
                info!("worker loop exited");
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM; worker exiting");
                transport.shutdown().await.ok();
            }
            _ = sigint.recv() => {
                info!("received SIGINT; worker exiting");
                transport.shutdown().await.ok();
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = loop_handle => {
                info!("worker loop exited");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal; worker exiting");
                transport.shutdown().await.ok();
            }
        }
    }

    info!("kata worker shut down");
    Ok(())
}

/// Prove credential possession to the main and bind this worker's effect domain,
/// stating THIS BUILD's executor term on the enrollment probe. The main binds back
/// the heartbeat period this worker must send at.
///
/// The term rides the probe so the main can tell whether the fence this
/// daemon runs capsules under is its own. A main whose term differs still places
/// work here and stops seeding capsule reuse from it.
async fn enroll_with_main(
    transport: &dyn WorkerSideTransport,
    shared_secret: &str,
    membrane_id: kata_types::identity::WorkerMembraneId,
    worker_info: serde_json::Value,
) -> Result<kata_transport::enrollment::WorkerEnrollment> {
    let executor_term =
        crate::executor_term::node_executor_term().context("derive this build's executor term")?;
    kata_transport::enrollment::authenticate_worker(
        transport,
        shared_secret,
        membrane_id,
        &executor_term,
        worker_info,
    )
    .await
    .context("local worker mutual enrollment authentication failed")
}

/// Connect the worker config's `home_node_endpoint`, retrying transient
/// failures. Only a `unix://` local-socket endpoint is served; any other scheme
/// is refused by name (`load_worker_config` already refuses one at load).
async fn connect_main_transport(
    worker_cfg: &WorkerNodeConfig,
) -> Result<Arc<dyn WorkerSideTransport>> {
    let endpoint = &worker_cfg.home_node_endpoint;
    let Some(path) = endpoint.strip_prefix("unix://") else {
        anyhow::bail!("unsupported endpoint scheme in '{endpoint}': expected unix://");
    };
    info!(%path, "connecting via local socket");
    connect_local_socket_with_retry(path).await
}

/// Assemble the handshake `Hello` worker-info JSON: hostname,
/// the augmented capability list (`agent:shell` always advertised), and the
/// containment claim the admitted `capsule_route` establishes. Local capacity
/// authenticates the owner-only enrollment secret, not anything in this object.
///
/// `hostname` is pulled from the `$HOSTNAME` env var rather than via a
/// dedicated crate — every production host sets it; falls back to
/// "unknown" on minimal images.
// `pub` (not private) so the `daemon::testing` re-export can surface it to
// `crates/worker/tests/daemon_tests.rs`, which asserts that Hello ADVERTISES the
// containment claim, against the frame this function really builds rather than
// against a hand-assembled JSON object.
#[doc(hidden)]
pub fn build_hello_worker_info(
    worker_cfg: &WorkerNodeConfig,
    capsule_route: &crate::capsule_route::CapsuleRoute,
) -> Result<serde_json::Value> {
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    // The `capabilities` list is the operator's free-form scheduling vocabulary,
    // passed through verbatim — PLUS `agent:shell`, which a capsule worker
    // always serves: a stage's `agent = "shell"` runs `sh -c` inside the
    // container the certified route delivers, so the label is a property of
    // the ROUTE and no `agent_backend=shell` declaration is needed. Dedup
    // keeps an operator who typed one a no-op.
    //
    // Containment and the enrolled membrane are separate Hello keys because
    // they are MEASURED facts, not declared ones.
    let mut hello_capabilities = worker_cfg.capabilities.clone();
    if !hello_capabilities.iter().any(|cap| {
        matches!(
            cap,
            WorkerResource::AgentBackend(kata_types::agent::BackendType::Shell)
        )
    }) {
        hello_capabilities.push(WorkerResource::AgentBackend(
            kata_types::agent::BackendType::Shell,
        ));
    }
    let mut worker_info = serde_json::json!({
        "hostname": hostname,
        "capabilities": hello_capabilities,
    });

    // ADVERTISE the containment capability, on its OWN key.
    //
    // Deliberately NOT folded into `capabilities`: that list is copied from the
    // operator's `WorkerNodeConfig`, so a token in it is something a human typed,
    // and `WorkerResource` says of itself that it "never certifies containment".
    // This key carries a MEASUREMENT — under the capsule engine that measurement
    // is the admitted route itself (its `certified_oci_route` fold ran during
    // `CapsuleRoute::admit`), demoted to a claim because that is all it can be
    // once it leaves this process.
    worker_info[kata_types::containment_claim::ClaimedContainment::HELLO_KEY] =
        serde_json::to_value(capsule_route.claimed_containment())
            .context("failed to encode this node's containment claim")?;

    Ok(worker_info)
}

/// Connect to a local socket with retries on transient failures.
///
/// `LocalSocketTransport::connect` fails only with an I/O error; a handshake
/// rejection on this transport is the main closing the socket, which the worker
/// observes as a closed connection once its loop next receives.
pub async fn connect_local_socket_with_retry(path: &str) -> Result<Arc<dyn WorkerSideTransport>> {
    let max_retries = 5;
    let mut attempt = 0u32;
    loop {
        match LocalSocketTransport::connect(path).await {
            Ok(transport) => return Ok(Arc::new(transport)),
            Err(e) => {
                attempt += 1;
                if attempt >= max_retries {
                    return Err(anyhow::anyhow!(
                        "failed to connect to local socket at {} after {max_retries} attempts: {e}",
                        path
                    ));
                }
                warn!(
                    attempt,
                    max_retries, path, "local socket connect failed, retrying: {e}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(500 * u64::from(attempt)))
                    .await;
            }
        }
    }
}

/// Load a local-worker enrollment secret without ever putting it in argv.
/// The source must be an owner-only regular file and must not be a symlink.
pub fn load_local_enrollment_secret(path: &std::path::Path) -> Result<String> {
    kata_types::config::validate_shared_secret_file_permissions(
        path,
        "local worker enrollment secret",
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let owner = std::fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect enrollment secret at {}", path.display()))?
            .uid();
        let expected_owner = nix::unistd::geteuid().as_raw();
        if owner != expected_owner {
            anyhow::bail!(
                "enrollment secret {} is owned by uid {owner}, expected {expected_owner}",
                path.display()
            );
        }
    }
    let secret = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read enrollment secret at {}", path.display()))?;
    let secret = secret.trim().to_string();
    if secret.is_empty() {
        anyhow::bail!("enrollment secret file {} is empty", path.display());
    }
    Ok(secret)
}

/// Provision local-worker files for `kata-worker run --config <path>`.
///
/// Local enrollment only: a worker reaches its main over a unix:// endpoint.
/// Synchronous — no network I/O.
///
/// `capabilities` is written verbatim into `WorkerNodeConfig.capabilities`.
/// Both binaries parse `--capability <spec>` flags through
/// [`kata_types::identity::WorkerResource::from_str`] before calling
/// in, so an empty vec here means the operator passed no `--capability`
/// flags. The worker advertises exactly these to the main, plus
/// `agent:shell` (`run_worker_daemon`'s Hello). Nothing is routed or gated
/// on those labels: capsule placement demands none, and neither does the
/// bring-your-own agent-run surface.
pub fn provision_worker(
    main_endpoint: String,
    secret: String,
    out: Option<PathBuf>,
    capabilities: Vec<WorkerResource>,
    main_data_dir: PathBuf,
) -> Result<()> {
    if !main_endpoint.starts_with("unix://") {
        anyhow::bail!(
            "remote worker provisioning is not supported: a worker reaches its main over a unix:// local-worker endpoint; this build has no versioned network worker protocol; use --main unix://<socket>"
        );
    }
    if secret.trim().is_empty() {
        anyhow::bail!("local enrollment secret must not be empty");
    }
    if main_data_dir.as_os_str().is_empty() {
        anyhow::bail!("--main-data-dir must name the installed main's data directory");
    }
    // Use $HOME directly rather than pulling in `dirs` — $HOME is
    // universally set on the platforms where kata runs (linux +
    // macos) and a new workspace dep just to read it is not worth
    // the churn.
    let out_path = if let Some(p) = out {
        p
    } else {
        let home_dir = std::env::var("HOME")
            .map_err(|_| anyhow::anyhow!("cannot locate home directory: HOME not set"))?;
        PathBuf::from(home_dir).join(".kata").join("worker.toml")
    };
    let out_dir = out_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("provisioning output has no parent directory"))?;
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    let cred_path = out_path.with_file_name("worker.cred");
    if matches!(
        out_path.file_name().and_then(|name| name.to_str()),
        Some(
            "worker.cred"
                | "idempotency.db"
                | "idempotency.db-wal"
                | "idempotency.db-shm"
                | "idempotency.db-journal"
        )
    ) {
        anyhow::bail!("worker config output aliases a reserved worker authority member");
    }
    let membrane_path = out_path.with_file_name("idempotency.db");
    // Serialize publishers on the existing directory itself; no new lock file
    // becomes an authority member. Existing state is never reprovisioned in place.
    #[cfg(unix)]
    let _provision_lock = nix::fcntl::Flock::lock(
        std::fs::File::open(out_dir)?,
        nix::fcntl::FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_, error)| {
        anyhow::anyhow!("worker provision directory is already in use: {error}")
    })?;
    let wal_path = out_path.with_file_name("idempotency.db-wal");
    let shm_path = out_path.with_file_name("idempotency.db-shm");
    let journal_path = out_path.with_file_name("idempotency.db-journal");
    for path in [
        &out_path,
        &cred_path,
        &membrane_path,
        &wal_path,
        &shm_path,
        &journal_path,
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_file() => anyhow::bail!(
                "refusing worker provision: {} is not a regular file",
                path.display()
            ),
            Ok(_) => anyhow::bail!(
                "refusing worker provision over existing authority {}; use a fresh destination and retain unresolved predecessor work",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect worker provision destination"),
        }
    }
    let membrane = kata_core::IdempotencyStore::open(&membrane_path)?;
    let expected_membrane_id = membrane.membrane_id()?;
    drop(membrane);
    kata_core::store::sqlite_backed::checkpoint_and_sync_initialized_file(
        &membrane_path,
        "provisioned worker membrane",
    )?;

    let config = kata_types::config::WorkerNodeConfig {
        home_node_endpoint: main_endpoint,
        credential_path: cred_path.clone(),
        expected_membrane_id,
        capabilities,
        // The provisioned worker runs the capsule route — `oci` is the only
        // engine and the emitted config writes no profile key. The capsule
        // route resolves the main's planes through `--main-data-dir` (required:
        // `worker_main_data_dir_undeclared` refuses the daemon's start without
        // it) and its provider through the process's `KATA_EXTERNAL_*` exports.
        main_data_dir: Some(main_data_dir),
    };
    let config_toml =
        toml::to_string_pretty(&config).context("failed to serialize WorkerNodeConfig")?;

    let cred = WorkerSharedSecret { secret };
    let cred_toml = toml::to_string_pretty(&cred).context("failed to serialize credential")?;
    write_owner_only_atomically(&cred_path, cred_toml.as_bytes(), "worker credential")?;
    // The runnable config publishes last, after its membrane and credential.
    write_owner_only_atomically(&out_path, config_toml.as_bytes(), "worker config")?;

    print!(
        "{}",
        render_provision_summary(&out_path, &cred_path, &config.home_node_endpoint)
    );
    Ok(())
}

#[cfg(unix)]
fn write_owner_only_atomically(path: &std::path::Path, bytes: &[u8], label: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() {
            anyhow::bail!(
                "refusing to replace {label} {}: existing target is not a regular file",
                path.display()
            );
        }
        let expected_uid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != expected_uid {
            anyhow::bail!(
                "refusing to replace {label} {}: owned by uid {}, expected {expected_uid}",
                path.display(),
                metadata.uid()
            );
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!(
                "refusing to replace {label} {}: existing permissions {:o} expose owner-only material",
                path.display(),
                metadata.permissions().mode() & 0o777
            );
        }
    }
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("{label} output has no parent directory: {}", path.display())
    })?;
    let temporary = parent.join(format!(
        ".kata-provision-{}-{}.tmp",
        std::process::id(),
        ulid::Ulid::new()
    ));
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("creating owner-only {label} {}", temporary.display()))?;
    let write_result = (|| -> Result<()> {
        file.write_all(bytes)
            .with_context(|| format!("writing {label} {}", temporary.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("protecting {label} {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {label} {}", temporary.display()))?;
        drop(file);
        std::fs::hard_link(&temporary, path).with_context(|| {
            format!(
                "publishing owner-only {label} {} -> {}",
                temporary.display(),
                path.display()
            )
        })?;
        std::fs::remove_file(&temporary)
            .context("remove published worker provision temporary link")?;
        std::fs::File::open(parent)
            .with_context(|| format!("opening {label} directory {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("syncing {label} directory {}", parent.display()))
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(not(unix))]
fn write_owner_only_atomically(_path: &std::path::Path, _bytes: &[u8], _label: &str) -> Result<()> {
    anyhow::bail!("local worker provisioning requires Linux or macOS owner-only file semantics")
}

#[doc(hidden)]
pub fn render_provision_summary(
    out_path: &std::path::Path,
    cred_path: &std::path::Path,
    main_endpoint: &str,
) -> String {
    format!(
        // kata-spacing: intentional
        "\
provisioned worker:
  config:     {config}
  credential: {credential}
  main:       {main}
  run via kata-worker: kata-worker run --config {config}
  supported boundary: local unix socket; remote enrollment is not supported
",
        config = out_path.display(),
        credential = cred_path.display(),
        main = main_endpoint,
    )
}

/// Open the worker's durable effect membrane, beside its credential.
///
/// Under the capsule route this store records no stage effects — the
/// attempt's claim on the main is the exactly-once — but its id is the
/// worker's durable identity the enrolled domain binds to, and the file is
/// what `kata recovery capture` exports for a live worker. Fail-closed: a
/// store that will not open refuses the boot, because an unbound id is a
/// worker identity that changes on every restart.
///
/// `#[doc(hidden)]` — re-exported through `daemon::testing` for the
/// integration test; not part of the public rustdoc API.
#[doc(hidden)]
pub fn open_worker_idempotency_store(
    worker_cfg: &WorkerNodeConfig,
) -> Result<std::sync::Arc<kata_core::IdempotencyStore>> {
    let idem_path = worker_cfg
        .credential_path
        .parent()
        .map(|dir| dir.join("idempotency.db"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "worker credential_path {} has no parent directory, so the worker's durable \
                 membrane has nowhere to live; point `credential_path` at a file inside a \
                 directory this worker owns",
                worker_cfg.credential_path.display()
            )
        })?;
    let store = kata_core::IdempotencyStore::open_existing_bound(
        &idem_path,
        worker_cfg.expected_membrane_id,
    )
    .with_context(|| {
        format!(
            "worker idempotency store: failed to open {}; this worker REFUSES to run without \
             its durable membrane, because the enrolled worker domain binds to it",
            idem_path.display()
        )
    })?;
    info!(path = %idem_path.display(), "worker idempotency store: opened");
    Ok(std::sync::Arc::new(store))
}

/// Test-only re-exports of items that are not part of the public
/// `daemon` API but are needed by integration tests in
/// `crates/worker/tests/daemon_tests.rs`. Hidden from rustdoc.
#[doc(hidden)]
pub mod testing {
    pub use super::build_hello_worker_info;
    pub use super::open_worker_idempotency_store;
    pub use super::render_provision_summary;
}

#[cfg(test)]
mod enrollment_tests {
    use kata_transport::LocalSocketTransport;
    use kata_types::identity::{WorkerEffectDomain, WorkerMembraneId};
    use ulid::Ulid;

    use super::enroll_with_main;

    /// **THE DAEMON STATES THIS BUILD'S EXECUTOR TERM ON HELLO** — the daemon
    /// half of the link that keeps a skewed worker's results out of the
    /// reuse cache. A real socket; the main side is the production
    /// `authenticate_main`, so the term asserted is the one the main reads off the wire.
    /// It must equal what a main of this source keys capsule reuse under
    /// (`node_executor_term`, which `BootRig::boot` installs on the stage cache): a
    /// daemon that stated any other term would have every result it delivers to a
    /// same-build main withheld from reuse.
    ///
    /// **Watched red:** with `enroll_with_main` stating
    /// `ExecutorTerm::derive(&[("mutant", b"x")])` in place of `node_executor_term()`,
    /// the main reads that term.
    #[tokio::test]
    async fn the_daemon_states_this_builds_executor_term_on_hello() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("worker.sock");
        let listener = LocalSocketTransport::listen(&path).unwrap();
        let worker = LocalSocketTransport::connect(&path).await.unwrap();
        let main = listener.accept_next().await.unwrap();
        let membrane = WorkerMembraneId(Ulid::new());
        let domain = WorkerEffectDomain {
            source_main: "main".into(),
            membrane,
            enrollment: Ulid::new(),
        };
        let bound = domain.clone();
        let (main_result, worker_result) = tokio::join!(
            kata_transport::enrollment::authenticate_main(
                &main,
                "fixture-secret",
                "main",
                std::time::Duration::from_secs(1),
                move |_| Ok(bound)
            ),
            enroll_with_main(
                &worker,
                "fixture-secret",
                membrane,
                serde_json::json!({"capabilities": []}),
            ),
        );
        assert_eq!(worker_result.unwrap().domain, domain);
        assert_eq!(
            main_result.unwrap().executor_term,
            *crate::executor_term::node_executor_term().unwrap().digest(),
            "the main reads the term a main of this build keys capsule reuse under"
        );
    }
}
