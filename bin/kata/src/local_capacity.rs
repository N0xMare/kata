//! Main-owned, same-host subprocess capacity over Unix domain sockets.
//!
//! This module is deliberately about disposable execution capacity, not a
//! second Kata authority. The installed main remains the only owner of checked
//! programs, durable transitions, recovery, policy, and operator APIs. A local
//! worker authenticates once, advertises capabilities, executes assignments,
//! and may disappear without acquiring durable workflow state.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::FutureExt as _;
use kata_transport::{
    HeartbeatMonitor, LocalSocketListener, LocalSocketTransport, WorkerPoolSupervisor,
    WorkerTransport,
};
use kata_types::identity::WorkerResource;
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::reactor::ResultReactor;
use smol_str::SmolStr;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::authority_file::{
    AuthorityFilePolicy, normalize_new_owner_only_file, read_bounded_utf8,
};

const ENROLLMENT_SECRET_FILE: &str = "local-worker.secret";
const MAX_ENROLLMENT_SECRET_BYTES: u64 = 4 * 1024;

/// Owned lifetime for every local-socket accept loop and dynamically-created
/// result reactor. Shutdown first closes admission to new connections, then
/// joins acceptors before the caller closes worker transports and joins the
/// reactors, so no connection can appear behind the shutdown snapshot.
pub struct LocalCapacityRuntime {
    shutdown: watch::Sender<bool>,
    accept_tasks: Vec<JoinHandle<()>>,
    reactor_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    failures: mpsc::UnboundedReceiver<LocalCapacityFailure>,
}

#[derive(Clone, Debug)]
pub struct LocalCapacityFailure {
    pub component: String,
    pub reason: String,
}

impl std::fmt::Display for LocalCapacityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.component, self.reason)
    }
}

impl LocalCapacityRuntime {
    /// Bind every configured local socket and start their accept loops: each
    /// operator `local_socket` path in `paths`, and the supervised node's
    /// `node_socket` when one is configured. Binding and enrollment-secret
    /// creation are boot prerequisites: a configured provider that cannot be
    /// established fails the main closed.
    ///
    /// `max_workers` counts every worker admitted. The node's socket admits
    /// from a pool of its own, one slot; every `paths` listener shares the rest.
    /// So a daemon on a `local_socket` path never takes the node's slot, and the
    /// node is never turned away for capacity while its own previous
    /// incarnation's slot is free.
    pub fn start(
        paths: &[PathBuf],
        node_socket: Option<&Path>,
        data_dir: &Path,
        source_main: String,
        max_workers: u32,
        supervisor: Arc<WorkerPoolSupervisor>,
        dispatcher: Arc<Dispatcher>,
        heartbeat: Arc<HeartbeatMonitor>,
        recovery_exchange: Arc<kata_workflow::recovery_exchange::RecoveryExchange>,
    ) -> Result<Option<Self>> {
        if paths.is_empty() && node_socket.is_none() {
            return Ok(None);
        }
        let listeners: Vec<PathBuf> = paths
            .iter()
            .cloned()
            .chain(node_socket.map(Path::to_path_buf))
            .collect();
        validate_listener_paths(&listeners, data_dir)?;
        let secret = Arc::new(load_or_create_enrollment_secret(data_dir)?);
        let sequence = Arc::new(AtomicU64::new(0));
        // Two atomic permit pools: the node's one slot, and the rest shared by
        // every `local_socket` listener. A worker holds its permit through
        // reactor teardown, so concurrent handshakes cannot oversubscribe a pool.
        let node_slots = u32::from(node_socket.is_some());
        let shared_slots = max_workers.checked_sub(node_slots).with_context(|| {
            format!("workers.max_workers={max_workers} leaves no slot for the supervised node")
        })?;
        let shared_slots = Arc::new(Semaphore::new(shared_slots as usize));
        let node_slots = Arc::new(Semaphore::new(node_slots as usize));
        let reactor_tasks = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, _) = watch::channel(false);
        let (failure_tx, failures) = mpsc::unbounded_channel();
        let mut accept_tasks = Vec::with_capacity(listeners.len());

        for path in &listeners {
            let worker_slots = if Some(path.as_path()) == node_socket {
                &node_slots
            } else {
                &shared_slots
            };
            let listener = LocalSocketTransport::listen(path)
                .with_context(|| format!("binding local worker capacity at {}", path.display()))?;
            info!(path = %path.display(), "local worker capacity listening");
            accept_tasks.push(spawn_accept_loop(
                listener,
                shutdown.subscribe(),
                Arc::clone(&secret),
                source_main.clone(),
                Arc::clone(worker_slots),
                Arc::clone(&sequence),
                Arc::clone(&supervisor),
                Arc::clone(&dispatcher),
                Arc::clone(&heartbeat),
                Arc::clone(&recovery_exchange),
                Arc::clone(&reactor_tasks),
                failure_tx.clone(),
            ));
        }

        Ok(Some(Self {
            shutdown,
            accept_tasks,
            reactor_tasks,
            failures,
        }))
    }

    /// Resolve only when a required local-capacity lifecycle component exits
    /// unexpectedly. The installed main supervises this alongside its API and
    /// its supervised node and fails closed instead of advertising false
    /// readiness.
    pub async fn wait_for_failure(&mut self) -> LocalCapacityFailure {
        self.failures
            .recv()
            .await
            .unwrap_or_else(|| LocalCapacityFailure {
                component: "local-capacity-supervisor".to_string(),
                reason: "all lifecycle reporters disappeared unexpectedly".to_string(),
            })
    }

    /// Stop accepting connections and join every main-owned local-capacity
    /// producer. The caller must close registered worker transports before this
    /// method so result reactors wake and finish their death reconciliation.
    pub async fn shutdown(mut self, budget: Duration) -> bool {
        let _ = self.shutdown.send(true);
        let mut tasks = std::mem::take(&mut self.accept_tasks);
        tasks.extend(
            self.reactor_tasks
                .lock()
                .expect("local capacity reactor registry poisoned")
                .drain(..),
        );
        join_owned_tasks(tasks, budget).await
    }

    /// Close connection admission and wait for acceptors to finish before the
    /// supervisor snapshots and closes registered transports.
    pub async fn stop_accepting(&mut self, budget: Duration) -> bool {
        let _ = self.shutdown.send(true);
        let tasks = std::mem::take(&mut self.accept_tasks);
        join_owned_tasks(tasks, budget).await
    }
}

/// Prove that every main-owned listener is inside the data directory whose
/// exclusive authority lock the caller holds. A local-capacity listener may
/// remove a stale socket left by this main after a crash; it must never be able
/// to unlink an arbitrary socket selected elsewhere on the host.
pub(crate) fn validate_listener_paths(paths: &[PathBuf], data_dir: &Path) -> Result<()> {
    let canonical_data_dir = data_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing Kata data directory {}", data_dir.display()))?;
    let mut unique = HashSet::with_capacity(paths.len());

    for path in paths {
        let file_name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "local worker socket path {} has no socket file name",
                    path.display()
                )
            })?;
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "local worker socket path {} has no parent directory",
                path.display()
            )
        })?;
        let canonical_parent = parent.canonicalize().with_context(|| {
            format!(
                "canonicalizing local worker socket parent {}",
                parent.display()
            )
        })?;
        if canonical_parent != canonical_data_dir {
            anyhow::bail!(
                "local worker socket {} must be a direct child of the locked Kata data directory {}; arbitrary host socket paths are not owned capacity",
                path.display(),
                canonical_data_dir.display()
            );
        }
        let owned_path = canonical_parent.join(file_name);
        if !unique.insert(owned_path.clone()) {
            anyhow::bail!(
                "local worker socket path {} is configured more than once",
                owned_path.display()
            );
        }
    }
    Ok(())
}

async fn join_owned_tasks(mut tasks: Vec<JoinHandle<()>>, budget: Duration) -> bool {
    let join = async {
        for task in &mut tasks {
            let _ = task.await;
        }
    };
    if tokio::time::timeout(budget, join).await.is_ok() {
        true
    } else {
        for task in tasks {
            task.abort();
        }
        false
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_accept_loop(
    listener: LocalSocketListener,
    shutdown: watch::Receiver<bool>,
    expected_secret: Arc<String>,
    source_main: String,
    worker_slots: Arc<Semaphore>,
    sequence: Arc<AtomicU64>,
    supervisor: Arc<WorkerPoolSupervisor>,
    dispatcher: Arc<Dispatcher>,
    heartbeat: Arc<HeartbeatMonitor>,
    recovery_exchange: Arc<kata_workflow::recovery_exchange::RecoveryExchange>,
    reactor_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    failure_tx: mpsc::UnboundedSender<LocalCapacityFailure>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let component = format!(
            "local-capacity-acceptor:{}",
            listener.socket_path().display()
        );
        let monitor_shutdown = shutdown.clone();
        let result = std::panic::AssertUnwindSafe(run_accept_loop(
            listener,
            shutdown,
            expected_secret,
            source_main,
            worker_slots,
            sequence,
            supervisor,
            dispatcher,
            heartbeat,
            recovery_exchange,
            reactor_tasks,
            failure_tx.clone(),
        ))
        .catch_unwind()
        .await;
        if !*monitor_shutdown.borrow() {
            let reason = match result {
                Ok(()) => "accept loop returned without a shutdown request".to_string(),
                Err(_) => "accept loop panicked".to_string(),
            };
            let _ = failure_tx.send(LocalCapacityFailure { component, reason });
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_accept_loop(
    listener: LocalSocketListener,
    mut shutdown: watch::Receiver<bool>,
    expected_secret: Arc<String>,
    source_main: String,
    worker_slots: Arc<Semaphore>,
    sequence: Arc<AtomicU64>,
    supervisor: Arc<WorkerPoolSupervisor>,
    dispatcher: Arc<Dispatcher>,
    heartbeat: Arc<HeartbeatMonitor>,
    recovery_exchange: Arc<kata_workflow::recovery_exchange::RecoveryExchange>,
    reactor_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    failure_tx: mpsc::UnboundedSender<LocalCapacityFailure>,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            accepted = listener.accept_next() => accepted,
        };
        let transport = match accepted {
            Ok(transport) => transport,
            Err(error) => {
                warn!(%error, "local worker accept failed; retrying");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let transport: Arc<dyn WorkerTransport> = Arc::new(transport);
        let hello = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let _ = transport.shutdown().await;
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            hello = verify_local_worker_hello(&transport, &expected_secret, &source_main, heartbeat.interval(), &dispatcher) => hello,
        };
        let Some(VerifiedHello {
            domain,
            capabilities: caps,
            containment,
            executor_term,
        }) = hello
        else {
            continue;
        };

        let Ok(permit) = Arc::clone(&worker_slots).try_acquire_owned() else {
            warn!("local worker refused: capacity limit reached");
            let _ = transport.shutdown().await;
            continue;
        };
        let worker_id = SmolStr::new(format!(
            "{}{}",
            kata_types::worker::LOCAL_WORKER_ID_PREFIX,
            sequence.fetch_add(1, Ordering::Relaxed)
        ));
        // The claim reaches the supervisor in its own slot, so
        // `worker_is_eligible` can route a `Contained`-class stage AROUND a
        // worker that would refuse it and the placement gate can refuse by name
        // when none is left.
        let recovery_peer = supervisor.register_worker_with_effect_domain(
            worker_id.clone(),
            Arc::clone(&transport),
            caps.clone(),
            containment.clone(),
            executor_term,
            domain,
        );
        info!(
            %worker_id,
            ?caps,
            containment = containment.verdict_label(),
            containment_evidence = containment.evidence(),
            %executor_term,
            "local worker registered"
        );
        let reactor = ResultReactor::new(
            worker_id.clone(),
            transport,
            Arc::clone(&dispatcher),
            Arc::clone(&heartbeat),
        );
        let reactor = reactor.with_recovery_peer(recovery_peer, Arc::clone(&recovery_exchange));
        let reactor_worker = worker_id.clone();
        let reactor_supervisor = Arc::clone(&supervisor);
        let reactor_shutdown = shutdown.clone();
        let reactor_failures = failure_tx.clone();
        let reactor = tokio::spawn(async move {
            let _worker_slot: OwnedSemaphorePermit = permit;
            let result = std::panic::AssertUnwindSafe(reactor.run())
                .catch_unwind()
                .await;
            // Worker-death reconciliation runs inside `ResultReactor::run`;
            // remove the stale registry entry only after that completes.
            reactor_supervisor.unregister_worker(reactor_worker.as_str());
            if result.is_err() && !*reactor_shutdown.borrow() {
                let _ = reactor_failures.send(LocalCapacityFailure {
                    component: format!("local-capacity-reactor:{reactor_worker}"),
                    reason: "result reactor panicked".to_string(),
                });
            }
        });
        reactor_tasks
            .lock()
            .expect("local capacity reactor registry poisoned")
            .push(reactor);
    }
}

/// What a verified Hello establishes about the worker behind it.
///
/// Two facts, kept apart on purpose. `capabilities` is the
/// operator's free-form scheduling vocabulary; `containment` is a claim about a
/// measured host capability that placement fails CLOSED on. Merging them would
/// let an operator's `WorkerResource::Custom` label satisfy a containment
/// demand, which is the defect
/// [`kata_types::containment_claim`] exists to make unrepresentable.
struct VerifiedHello {
    domain: kata_types::identity::WorkerEffectDomain,
    capabilities: Vec<String>,
    containment: kata_types::containment_claim::ClaimedContainment,
    /// The executor term the worker's own build runs capsules under, as its
    /// enrollment probe stated it. Not a placement input: it decides only whether
    /// this worker's results seed and serve capsule reuse
    /// (`kata_transport::supervisor::WorkerInfo::executor_term`).
    executor_term: kata_types::primitives::ContentHash,
}

async fn verify_local_worker_hello(
    transport: &Arc<dyn WorkerTransport>,
    expected_secret: &str,
    source_main: &str,
    heartbeat_interval: Duration,
    dispatcher: &Dispatcher,
) -> Option<VerifiedHello> {
    let result = kata_transport::enrollment::authenticate_main(
        transport.as_ref(),
        expected_secret,
        source_main,
        heartbeat_interval,
        |membrane| dispatcher.enroll_worker_membrane(source_main, membrane),
    )
    .await;
    let caps = match result {
        Ok(kata_transport::enrollment::EnrolledWorker {
            domain,
            executor_term,
            worker_info,
        }) => {
            if let Some(key) = undeclared_hello_key(&worker_info) {
                warn!(
                    key,
                    "local worker handshake rejected: the Hello carries a key outside the \
                     declared Hello vocabulary"
                );
                let _ = transport.shutdown().await;
                return None;
            }
            let membrane = worker_info
                .get("membrane_id")
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<kata_types::identity::WorkerMembraneId>(value).ok()
                })
                .filter(|identity| identity.0 != ulid::Ulid::nil());
            let Some(membrane) = membrane else {
                warn!("local worker handshake rejected: missing or invalid membrane identity");
                let _ = transport.shutdown().await;
                return None;
            };
            if membrane != domain.membrane {
                let _ = transport.shutdown().await;
                return None;
            }
            worker_capabilities(&worker_info).and_then(|capabilities| {
                // A claim the sender SPOKE and spoke wrong rejects the
                // handshake, exactly as a malformed capability list already
                // does: a permissive serde fallback is prohibited on the wire.
                // An ABSENT claim decodes to `Unstated` and is refused later, by
                // name, only for the placements that need containment.
                match kata_types::containment_claim::ClaimedContainment::in_hello_worker_info(
                    &worker_info,
                ) {
                    Ok(containment) => Some(VerifiedHello {
                        domain,
                        capabilities,
                        containment,
                        executor_term,
                    }),
                    Err(error) => {
                        warn!(
                            %error,
                            "local worker handshake rejected: malformed containment claim"
                        );
                        None
                    }
                }
            })
        }
        Err(error) => {
            warn!(%error, "local worker mutual enrollment refused");
            None
        }
    };
    if caps.is_none() {
        let _ = transport.shutdown().await;
    }
    caps
}

/// The declared Hello vocabulary: every key a local worker's Hello may carry.
///
/// That is what the worker's `build_hello_worker_info` writes (`hostname`,
/// `capabilities` and the containment claim), and the `membrane_id` the worker
/// daemon adds before enrollment. The executor term is not here: it travels in the
/// enrollment probe. It is a DECLARATION, not the set of keys this main reads:
/// `hostname` is declared and carried but read nowhere here.
const HELLO_WORKER_INFO_KEYS: &[&str] = &[
    "hostname",
    "capabilities",
    "membrane_id",
    kata_types::containment_claim::ClaimedContainment::HELLO_KEY,
];

/// The first Hello key outside [`HELLO_WORKER_INFO_KEYS`], if any.
///
/// Refused set: every key of the `worker_info` object that the vocabulary does not
/// name — and nothing else: a declared key passes whether or not this main reads
/// it. A sender speaking a vocabulary this main does not declare is a mismatched
/// worker, rejected at the handshake rather than half-understood (no permissive
/// fallback).
fn undeclared_hello_key(worker_info: &serde_json::Value) -> Option<&str> {
    worker_info
        .as_object()?
        .keys()
        .map(String::as_str)
        .find(|key| !HELLO_WORKER_INFO_KEYS.contains(key))
}

fn worker_capabilities(worker_info: &serde_json::Value) -> Option<Vec<String>> {
    let value = worker_info.get("capabilities")?;
    let resources: Vec<WorkerResource> = match serde_json::from_value(value.clone()) {
        Ok(resources) => resources,
        Err(error) => {
            warn!(%error, "local worker handshake rejected: malformed capabilities");
            return None;
        }
    };
    Some(
        resources
            .into_iter()
            .map(|resource| match resource {
                WorkerResource::AgentBackend(backend) => format!("agent:{}", backend.label()),
                WorkerResource::Shell => "shell".to_string(),
                WorkerResource::Network => "network".to_string(),
                WorkerResource::Disk { min_gb } => format!("disk:{min_gb}"),
                WorkerResource::Gpu { min_vram_gb } => format!("gpu:{min_vram_gb}"),
                WorkerResource::Custom(value) => value.to_string(),
            })
            .collect(),
    )
}

pub(crate) fn load_or_create_enrollment_secret(data_dir: &Path) -> Result<String> {
    let path = data_dir.join(ENROLLMENT_SECRET_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            return load_existing_enrollment_secret(&path);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    }

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data directory {}", data_dir.display()))?;
    let secret = kata_crypto::generate_shared_secret();
    if secret.len() as u64 > MAX_ENROLLMENT_SECRET_BYTES {
        anyhow::bail!(
            "generated local worker enrollment secret exceeds the {MAX_ENROLLMENT_SECRET_BYTES}-byte safety bound"
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    normalize_new_owner_only_file(&file, &path, "local worker enrollment secret")?;
    file.write_all(secret.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    info!(path = %path.display(), "local worker enrollment secret created");
    Ok(secret)
}

fn enrollment_secret_policy() -> AuthorityFilePolicy {
    AuthorityFilePolicy::owner_only(
        "local worker enrollment secret",
        MAX_ENROLLMENT_SECRET_BYTES,
    )
}

pub(crate) fn load_existing_enrollment_secret(path: &Path) -> Result<String> {
    load_existing_enrollment_secret_with(path, read_bounded_utf8)
}

fn load_existing_enrollment_secret_with(
    path: &Path,
    reader: impl FnOnce(&Path, AuthorityFilePolicy) -> Result<String>,
) -> Result<String> {
    let secret = reader(path, enrollment_secret_policy())?;
    let secret = secret.trim().to_string();
    if secret.is_empty() {
        anyhow::bail!("local worker enrollment secret {} is empty", path.display());
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[cfg(unix)]
    fn write_owner_only(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(path, bytes).expect("write owner-only fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("set owner-only fixture mode");
    }

    #[test]
    #[cfg(unix)]
    fn enrollment_secret_creation_is_owner_only_and_reloads_exact_bytes() {
        use std::os::unix::fs::MetadataExt as _;

        let data = tempfile::tempdir().expect("data dir");
        let created = load_or_create_enrollment_secret(data.path()).expect("create secret");
        assert!(!created.is_empty());
        assert!(created.len() as u64 <= MAX_ENROLLMENT_SECRET_BYTES);
        let path = data.path().join(ENROLLMENT_SECRET_FILE);
        let metadata = std::fs::symlink_metadata(&path).expect("secret metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(
            load_or_create_enrollment_secret(data.path()).expect("reload exact secret"),
            created
        );
    }

    #[test]
    #[cfg(unix)]
    fn enrollment_secret_rejects_oversize_without_mutation() {
        let data = tempfile::tempdir().expect("data dir");
        let path = data.path().join(ENROLLMENT_SECRET_FILE);
        let oversized =
            vec![
                b'x';
                usize::try_from(MAX_ENROLLMENT_SECRET_BYTES).expect("secret bound fits usize") + 1
            ];
        write_owner_only(&path, &oversized);
        let unrelated = data.path().join("unrelated");
        std::fs::write(&unrelated, b"unrelated-sentinel").expect("write unrelated sentinel");

        let error = load_or_create_enrollment_secret(data.path())
            .expect_err("oversized enrollment authority must fail closed");
        assert!(format!("{error:#}").contains("4096-byte safety bound"));
        assert_eq!(
            std::fs::read(&path).expect("read oversized file"),
            oversized
        );
        assert_eq!(
            std::fs::read(&unrelated).expect("read unrelated sentinel"),
            b"unrelated-sentinel"
        );
    }

    #[test]
    #[cfg(unix)]
    fn enrollment_secret_rejects_same_owner_hardlink_without_mutation() {
        let data = tempfile::tempdir().expect("data dir");
        let path = data.path().join(ENROLLMENT_SECRET_FILE);
        let alias = data.path().join("secret-alias");
        let sentinel = b"hardlink-secret-sentinel";
        write_owner_only(&path, sentinel);
        std::fs::hard_link(&path, &alias).expect("create hardlink alias");

        let error = load_or_create_enrollment_secret(data.path())
            .expect_err("multiply-linked enrollment authority must fail closed");
        assert!(format!("{error:#}").contains("exactly one link"));
        assert_eq!(std::fs::read(&path).expect("read secret"), sentinel);
        assert_eq!(std::fs::read(&alias).expect("read alias"), sentinel);
    }

    #[test]
    #[cfg(unix)]
    fn enrollment_secret_rejects_symlink_without_mutating_target() {
        use std::os::unix::fs::symlink;

        let data = tempfile::tempdir().expect("data dir");
        let path = data.path().join(ENROLLMENT_SECRET_FILE);
        let target = data.path().join("secret-target");
        let sentinel = b"symlink-target-sentinel";
        write_owner_only(&target, sentinel);
        symlink(&target, &path).expect("create secret symlink");

        load_or_create_enrollment_secret(data.path())
            .expect_err("symlink enrollment authority must fail closed");
        assert_eq!(std::fs::read(&target).expect("read target"), sentinel);
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    #[cfg(unix)]
    fn enrollment_secret_rejects_permissive_mode_without_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let data = tempfile::tempdir().expect("data dir");
        let path = data.path().join(ENROLLMENT_SECRET_FILE);
        let sentinel = b"permissive-secret-sentinel";
        std::fs::write(&path, sentinel).expect("write permissive secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("set permissive mode");

        let error = load_or_create_enrollment_secret(data.path())
            .expect_err("permissive enrollment authority must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains("mode 640"), "{message}");
        assert_eq!(std::fs::read(&path).expect("read secret"), sentinel);
    }

    #[test]
    #[cfg(unix)]
    fn enrollment_secret_rejects_deterministic_replacement_race() {
        let data = tempfile::tempdir().expect("data dir");
        let path = data.path().join(ENROLLMENT_SECRET_FILE);
        let replacement = data.path().join("replacement-secret");
        let retained = data.path().join("retained-open-secret");
        let unrelated = data.path().join("unrelated");
        let original_bytes = b"original-secret-sentinel";
        let replacement_bytes = b"replacement-secret-sentinel";
        write_owner_only(&path, original_bytes);
        write_owner_only(&replacement, replacement_bytes);
        std::fs::write(&unrelated, b"unrelated-sentinel").expect("write unrelated sentinel");

        let error = load_existing_enrollment_secret_with(&path, |path, policy| {
            crate::authority_file::read_bounded_utf8_with_post_read(path, policy, || {
                std::fs::rename(path, &retained).expect("retain opened inode");
                std::fs::rename(&replacement, path).expect("publish replacement inode");
            })
        })
        .expect_err("path replacement during descriptor snapshot must fail closed");
        let message = format!("{error:#}");
        assert!(
            message.contains("changed while") || message.contains("was replaced"),
            "{message}"
        );
        assert_eq!(
            std::fs::read(&retained).expect("read retained original"),
            original_bytes
        );
        assert_eq!(
            std::fs::read(&path).expect("read replacement"),
            replacement_bytes
        );
        assert_eq!(
            std::fs::read(&unrelated).expect("read unrelated sentinel"),
            b"unrelated-sentinel"
        );
    }

    /// A Hello as the worker's own `build_hello_worker_info` writes it, plus the
    /// `membrane_id` the worker daemon adds before enrollment.
    fn real_hello(membrane: kata_types::identity::WorkerMembraneId) -> serde_json::Value {
        struct NeverExecuted;
        #[async_trait::async_trait]
        impl kata_worker::capsule_route::StandInExecution for NeverExecuted {
            async fn execute(
                &self,
                _frame: &kata_transport::types::CapsuleAssignment,
                _cancel: tokio::sync::oneshot::Receiver<String>,
                _progress: Option<&kata_worker::capsule_progress::CapsuleProgress>,
            ) -> Result<
                kata_transport::types::WorkerMessage,
                kata_worker::capsule_execution::CapsuleAttemptRefusal,
            > {
                unreachable!("the Hello builder executes nothing")
            }
        }
        let worker_cfg = kata_types::config::WorkerNodeConfig {
            main_data_dir: None,
            home_node_endpoint: "unix:///tmp/kata-hello-keys-not-dialed.sock".to_string(),
            credential_path: PathBuf::from("/tmp/kata-hello-keys-not-read"),
            expected_membrane_id: membrane,
            capabilities: vec![WorkerResource::Shell],
        };
        let route =
            kata_worker::capsule_route::CapsuleRoute::stand_in_for_test(Arc::new(NeverExecuted));
        let mut hello = kata_worker::daemon::testing::build_hello_worker_info(&worker_cfg, &route)
            .expect("the Hello builds");
        hello["membrane_id"] = serde_json::to_value(membrane).expect("membrane encodes");
        hello
    }

    /// The declared vocabulary agrees with the writer: a Hello built by the
    /// worker's own builder carries no key outside it, and each key outside it is
    /// named.
    ///
    /// `worker_id` and `credential` are among the refused keys: no worker writes
    /// a signed-credential claim, so a Hello carrying one is a mismatched worker.
    ///
    /// **Watched red:** with `hostname` dropped from [`HELLO_WORKER_INFO_KEYS`], the
    /// real Hello is refused naming `hostname`; with `credential` added to it, the
    /// `credential` Hello passes.
    #[test]
    fn a_hello_key_outside_the_declared_vocabulary_is_named() {
        let hello = real_hello(kata_types::identity::WorkerMembraneId(ulid::Ulid::new()));
        assert_eq!(undeclared_hello_key(&hello), None, "{hello}");

        for key in [
            "execution_profile",
            "queue_depth",
            "worker_id",
            "credential",
        ] {
            let mut extended = hello.clone();
            extended[key] = serde_json::json!("oci");
            assert_eq!(undeclared_hello_key(&extended), Some(key), "{extended}");
        }
    }

    /// The vocabulary check is WIRED into the handshake, not only true of the
    /// predicate: a worker that enrolls over a real local socket with the real
    /// Hello is admitted, and the same worker with one undeclared key added is
    /// refused at the handshake — the main returns no verified Hello and closes
    /// the socket, which the WORKER observes as its connection ending.
    ///
    /// **Watched red:** with the check disabled in `verify_local_worker_hello`
    /// (`undeclared_hello_key(..).filter(|_| false)`), the `queue_depth` Hello is
    /// admitted.
    #[tokio::test]
    async fn the_handshake_refuses_a_hello_carrying_an_undeclared_key() {
        let dispatcher = Dispatcher::new(
            Arc::new(WorkerPoolSupervisor::new()),
            Arc::new(HeartbeatMonitor::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
            )),
            kata_core::InFlightLedger::in_memory(),
        );
        let directory = tempfile::tempdir().expect("socket dir");
        let path = directory.path().join("worker.sock");
        let listener = LocalSocketTransport::listen(&path).expect("listen");
        let term = kata_worker::executor_term::node_executor_term().expect("this build's term");
        for extra in [None, Some("queue_depth")] {
            let worker = LocalSocketTransport::connect(&path).await.expect("connect");
            let main: Arc<dyn WorkerTransport> =
                Arc::new(listener.accept_next().await.expect("accept"));
            let membrane = kata_types::identity::WorkerMembraneId(ulid::Ulid::new());
            let mut hello = real_hello(membrane);
            if let Some(key) = extra {
                hello[key] = serde_json::json!(1);
            }
            let (verified, enrolled) = tokio::join!(
                verify_local_worker_hello(
                    &main,
                    "fixture-secret",
                    "main",
                    Duration::from_secs(1),
                    &dispatcher
                ),
                kata_transport::enrollment::authenticate_worker(
                    &worker,
                    "fixture-secret",
                    membrane,
                    &term,
                    hello,
                ),
            );
            enrolled.expect("the worker's own enrollment proof completes either way");
            let closed = tokio::time::timeout(Duration::from_millis(500), worker.recv_frame())
                .await
                .map(|frame| frame.is_err());
            match extra {
                None => {
                    assert!(verified.is_some(), "the real Hello must be admitted");
                    assert!(closed.is_err(), "an admitted worker's socket stays open");
                }
                Some(key) => {
                    assert!(
                        verified.is_none(),
                        "a Hello carrying `{key}` must be refused"
                    );
                    assert_eq!(
                        closed,
                        Ok(true),
                        "the refused worker's socket must be closed by the main"
                    );
                }
            }
        }
    }

    #[test]
    fn worker_capabilities_are_lowered_to_scheduler_labels() {
        let info = serde_json::json!({
            "capabilities": [
                {"kind": "shell"},
                {"kind": "agent_backend", "data": "harness"},
                {"kind": "disk", "data": {"min_gb": 12}}
            ]
        });
        let caps = worker_capabilities(&info).expect("typed capabilities");
        assert_eq!(caps, ["shell", "agent:harness", "disk:12"]);
    }

    #[test]
    fn local_listener_paths_are_unique_children_of_locked_data_dir() {
        let data = tempfile::tempdir().expect("data dir");
        let owned = data.path().join("worker.sock");
        validate_listener_paths(std::slice::from_ref(&owned), data.path())
            .expect("owned socket accepted");

        let outside = tempfile::tempdir().expect("outside dir");
        let error = validate_listener_paths(&[outside.path().join("worker.sock")], data.path())
            .expect_err("outside socket must be rejected");
        assert!(error.to_string().contains("direct child"), "{error:#}");

        let error = validate_listener_paths(&[owned.clone(), owned], data.path())
            .expect_err("duplicate socket must be rejected");
        assert!(error.to_string().contains("more than once"), "{error:#}");
    }

    #[tokio::test]
    async fn two_listener_admission_shares_one_atomic_worker_slot() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let start = Arc::new(tokio::sync::Barrier::new(3));
        let release = Arc::new(tokio::sync::Notify::new());
        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = Vec::new();

        for _listener in 0..2 {
            let slots = Arc::clone(&slots);
            let start = Arc::clone(&start);
            let release = Arc::clone(&release);
            let result_tx = result_tx.clone();
            tasks.push(tokio::spawn(async move {
                start.wait().await;
                match slots.try_acquire_owned() {
                    Ok(permit) => {
                        result_tx.send(true).unwrap();
                        release.notified().await;
                        drop(permit);
                    }
                    Err(_) => result_tx.send(false).unwrap(),
                }
            }));
        }

        start.wait().await;
        let admitted = usize::from(result_rx.recv().await.unwrap())
            + usize::from(result_rx.recv().await.unwrap());
        assert_eq!(admitted, 1, "concurrent listeners must not oversubscribe");
        release.notify_waiters();
        for task in tasks {
            task.await.unwrap();
        }
    }

    /// **A SOCKET WORKER IS REGISTERED UNDER THE EXECUTOR TERM ITS HELLO STATED**
    /// — the main half of the link that keeps a skewed
    /// worker's results out of the reuse cache, driven through the production acceptor:
    /// `LocalCapacityRuntime::start` binds a real socket, the worker side is the
    /// production `authenticate_worker` stating another build's term, and the term is
    /// read back off the supervisor registration the reactor stamps results from. A
    /// registration under any other term — the main's own, above all — would let a
    /// skewed worker's results seed and serve reuse.
    ///
    /// The same acceptor binds THIS MAIN'S heartbeat interval into the enrollment:
    /// the worker comes back with half the 60 s the main was configured with, the
    /// cadence the main's `interval + grace` deadline assumes.
    ///
    /// **Watched red:** with `run_accept_loop` registering
    /// `*kata_worker::executor_term::node_executor_term().unwrap().digest()` in place of
    /// the Hello's term, the registration holds the main's term.
    #[tokio::test]
    #[cfg(unix)]
    async fn a_socket_worker_is_registered_under_the_term_its_hello_stated() {
        let data = tempfile::tempdir().expect("data dir");
        let socket = data.path().join("worker.sock");
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
        ));
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::clone(&supervisor),
            Arc::clone(&heartbeat),
            kata_core::ledger::InFlightLedger::in_memory(),
        ));
        let recovery_exchange =
            kata_workflow::recovery_exchange::RecoveryExchange::new(Arc::clone(&supervisor));
        let runtime = LocalCapacityRuntime::start(
            std::slice::from_ref(&socket),
            None,
            data.path(),
            "main".to_owned(),
            1,
            Arc::clone(&supervisor),
            dispatcher,
            heartbeat,
            recovery_exchange,
        )
        .expect("start local capacity")
        .expect("one listener configured");
        let secret = load_existing_enrollment_secret(&data.path().join(ENROLLMENT_SECRET_FILE))
            .expect("the acceptor created the enrollment secret");

        let stated = kata_types::execution_platform::ExecutorTerm::derive(&[(
            "oci_seccomp_rules",
            b"another build's deny list",
        )])
        .unwrap();
        assert_ne!(
            stated,
            kata_worker::executor_term::node_executor_term().unwrap(),
            "the premise: the worker is of another build"
        );
        let worker = LocalSocketTransport::connect(&socket)
            .await
            .expect("dial the acceptor");
        let membrane = kata_types::identity::WorkerMembraneId(ulid::Ulid::new());
        let kata_transport::enrollment::WorkerEnrollment {
            domain,
            heartbeat_period,
        } = kata_transport::enrollment::authenticate_worker(
            &worker,
            &secret,
            membrane,
            &stated,
            serde_json::json!({"membrane_id": membrane, "capabilities": []}),
        )
        .await
        .expect("the acceptor enrolls the worker");
        assert_eq!(
            heartbeat_period,
            Duration::from_secs(30),
            "the worker heartbeats at half the interval this main was configured with"
        );

        let worker_id = format!("{}0", kata_types::worker::LOCAL_WORKER_ID_PREFIX);
        // Generous on purpose: registration follows an enrollment commit a loaded
        // host delays; no time property is under test.
        let registered = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(info) = supervisor.get_worker(&worker_id) {
                    break (info.executor_term, info.effect_domain.clone());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the acceptor registers the enrolled worker");
        assert_eq!(registered.1, Some(domain));
        assert_eq!(
            registered.0,
            Some(*stated.digest()),
            "the registration carries the term the worker stated, not the main's"
        );

        kata_transport::WorkerSideTransport::shutdown(&worker)
            .await
            .expect("close the worker side");
        assert!(runtime.shutdown(Duration::from_secs(5)).await);
    }

    /// Enroll one worker on `socket` the way a `kata-worker` does (the
    /// production `authenticate_worker`, a fresh membrane), and read whether the
    /// acceptor ADMITTED it: registered under its membrane, or its socket closed
    /// by the main — the worker side's read ending, which the kernel reports.
    async fn enroll_one(
        socket: &Path,
        secret: &str,
        supervisor: &WorkerPoolSupervisor,
    ) -> (bool, Arc<LocalSocketTransport>) {
        let worker = Arc::new(
            LocalSocketTransport::connect(socket)
                .await
                .expect("dial the acceptor"),
        );
        let membrane = kata_types::identity::WorkerMembraneId(ulid::Ulid::new());
        let term = kata_worker::executor_term::node_executor_term().expect("this build's term");
        kata_transport::enrollment::authenticate_worker(
            worker.as_ref(),
            secret,
            membrane,
            &term,
            serde_json::json!({"membrane_id": membrane, "capabilities": []}),
        )
        .await
        .expect("the acceptor completes the worker's half of enrollment");
        let closed = tokio::spawn({
            let worker = Arc::clone(&worker);
            async move {
                while kata_transport::WorkerSideTransport::recv_frame(worker.as_ref())
                    .await
                    .is_ok()
                {}
            }
        });
        // Generous on purpose: admission follows an enrollment commit a loaded
        // host delays; no time property is under test.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if supervisor
                .recovery_peers()
                .iter()
                .any(|peer| peer.domain().membrane == membrane)
            {
                closed.abort();
                return (true, worker);
            }
            if closed.is_finished() {
                return (false, worker);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the acceptor neither admitted nor closed the worker on {}",
                socket.display()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// **THE SUPERVISED NODE'S SLOT IS ITS OWN.** With a `supervised_node`
    /// transport, `workers.max_workers` keeps one slot for `node.sock` and
    /// shares the rest among the `local_socket` listeners, so operator daemons
    /// that try to take every slot are turned away past their share and the
    /// node still enrolls — at boot, where a refused node fails the boot, and
    /// when a dead node's successor dials. Driven through the production
    /// acceptor on real sockets with `max_workers = 2`: two daemons and then
    /// the node; then the node leaves, a third daemon dials, and the node's
    /// successor.
    ///
    /// **Watched red:** with the node's listener drawing on the shared pool
    /// (`LocalCapacityRuntime::start` sizing one pool of `max_workers` for every
    /// listener), the second daemon is admitted and the node is turned away.
    #[tokio::test]
    #[cfg(unix)]
    async fn operator_daemons_never_take_the_supervised_node_slot() {
        let data = tempfile::tempdir().expect("data dir");
        let daemons = data.path().join("w.sock");
        let node = crate::supervised_node::socket_path(data.path());
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
        ));
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::clone(&supervisor),
            Arc::clone(&heartbeat),
            kata_core::ledger::InFlightLedger::in_memory(),
        ));
        let recovery_exchange =
            kata_workflow::recovery_exchange::RecoveryExchange::new(Arc::clone(&supervisor));
        let runtime = LocalCapacityRuntime::start(
            std::slice::from_ref(&daemons),
            Some(&node),
            data.path(),
            "main".to_owned(),
            2,
            Arc::clone(&supervisor),
            dispatcher,
            heartbeat,
            recovery_exchange,
        )
        .expect("start local capacity")
        .expect("two listeners configured");
        let secret = load_existing_enrollment_secret(&data.path().join(ENROLLMENT_SECRET_FILE))
            .expect("the acceptor created the enrollment secret");

        let (first, first_daemon) = enroll_one(&daemons, &secret, &supervisor).await;
        let (second, _second_daemon) = enroll_one(&daemons, &secret, &supervisor).await;
        let (node_admitted, first_node) = enroll_one(&node, &secret, &supervisor).await;
        assert_eq!(
            (first, second, node_admitted),
            (true, false, true),
            "(first daemon, second daemon, node) admitted: the daemons share one slot and the \
             node keeps its own"
        );

        // The node leaves; its slot frees once the main's reactor finished with it.
        kata_transport::WorkerSideTransport::shutdown(first_node.as_ref())
            .await
            .expect("close the first node");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while supervisor.recovery_peers().len() != 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the first node's registration outlived its connection"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (third, _third_daemon) = enroll_one(&daemons, &secret, &supervisor).await;
        let (successor, next_node) = enroll_one(&node, &secret, &supervisor).await;
        assert_eq!(
            (third, successor),
            (false, true),
            "(a daemon dialing while the node was away, the node's successor) admitted"
        );

        for worker in [first_daemon, next_node] {
            kata_transport::WorkerSideTransport::shutdown(worker.as_ref())
                .await
                .expect("close an admitted worker");
        }
        assert!(runtime.shutdown(Duration::from_secs(5)).await);
    }
}
