//! Authenticated worker generations and their bounded control-session lifetimes.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use kata_core::store::backup::{ExternalRecoveryGeneration, RecoveryMemberSource};
use kata_transport::supervisor::{WorkerPoolSupervisor, WorkerRecoveryPeer};
use kata_types::identity::WorkerEffectDomain;
use kata_types::recovery::{
    MAX_RECOVERY_CHUNK_BYTES, MAX_RECOVERY_DATABASE_BYTES, MAX_RECOVERY_HOLD_MS, RecoveryCommand,
    RecoveryReply, RecoveryRequest, WorkerRecoveryReceipt,
};
use kata_workflow::recovery_exchange::RecoveryExchange;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use ulid::Ulid;

/// The unavailable set is retained as data for callers and rendered without
/// credentials. A refused handshake cannot stand in for an empty inventory.
#[derive(Debug)]
pub(super) struct UnavailableWorkerDomains {
    pub domains: Vec<WorkerEffectDomain>,
}

impl std::fmt::Display for UnavailableWorkerDomains {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "unavailable retained worker domains:")?;
        for domain in &self.domains {
            write!(
                formatter,
                " [main={} membrane={} enrollment={}]",
                domain.source_main, domain.membrane.0, domain.enrollment
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for UnavailableWorkerDomains {}

pub(super) struct LocalExport {
    pub generation: ExternalRecoveryGeneration,
    pub members: Vec<RecoveryMemberSource>,
    hold: Arc<kata_core::idempotency_store::IdempotencyRecoveryHold>,
    renewal: JoinHandle<()>,
}

impl LocalExport {
    pub fn require_live(&self) -> Result<()> {
        if !self.hold.is_live() {
            bail!("main-local recovery generation expired");
        }
        Ok(())
    }

    pub(super) async fn release(mut self) {
        self.renewal.abort();
        let _ = (&mut self.renewal).await;
    }
}

impl Drop for LocalExport {
    fn drop(&mut self) {
        self.renewal.abort();
    }
}

pub(super) async fn export_local_worker(
    store: Arc<kata_core::IdempotencyStore>,
    domain: WorkerEffectDomain,
    artifact_id: Ulid,
    staging: &Path,
) -> Result<LocalExport> {
    let request = RecoveryRequest {
        artifact_id,
        request_nonce: Ulid::new(),
        domain,
    };
    let database_path = staging.join("main-local-idempotency.db");
    let receipt_path = staging.join("main-local-receipt.json");
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&database_path)
        .await?;
    drop(file);
    let hold = Arc::new(tokio::task::block_in_place(|| {
        store.begin_recovery_capture(
            &request,
            &database_path,
            MAX_RECOVERY_HOLD_MS,
            MAX_RECOVERY_DATABASE_BYTES,
        )
    })?);
    let receipt = hold.receipt();
    validate_receipt(&request, receipt)?;
    let prefix = format!(
        "recovery/workers/{}/{}",
        receipt.domain.membrane.0, receipt.domain.enrollment
    );
    let renewal_hold = Arc::clone(&hold);
    let renewal = tokio::spawn(async move {
        loop {
            tokio::time::sleep(RENEW_INTERVAL).await;
            if renewal_hold.renew(MAX_RECOVERY_HOLD_MS).is_err() {
                return;
            }
        }
    });
    let export = LocalExport {
        generation: ExternalRecoveryGeneration {
            domain: receipt.domain.clone(),
            generation_id: receipt.generation_id,
            request_nonce: receipt.request_nonce,
            database_member: format!("{prefix}/idempotency.db"),
            receipt_member: format!("{prefix}/receipt.json"),
        },
        members: vec![
            RecoveryMemberSource {
                name: format!("{prefix}/idempotency.db"),
                source_path: database_path,
            },
            RecoveryMemberSource {
                name: format!("{prefix}/receipt.json"),
                source_path: receipt_path.clone(),
            },
        ],
        hold,
        renewal,
    };
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipt_path)
        .await?;
    file.write_all(&serde_json::to_vec(export.hold.receipt())?)
        .await?;
    file.sync_all().await?;
    export.require_live()?;
    Ok(export)
}

/// Owns only control receivers. Dropping this scope cancels all of them, which
/// invalidates their exact registrations through RecoveryExchange's guard.
pub(super) struct WorkerSessions {
    pub peers: Vec<WorkerRecoveryPeer>,
    receivers: tokio::task::JoinSet<()>,
}

impl WorkerSessions {
    pub(super) async fn shutdown(mut self) {
        self.receivers.abort_all();
        let _ = tokio::time::timeout(REQUEST_BUDGET, async {
            while self.receivers.join_next().await.is_some() {}
        })
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_retained_workers(
    paths: &[std::path::PathBuf],
    data_dir: &Path,
    source_main: &str,
    domains: &[WorkerEffectDomain],
    supervisor: &Arc<WorkerPoolSupervisor>,
    exchange: &Arc<RecoveryExchange>,
    heartbeat_interval: Duration,
    deadline: tokio::time::Instant,
) -> Result<WorkerSessions> {
    use kata_transport::{LocalSocketTransport, WorkerTransport};
    use kata_types::containment_claim::ClaimedContainment;
    let mut sessions = WorkerSessions {
        peers: Vec::new(),
        receivers: tokio::task::JoinSet::new(),
    };
    if domains.is_empty() {
        return Ok(sessions);
    }
    if paths.is_empty() {
        return Err(UnavailableWorkerDomains {
            domains: domains.to_vec(),
        }
        .into());
    }
    crate::local_capacity::validate_listener_paths(paths, data_dir)?;
    let secret = crate::local_capacity::load_existing_enrollment_secret(
        &data_dir.join("local-worker.secret"),
    )
    .context(UnavailableWorkerDomains {
        domains: domains.to_vec(),
    })?;
    let mut listeners = Vec::new();
    for path in paths {
        listeners.push(
            LocalSocketTransport::listen(path).context(UnavailableWorkerDomains {
                domains: domains.to_vec(),
            })?,
        );
    }
    let mut pending = domains.to_vec();
    let connected: Result<()> = async {
        // Retained domain count bounds accepted sessions. A malformed/unknown peer
        // fails this capture instead of consuming an unbounded authentication loop.
        while !pending.is_empty() {
            let accept = futures::future::select_all(
                listeners
                    .iter()
                    .map(|listener| Box::pin(listener.accept_next())),
            );
            let (transport, _, _) = tokio::time::timeout_at(deadline, accept)
                .await
                .with_context(|| UnavailableWorkerDomains {
                    domains: pending.clone(),
                })?;
            let transport: Arc<dyn WorkerTransport> =
                Arc::new(transport.with_context(|| UnavailableWorkerDomains {
                    domains: pending.clone(),
                })?);
            let authenticated = tokio::time::timeout_at(
                deadline,
                kata_transport::enrollment::authenticate_main(
                    transport.as_ref(),
                    &secret,
                    source_main,
                    heartbeat_interval,
                    |membrane| {
                        pending
                            .iter()
                            .find(|domain| domain.membrane == membrane)
                            .cloned()
                            .ok_or_else(|| {
                                kata_types::error::KataError::Validation(
                                    "recovery refuses unknown or duplicate source enrollment"
                                        .into(),
                                )
                            })
                    },
                ),
            )
            .await
            .with_context(|| UnavailableWorkerDomains {
                domains: pending.clone(),
            })?;
            let kata_transport::enrollment::EnrolledWorker {
                domain,
                executor_term,
                ..
            } = match authenticated {
                Ok(authenticated) => authenticated,
                Err(error) => {
                    let _ = tokio::time::timeout(REQUEST_BUDGET, transport.shutdown()).await;
                    return Err(
                        anyhow::Error::from(error).context(UnavailableWorkerDomains {
                            domains: pending.clone(),
                        }),
                    );
                }
            };
            pending.retain(|retained| retained != &domain);
            let peer = supervisor.register_worker_with_effect_domain(
                format!("recovery-{}", domain.enrollment).into(),
                transport,
                Vec::new(),
                ClaimedContainment::Unstated {
                    evidence: "recovery-only session admits no work".into(),
                },
                executor_term,
                domain,
            );
            let receiver_peer = peer.clone();
            let receiver_exchange = Arc::clone(exchange);
            sessions.receivers.spawn(async move {
                let _ = receiver_exchange.run_control_peer(receiver_peer).await;
            });
            sessions.peers.push(peer);
        }
        Ok(())
    }
    .await;
    // No new enrollment or reconnection can enter behind the capture census.
    drop(listeners);
    if let Err(error) = connected {
        let _ =
            tokio::time::timeout(REQUEST_BUDGET, supervisor.shutdown_registered_workers()).await;
        sessions.shutdown().await;
        return Err(error);
    }
    Ok(sessions)
}

pub(super) const REQUEST_BUDGET: Duration = Duration::from_secs(10);
const RENEW_INTERVAL: Duration = Duration::from_secs(10);
const HOLD_DURATION: Duration = Duration::from_millis(MAX_RECOVERY_HOLD_MS);

/// A reply consumes part of the worker's grant while travelling back to main.
/// All deadlines therefore start before send, including the initial VACUUM.
struct LeaseState {
    until: Instant,
    failed: bool,
}

pub(super) struct ExportedWorker {
    pub generation: ExternalRecoveryGeneration,
    pub members: Vec<RecoveryMemberSource>,
    peer: WorkerRecoveryPeer,
    exchange: Arc<RecoveryExchange>,
    supervisor: Arc<WorkerPoolSupervisor>,
    lease: Arc<parking_lot::Mutex<LeaseState>>,
    renewal: JoinHandle<()>,
    request: RecoveryRequest,
}

impl ExportedWorker {
    pub fn require_live(&self) -> Result<()> {
        let lease = self.lease.lock();
        if lease.failed
            || Instant::now() >= lease.until
            || !self.supervisor.recovery_peer_is_current(&self.peer)
        {
            bail!(
                "worker recovery generation is no longer held: {:?}",
                self.generation.domain
            );
        }
        Ok(())
    }

    pub async fn release(mut self) {
        self.renewal.abort();
        let _ = (&mut self.renewal).await;
        let _ = self
            .exchange
            .request(
                &self.peer,
                RecoveryCommand::Release {
                    request: self.request.clone(),
                    generation_id: self.generation.generation_id,
                },
                REQUEST_BUDGET,
            )
            .await;
    }
}

impl Drop for ExportedWorker {
    fn drop(&mut self) {
        // Never leave a detached renewal keeping a worker paused after failure.
        self.renewal.abort();
    }
}

/// Stream one authenticated generation into a private staging directory.
/// Renewals share the request mutex, preventing overlap with chunk requests.
pub(super) async fn export_worker(
    artifact_id: Ulid,
    peer: WorkerRecoveryPeer,
    supervisor: Arc<WorkerPoolSupervisor>,
    exchange: Arc<RecoveryExchange>,
    staging: &Path,
) -> Result<ExportedWorker> {
    let request = RecoveryRequest {
        artifact_id,
        request_nonce: Ulid::new(),
        domain: peer.domain().clone(),
    };
    let started = Instant::now();
    let reply = exchange
        .request(
            &peer,
            RecoveryCommand::Begin {
                request: request.clone(),
                hold_ms: MAX_RECOVERY_HOLD_MS,
                max_bytes: MAX_RECOVERY_DATABASE_BYTES,
            },
            HOLD_DURATION,
        )
        .await?;
    let RecoveryReply::Ready { receipt } = reply else {
        bail!("worker refused recovery generation: {:?}", peer.domain());
    };
    validate_receipt(&request, &receipt)?;
    let lease = Arc::new(parking_lot::Mutex::new(LeaseState {
        until: started + HOLD_DURATION,
        failed: Instant::now() >= started + HOLD_DURATION,
    }));
    let request_lock = Arc::new(Mutex::new(()));
    let renewal = spawn_renewal(
        peer.clone(),
        Arc::clone(&exchange),
        request.clone(),
        receipt.generation_id,
        Arc::clone(&lease),
        Arc::clone(&request_lock),
    );
    let prefix = format!(
        "recovery/workers/{}/{}",
        receipt.domain.membrane.0, receipt.domain.enrollment
    );
    let database_path = staging.join(format!(
        "{}-{}.db",
        receipt.domain.membrane.0, receipt.domain.enrollment
    ));
    let receipt_path = staging.join(format!(
        "{}-{}.json",
        receipt.domain.membrane.0, receipt.domain.enrollment
    ));
    let exported = ExportedWorker {
        generation: ExternalRecoveryGeneration {
            domain: receipt.domain.clone(),
            generation_id: receipt.generation_id,
            request_nonce: receipt.request_nonce,
            database_member: format!("{prefix}/idempotency.db"),
            receipt_member: format!("{prefix}/receipt.json"),
        },
        members: vec![
            RecoveryMemberSource {
                name: format!("{prefix}/idempotency.db"),
                source_path: database_path.clone(),
            },
            RecoveryMemberSource {
                name: format!("{prefix}/receipt.json"),
                source_path: receipt_path.clone(),
            },
        ],
        peer,
        exchange,
        supervisor,
        lease,
        renewal,
        request: request.clone(),
    };
    download(&exported, &request, &receipt, &database_path, &request_lock).await?;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_path)
        .await?;
    file.write_all(&serde_json::to_vec(&receipt)?).await?;
    file.sync_all().await?;
    exported.require_live()?;
    Ok(exported)
}

fn validate_receipt(request: &RecoveryRequest, receipt: &WorkerRecoveryReceipt) -> Result<()> {
    if receipt.artifact_id != request.artifact_id
        || receipt.request_nonce != request.request_nonce
        || receipt.domain != request.domain
        || receipt.generation_id == Ulid::nil()
        || receipt.schema_version != kata_core::idempotency_store::IDEMPOTENCY_SCHEMA_VERSION
        || receipt.database_byte_len == 0
        || receipt.database_byte_len > MAX_RECOVERY_DATABASE_BYTES
        || receipt.database_digest.len() != 64
        || !receipt
            .database_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("invalid authenticated worker recovery receipt");
    }
    Ok(())
}

fn spawn_renewal(
    peer: WorkerRecoveryPeer,
    exchange: Arc<RecoveryExchange>,
    request: RecoveryRequest,
    generation_id: Ulid,
    lease: Arc<parking_lot::Mutex<LeaseState>>,
    request_lock: Arc<Mutex<()>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(RENEW_INTERVAL).await;
            let _request_guard = request_lock.lock().await;
            let started = Instant::now();
            if started >= lease.lock().until {
                lease.lock().failed = true;
                return;
            }
            let reply = exchange
                .request(
                    &peer,
                    RecoveryCommand::Renew {
                        request: request.clone(),
                        generation_id,
                        hold_ms: MAX_RECOVERY_HOLD_MS,
                    },
                    REQUEST_BUDGET,
                )
                .await;
            let mut state = lease.lock();
            if !matches!(reply, Ok(RecoveryReply::Renewed { .. })) || Instant::now() >= state.until
            {
                state.failed = true;
                return;
            }
            state.until = started + HOLD_DURATION;
        }
    })
}

async fn download(
    export: &ExportedWorker,
    request: &RecoveryRequest,
    receipt: &WorkerRecoveryReceipt,
    destination: &Path,
    request_lock: &Mutex<()>,
) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .await?;
    let mut offset = 0u64;
    let mut digest = blake3::Hasher::new();
    while offset < receipt.database_byte_len {
        export.require_live()?;
        let _guard = request_lock.lock().await;
        let reply = export
            .exchange
            .request(
                &export.peer,
                RecoveryCommand::Read {
                    request: request.clone(),
                    generation_id: receipt.generation_id,
                    offset,
                    max_bytes: MAX_RECOVERY_CHUNK_BYTES,
                },
                REQUEST_BUDGET,
            )
            .await?;
        let RecoveryReply::Chunk {
            bytes,
            offset: actual_offset,
            ..
        } = reply
        else {
            bail!("worker refused a recovery chunk");
        };
        let next = offset
            .checked_add(bytes.len() as u64)
            .context("recovery offset overflow")?;
        if bytes.is_empty()
            || actual_offset != offset
            || bytes.len() > MAX_RECOVERY_CHUNK_BYTES as usize
            || next > receipt.database_byte_len
        {
            bail!("worker returned an invalid recovery chunk");
        }
        digest.update(&bytes);
        file.write_all(&bytes).await?;
        offset = next;
    }
    file.sync_all().await?;
    if digest.finalize().to_hex().as_str() != receipt.database_digest {
        bail!("worker recovery bytes disagree with authenticated receipt digest");
    }
    export.require_live()
}
