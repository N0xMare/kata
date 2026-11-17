//! Offline source ownership and bounded recovery-only worker exports.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use kata_core::store::backup::{ExternalRecoveryGeneration, RecoveryMemberSource};
use kata_transport::supervisor::WorkerPoolSupervisor;
use kata_workflow::recovery_exchange::RecoveryExchange;
use ulid::Ulid;

#[path = "recovery_capture/workers.rs"]
mod workers;
#[path = "recovery_capture/workspaces.rs"]
mod workspaces;
use workers::{REQUEST_BUDGET, connect_retained_workers, export_local_worker, export_worker};
pub(super) use workspaces::verify_workspace_population;
#[cfg(test)]
#[path = "recovery_capture/checkpoint_live_tests.rs"]
mod checkpoint_live_tests;
#[cfg(test)]
#[path = "recovery_capture/checkpoint_tests.rs"]
pub(super) mod checkpoint_tests;

const CAPTURE_BUDGET: Duration = Duration::from_mins(15);
const CONNECTION_BUDGET: Duration = Duration::from_secs(60);

/// The source main must be stopped. Existing source identity and store lifetimes
/// are retained; this path starts no scheduler, dispatcher or workflow runner.
pub(super) fn run_backup_recoverable_cmd(
    config: std::path::PathBuf,
    out: std::path::PathBuf,
) -> Result<()> {
    use crate::attachment::{InstalledDiscoveryLease, InstalledLifecycleOperationLease};
    use crate::data_dir_lock::{InstalledDataDirLock, inspect_identity};
    let manager = kata_core::ConfigManager::load(&config)?;
    let cfg = manager.snapshot();
    if cfg.vcs.recovery_remote.is_none() {
        bail!("recoverable backup requires vcs.recovery_remote");
    }
    refuse_capture_overlap(&cfg.node.data_dir, &cfg.vcs.jj_repo, &out)?;
    let identity = inspect_identity(&cfg.node.data_dir)?
        .context("recoverable backup requires an existing identified source")?;
    let _operation = InstalledLifecycleOperationLease::acquire()
        .context("recoverable backup cannot acquire the lifecycle operation lease")?;
    let discovery = InstalledDiscoveryLease::acquire()
        .context("recoverable backup requires the installed main to be stopped")?;
    let source = InstalledDataDirLock::acquire_expected(
        &discovery,
        &cfg.node.data_dir,
        None,
        &identity.directory_id,
    )?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let manifest = runtime.block_on(capture_locked(
        &manager,
        source.data_dir(),
        &identity.directory_id,
        &out,
    ))?;
    println!(
        "recoverable artifact = {}\nartifact_id = {}\nsource_directory_id = {}\n{}",
        out.display(),
        manifest
            .manifest()
            .artifact_id
            .context("verified artifact lacks identity")?,
        identity.directory_id,
        manifest.completeness()
    );
    Ok(())
}

async fn capture_locked(
    manager: &kata_core::ConfigManager,
    data_dir: &Path,
    source_main: &str,
    out: &Path,
) -> Result<kata_core::store::backup::VerifiedRecoveryArtifact> {
    use kata_core::store::backup::{
        RecoveryCapture, backup_recovery_data_dir, inherited_worker_generations,
    };
    use kata_types::config::WorkerTransportConfig;
    let cfg = manager.snapshot();
    refuse_capture_overlap(data_dir, &cfg.vcs.jj_repo, out)?;
    let deadline = Instant::now() + CAPTURE_BUDGET;
    let cohort = super::recovery_references::recovery_cohort_source(data_dir, deadline)?;
    let permitted = cohort.executions.keys().copied().collect();
    verify_workspace_population(&cfg.vcs.jj_repo, &permitted)?;
    let artifact_id = Ulid::new();
    let staging = tempfile::tempdir()?;
    let operational = kata_core::OperationalDb::open(data_dir.join("operational.db"))?;
    let inherited = inherited_worker_generations(data_dir, &operational, deadline)?;
    let domains = operational.worker_recovery_domains()?;
    let native: Vec<_> = domains
        .iter()
        .filter(|domain| domain.source_main == source_main)
        .cloned()
        .collect();
    for domain in &domains {
        if domain.source_main != source_main && !inherited.iter().any(|item| item.domain == *domain)
        {
            bail!("foreign worker domain has no verified import evidence: {domain:?}");
        }
    }
    let local_store = Arc::new(kata_core::IdempotencyStore::open_existing(
        data_dir.join("idempotency.db"),
    )?);
    let local_membrane = local_store.membrane_id()?;
    let local_domain = native
        .iter()
        .find(|domain| domain.membrane == local_membrane)
        .cloned();
    let remote_domains: Vec<_> = native
        .into_iter()
        .filter(|domain| domain.membrane != local_membrane)
        .collect();
    let paths = cfg
        .workers
        .transports
        .iter()
        .filter_map(|transport| match transport {
            WorkerTransportConfig::LocalSocket { path } => Some(path.clone()),
            WorkerTransportConfig::SupervisedNode {} => None,
        })
        .collect::<Vec<_>>();
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let exchange = RecoveryExchange::new(Arc::clone(&supervisor));
    let sessions = connect_retained_workers(
        &paths,
        data_dir,
        source_main,
        &remote_domains,
        &supervisor,
        &exchange,
        Duration::from_millis(cfg.workers.heartbeat_interval_ms),
        tokio::time::Instant::now() + CONNECTION_BUDGET,
    )
    .await?;
    let mut local = None;
    let mut exports = Vec::new();
    let result = async {
        local = match local_domain {
            Some(domain) => Some(
                export_local_worker(
                    Arc::clone(&local_store),
                    domain,
                    artifact_id,
                    staging.path(),
                )
                .await?,
            ),
            None => None,
        };
        for peer in &sessions.peers {
            exports.push(
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    export_worker(
                        artifact_id,
                        peer.clone(),
                        Arc::clone(&supervisor),
                        Arc::clone(&exchange),
                        staging.path(),
                    ),
                )
                .await??,
            );
        }
        let check_workers = || -> Result<()> {
            verify_workspace_population(&cfg.vcs.jj_repo, &permitted)?;
            if Instant::now() >= deadline {
                bail!("recoverable capture exceeded its finite capture budget");
            }
            if let Some(local) = &local {
                local.require_live()?;
            }
            for export in &exports {
                export.require_live()?;
            }
            Ok(())
        };
        check_workers()?;
        let remote = cfg
            .vcs
            .recovery_remote
            .as_ref()
            .context("missing recovery remote")?;
        let verifier = super::recovery_artifact_verifier::ArtifactVerifier::new(
            remote.id.clone(),
            remote.url.clone(),
            deadline,
        );
        tokio::task::block_in_place(|| -> Result<_> {
            let census = super::recovery_references::census_source(data_dir, deadline)?;
            kata_vcs::jj::recovery_references::with_recovery_references(
                &cfg.vcs.jj_repo,
                census.changes(),
                census.commits(),
                census.named_refs(),
                deadline,
                |snapshot, workspaces| -> Result<_> {
                    let registered = workspaces.execution_workspaces()?;
                    let registered_ids: std::collections::BTreeSet<_> = registered.iter().map(|item| item.execution_id).collect();
                    if registered_ids != permitted || registered.len() != permitted.len() {
                        bail!("recoverable backup requires exact supported execution workspace registrations");
                    }
                    let mut checkpoints = Vec::new();
                    let mut checkpoint_members = Vec::new();
                    let mut checkpoint_bytes = 0u64;
                    for workspace in registered {
                        use kata_core::store::backup::{capture_checkpoint_tree, RecoveryWorkspaceCheckpoint};
                        let boundary = &cohort.executions[&workspace.execution_id];
                        let prefix = format!("recovery/jj/checkpoints/{}", workspace.execution_id);
                        let (candidate, members) = capture_checkpoint_tree(&workspace.path, &format!("{prefix}/candidate"), true, deadline)?;
                        extend_checkpoint_members(&mut checkpoint_members, &mut checkpoint_bytes, members)?;
                        checkpoints.push(RecoveryWorkspaceCheckpoint {
                            execution_id: workspace.execution_id,
                            program_hash: boundary.program_hash.clone(),
                            authority_head: cohort.authority_head,
                            sleeps: boundary.sleeps.clone(),
                            workspace_commit_id: workspace.commit_id.clone(),
                            candidate,
                        });
                    }
                    checkpoints.sort_by_key(|item| item.execution_id);
                    let proof = verifier.build_proof(snapshot, artifact_id)?;
                    check_workers()?;
                    let proof_path = staging.path().join("proof.json");
                    write_private_json(&proof_path, &proof)?;
                    let mut instances = exports
                        .iter()
                        .map(|export| export.generation.clone())
                        .collect::<Vec<_>>();
                    let mut members = exports
                        .iter()
                        .flat_map(|export| export.members.clone())
                        .collect::<Vec<_>>();
                    members.extend(checkpoint_members);
                    if let Some(local) = &local {
                        instances.push(local.generation.clone());
                        members.extend(local.members.clone());
                    }
                    instances.sort_by_key(|instance| {
                        (instance.domain.membrane.0, instance.domain.enrollment)
                    });
                    members.push(RecoveryMemberSource {
                        name: "recovery/jj/proof.json".into(),
                        source_path: proof_path,
                    });
                    let capture = RecoveryCapture {
                        artifact_id,
                        source_directory_id: source_main.into(),
                        recovery_assets: treatments(&proof, instances, inherited.clone(), checkpoints)?,
                        members,
                    };
                    let guarded = LiveSourceVerifier {
                        verifier: &verifier,
                        check_workers: &check_workers,
                    };
                    Ok(backup_recovery_data_dir(
                        data_dir,
                        out,
                        Some(manager),
                        &capture,
                        &guarded,
                    )?)
                },
            )?
        })
    }
    .await;
    use futures::StreamExt as _;
    let _ = tokio::time::timeout(
        REQUEST_BUDGET,
        futures::stream::iter(exports).for_each_concurrent(16, workers::ExportedWorker::release),
    )
    .await;
    if let Some(local) = local {
        local.release().await;
    }
    let _ = tokio::time::timeout(REQUEST_BUDGET, supervisor.shutdown_registered_workers()).await;
    sessions.shutdown().await;
    result
}

fn extend_checkpoint_members(
    destination: &mut Vec<RecoveryMemberSource>,
    bytes: &mut u64,
    members: Vec<RecoveryMemberSource>,
) -> Result<()> {
    for member in &members {
        let metadata = std::fs::symlink_metadata(&member.source_path)?;
        if !metadata.is_file() {
            bail!("checkpoint source member changed kind before capture");
        }
        *bytes = bytes
            .checked_add(metadata.len())
            .context("checkpoint byte count overflow")?;
        if *bytes > kata_core::store::backup::MAX_CHECKPOINT_BYTES {
            bail!("checkpoint population exceeds aggregate 16 GiB capture bound");
        }
    }
    destination.extend(members);
    Ok(())
}

fn refuse_capture_overlap(data_dir: &Path, repo: &Path, out: &Path) -> Result<()> {
    let source = data_dir
        .canonicalize()
        .context("resolve recovery source directory")?;
    let repo = repo
        .canonicalize()
        .context("resolve recovery jj repository")?;
    let output = if out.try_exists()? {
        let metadata = std::fs::symlink_metadata(out)?;
        if metadata.file_type().is_symlink() {
            bail!("recovery output must not be a symlink");
        }
        out.canonicalize()?
    } else {
        let name = out
            .file_name()
            .context("recovery output needs a final directory name")?;
        let parent = out
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        parent
            .canonicalize()
            .context("recovery output parent must exist")?
            .join(name)
    };
    for root in [&source, &repo] {
        if output.starts_with(root) || root.starts_with(&output) {
            bail!("recovery output overlaps a source authority or jj repository root");
        }
    }
    Ok(())
}

struct LiveSourceVerifier<'a> {
    verifier: &'a dyn kata_core::store::backup::RecoveryVerifier,
    check_workers: &'a dyn Fn() -> Result<()>,
}

impl kata_core::store::backup::RecoveryVerifier for LiveSourceVerifier<'_> {
    fn deadline(&self) -> Instant {
        self.verifier.deadline()
    }

    fn verify_captured_references(
        &self,
        artifact: &Path,
        manifest: &kata_core::store::backup::BackupManifest,
    ) -> kata_types::error::KataResult<kata_core::store::backup::CapturedRecoveryReferences> {
        let references = self
            .verifier
            .verify_captured_references(artifact, manifest)?;
        (self.check_workers)()
            .map_err(|error| kata_types::error::KataError::Storage(error.to_string()))?;
        Ok(references)
    }
}

fn write_private_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    use std::io::Write as _;
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 1024 * 1024 {
        bail!("recovery proof exceeds its 1 MiB bound");
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn treatments(
    proof: &kata_core::store::backup::RemoteRecoveryProof,
    instances: Vec<ExternalRecoveryGeneration>,
    inherited: Vec<kata_core::store::backup::InheritedRecoveryGeneration>,
    checkpoints: Vec<kata_core::store::backup::RecoveryWorkspaceCheckpoint>,
) -> Result<Vec<kata_core::store::backup::RecoveryAsset>> {
    use kata_core::durable_assets::{AssetLocation, DURABLE_ASSETS};
    use kata_core::store::backup::{RecoveryAsset, RecoveryRebindTarget, RecoveryTreatment};
    DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.authority.is_authoritative())
        .map(|asset| {
            let location = asset.location.name();
            let target_kind = match location {
                "main-identity.json" => Some(RecoveryRebindTarget::MainIdentity),
                "local-worker.secret" => Some(RecoveryRebindTarget::LocalWorkerCredential),
                "subordinate-worker:credential_path" => {
                    Some(RecoveryRebindTarget::SubordinateWorkerCredential)
                }
                "workflow roots" => Some(RecoveryRebindTarget::WorkflowRoots),
                "operator secret/proxy backend" => Some(RecoveryRebindTarget::OperatorBackend),
                _ => None,
            };
            let treatment = if let Some(target_kind) = target_kind {
                RecoveryTreatment::RebindRequired { target_kind }
            } else if location == "subordinate-worker:idempotency.db" {
                RecoveryTreatment::ExternalGenerations {
                    instances: instances.clone(),
                    inherited: inherited.clone(),
                }
            } else if location == "vcs.jj_repo" {
                RecoveryTreatment::ReacquireVerified {
                    checkpoints: checkpoints.clone(),
                    remote_id: proof.remote_id.clone(),
                    required_commits: proof.required_commits.clone(),
                    reference_set_digest: proof.reference_set_digest.clone(),
                    proof_member: "recovery/jj/proof.json".into(),
                }
            } else if location == "--config" {
                RecoveryTreatment::CapturedMembers {
                    asset_names: vec!["kata.toml".into()],
                    tree_locations: vec![],
                }
            } else {
                match asset.location {
                    AssetLocation::DataDirFile(name) => RecoveryTreatment::CapturedMembers {
                        asset_names: vec![name.into()],
                        tree_locations: vec![],
                    },
                    AssetLocation::DataDirTree(name) => RecoveryTreatment::CapturedMembers {
                        asset_names: vec![],
                        tree_locations: vec![name.into()],
                    },
                    _ => bail!(
                        "recoverable capture has no treatment for authoritative asset {location}"
                    ),
                }
            };
            Ok(RecoveryAsset {
                location: location.into(),
                treatment,
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "recovery_capture/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "recovery_capture/disk_full_tests.rs"]
mod disk_full_tests;
