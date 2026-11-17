//! Verified clone extraction into a fresh, explicitly configured target.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use kata_core::store::backup::{
    read_remote_recovery_proof, restore_recovery_data_dir, verify_recovery_artifact,
};
use kata_types::recovery::{RecoveryReferenceKind, RecoveryReferenceSnapshot};
use kata_vcs::VcsBackend as _;
use kata_vcs::jj::recovery_references::RecoveryNamedReference;

use super::recovery_artifact_verifier::ArtifactVerifier;

/// The wall-clock bound on one `kata restore --recoverable`, from the config load
/// through the import release. The artifact and remote verification, the repository
/// install, the checkpoint-tree extraction, the metadata sync, the activation and the
/// readiness SQL all spend it. Each step checks it between pieces of real work and
/// refuses once it has passed. The one lock wait it bounds is the target repository's
/// jj op-heads fence, which no main holds during an offline restore; the operational.db
/// writer transactions restore opens wait on their own busy_timeout, not on this
/// budget. Its scale is
/// `CAPTURE_BUDGET`'s because it bounds the reverse of that copy: a whole data
/// directory and repository written and fsynced on the target host. A caller that
/// does not prove a deadline property runs `restore_locked` under this budget.
pub(super) const RESTORE_BUDGET: Duration = Duration::from_mins(15);

fn read_recovery_decisions(path: &Path) -> Result<kata_core::operational::ImportDecisionPacket> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    const MAX_BYTES: u64 = 1024 * 1024;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        bail!("recovery decisions must be a regular file no larger than 1 MiB");
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(MAX_BYTES)? {
        bail!("recovery decisions exceed 1 MiB");
    }
    serde_json::from_slice(&bytes).context("invalid recovery decision packet")
}

fn validate_recovery_decisions(
    decisions: Option<&kata_core::operational::ImportDecisionPacket>,
    manifest: &kata_core::store::backup::BackupManifest,
    cohort: &super::recovery_references::RecoveryCohort,
) -> Result<()> {
    let executions: Vec<_> = cohort.executions.keys().copied().collect();
    match decisions {
        Some(packet) => packet.validate_execution_resume_set(
            manifest.artifact_id.context("artifact identity missing")?,
            &executions,
        )?,
        None if !executions.is_empty() => bail!(
            "checkpointed execution restore requires --recovery-decisions with exact artifact-bound resume approvals"
        ),
        None => {}
    }
    Ok(())
}

pub(super) fn run_restore_recoverable_cmd(
    from: PathBuf,
    config: PathBuf,
    recovery_decisions: Option<PathBuf>,
) -> Result<()> {
    use crate::attachment::{InstalledDiscoveryLease, InstalledLifecycleOperationLease};
    use crate::data_dir_lock::OfflineRestoreLock;
    let manager = kata_core::ConfigManager::load(&config)?;
    let cfg = manager.snapshot();
    let deadline = Instant::now() + RESTORE_BUDGET;
    let decisions = recovery_decisions
        .as_deref()
        .map(read_recovery_decisions)
        .transpose()?;
    let remote = cfg
        .vcs
        .recovery_remote
        .as_ref()
        .context("recoverable restore requires an explicit vcs.recovery_remote")?;
    let trunk = cfg
        .vcs
        .trunk
        .as_deref()
        .context("recoverable restore requires an explicit vcs.trunk name")?;
    let from = from.canonicalize()?;
    let data = new_target_path(&cfg.node.data_dir)?;
    let repo = new_target_path(&cfg.vcs.jj_repo)?;
    for (left, right) in [(&from, &data), (&from, &repo), (&data, &repo)] {
        if left.starts_with(right) || right.starts_with(left) {
            bail!(
                "recoverable restore requires disjoint artifact, data-directory and repository paths"
            );
        }
    }
    verify_config_bindings(&config, &cfg, deadline)?;
    let verifier = ArtifactVerifier::new(remote.id.clone(), remote.url.clone(), deadline);
    let checked = verify_recovery_artifact(&from, &verifier)?;
    let cohort =
        super::recovery_references::recovery_cohort_captured(&from, checked.manifest(), deadline)?;
    validate_recovery_decisions(decisions.as_ref(), checked.manifest(), &cohort)?;
    cohort.verify_target_agents(&cfg)?;
    let proof = read_remote_recovery_proof(&from, checked.manifest())?;
    let census = super::recovery_references::census_captured(&from, checked.manifest(), deadline)?;
    let bookmarks = target_bookmarks(&proof.reference_snapshot, census.named_refs(), trunk)?;
    let _operation = InstalledLifecycleOperationLease::acquire()?;
    let discovery = InstalledDiscoveryLease::acquire()?;
    let ownership = OfflineRestoreLock::acquire(&discovery, &data)?;
    restore_locked(
        &ownership,
        &from,
        &config,
        &cfg,
        &verifier,
        deadline,
        &bookmarks,
        decisions.as_ref(),
    )
}

pub(super) fn restore_locked(
    ownership: &crate::data_dir_lock::OfflineRestoreLock<'_>,
    from: &Path,
    config: &Path,
    cfg: &kata_types::KataConfig,
    verifier: &ArtifactVerifier,
    deadline: Instant,
    bookmarks: &BTreeMap<String, String>,
    decisions: Option<&kata_core::operational::ImportDecisionPacket>,
) -> Result<()> {
    let repo = &cfg.vcs.jj_repo;
    let trunk = cfg.vcs.trunk.as_deref().context("target trunk is absent")?;
    verify_config_bindings(config, cfg, deadline)?;
    verify_owned_worker_paths(cfg, ownership.data_dir())?;
    let preflight = verify_recovery_artifact(from, verifier)?;
    let cohort =
        super::recovery_references::recovery_cohort_captured(from, preflight.manifest(), deadline)?;
    validate_recovery_decisions(decisions, preflight.manifest(), &cohort)?;
    cohort.verify_target_agents(cfg)?;
    let artifact = restore_recovery_data_dir(from, ownership.data_dir(), None, verifier)?;
    let repository = verifier.take_repository()?;
    repository.install_git_repository(
        repo,
        bookmarks,
        trunk,
        kata_workflow::repo_artifacts::repo_local_artifact_roots(),
        remote_limits(deadline)?,
    )?;
    let backend = kata_vcs::jj::JjBackend::open(repo)?;
    let checkpoints =
        kata_core::store::backup::recovery_workspace_checkpoints(artifact.manifest())?;
    for checkpoint in checkpoints {
        let candidate = backend.restore_execution_workspace(
            checkpoint.execution_id,
            &checkpoint.workspace_commit_id,
        )?;
        kata_core::store::backup::restore_checkpoint_tree(
            from,
            artifact.manifest(),
            &checkpoint.candidate,
            &candidate,
            true,
            deadline,
        )?;
    }
    backend.sync_recovery_metadata(deadline)?;
    let identity = ownership.activate_verified_import(
        &artifact,
        crate::data_dir_lock::MainMode::Installed,
        deadline,
        |data_dir, _| {
            verify_config_bindings(config, cfg, deadline)?;
            verify_owned_worker_paths(cfg, data_dir)?;
            crate::local_capacity::load_or_create_enrollment_secret(data_dir)?;
            Ok(())
        },
    )?;
    let source_proof = read_remote_recovery_proof(from, artifact.manifest())?;
    let target_verifier = TargetVerifier {
        ownership,
        config,
        cfg,
        bookmarks,
        source_changes: &source_proof.reference_snapshot.resolved_changes,
        manifest: artifact.manifest(),
        deadline,
    };
    let db =
        kata_core::operational::OperationalDb::open(ownership.data_dir().join("operational.db"))?;
    if let Some(packet) = decisions
        && !packet.decisions.is_empty()
    {
        db.apply_import_decisions(packet)?;
    }
    for authority in db.pending_import_authorities()? {
        let readiness = db.verify_import_readiness(
            ownership.data_dir(),
            &identity.directory_id,
            authority.artifact_id,
            deadline,
            &target_verifier,
        )?;
        db.release_reconciled_import(readiness)?;
    }
    db.require_imports_reconciled()?;
    println!(
        "verified recovery clone activated\nsource_directory_id = {}\ntarget_directory_id = {}\ndata_dir = {}\nrepository = {}",
        artifact
            .manifest()
            .source_directory_id
            .as_deref()
            .context("verified artifact lacks source identity")?,
        identity.directory_id,
        ownership.data_dir().display(),
        repo.display()
    );
    Ok(())
}

/// Whether `subjects` differ from naming every `expected` key exactly once and
/// nothing else: a missing, foreign or repeated subject key is a different
/// population.
fn subjects_differ(
    subjects: &[kata_core::operational::ImportSubject],
    expected: &BTreeSet<String>,
) -> bool {
    let actual: BTreeSet<_> = subjects.iter().map(|item| item.key.clone()).collect();
    actual != *expected || subjects.len() != expected.len()
}

struct TargetVerifier<'a, 'lease> {
    ownership: &'a crate::data_dir_lock::OfflineRestoreLock<'lease>,
    config: &'a Path,
    cfg: &'a kata_types::KataConfig,
    bookmarks: &'a BTreeMap<String, String>,
    source_changes: &'a BTreeMap<String, String>,
    manifest: &'a kata_core::store::backup::BackupManifest,
    deadline: Instant,
}

impl kata_core::operational::ImportTargetVerifier for TargetVerifier<'_, '_> {
    fn verify_current_target(
        &self,
        data_dir: &Path,
        current_target_id: &str,
        authority: &kata_core::operational::ImportAuthority,
        subjects: &[kata_core::operational::ImportSubject],
    ) -> kata_types::KataResult<()> {
        let checked = || -> Result<()> {
            if data_dir != self.ownership.data_dir() {
                bail!("target recovery ownership differs from verified directory");
            }
            if self.manifest.artifact_id != Some(authority.artifact_id) {
                bail!("target readiness cannot authorize an inherited pending import");
            }
            let checkpoints =
                kata_core::store::backup::recovery_workspace_checkpoints(self.manifest)?;
            let expected: BTreeSet<_> = checkpoints
                .iter()
                .map(|item| format!("{:032x}", u128::from(item.execution_id)))
                .collect();
            if subjects_differ(subjects, &expected) {
                bail!("target continuation subjects differ from authorized checkpoint population");
            }
            let identity = crate::data_dir_lock::inspect_identity(data_dir)?
                .context("target identity is absent")?;
            if identity.directory_id != current_target_id {
                bail!("target identity changed during restore");
            }
            verify_config_bindings(self.config, self.cfg, self.deadline)?;
            verify_owned_worker_paths(self.cfg, data_dir)?;
            crate::local_capacity::load_existing_enrollment_secret(
                &data_dir.join("local-worker.secret"),
            )?;
            let cohort =
                super::recovery_references::recovery_cohort_target(data_dir, self.deadline)?;
            cohort.verify_checkpoints(checkpoints)?;
            cohort.verify_target_agents(self.cfg)?;
            super::recovery_capture::verify_workspace_population(
                &self.cfg.vcs.jj_repo,
                &cohort.executions.keys().copied().collect(),
            )?;
            let backend = kata_vcs::jj::JjBackend::open(&self.cfg.vcs.jj_repo)?;
            for checkpoint in checkpoints {
                let candidate = backend.verify_recovery_execution_workspace(
                    checkpoint.execution_id,
                    &checkpoint.workspace_commit_id,
                )?;
                kata_core::store::backup::verify_materialized_checkpoint_tree(
                    &candidate,
                    &checkpoint.candidate,
                    self.manifest,
                    true,
                    self.deadline,
                )?;
            }
            let census = super::recovery_references::census_source(data_dir, self.deadline)?;
            let names: Vec<_> = self
                .bookmarks
                .keys()
                .cloned()
                .map(RecoveryNamedReference::LocalBookmark)
                .collect();
            kata_vcs::jj::recovery_references::with_recovery_references(
                &self.cfg.vcs.jj_repo,
                census.changes(),
                census.commits(),
                &names,
                self.deadline,
                |snapshot, workspaces| -> Result<()> {
                    let registered = workspaces.execution_workspaces()?;
                    let registered_ids: BTreeSet<_> =
                        registered.iter().map(|item| item.execution_id).collect();
                    let expected_ids: BTreeSet<_> =
                        checkpoints.iter().map(|item| item.execution_id).collect();
                    if registered_ids != expected_ids {
                        bail!("target workspace registrations differ from checkpoints");
                    }
                    let mapped = target_bookmarks(
                        snapshot,
                        &names,
                        self.cfg
                            .vcs
                            .trunk
                            .as_deref()
                            .context("target trunk missing")?,
                    )?;
                    if &mapped != self.bookmarks {
                        bail!("target bookmark bindings changed before activation release");
                    }
                    if &snapshot.resolved_changes != self.source_changes {
                        bail!(
                            "target durable change identifiers do not reconstruct the source commit bindings"
                        );
                    }
                    Ok(())
                },
            )??;
            Ok(())
        };
        checked().map_err(|error| {
            kata_types::KataError::Validation(format!(
                "target recovery binding verification refused: {error}"
            ))
        })
    }
}

fn new_target_path(path: &Path) -> Result<PathBuf> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "recoverable restore requires a nonexistent target: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .context("target lacks a parent directory")?
        .canonicalize()?;
    Ok(parent.join(path.file_name().context("target lacks a final component")?))
}

fn remote_limits(deadline: Instant) -> Result<kata_vcs::recovery_remote::RecoveryRemoteLimits> {
    Ok(kata_vcs::recovery_remote::RecoveryRemoteLimits {
        timeout: deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("restore deadline elapsed")?
            .min(Duration::from_secs(600)),
        max_storage_bytes: 16 * 1024 * 1024 * 1024,
        max_objects: 1_000_000,
        max_uncompressed_bytes: 64 * 1024 * 1024 * 1024,
        max_output_bytes: 128 * 1024 * 1024,
    })
}

pub(super) fn target_bookmarks(
    snapshot: &RecoveryReferenceSnapshot,
    durable: &[RecoveryNamedReference],
    trunk: &str,
) -> Result<BTreeMap<String, String>> {
    let mut names = BTreeSet::from([trunk.to_owned()]);
    for RecoveryNamedReference::LocalBookmark(name) in durable {
        names.insert(name.clone());
    }
    names
        .into_iter()
        .map(|name| {
            let digest = blake3::hash(name.as_bytes()).to_hex().to_string();
            let matches: Vec<_> = snapshot
                .references
                .iter()
                .filter(|reference| {
                    reference.kind == RecoveryReferenceKind::Bookmark
                        && reference.name_digest == digest
                })
                .collect();
            let [reference] = matches.as_slice() else {
                bail!("required target bookmark {name:?} has no unique source binding");
            };
            let [Some(commit)] = reference.adds.as_slice() else {
                bail!("required target bookmark {name:?} is absent or conflicted");
            };
            if !reference.removes.is_empty() || !snapshot.required_commits.contains(commit) {
                bail!("required target bookmark {name:?} lacks an unconflicted verified root");
            }
            Ok((name, commit.clone()))
        })
        .collect()
}

fn verify_config_bindings(
    config: &Path,
    cfg: &kata_types::KataConfig,
    deadline: Instant,
) -> Result<()> {
    let current = kata_core::ConfigManager::load(config)?;
    if serde_json::to_vec(current.snapshot().as_ref())? != serde_json::to_vec(cfg)? {
        bail!("target configuration changed during recovery verification");
    }
    // Judge the target as the node that owns this config would: its `[node]`
    // facts installed first, as a doctor run installs them, so the backend row's
    // agent-block doors and the pack compiles below read this config's
    // declaration, not the shipped default.
    crate::cli::install_node_facts_from_config(cfg);
    let mut checks = Vec::new();
    super::doctor::push_agent_backend_reachability_check(&mut checks, cfg);
    if let Some(check) = checks
        .iter()
        .find(|check| check.status != super::doctor::DoctorStatus::Pass)
    {
        bail!(
            "recovery target backend binding refused: {} ({})",
            check.message,
            check.diagnostic.join("; ")
        );
    }
    let config = config.canonicalize()?;
    let library = super::doctor::workflow_library_for_config_dir(
        config.parent().context("config lacks parent")?,
    );
    // Only target project packs are newly declared local authority. Bundled and
    // user-library modules are dependencies, not invented required workflows.
    for entry in library
        .list_effective()
        .into_iter()
        .filter(|entry| entry.root_priority == 0)
    {
        if Instant::now() >= deadline {
            bail!("restore configuration verification deadline elapsed");
        }
        let artifact = kata_program::preflight::build_workflow_compiled_artifact_from_file(
            &entry.path,
            library.roots(),
        )?;
        if artifact
            .execution_program
            .verifier
            .diagnostics
            .iter()
            .any(|diagnostic| {
                diagnostic.severity == kata_program::execution_program::VerifierSeverity::Error
            })
        {
            bail!(
                "target workflow {} does not pass checked compilation",
                entry.name
            );
        }
    }
    Ok(())
}

fn verify_owned_worker_paths(cfg: &kata_types::KataConfig, data_dir: &Path) -> Result<()> {
    let paths: Vec<_> = cfg
        .workers
        .transports
        .iter()
        .map(|transport| match transport {
            kata_types::config::WorkerTransportConfig::LocalSocket { path } => path.clone(),
            kata_types::config::WorkerTransportConfig::SupervisedNode {} => {
                crate::supervised_node::socket_path(data_dir)
            }
        })
        .collect();
    crate::local_capacity::validate_listener_paths(&paths, data_dir)?;
    for path in paths {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect target local worker socket {}", path.display())
                });
            }
            Ok(_) => anyhow::bail!(
                "target local worker socket path is occupied: {}; restore will not remove or reuse it",
                path.display()
            ),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use kata_types::recovery::RecoveryReference;

    #[test]
    fn recovery_decision_fifo_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::fs::FileTypeExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("decisions.fifo");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let input = path.clone();
        std::thread::spawn(move || sender.send(read_recovery_decisions(&input)).unwrap());
        assert!(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("FIFO read must not wait for a writer")
                .is_err()
        );
        assert!(
            std::fs::symlink_metadata(path)
                .unwrap()
                .file_type()
                .is_fifo()
        );
    }

    #[test]
    fn recoverable_restore_requires_target_configuration_not_source_config_replacement() {
        let parsed = super::super::Cli::try_parse_from([
            "kata",
            "restore",
            "--from",
            "artifact",
            "--config",
            "target.toml",
            "--recoverable",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            super::super::Command::Restore {
                recoverable: true,
                restore_config: false,
                ..
            }
        ));
        assert!(
            super::super::Cli::try_parse_from([
                "kata",
                "restore",
                "--from",
                "artifact",
                "--recoverable",
                "--restore-config"
            ])
            .is_err()
        );
        assert!(
            super::super::Cli::try_parse_from([
                "kata",
                "restore",
                "--from",
                "artifact",
                "--recovery-decisions",
                "decisions.json",
            ])
            .is_err()
        );
        let parsed = super::super::Cli::try_parse_from([
            "kata",
            "restore",
            "--from",
            "artifact",
            "--recoverable",
            "--recovery-decisions",
            "decisions.json",
        ])
        .unwrap();
        assert!(matches!(parsed.command, super::super::Command::Restore {
            recovery_decisions: Some(path), ..
        } if path == Path::new("decisions.json")));
    }

    #[test]
    fn continuation_subjects_must_be_the_checkpoint_population_exactly_once() {
        let artifact_id = ulid::Ulid::nil();
        let subject = |key: &str| kata_core::operational::ImportSubject {
            artifact_id,
            key: key.into(),
            reconciled: false,
        };
        let expected = BTreeSet::from(["a".to_string(), "b".to_string()]);
        assert!(!subjects_differ(&[subject("a"), subject("b")], &expected));
        assert!(
            subjects_differ(&[subject("a"), subject("c")], &expected),
            "a foreign key at the same count is a different population"
        );
        assert!(subjects_differ(&[subject("a")], &expected));
        assert!(
            subjects_differ(&[subject("a"), subject("b"), subject("b")], &expected),
            "a repeated key is a different population"
        );
    }

    #[test]
    fn restore_bookmark_mapping_requires_the_exact_name_and_unconflicted_source_target() {
        let commit = "a".repeat(40);
        let mut snapshot = RecoveryReferenceSnapshot {
            operation_id: "b".repeat(128),
            references: vec![RecoveryReference {
                kind: RecoveryReferenceKind::Bookmark,
                name_digest: blake3::hash(b"main").to_hex().to_string(),
                remote_name_digest: None,
                tracked: None,
                removes: Vec::new(),
                adds: vec![Some(commit.clone())],
            }],
            required_commits: vec![commit.clone()],
            resolved_changes: BTreeMap::new(),
            reference_set_digest: String::new(),
        };
        assert_eq!(
            target_bookmarks(&snapshot, &[], "main").unwrap(),
            BTreeMap::from([("main".into(), commit.clone())])
        );
        assert!(target_bookmarks(&snapshot, &[], "guessed").is_err());
        assert!(
            target_bookmarks(
                &snapshot,
                &[RecoveryNamedReference::LocalBookmark("missing".into())],
                "main"
            )
            .is_err()
        );
        snapshot.references[0].removes = vec![Some(commit.clone())];
        snapshot.references[0].adds.push(Some("c".repeat(40)));
        assert!(target_bookmarks(&snapshot, &[], "main").is_err());
    }

    /// **Restore judges the target's agent blocks by the CHECK's doors.** A
    /// target config whose `[agents.coder]` is the embedded harness under kata's
    /// own login binds; the same config naming an adapter this build does not
    /// carry is refused by the CHECK's door, named. The oracle is the config
    /// file's own `[agents.coder]` lines, written here.
    ///
    /// **Would red if:** the binding verification skipped the target's agent
    /// blocks (the unqualified block bound).
    #[test]
    fn restore_judges_its_targets_agent_blocks_by_the_checks_doors() {
        let dir = tempfile::tempdir().unwrap();
        let write = |adapter: &str| {
            let path = dir.path().join("kata.toml");
            std::fs::write(
                &path,
                format!(
                    "[node]\nid = \"restore\"\ndata_dir = \"data\"\n\
                     [workers]\ndispatch_deadline_ms = 30000\nassignment_start_deadline_ms = \
                     900000\nheartbeat_interval_ms = 10000\nheartbeat_grace_ms = \
                     30000\nmax_workers = 4\n\n[[workers.transports]]\ntype = \
                     \"supervised_node\"\n\n[api]\nbind = \"127.0.0.1:8400\"\n\n[api.auth]\n\
                     type = \"disabled\"\n\n[agents.coder]\nadapter = \
                     \"{adapter}\"\ncredential = \
                     {{ mode = \"subscription\", source = \"kata_login\" }}\n"
                ),
            )
            .unwrap();
            let cfg = kata_core::ConfigManager::load(&path).unwrap().snapshot();
            verify_config_bindings(&path, &cfg, Instant::now() + Duration::from_mins(1))
        };
        write("nanocode_openai").expect("the embedded harness's block binds");
        let refused = write("codex_app_server")
            .expect_err("a block naming a removed adapter is refused")
            .to_string();
        assert!(refused.contains("adapter_unqualified:"), "{refused}");
    }
}
