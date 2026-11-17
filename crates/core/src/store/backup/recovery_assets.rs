//! Closed recovery treatments and artifact-bound evidence for manifest v4.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use kata_types::identity::WorkerEffectDomain;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{BackupManifest, DurabilityTier, KataError, KataResult};

pub const RECOVERY_MANIFEST_VERSION: u32 = 7;
const MAX_WORKER_GENERATIONS: usize = 4096;
const MAX_REQUIRED_COMMITS: usize = 100_000;
const MAX_PROOF_BYTES: u64 = 1024 * 1024;

/// Cooperative between-read cancellation, not an interrupt for blocking filesystem calls.
pub(super) struct DeadlineReader<R> {
    input: R,
    deadline: Option<Instant>,
}
impl<R> DeadlineReader<R> {
    pub(super) fn new(input: R, deadline: Option<Instant>) -> Self {
        Self { input, deadline }
    }
}
impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "recovery byte-processing deadline expired",
            ));
        }
        self.input.read(buffer)
    }
}
pub(super) fn check_deadline(deadline: Instant) -> KataResult<()> {
    if Instant::now() >= deadline {
        return Err(refusal("recovery byte-processing deadline expired"));
    }
    Ok(())
}

/// Validated operation-local lookup; never retained beside a mutable manifest.
pub(super) struct MemberIndex<'a> {
    records: BTreeMap<&'a str, &'a super::CapturedAsset>,
}
impl<'a> MemberIndex<'a> {
    pub(super) fn new(manifest: &'a BackupManifest) -> KataResult<Self> {
        // Closed treatments admit checkpoint files, two files per worker export,
        // one proof and the fixed local durable-asset inventory.
        let maximum = super::workspace_checkpoints::MAX_CHECKPOINT_ENTRIES
            + MAX_WORKER_GENERATIONS * 2
            + super::DURABLE_ASSETS.len()
            + 1;
        if manifest.assets.len() > maximum {
            return Err(refusal(
                "manifest member population exceeds treatment bounds",
            ));
        }
        let mut records = BTreeMap::new();
        for record in &manifest.assets {
            if records.insert(record.name.as_str(), record).is_some() {
                return Err(refusal("duplicate manifest member"));
            }
        }
        Ok(Self { records })
    }
    pub(super) fn require(&self, name: &str) -> KataResult<&'a super::CapturedAsset> {
        let record = self
            .records
            .get(name)
            .copied()
            .ok_or_else(|| refusal(format!("missing recovery member {name:?}")))?;
        if record.tier != DurabilityTier::Durable || !record.digest.as_deref().is_some_and(digest) {
            return Err(refusal(format!(
                "recovery member {name:?} must have one durable digest record"
            )));
        }
        Ok(record)
    }
}

fn member_maximum(name: &str) -> u64 {
    if name.starts_with("recovery/jj/checkpoints/") {
        super::workspace_checkpoints::MAX_CHECKPOINT_BYTES
    } else if Path::new(name).extension() == Some(OsStr::new("db")) {
        super::MAX_DATABASE_BYTES
    } else {
        MAX_PROOF_BYTES
    }
}

/// A closed treatment for one exact durable-asset location name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAsset {
    pub location: String,
    pub treatment: RecoveryTreatment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryTreatment {
    CapturedMembers {
        asset_names: Vec<String>,
        tree_locations: Vec<String>,
    },
    RebindRequired {
        target_kind: RecoveryRebindTarget,
    },
    ReacquireVerified {
        remote_id: String,
        required_commits: Vec<String>,
        reference_set_digest: String,
        proof_member: String,
        checkpoints: Vec<super::RecoveryWorkspaceCheckpoint>,
    },
    ExternalGenerations {
        instances: Vec<ExternalRecoveryGeneration>,
        inherited: Vec<InheritedRecoveryGeneration>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRebindTarget {
    MainIdentity,
    LocalWorkerCredential,
    SubordinateWorkerCredential,
    WorkflowRoots,
    OperatorBackend,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRecoveryGeneration {
    pub domain: WorkerEffectDomain,
    pub generation_id: Ulid,
    pub request_nonce: Ulid,
    pub database_member: String,
    pub receipt_member: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InheritedRecoveryGeneration {
    pub domain: WorkerEffectDomain,
    pub origin_artifact_id: Ulid,
}

pub use kata_types::recovery::WorkerRecoveryReceipt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteRecoveryProof {
    pub artifact_id: Ulid,
    pub reference_snapshot: kata_types::recovery::RecoveryReferenceSnapshot,
    pub remote_id: String,
    pub required_commits: Vec<String>,
    pub reference_set_digest: String,
    pub closure_digest: String,
}

/// Input bytes belong to the fenced source generation. Paths are never serialized.
#[derive(Clone, Debug)]
pub struct RecoveryMemberSource {
    pub name: String,
    pub source_path: PathBuf,
}

/// Allocate `artifact_id` before requesting worker exports or remote proofs.
#[derive(Clone, Debug)]
pub struct RecoveryCapture {
    pub artifact_id: Ulid,
    pub source_directory_id: String,
    pub recovery_assets: Vec<RecoveryAsset>,
    pub members: Vec<RecoveryMemberSource>,
}

/// A trusted runtime mapper enumerates the actual captured reference population
/// and verifies an isolated fetch of the configured remote's complete closure.
pub trait RecoveryVerifier {
    /// One absolute deadline shared by all recovery byte processing and proofs.
    fn deadline(&self) -> std::time::Instant;
    fn verify_captured_references(
        &self,
        artifact: &Path,
        manifest: &BackupManifest,
    ) -> KataResult<CapturedRecoveryReferences>;
}

#[derive(Clone, Debug)]
pub struct CapturedRecoveryReferences {
    pub remote_id: String,
    pub required_commits: Vec<String>,
    pub reference_set_digest: String,
    pub closure_digest: String,
}

/// Immutable result of complete byte, receipt and runtime closure verification.
#[derive(Debug)]
pub struct VerifiedRecoveryArtifact {
    manifest: BackupManifest,
}

impl VerifiedRecoveryArtifact {
    pub fn manifest(&self) -> &BackupManifest {
        &self.manifest
    }

    pub fn completeness(&self) -> super::CompletenessVerdict {
        let mut verdict = super::assess_backup_class(
            &super::DURABLE_ASSETS
                .iter()
                .filter(|asset| asset.authority.is_authoritative())
                .map(|asset| asset.location.name().to_string())
                .collect(),
        );
        verdict.requires_external_rebind = super::DURABLE_ASSETS
            .iter()
            .filter(|asset| {
                self.manifest
                    .recovery_assets
                    .as_ref()
                    .is_some_and(|treatments| {
                        treatments.iter().any(|treatment| {
                            treatment.location == asset.location.name()
                                && matches!(
                                    treatment.treatment,
                                    RecoveryTreatment::RebindRequired { .. }
                                )
                        })
                    })
            })
            .map(|asset| asset.location.name())
            .collect();
        verdict
    }

    pub(super) fn from_verified(manifest: BackupManifest) -> Self {
        Self { manifest }
    }
}

fn refusal(message: impl Into<String>) -> KataError {
    KataError::Storage(format!("recovery artifact: {}", message.into()))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn ordered_commits(commits: &[String]) -> bool {
    commits.len() <= MAX_REQUIRED_COMMITS
        && commits.windows(2).all(|pair| pair[0] < pair[1])
        && commits.iter().all(|id| {
            matches!(id.len(), 40 | 64)
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

fn expected_rebind(location: &str) -> Option<RecoveryRebindTarget> {
    Some(match location {
        "main-identity.json" => RecoveryRebindTarget::MainIdentity,
        "local-worker.secret" => RecoveryRebindTarget::LocalWorkerCredential,
        "subordinate-worker:credential_path" => RecoveryRebindTarget::SubordinateWorkerCredential,
        "workflow roots" => RecoveryRebindTarget::WorkflowRoots,
        "operator secret/proxy backend" => RecoveryRebindTarget::OperatorBackend,
        _ => return None,
    })
}

fn worker_member(instance: &ExternalRecoveryGeneration, name: &str) -> String {
    format!(
        "recovery/workers/{}/{}/{name}",
        instance.domain.membrane.0, instance.domain.enrollment
    )
}

/// Validate the complete family map before opening evidence bytes or targets.
pub(super) fn validate_treatments(manifest: &BackupManifest) -> KataResult<BTreeSet<String>> {
    let members = MemberIndex::new(manifest)?;
    if manifest
        .source_directory_id
        .as_ref()
        .is_none_or(|id| id.is_empty() || id.len() > 128)
    {
        return Err(refusal(
            "recovery requires a bounded non-secret source_directory_id",
        ));
    }
    if manifest
        .databases
        .iter()
        .any(|name| super::classify_data_dir_entry(name).is_none())
    {
        return Err(refusal(
            "a recoverable artifact cannot contain an unclassified database",
        ));
    }
    let Some(treatments) = manifest.recovery_assets.as_ref() else {
        return Err(refusal("recovery requires recovery_assets"));
    };
    let authoritative: BTreeSet<_> = super::DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.authority.is_authoritative())
        .map(|asset| asset.location.name())
        .collect();
    if treatments.len() != authoritative.len() {
        return Err(refusal(
            "recovery_assets must cover every authoritative family exactly once",
        ));
    }
    let mut covered = BTreeSet::new();
    let mut extra_members = BTreeSet::new();
    let mut used_assets = BTreeSet::new();
    let mut used_trees = BTreeSet::new();
    for asset in treatments {
        let location = asset.location.as_str();
        if !authoritative.contains(location) || !covered.insert(location) {
            return Err(refusal(format!(
                "unknown or duplicate recovery location {location:?}"
            )));
        }
        if let Some(expected) = expected_rebind(location) {
            if !matches!(asset.treatment, RecoveryTreatment::RebindRequired { target_kind } if target_kind == expected)
            {
                return Err(refusal(format!(
                    "{location} requires its exact fresh target rebind"
                )));
            }
            continue;
        }
        match (&asset.treatment, location) {
            (
                RecoveryTreatment::ExternalGenerations {
                    instances,
                    inherited,
                },
                "subordinate-worker:idempotency.db",
            ) => {
                if instances.len() + inherited.len() > MAX_WORKER_GENERATIONS {
                    return Err(refusal("too many external worker generations"));
                }
                let mut previous = None;
                for instance in instances {
                    let key = (instance.domain.membrane.0, instance.domain.enrollment);
                    if previous.is_some_and(|held| held >= key)
                        || Some(&instance.domain.source_main)
                            != manifest.source_directory_id.as_ref()
                    {
                        return Err(refusal(
                            "worker generations must be uniquely sorted with a source main",
                        ));
                    }
                    previous = Some(key);
                    if instance.database_member != worker_member(instance, "idempotency.db")
                        || instance.receipt_member != worker_member(instance, "receipt.json")
                    {
                        return Err(refusal(
                            "worker evidence is outside its exact generation namespace",
                        ));
                    }
                    extra_members.insert(instance.database_member.clone());
                    extra_members.insert(instance.receipt_member.clone());
                }
                let mut inherited_domains = BTreeSet::new();
                for instance in inherited {
                    if Some(&instance.domain.source_main) == manifest.source_directory_id.as_ref()
                        || instance.origin_artifact_id == Ulid::nil()
                        || !inherited_domains.insert((
                            instance.domain.source_main.clone(),
                            instance.domain.membrane.0,
                            instance.domain.enrollment,
                        ))
                    {
                        return Err(refusal(
                            "inherited worker domains must be unique and foreign to this source",
                        ));
                    }
                }
            }
            (
                RecoveryTreatment::ReacquireVerified {
                    remote_id,
                    required_commits,
                    reference_set_digest,
                    proof_member,
                    checkpoints,
                },
                "vcs.jj_repo",
            ) => {
                if remote_id.is_empty()
                    || remote_id.len() > 255
                    || !ordered_commits(required_commits)
                    || !digest(reference_set_digest)
                    || proof_member != "recovery/jj/proof.json"
                {
                    return Err(refusal("invalid verified jj reacquisition treatment"));
                }
                extra_members.insert(proof_member.clone());
                extra_members.extend(super::workspace_checkpoints::validate_checkpoint_catalog(
                    checkpoints,
                    required_commits,
                )?);
            }
            (
                RecoveryTreatment::CapturedMembers {
                    asset_names,
                    tree_locations,
                },
                _,
            ) => {
                if asset_names.is_empty() && tree_locations.is_empty() {
                    return Err(refusal(format!("{location} has no captured members")));
                }
                for name in asset_names {
                    let resolved = if name == super::CONFIG_COPY_NAME && manifest.config_included {
                        Some("--config")
                    } else {
                        super::classify_data_dir_entry(name).map(|asset| asset.location.name())
                    };
                    if resolved != Some(location) || !used_assets.insert(name.as_str()) {
                        return Err(refusal(format!(
                            "wrongly rooted or duplicate member {name:?}"
                        )));
                    }
                    members.require(name)?;
                }
                for tree in tree_locations {
                    if tree != location
                        || !used_trees.insert(tree.as_str())
                        || !manifest
                            .trees
                            .iter()
                            .any(|held| held.name == *tree && held.tier == DurabilityTier::Durable)
                    {
                        return Err(refusal(format!(
                            "wrongly rooted or duplicate tree {tree:?}"
                        )));
                    }
                }
            }
            _ => return Err(refusal(format!("wrong treatment for {location}"))),
        }
    }
    for name in &extra_members {
        members.require(name)?;
    }
    Ok(extra_members)
}

pub(super) fn require_durable_member<'a>(
    manifest: &'a BackupManifest,
    name: &str,
) -> KataResult<&'a super::CapturedAsset> {
    let mut records = manifest.assets.iter().filter(|asset| asset.name == name);
    let record = records
        .next()
        .ok_or_else(|| refusal(format!("missing recovery member {name:?}")))?;
    if records.next().is_some()
        || record.tier != DurabilityTier::Durable
        || !record.digest.as_deref().is_some_and(digest)
    {
        return Err(refusal(format!(
            "recovery member {name:?} must have one durable digest record"
        )));
    }
    Ok(record)
}

/// Read the exact treatment-selected remote proof through the bounded,
/// descriptor-relative digest-checked artifact reader.
pub fn read_remote_recovery_proof(
    artifact: &Path,
    manifest: &BackupManifest,
) -> KataResult<RemoteRecoveryProof> {
    validate_treatments(manifest)?;
    let treatment = manifest
        .recovery_assets
        .iter()
        .flatten()
        .find(|asset| asset.location == "vcs.jj_repo")
        .ok_or_else(|| refusal("missing jj recovery treatment"))?;
    let RecoveryTreatment::ReacquireVerified { proof_member, .. } = &treatment.treatment else {
        return Err(refusal(
            "jj recovery treatment is not verified reacquisition",
        ));
    };
    read_proof(artifact, manifest, proof_member)
}

fn read_proof<T: serde::de::DeserializeOwned>(
    artifact: &Path,
    manifest: &BackupManifest,
    name: &str,
) -> KataResult<T> {
    let record = require_durable_member(manifest, name)?;
    let path = artifact.join(name);
    let (file, _) = open_member(artifact, name, MAX_PROOF_BYTES)?;
    let mut bytes = Vec::new();
    file.take(MAX_PROOF_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refusal(format!("read recovery proof: {error}")))?;
    if bytes.len() as u64 != record.byte_len {
        return Err(refusal("recovery proof length disagrees with its record"));
    }
    super::verify_captured_digest(bytes.as_slice(), &path, record)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| refusal(format!("invalid recovery proof: {error}")))
}

/// Bind receipts and proofs to this artifact. Runtime still owes authenticated
/// export, semantic reference enumeration and actual remote closure verification.
pub(super) fn validate_evidence(
    artifact: &Path,
    manifest: &BackupManifest,
    deadline: Instant,
) -> KataResult<()> {
    check_deadline(deadline)?;
    let indexed = MemberIndex::new(manifest)?;
    let members = validate_treatments(manifest)?;
    let mut total = manifest
        .assets
        .iter()
        .filter(|asset| !members.contains(&asset.name))
        .try_fold(0_u64, |total, asset| total.checked_add(asset.byte_len))
        .ok_or_else(|| refusal("artifact byte overflow"))?;
    for name in &members {
        let record = indexed.require(name)?;
        let maximum = member_maximum(name);
        let (file, length) = open_member(artifact, name, maximum)?;
        total = total
            .checked_add(length)
            .ok_or_else(|| refusal("recovery member byte overflow"))?;
        if length != record.byte_len || total > super::MAX_TOTAL_DATABASE_BYTES {
            return Err(refusal(
                "recovery member length or aggregate bound mismatch",
            ));
        }
        super::verify_captured_digest(
            DeadlineReader::new(file, Some(deadline)),
            &artifact.join(name),
            record,
        )?;
    }
    let artifact_id = manifest
        .artifact_id
        .ok_or_else(|| refusal("missing artifact identity"))?;
    let mut exported_domains = BTreeSet::new();
    for asset in manifest
        .recovery_assets
        .as_ref()
        .ok_or_else(|| refusal("missing recovery assets"))?
    {
        match &asset.treatment {
            RecoveryTreatment::ExternalGenerations { instances, .. } => {
                for instance in instances {
                    let record = indexed.require(&instance.database_member)?;
                    let receipt: WorkerRecoveryReceipt =
                        read_proof(artifact, manifest, &instance.receipt_member)?;
                    if receipt.artifact_id != artifact_id
                        || receipt.request_nonce != instance.request_nonce
                        || receipt.domain != instance.domain
                        || receipt.generation_id != instance.generation_id
                        || receipt.database_byte_len != record.byte_len
                        || Some(&receipt.database_digest) != record.digest.as_ref()
                        || receipt.schema_version
                            != crate::idempotency_store::IDEMPOTENCY_SCHEMA_VERSION
                    {
                        return Err(refusal(
                            "worker export receipt does not bind this artifact generation",
                        ));
                    }
                    let (database, _) = open_member(
                        artifact,
                        &instance.database_member,
                        super::MAX_DATABASE_BYTES,
                    )?;
                    let connection = immutable_connection(&database)?;
                    crate::IdempotencyStore::validate_current_schema(&connection)?;
                    let schema: u32 = connection
                        .query_row("PRAGMA user_version", [], |row| row.get(0))
                        .map_err(|error| refusal(format!("read worker schema: {error}")))?;
                    let membrane = crate::IdempotencyStore::read_membrane_identity(&connection)?;
                    let integrity: String = connection
                        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
                        .map_err(|error| refusal(format!("check worker export: {error}")))?;
                    if schema != receipt.schema_version
                        || membrane != instance.domain.membrane
                        || integrity != "ok"
                    {
                        return Err(refusal(
                            "worker receipt disagrees with the captured database",
                        ));
                    }
                    exported_domains.insert((
                        instance.domain.source_main.clone(),
                        instance.domain.membrane.0.to_bytes().to_vec(),
                        instance.domain.enrollment.to_bytes().to_vec(),
                    ));
                }
            }
            RecoveryTreatment::ReacquireVerified {
                remote_id,
                required_commits,
                reference_set_digest,
                proof_member,
                checkpoints,
            } => {
                let mut checkpoint_bytes = 0u64;
                for checkpoint in checkpoints {
                    let tree = &checkpoint.candidate;
                    if super::workspace_checkpoints::checkpoint_tree_digest(&indexed, tree)?
                        != tree.digest
                    {
                        return Err(refusal("workspace checkpoint tree digest mismatch"));
                    }
                    for entry in &tree.entries {
                        if let super::RecoveryCheckpointEntry::File { member, .. } = entry {
                            checkpoint_bytes = checkpoint_bytes
                                .checked_add(indexed.require(member)?.byte_len)
                                .ok_or_else(|| refusal("checkpoint byte overflow"))?;
                        }
                    }
                }
                if checkpoint_bytes > super::workspace_checkpoints::MAX_CHECKPOINT_BYTES {
                    return Err(refusal("checkpoint population exceeds 16 GiB"));
                }
                let proof: RemoteRecoveryProof = read_proof(artifact, manifest, proof_member)?;
                super::workspace_checkpoints::validate_checkpoint_references(
                    checkpoints,
                    &proof.reference_snapshot,
                )?;
                if proof.artifact_id != artifact_id
                    || &proof.remote_id != remote_id
                    || &proof.required_commits != required_commits
                    || &proof.reference_set_digest != reference_set_digest
                    || proof.reference_snapshot.required_commits != proof.required_commits
                    || proof.reference_snapshot.reference_set_digest != proof.reference_set_digest
                    || proof.reference_snapshot.computed_digest() != proof.reference_set_digest
                    || !digest(&proof.closure_digest)
                {
                    return Err(refusal(
                        "remote recovery proof does not bind this artifact reference set",
                    ));
                }
            }
            _ => {}
        }
    }
    let (operational, _) =
        open_member(artifact, "stores/operational.db", super::MAX_DATABASE_BYTES)?;
    let connection = immutable_connection(&operational)?;
    for treatment in manifest.recovery_assets.iter().flatten() {
        if let RecoveryTreatment::ExternalGenerations { inherited, .. } = &treatment.treatment {
            super::import_catalog::verify_inherited_workers(
                artifact,
                &connection,
                inherited,
                deadline,
            )?;
            for instance in inherited {
                if !exported_domains.insert((
                    instance.domain.source_main.clone(),
                    instance.domain.membrane.0.to_bytes().to_vec(),
                    instance.domain.enrollment.to_bytes().to_vec(),
                )) {
                    return Err(refusal("native and inherited worker evidence overlap"));
                }
            }
        }
    }
    let mut statement = connection.prepare(
        "SELECT source_main, membrane_id, enrollment_id FROM worker_effect_domains ORDER BY source_main, membrane_id LIMIT 4097")
        .map_err(|error| refusal(format!("read captured worker census: {error}")))?;
    let domains = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|error| refusal(format!("query captured worker census: {error}")))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| refusal(format!("decode captured worker census: {error}")))?;
    if domains.len() > MAX_WORKER_GENERATIONS || domains != exported_domains {
        return Err(refusal(
            "external generations do not cover the captured worker enrollment census",
        ));
    }
    Ok(())
}

pub(super) fn immutable_connection(file: &std::fs::File) -> KataResult<rusqlite::Connection> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        rusqlite::Connection::open_with_flags(
            format!("file:/proc/self/fd/{}?immutable=1", file.as_raw_fd()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_URI
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| refusal(format!("open immutable recovery evidence: {error}")))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(refusal(
            "descriptor-bound recovery evidence inspection currently requires Linux",
        ))
    }
}

pub(super) fn member_parent(
    artifact: &Path,
    name: &str,
    create: bool,
) -> KataResult<(super::ProvenDir, String)> {
    let components: Vec<_> = name.split('/').collect();
    if components
        .iter()
        .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return Err(refusal("invalid recovery member path"));
    }
    let mut directory = super::ProvenDir::open_operator_root(
        artifact,
        "recovery",
        "artifact root must be a directory",
    )?;
    for component in &components[..components.len() - 1] {
        directory = if create {
            let next = directory.child(
                OsStr::new(component),
                "recovery",
                "recovery directories must not be links",
            )?;
            directory.sync("recovery")?;
            next
        } else {
            directory.open_child(
                OsStr::new(component),
                "recovery",
                "recovery directories must not be links",
            )?
        };
    }
    Ok((directory, components[components.len() - 1].to_string()))
}

pub(super) fn open_member(
    artifact: &Path,
    name: &str,
    maximum: u64,
) -> KataResult<(std::fs::File, u64)> {
    let (directory, name) = member_parent(artifact, name, false)?;
    directory.open_source_file(OsStr::new(&name), maximum, "recovery", "recovery member")
}

pub(super) fn finish_capture(
    artifact: &Path,
    manifest: &mut BackupManifest,
    capture: &RecoveryCapture,
    verifier: &dyn RecoveryVerifier,
) -> KataResult<()> {
    let deadline = verifier.deadline();
    check_deadline(deadline)?;
    manifest.version = RECOVERY_MANIFEST_VERSION;
    manifest.artifact_id = Some(capture.artifact_id);
    manifest.source_directory_id = Some(capture.source_directory_id.clone());
    manifest.recovery_assets = Some(capture.recovery_assets.clone());
    // First check source names against treatment-derived destinations. No source
    // input can grant itself a path or replace an ordinary captured database.
    let mut destinations = BTreeSet::new();
    for asset in &capture.recovery_assets {
        match &asset.treatment {
            RecoveryTreatment::ExternalGenerations { instances, .. } => {
                for instance in instances {
                    destinations.insert(worker_member(instance, "idempotency.db"));
                    destinations.insert(worker_member(instance, "receipt.json"));
                }
            }
            RecoveryTreatment::ReacquireVerified {
                checkpoints,
                required_commits,
                ..
            } => {
                destinations.insert("recovery/jj/proof.json".into());
                destinations.extend(super::workspace_checkpoints::validate_checkpoint_catalog(
                    checkpoints,
                    required_commits,
                )?);
            }
            _ => {}
        }
    }
    let mut provided = BTreeSet::new();
    if capture.members.len() != destinations.len()
        || capture.members.len()
            > MAX_WORKER_GENERATIONS * 2 + 1 + super::workspace_checkpoints::MAX_CHECKPOINT_ENTRIES
    {
        return Err(refusal(
            "recovery member input does not match treatment references",
        ));
    }
    let mut checkpoint_bytes = 0u64;
    for source in &capture.members {
        check_deadline(deadline)?;
        if !destinations.contains(&source.name) || !provided.insert(source.name.as_str()) {
            return Err(refusal("unknown or duplicate recovery source member"));
        }
        let maximum = member_maximum(&source.name);
        let parent = source
            .source_path
            .parent()
            .ok_or_else(|| refusal("source has no parent"))?;
        let name = source
            .source_path
            .file_name()
            .ok_or_else(|| refusal("source has no filename"))?;
        let source_dir = super::ProvenDir::open_operator_root(
            parent,
            "recovery",
            "source root must be a directory",
        )?;
        let (input, expected_length) =
            source_dir.open_source_file(name, maximum, "recovery", "exported recovery member")?;
        if source.name.starts_with("recovery/jj/checkpoints/") {
            checkpoint_bytes = checkpoint_bytes
                .checked_add(expected_length)
                .ok_or_else(|| refusal("checkpoint byte overflow"))?;
            if checkpoint_bytes > super::workspace_checkpoints::MAX_CHECKPOINT_BYTES {
                return Err(refusal("checkpoint population exceeds 16 GiB before copy"));
            }
        }
        let (target, name) = member_parent(artifact, &source.name, true)?;
        let temporary = format!("{name}.capture-tmp");
        let (hash, byte_len) = super::copy_hashing(
            DeadlineReader::new(input, Some(deadline)),
            &source.source_path,
            &target,
            OsStr::new(&temporary),
            maximum.min(expected_length),
            true,
            "recovery",
        )?;
        if byte_len != expected_length {
            return Err(refusal("recovery source changed during capture"));
        }
        target.rename_within(
            OsStr::new(&temporary),
            OsStr::new(&name),
            "recovery",
            "verified member",
        )?;
        target.sync("recovery")?;
        manifest.assets.push(super::CapturedAsset {
            name: source.name.clone(),
            tier: DurabilityTier::Durable,
            digest: Some(super::hex_digest(&hash)),
            byte_len,
        });
    }
    super::validate_asset_records(manifest)?;
    verify(artifact, manifest, verifier)
}

pub(super) fn verify(
    artifact: &Path,
    manifest: &BackupManifest,
    verifier: &dyn RecoveryVerifier,
) -> KataResult<()> {
    let deadline = verifier.deadline();
    check_deadline(deadline)?;
    super::preflight_restore_manifest(artifact, artifact, None, manifest.clone())?;
    validate_evidence(artifact, manifest, deadline)?;
    let references = verifier.verify_captured_references(artifact, manifest)?;
    check_deadline(deadline)?;
    let proof_member = manifest
        .recovery_assets
        .as_ref()
        .and_then(|assets| {
            assets.iter().find_map(|asset| {
                if let RecoveryTreatment::ReacquireVerified { proof_member, .. } = &asset.treatment
                {
                    Some(proof_member)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| refusal("missing remote closure proof"))?;
    let proof: RemoteRecoveryProof = read_proof(artifact, manifest, proof_member)?;
    if references.remote_id != proof.remote_id
        || references.required_commits != proof.required_commits
        || references.reference_set_digest != proof.reference_set_digest
        || references.closure_digest != proof.closure_digest
    {
        return Err(refusal(
            "captured reference enumeration or remote closure disagrees with proof",
        ));
    }
    Ok(())
}

/// External generations stay in the imported artifact's evidence namespace.
/// They are never installed at a main or worker idempotency-store boot path.
pub fn recovery_evidence_root(data_dir: &Path, artifact_id: Ulid) -> PathBuf {
    data_dir
        .join("recovery-evidence")
        .join(artifact_id.to_string())
}

/// Retained checkpoint bytes use content addresses, not user filenames: later
/// evidence-tree captures must not mistake a user suffix for staging residue or
/// inherit the source checkout's depth. The catalog still binds the original
/// logical asset name, length and digest; worker evidence paths stay unchanged.
pub(super) fn retained_member_name(members: &MemberIndex<'_>, source: &str) -> KataResult<String> {
    if source.starts_with("recovery/jj/checkpoints/") {
        let record = members.require(source)?;
        let digest = record
            .digest
            .as_deref()
            .ok_or_else(|| refusal("checkpoint lacks content digest"))?;
        Ok(format!("checkpoint-files/{digest}"))
    } else {
        Ok(source.to_owned())
    }
}

pub(super) fn restore_evidence(
    artifact: &Path,
    target: &Path,
    manifest: &BackupManifest,
    deadline: Instant,
) -> KataResult<()> {
    check_deadline(deadline)?;
    let indexed = MemberIndex::new(manifest)?;
    let artifact_id = manifest
        .artifact_id
        .ok_or_else(|| refusal("missing artifact identity"))?;
    let mut sources = validate_treatments(manifest)?
        .into_iter()
        .map(|name| Ok((name.clone(), retained_member_name(&indexed, &name)?, name)))
        .collect::<KataResult<Vec<_>>>()?;
    sources.push((
        format!("{}/idempotency.db", super::STORES_SUBDIR),
        "source-main/idempotency.db".into(),
        "idempotency.db".into(),
    ));
    for (source, name, record_name) in sources {
        check_deadline(deadline)?;
        let record = indexed.require(&record_name)?;
        let maximum = member_maximum(&source);
        let (input, _) = open_member(artifact, &source, maximum)?;
        let destination = format!("recovery-evidence/{artifact_id}/{name}");
        let (directory, filename) = member_parent(target, &destination, true)?;
        let temporary = format!("{filename}.restore-tmp");
        let (hash, length) = super::copy_hashing(
            DeadlineReader::new(input, Some(deadline)),
            &artifact.join(&source),
            &directory,
            OsStr::new(&temporary),
            maximum,
            true,
            "recovery restore",
        )?;
        let actual_digest = super::hex_digest(&hash);
        if length != record.byte_len || record.digest.as_deref() != Some(actual_digest.as_str()) {
            directory.remove_file(OsStr::new(&temporary));
            return Err(refusal("recovery evidence changed while being restored"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = directory
                .open_regular(OsStr::new(&temporary), "recovery restore")?
                .ok_or_else(|| refusal("staged recovery evidence disappeared"))?;
            file.set_permissions(std::fs::Permissions::from_mode(0o400))
                .and_then(|()| file.sync_all())
                .map_err(|error| refusal(format!("make recovery evidence read-only: {error}")))?;
        }
        directory.rename_within(
            OsStr::new(&temporary),
            OsStr::new(&filename),
            "recovery restore",
            "read-only evidence",
        )?;
        directory.sync("recovery restore")?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "recovery_assets_tests.rs"]
mod tests;
