//! Immutable origin evidence and verified, identity-last clone preparation.
use super::recovery_assets::{
    DeadlineReader, MemberIndex, immutable_connection, member_parent, open_member,
};
use super::{
    BackupManifest, CapturedAsset, InheritedRecoveryGeneration, KataError, KataResult,
    RecoveryTreatment, VerifiedRecoveryArtifact,
};
use crate::{
    IdempotencyStore,
    operational::{ImportAuthority, OperationalDb},
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use ulid::Ulid;

const CATALOG: &str = "catalog.json";
const SOURCE_MANIFEST: &str = "source-manifest.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportCatalog {
    origin_artifact_id: Ulid,
    source_directory_id: String,
    target_directory_id: String,
    source_manifest_digest: String,
    members: Vec<CatalogMember>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogMember {
    path: String,
    source_asset: String,
    byte_len: u64,
    digest: String,
}

/// No public fields or constructor: only verified preparation creates it.
pub struct PreparedCloneImport {
    data_dir: PathBuf,
    authority: ImportAuthority,
}
impl PreparedCloneImport {
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
    pub fn target_directory_id(&self) -> &str {
        &self.authority.target_directory_id
    }
}

fn refusal(message: impl Into<String>) -> KataError {
    KataError::Storage(format!("recovery import: {}", message.into()))
}
fn read_bytes(
    root: &Path,
    name: &str,
    maximum: u64,
    deadline: Option<std::time::Instant>,
) -> KataResult<Vec<u8>> {
    let (file, _) = open_member(root, name, maximum)?;
    let mut bytes = Vec::new();
    DeadlineReader::new(file, deadline)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refusal(error.to_string()))?;
    if bytes.len() as u64 > maximum {
        return Err(refusal("evidence member grew beyond bound"));
    }
    Ok(bytes)
}
fn write_immutable(root: &Path, name: &str, bytes: &[u8]) -> KataResult<()> {
    let (directory, filename) = member_parent(root, name, true)?;
    if let Some(mut existing) = directory.open_regular(OsStr::new(&filename), "import evidence")? {
        let mut observed = Vec::new();
        Read::by_ref(&mut existing)
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut observed)
            .map_err(|error| refusal(error.to_string()))?;
        if observed != bytes {
            return Err(refusal("existing immutable origin evidence differs"));
        }
        return Ok(());
    }
    let temporary = format!("{filename}.publish-tmp");
    let mut file = directory.create_owned_file(
        OsStr::new(&temporary),
        "import evidence",
        "evidence cannot follow links",
    )?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| refusal(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o400))
            .and_then(|()| file.sync_all())
            .map_err(|error| refusal(error.to_string()))?;
    }
    directory.rename_within(
        OsStr::new(&temporary),
        OsStr::new(&filename),
        "import evidence",
        "immutable publication",
    )?;
    directory.sync("import evidence")
}

pub(super) fn preserve_source_manifest(target: &Path, manifest: &BackupManifest) -> KataResult<()> {
    let id = manifest
        .artifact_id
        .ok_or_else(|| refusal("missing origin artifact"))?;
    let bytes = serde_json::to_vec(manifest).map_err(|error| refusal(error.to_string()))?;
    write_immutable(
        target,
        &format!("recovery-evidence/{id}/{SOURCE_MANIFEST}"),
        &bytes,
    )
}

fn catalog_members(manifest: &BackupManifest) -> KataResult<Vec<CatalogMember>> {
    let indexed = super::recovery_assets::MemberIndex::new(manifest)?;
    let mut names = super::recovery_assets::validate_treatments(manifest)?
        .into_iter()
        .map(|name| {
            Ok((
                super::recovery_assets::retained_member_name(&indexed, &name)?,
                name,
            ))
        })
        .collect::<KataResult<Vec<_>>>()?;
    names.push(("source-main/idempotency.db".into(), "idempotency.db".into()));
    names
        .into_iter()
        .map(|(path, source_asset)| {
            let record = indexed.require(&source_asset)?;
            Ok(CatalogMember {
                path,
                source_asset,
                byte_len: record.byte_len,
                digest: record
                    .digest
                    .clone()
                    .ok_or_else(|| refusal("missing source digest"))?,
            })
        })
        .collect()
}

fn check_member(
    root: &Path,
    member: &CatalogMember,
    deadline: Option<std::time::Instant>,
) -> KataResult<()> {
    let (file, len) = open_member(root, &member.path, super::MAX_DATABASE_BYTES)?;
    let mut file = DeadlineReader::new(file, deadline);
    if len != member.byte_len {
        return Err(refusal("origin evidence length changed"));
    }
    let mut hash = blake3::Hasher::new();
    let mut buffer = vec![0; 64 * 1024];
    let mut actual = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| refusal(error.to_string()))?;
        if count == 0 {
            break;
        }
        actual += count as u64;
        if actual > member.byte_len {
            return Err(refusal("origin evidence grew"));
        }
        hash.update(&buffer[..count]);
    }
    if actual != member.byte_len || hash.finalize().to_hex().as_str() != member.digest {
        return Err(refusal("origin evidence digest changed"));
    }
    Ok(())
}

fn origin_prefix(id: Ulid, in_artifact: bool) -> String {
    if in_artifact {
        format!("{}/recovery-evidence/{id}", super::TREES_SUBDIR)
    } else {
        format!("recovery-evidence/{id}")
    }
}
fn read_catalog(
    root: &Path,
    authority: &ImportAuthority,
    in_artifact: bool,
    deadline: Option<std::time::Instant>,
) -> KataResult<(ImportCatalog, BackupManifest)> {
    let prefix = origin_prefix(authority.artifact_id, in_artifact);
    let bytes = read_bytes(
        root,
        &format!("{prefix}/{CATALOG}"),
        super::MAX_MANIFEST_BYTES,
        deadline,
    )?;
    if blake3::hash(&bytes).to_hex().as_str() != authority.catalog_digest {
        return Err(refusal("catalog differs from operational import authority"));
    }
    let catalog: ImportCatalog =
        serde_json::from_slice(&bytes).map_err(|error| refusal(error.to_string()))?;
    if catalog.origin_artifact_id != authority.artifact_id
        || catalog.source_directory_id != authority.source_directory_id
        || catalog.target_directory_id != authority.target_directory_id
    {
        return Err(refusal(
            "catalog identity differs from operational import authority",
        ));
    }
    let source = read_bytes(
        root,
        &format!("{prefix}/{SOURCE_MANIFEST}"),
        super::MAX_MANIFEST_BYTES,
        deadline,
    )?;
    if blake3::hash(&source).to_hex().as_str() != catalog.source_manifest_digest {
        return Err(refusal("source manifest anchor changed"));
    }
    let manifest: BackupManifest =
        serde_json::from_slice(&source).map_err(|error| refusal(error.to_string()))?;
    if manifest.artifact_id != Some(catalog.origin_artifact_id)
        || manifest.source_directory_id.as_deref() != Some(catalog.source_directory_id.as_str())
    {
        return Err(refusal("source manifest identity mismatch"));
    }
    let expected = catalog_members(&manifest)?;
    if serde_json::to_vec(&expected).map_err(|error| refusal(error.to_string()))?
        != serde_json::to_vec(&catalog.members).map_err(|error| refusal(error.to_string()))?
    {
        return Err(refusal(
            "catalog does not exactly bind origin evidence members",
        ));
    }
    for member in &catalog.members {
        let mut rooted = member.clone();
        rooted.path = format!("{prefix}/{}", member.path);
        check_member(root, &rooted, deadline)?;
    }
    Ok((catalog, manifest))
}

/// Verify immutable evidence against operational authority on every boot and
/// offline maintenance open, including inherited origins from earlier clones.
/// This boot API has byte bounds but no caller-supplied wall-clock deadline.
/// Recovery preparation uses the same verifier with its explicit operation deadline.
pub fn verify_import_evidence(
    data_dir: &Path,
    current_directory_id: &str,
    db: &OperationalDb,
) -> KataResult<()> {
    verify_import_evidence_at(data_dir, current_directory_id, db, None)
}

fn verify_import_evidence_at(
    data_dir: &Path,
    current_directory_id: &str,
    db: &OperationalDb,
    deadline: Option<std::time::Instant>,
) -> KataResult<()> {
    let authorities = db.import_authorities()?;
    if !authorities.is_empty()
        && !authorities
            .iter()
            .any(|entry| entry.target_directory_id == current_directory_id)
    {
        return Err(refusal(
            "no import catalog binds current directory identity",
        ));
    }
    for authority in &authorities {
        read_catalog(data_dir, authority, false, deadline)?;
    }
    Ok(())
}

/// Recovery readiness shares its supplied operation deadline with evidence hashing.
pub fn verify_import_evidence_before(
    data_dir: &Path,
    current_directory_id: &str,
    db: &OperationalDb,
    deadline: std::time::Instant,
) -> KataResult<()> {
    super::recovery_assets::check_deadline(deadline)?;
    verify_import_evidence_at(data_dir, current_directory_id, db, Some(deadline))
}

/// Root supplies verified extraction and the freshly allocated target ID while
/// holding the offline directory lock. No target identity is published here.
pub fn prepare_clone_import(
    data_dir: &Path,
    verified: &VerifiedRecoveryArtifact,
    target_directory_id: &str,
    deadline: std::time::Instant,
) -> KataResult<PreparedCloneImport> {
    let manifest = verified.manifest();
    let origin_artifact_id = manifest
        .artifact_id
        .ok_or_else(|| refusal("missing origin artifact"))?;
    let source_directory_id = manifest
        .source_directory_id
        .clone()
        .ok_or_else(|| refusal("missing source identity"))?;
    if target_directory_id.is_empty()
        || target_directory_id.len() > 128
        || source_directory_id == target_directory_id
    {
        return Err(refusal("clone requires a fresh target identity"));
    }
    let prefix = origin_prefix(origin_artifact_id, false);
    let source = read_bytes(
        data_dir,
        &format!("{prefix}/{SOURCE_MANIFEST}"),
        super::MAX_MANIFEST_BYTES,
        Some(deadline),
    )?;
    let retained: BackupManifest =
        serde_json::from_slice(&source).map_err(|error| refusal(error.to_string()))?;
    if retained != *manifest {
        return Err(refusal(
            "restored source manifest differs from verified artifact",
        ));
    }
    let members = catalog_members(manifest)?;
    for name in &manifest.databases {
        if name == "idempotency.db" {
            continue;
        }
        let Some(record) = manifest
            .assets
            .iter()
            .find(|record| record.name == *name && record.tier == super::DurabilityTier::Durable)
        else {
            continue;
        };
        check_member(
            data_dir,
            &CatalogMember {
                path: name.clone(),
                source_asset: name.clone(),
                byte_len: record.byte_len,
                digest: record
                    .digest
                    .clone()
                    .ok_or_else(|| refusal("missing restored database digest"))?,
            },
            Some(deadline),
        )?;
    }
    for tree in &manifest.trees {
        for entry in &tree.entries {
            check_member(
                data_dir,
                &CatalogMember {
                    path: format!("{}/{}", tree.name, entry.path),
                    source_asset: tree.name.clone(),
                    byte_len: entry.byte_len,
                    digest: entry
                        .digest
                        .clone()
                        .ok_or_else(|| refusal("missing restored tree digest"))?,
                },
                Some(deadline),
            )?;
        }
    }
    for member in &members {
        let mut rooted = member.clone();
        rooted.path = format!("{prefix}/{}", member.path);
        check_member(data_dir, &rooted, Some(deadline))?;
    }
    let (source_membrane, _) = open_member(
        data_dir,
        &format!("{prefix}/source-main/idempotency.db"),
        super::MAX_DATABASE_BYTES,
    )?;
    let conn = immutable_connection(&source_membrane)?;
    IdempotencyStore::validate_current_schema(&conn)?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| refusal(error.to_string()))?;
    if version != i64::from(crate::idempotency_store::IDEMPOTENCY_SCHEMA_VERSION) {
        return Err(refusal(
            "source main evidence has an unsupported replay-store version",
        ));
    }
    let source_membrane = IdempotencyStore::read_membrane_identity(&conn)?;
    let replay_path = data_dir.join("idempotency.db");
    if replay_path.symlink_metadata().is_ok() {
        return Err(refusal(
            "fresh target replay store already exists; preserve interrupted activation offline",
        ));
    }
    let replay = IdempotencyStore::open(&replay_path)?;
    if replay.membrane_id()? == source_membrane {
        return Err(refusal("fresh replay membrane reused source identity"));
    }
    drop(replay);
    super::fsync_dir(data_dir)?;
    let catalog = ImportCatalog {
        origin_artifact_id,
        source_directory_id: source_directory_id.clone(),
        target_directory_id: target_directory_id.into(),
        source_manifest_digest: blake3::hash(&source).to_hex().to_string(),
        members,
    };
    let encoded = serde_json::to_vec(&catalog).map_err(|error| refusal(error.to_string()))?;
    write_immutable(data_dir, &format!("{prefix}/{CATALOG}"), &encoded)?;
    let authority = ImportAuthority {
        artifact_id: origin_artifact_id,
        source_directory_id,
        target_directory_id: target_directory_id.into(),
        catalog_digest: blake3::hash(&encoded).to_hex().to_string(),
    };
    let db = OperationalDb::open(data_dir.join("operational.db"))?;
    db.quarantine_verified_import(&authority, deadline)?;
    verify_import_evidence_at(data_dir, target_directory_id, &db, Some(deadline))?;
    drop(db);
    super::fsync_dir(data_dir)?;
    Ok(PreparedCloneImport {
        data_dir: data_dir
            .canonicalize()
            .map_err(|error| refusal(error.to_string()))?,
        authority,
    })
}

/// Enumerate original exchanges for foreign domains; never relabel their
/// artifact IDs or contact retired source workers on a subsequent backup.
pub fn inherited_worker_generations(
    data_dir: &Path,
    db: &OperationalDb,
    deadline: std::time::Instant,
) -> KataResult<Vec<InheritedRecoveryGeneration>> {
    super::recovery_assets::check_deadline(deadline)?;
    let mut inherited = Vec::new();
    for authority in db.import_authorities()? {
        let (_, manifest) = read_catalog(data_dir, &authority, false, Some(deadline))?;
        for treatment in manifest.recovery_assets.into_iter().flatten() {
            if let RecoveryTreatment::ExternalGenerations { instances, .. } = treatment.treatment {
                inherited.extend(instances.into_iter().map(|instance| {
                    InheritedRecoveryGeneration {
                        domain: instance.domain,
                        origin_artifact_id: authority.artifact_id,
                    }
                }));
            }
        }
    }
    inherited.sort_by_key(|entry| {
        (
            entry.domain.source_main.clone(),
            entry.domain.membrane.0,
            entry.domain.enrollment,
        )
    });
    inherited.dedup();
    Ok(inherited)
}

pub(super) fn verify_inherited_workers(
    artifact: &Path,
    operational: &rusqlite::Connection,
    inherited: &[InheritedRecoveryGeneration],
    deadline: std::time::Instant,
) -> KataResult<()> {
    let mut origins: std::collections::BTreeMap<Ulid, Vec<&InheritedRecoveryGeneration>> =
        std::collections::BTreeMap::new();
    for generation in inherited {
        origins
            .entry(generation.origin_artifact_id)
            .or_default()
            .push(generation);
    }
    for (origin, generations) in origins {
        super::recovery_assets::check_deadline(deadline)?;
        let authority = operational.query_row("SELECT source_directory_id,target_directory_id,catalog_digest FROM recovery_imports WHERE artifact_id=?1", rusqlite::params![origin.to_bytes().as_slice()], |row| Ok(ImportAuthority { artifact_id: origin, source_directory_id: row.get(0)?, target_directory_id: row.get(1)?, catalog_digest: row.get(2)? })).map_err(|error| refusal(error.to_string()))?;
        let prefix = origin_prefix(origin, true);
        // Catalog bytes and all retained checkpoint members are verified once
        // per origin, not once for every worker originally exported with it.
        let (_, manifest) = read_catalog(artifact, &authority, true, Some(deadline))?;
        let indexed = MemberIndex::new(&manifest)?;
        let domains = inherited_domains(&manifest)?;
        for generation in generations {
            let instance = domains
                .get(&generation.domain)
                .ok_or_else(|| refusal("foreign domain has no original authenticated evidence"))?;
            verify_inherited_domain(artifact, &prefix, &indexed, instance, origin, deadline)?;
        }
    }
    Ok(())
}

fn inherited_domains(
    manifest: &BackupManifest,
) -> KataResult<
    std::collections::HashMap<
        &kata_types::identity::WorkerEffectDomain,
        &super::ExternalRecoveryGeneration,
    >,
> {
    let mut domains = std::collections::HashMap::new();
    for treatment in manifest.recovery_assets.iter().flatten() {
        if let RecoveryTreatment::ExternalGenerations { instances, .. } = &treatment.treatment {
            for instance in instances {
                if domains.insert(&instance.domain, instance).is_some() {
                    return Err(refusal("duplicate inherited worker provenance"));
                }
            }
        }
    }
    Ok(domains)
}

fn verify_inherited_domain(
    artifact: &Path,
    prefix: &str,
    indexed: &MemberIndex<'_>,
    instance: &super::ExternalRecoveryGeneration,
    origin: Ulid,
    deadline: std::time::Instant,
) -> KataResult<()> {
    super::recovery_assets::check_deadline(deadline)?;
    let bytes = read_bytes(
        artifact,
        &format!("{prefix}/{}", instance.receipt_member),
        1024 * 1024,
        Some(deadline),
    )?;
    let receipt: super::WorkerRecoveryReceipt =
        serde_json::from_slice(&bytes).map_err(|error| refusal(error.to_string()))?;
    if receipt.schema_version != crate::idempotency_store::IDEMPOTENCY_SCHEMA_VERSION
        || receipt.artifact_id != origin
        || receipt.domain != instance.domain
        || receipt.generation_id != instance.generation_id
        || receipt.request_nonce != instance.request_nonce
    {
        return Err(refusal("inherited receipt tuple mismatch"));
    }
    let (file, len) = open_member(
        artifact,
        &format!("{prefix}/{}", instance.database_member),
        super::MAX_DATABASE_BYTES,
    )?;
    let db = immutable_connection(&file)?;
    IdempotencyStore::validate_current_schema(&db)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| refusal(error.to_string()))?;
    if version != i64::from(receipt.schema_version) {
        return Err(refusal(
            "inherited database version disagrees with original receipt",
        ));
    }
    let record: &CapturedAsset = indexed.require(&instance.database_member)?;
    if receipt.database_byte_len != len
        || Some(&receipt.database_digest) != record.digest.as_ref()
        || IdempotencyStore::read_membrane_identity(&db)? != instance.domain.membrane
    {
        return Err(refusal(
            "inherited database disagrees with original receipt",
        ));
    }
    Ok(())
}
