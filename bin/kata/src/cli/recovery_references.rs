//! Typed durable VCS roots from the databases actually captured in an artifact.
//!
//! Opaque agent prose, content hashes and tree hashes are not commit authority.
//! Historical receipts retain their concrete commits; unresolved typed reference
//! arguments require a current named target.
//! Unadjudicated buffered events and typed records above 64 MiB refuse. History
//! has no cumulative byte cap. Deadlines are checked between SQLite operations;
//! this is not interruption of blocked filesystem calls or corrupt SQLite reads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::Instant;

use kata_core::store::backup::{BackupManifest, STORES_SUBDIR, TREES_SUBDIR};
use kata_types::error::{KataError, KataResult};
use kata_types::execution::{ExecutionEvidence, ExecutionWorkspaceIdentity, ParkedExecution};
use kata_types::recovery::{RecoveryReferenceKind, RecoveryReferenceSnapshot};
use kata_vcs::jj::recovery_references::{
    RecoveryNamedReference, validate_recovery_reference_snapshot,
};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use ulid::Ulid;

// Matches the operational outcome and ledger output writer bound. This is a
// per-record decode bound, not a cumulative limit on retained history.
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

#[path = "recovery_references/cohort.rs"]
mod cohort;
pub(super) use cohort::{
    RecoveryCohort, recovery_cohort_captured, recovery_cohort_source, recovery_cohort_target,
};

fn refused(message: &str) -> KataError {
    KataError::Validation(format!("recovery reference census refused: {message}"))
}

fn sql(error: rusqlite::Error) -> KataError {
    // SQLite messages can carry host paths or retained data.
    let _ = error;
    refused("authoritative database query failed")
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct DurableReferenceCensus {
    commits: Vec<String>,
    changes: Vec<String>,
    named_refs: Vec<RecoveryNamedReference>,
    isolated_executions: BTreeSet<Vec<u8>>,
    durable_candidates: BTreeSet<Vec<u8>>,
}

impl DurableReferenceCensus {
    pub fn commits(&self) -> &[String] {
        &self.commits
    }
    pub fn changes(&self) -> &[String] {
        &self.changes
    }
    pub fn named_refs(&self) -> &[RecoveryNamedReference] {
        &self.named_refs
    }

    /// Equality, not inclusion: a proof cannot silently omit or invent a durable
    /// request while retaining an otherwise authentic source view.
    pub fn validate_snapshot(&self, snapshot: &RecoveryReferenceSnapshot) -> KataResult<()> {
        validate_recovery_reference_snapshot(snapshot)
            .map_err(|_| refused("invalid retained reference snapshot"))?;
        for (kind, expected) in [
            (
                RecoveryReferenceKind::DurableCommit,
                self.commits.iter().map(String::as_str).collect::<Vec<_>>(),
            ),
            (
                RecoveryReferenceKind::DurableChange,
                self.changes.iter().map(String::as_str).collect(),
            ),
            (
                RecoveryReferenceKind::DurableBookmark,
                self.named_refs
                    .iter()
                    .map(|reference| match reference {
                        RecoveryNamedReference::LocalBookmark(name) => name.as_str(),
                    })
                    .collect(),
            ),
        ] {
            let expected: BTreeSet<_> = expected
                .into_iter()
                .map(|name| blake3::hash(name.as_bytes()).to_hex().to_string())
                .collect();
            let actual: BTreeSet<_> = snapshot
                .references
                .iter()
                .filter(|reference| reference.kind == kind)
                .map(|reference| reference.name_digest.clone())
                .collect();
            if expected != actual {
                return Err(refused(
                    "captured durable reference population differs from proof",
                ));
            }
        }
        Ok(())
    }
}

struct Reader {
    deadline: Instant,
    commits: BTreeSet<String>,
    names: BTreeSet<RecoveryNamedReference>,
    isolated_executions: BTreeSet<Vec<u8>>,
    durable_candidates: BTreeSet<Vec<u8>>,
}

impl Reader {
    fn charge(&mut self, bytes: usize) -> KataResult<()> {
        if Instant::now() >= self.deadline {
            return Err(refused("deadline elapsed"));
        }
        if bytes > MAX_RECORD_BYTES {
            return Err(refused("typed record exceeds 64 MiB decode bound"));
        }
        Ok(())
    }

    fn decode<T: serde::de::DeserializeOwned>(&mut self, bytes: &[u8]) -> KataResult<T> {
        self.charge(bytes.len())?;
        serde_json::from_slice(bytes).map_err(|_| refused("malformed typed retained metadata"))
    }

    fn commit(&mut self, commit: &str) -> KataResult<()> {
        if commit.len() != 40
            || !commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refused("expected concrete lowercase SHA-1 commit receipt"));
        }
        self.commits.insert(commit.to_owned());
        if self.commits.len() > 100_000 {
            return Err(refused("durable commits exceed 100k bound"));
        }
        Ok(())
    }

    fn name(&mut self, name: &str) -> KataResult<()> {
        if name.is_empty() || name.len() > 1024 || name.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(refused("malformed retained bookmark name"));
        }
        self.names
            .insert(RecoveryNamedReference::LocalBookmark(name.to_owned()));
        Ok(())
    }

    fn pair(&mut self, commit: Option<&str>, name: Option<&str>) -> KataResult<()> {
        if let Some(commit) = commit {
            self.commit(commit)
        } else if let Some(name) = name {
            self.name(name)
        } else {
            Ok(())
        }
    }

    fn identity(&mut self, identity: &ExecutionWorkspaceIdentity) -> KataResult<()> {
        backend(&identity.backend)?;
        if identity.schema_version != 1 {
            return Err(refused("unknown workspace identity schema"));
        }
        for commit in [
            &identity.workspace_commit_sha,
            &identity.base_commit_sha,
            &identity.target_commit_sha,
        ]
        .into_iter()
        .flatten()
        {
            self.commit(commit)?;
        }
        // Generic identity labels are provenance, including jj workspace names
        // that are not bookmarks. The incomplete-promotion lookup below is the
        // one retained identity consumer that establishes a current-name duty.
        Ok(())
    }

    fn parked(&mut self, parked: &ParkedExecution) -> KataResult<()> {
        self.commit(&parked.commit_sha)?;
        if let Some(identity) = &parked.identity {
            self.identity(identity)?;
        }
        Ok(())
    }

    fn evidence(&mut self, evidence: &ExecutionEvidence) -> KataResult<()> {
        // New durable evidence fields require an explicit reference-authority
        // classification. The other fields below are policy/prose/content hashes,
        // not VCS commit identities; they must not be recursively hex-scanned.
        let ExecutionEvidence {
            execution_program: _,
            checked_runtime_authority: _,
            parked_candidate: _,
            auto_parked: _,
            // A closeout park refusal names the ref it refused to overwrite and,
            // in its message, the commits it judged — prose about a park that
            // did not happen. The standing ref keeps its own commit and the
            // standing workspace its candidate; nothing reads the record as a
            // commit authority, so it is classified out of the hex-scan.
            closeout_park_refusal: _,
            validation_reports: _,
            closeout_reports: _,
            human_requests: _,
            external_inputs: _,
            param_provenance: _,
            memory_selectors: _,
            check_artifacts: _,
            memory_writebacks: _,
            controller_decisions: _,
            controller_applications: _,
            checked_dispatch_guards: _,
            output_closures: _,
            worker_stops: _,
            // `EgressRefusalReport`s carry authority strings and refusal labels —
            // network policy facts, not VCS commit identities, so they are
            // classified out of the hex-scan like the fields above.
            egress_refusals: _,
            // `ExecutionAgentTurnEvidence` carries a stage/attempt id, an
            // adapter label, a model name and CAS addresses — never a VCS
            // commit identity, so it is classified out of the hex-scan too.
            // (A turn's scratch commits live inside the session-evidence BLOB
            // these rows name — `SessionEvidence::scratch_commits` — which is
            // Private CAS content this scan never opens, and their object ids
            // are the scratch repository's own names that die with the
            // attempt's gitdir, never hashes of a host commit.)
            agent_turns: _,
        } = evidence;
        if let Some(parked) = &evidence.parked_candidate {
            self.parked(parked)?;
        }
        for report in &evidence.validation_reports {
            if let Some(commit) = &report.git_sha {
                self.commit(commit)?;
            }
            for criterion in &report.criteria {
                if let Some(candidate) = &criterion.candidate {
                    if let Some(provider) = &candidate.workspace_backend {
                        backend(provider)?;
                    }
                    if let Some(commit) = &candidate.head_commit {
                        self.commit(commit)?;
                    }
                }
            }
        }
        for application in &evidence.controller_applications {
            if let Some(parked) = &application.parked_candidate {
                self.parked(parked)?;
            }
            if let Some(promotion) = &application.promotion {
                self.pair(
                    promotion.promoted_commit_sha.as_deref(),
                    promotion.promoted_ref.as_deref(),
                )?;
                if let Some(identity) = &promotion.identity {
                    self.identity(identity)?;
                    // ApiExecutor::observed_promoted_workspace_for_claim uses
                    // this retained base bookmark only when a complete promotion
                    // receipt is absent. Paired historical workspace labels are
                    // not current-name obligations merely by being recorded.
                    let complete = promotion
                        .promoted_ref
                        .as_deref()
                        .is_some_and(|name| !name.trim().is_empty())
                        && promotion
                            .promoted_commit_sha
                            .as_deref()
                            .is_some_and(|commit| !commit.trim().is_empty());
                    if !application.applied
                        && application.action == "promote"
                        && !complete
                        && identity
                            .target_commit_sha
                            .as_ref()
                            .or(identity.workspace_commit_sha.as_ref())
                            .is_some()
                        && let Some(base) = identity
                            .base_ref
                            .as_deref()
                            .filter(|name| !name.trim().is_empty())
                    {
                        self.name(base.trim())?;
                    }
                }
            }
            if application.parked_candidate.is_none()
                && application.promotion.is_none()
                && let Some(name) = application
                    .side_effect
                    .as_ref()
                    .and_then(|effect| effect.parked_ref.as_deref())
            {
                self.name(name)?;
            }
        }
        Ok(())
    }

    fn output(&mut self, output: &serde_json::Value) -> KataResult<bool> {
        if output.is_null() {
            return Ok(false);
        }
        // WorkspaceEffectBackend::run_effect emits one JSON receipt. The worker
        // places it in `parsed` and also retains the original content string.
        let receipt: WorkspaceReceipt = if let Some(parsed) = output.get("parsed") {
            serde_json::from_value(parsed.clone())
                .map_err(|_| refused("malformed workspace effect parsed receipt"))?
        } else if let Some(content) = output.get("content").and_then(serde_json::Value::as_str) {
            serde_json::from_str(content)
                .map_err(|_| refused("malformed workspace effect content receipt"))?
        } else {
            return Err(refused("workspace effect output lacks typed receipt"));
        };
        let (name, commit) = match &receipt {
            WorkspaceReceipt::Park {
                ref_name,
                commit_sha,
            }
            | WorkspaceReceipt::Commit {
                ref_name,
                commit_sha,
            }
            | WorkspaceReceipt::Promote {
                ref_name,
                commit_sha,
                ..
            }
            | WorkspaceReceipt::ForgeExport {
                ref_name,
                commit_sha,
                ..
            } => (ref_name, commit_sha),
        };
        if name.is_empty() {
            return Err(refused("unknown workspace effect receipt"));
        }
        self.commit(commit)?;
        Ok(!matches!(receipt, WorkspaceReceipt::Commit { .. }))
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum WorkspaceReceipt {
    Park {
        ref_name: String,
        commit_sha: String,
    },
    Commit {
        ref_name: String,
        commit_sha: String,
    },
    Promote {
        ref_name: String,
        commit_sha: String,
        #[serde(rename = "ref_moved")]
        _ref_moved: bool,
    },
    ForgeExport {
        ref_name: String,
        commit_sha: String,
        #[serde(rename = "remote")]
        _remote: String,
        #[serde(rename = "base")]
        _base: String,
        #[serde(rename = "pr_url")]
        _pr_url: String,
        #[serde(rename = "pr_number")]
        _pr_number: u64,
    },
}

fn backend(backend: &str) -> KataResult<()> {
    if backend != "jj" {
        return Err(refused("unknown workspace backend"));
    }
    Ok(())
}

/// The main-data-directory guard must remain held throughout live SQL reads.
/// READ_ONLY includes committed WAL bytes; immutable=1 would silently omit them.
pub(super) fn census_source(
    data_dir: &Path,
    deadline: Instant,
) -> KataResult<DurableReferenceCensus> {
    census(data_dir, false, deadline)
}

pub(super) fn census_captured(
    artifact: &Path,
    manifest: &BackupManifest,
    deadline: Instant,
) -> KataResult<DurableReferenceCensus> {
    // ONE required database. The `execution_evidence` table this census reads lives in
    // `operational.db`, and the census opens no other database, so requiring another
    // would refuse an artifact over a store this census never reads.
    if !manifest
        .databases
        .iter()
        .any(|name| name == "operational.db")
    {
        return Err(refused("required captured reference database missing"));
    }
    census(&artifact.join(STORES_SUBDIR), true, deadline)
}

fn open(path: &Path, immutable: bool) -> KataResult<(File, Connection)> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| refused("missing or unreadable reference database"))?;
    if !file
        .metadata()
        .map_err(|_| refused("reference database metadata unreadable"))?
        .is_file()
    {
        return Err(refused("reference database is not a regular file"));
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = if immutable {
        Connection::open_with_flags(
            format!("file:/proc/self/fd/{}?immutable=1", file.as_raw_fd()),
            flags | OpenFlags::SQLITE_OPEN_URI,
        )
    } else {
        Connection::open_with_flags(path, flags)
    }
    .map_err(sql)?;
    connection
        .busy_timeout(std::time::Duration::ZERO)
        .map_err(sql)?;
    Ok((file, connection))
}

fn census(
    directory: &Path,
    immutable: bool,
    deadline: Instant,
) -> KataResult<DurableReferenceCensus> {
    let mut reader = Reader {
        deadline,
        commits: BTreeSet::new(),
        names: BTreeSet::new(),
        isolated_executions: BTreeSet::new(),
        durable_candidates: BTreeSet::new(),
    };
    reader.charge(0)?;
    // ONE file view. `cas_roots` and `execution_evidence` both live in `operational.db`,
    // so there is no cross-file snapshot hazard to guard: a single `BEGIN` is one
    // snapshot of both.
    let (_operational_file, operational) = open(&directory.join("operational.db"), immutable)?;
    let _operational_deadline =
        kata_core::operational::RecoveryReadDeadline::new(&operational, deadline)?;
    // Pin the file view. The caller's source-owner fence prevents writes; a captured file
    // already is an immutable checkpointed copy.
    operational.execute_batch("BEGIN").map_err(sql)?;
    // Accepted terminal frames fold into the transition chain in the same
    // transaction. A not-yet-adjudicated buffered frame is not that authority;
    // do not silently treat a captured pending payload as a proven receipt.
    let buffered: bool = operational
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM event_inbox WHERE accepted = 0)",
            [],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if buffered {
        return Err(refused(
            "unadjudicated buffered event requires reference classification",
        ));
    }
    // Object roots protect captured opaque content, not VCS identities, so the census
    // only checks their shape.
    let mut roots = operational
        .prepare("SELECT object_digest FROM cas_roots")
        .map_err(sql)?;
    let mut rows = roots.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        reader.charge(64)?;
        if !matches!(row.get_ref(0).map_err(sql)?,
            rusqlite::types::ValueRef::Blob(digest) if digest.len() == 32)
        {
            return Err(refused("malformed CAS object root"));
        }
    }
    let mut evidence = operational
        .prepare(&format!("SELECT CASE WHEN length(evidence_json) <= {MAX_RECORD_BYTES} THEN evidence_json END FROM execution_evidence"))
        .map_err(sql)?;
    let mut rows = evidence.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let record: kata_core::ExecutionEvidenceRecord = reader.decode(row_bytes(row, 0)?)?;
        reader.evidence(&record.evidence)?;
        if record.evidence.parked_candidate.is_some()
            || record
                .evidence
                .controller_applications
                .iter()
                .any(|application| {
                    application.parked_candidate.is_some()
                        || application.promotion.as_ref().is_some_and(|promotion| {
                            promotion
                                .promoted_ref
                                .as_ref()
                                .is_some_and(|name| !name.is_empty())
                                && promotion.promoted_commit_sha.is_some()
                        })
                })
        {
            reader
                .durable_candidates
                .insert(record.execution_id.to_bytes().to_vec());
        }
    }
    operational_outputs(directory, immutable, &operational, &mut reader)?;
    Ok(DurableReferenceCensus {
        commits: reader.commits.into_iter().collect(),
        changes: Vec::new(),
        named_refs: reader.names.into_iter().collect(),
        isolated_executions: reader.isolated_executions,
        durable_candidates: reader.durable_candidates,
    })
}

/// Refuse a retained checked program by its SCHEMA before the typed decode, so a
/// program another binary wrote is named for what it is — `checked program schema 8
/// is not the supported schema 9` — rather than failing the decode as "malformed
/// typed retained metadata". The message carries only the version
/// `kata_workflow::execution_program_store::execution_program_metadata` reads off
/// the header, never retained data. The reference census and the recovery
/// cohort (`cohort::inspect`) both refuse through it, each after its own size and
/// deadline bound.
fn refuse_noncurrent_program_schema(bytes: &[u8]) -> KataResult<()> {
    let metadata = kata_workflow::execution_program_store::execution_program_metadata(bytes, None)
        .map_err(|_| refused("malformed typed retained metadata"))?;
    let current = u64::from(kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION);
    match metadata.schema_version {
        Some(version) if version == current => Ok(()),
        Some(version) => Err(refused(&format!(
            "checked program schema {version} is not the supported schema {current}"
        ))),
        None => Err(refused("checked program carries no integer schema_version")),
    }
}

fn row_bytes<'a>(row: &'a rusqlite::Row<'a>, index: usize) -> KataResult<&'a [u8]> {
    match row.get_ref(index).map_err(sql)? {
        rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes) => {
            Ok(bytes)
        }
        _ => Err(refused("oversized or malformed retained metadata column")),
    }
}

fn operational_outputs(
    directory: &Path,
    immutable: bool,
    connection: &Connection,
    reader: &mut Reader,
) -> KataResult<()> {
    // A captured SQLite directory is `<artifact>/stores`; blob bytes live in
    // `<artifact>/trees/cas`. Never open a writable CasStore on either census
    // path: inspection cannot initialize missing authority or create lockfiles.
    let blobs = if immutable {
        directory
            .parent()
            .ok_or_else(|| refused("captured store directory has no artifact parent"))?
            .join(TREES_SUBDIR)
            .join("cas")
    } else {
        directory.join("cas")
    };
    let mut cas = None;
    let mut read_output = |address: kata_types::cache::CasAddress, size, maximum| {
        if cas.is_none() {
            cas = Some(open(&directory.join("cas.db"), immutable)?);
        }
        let (_, database) = cas.as_ref().expect("CAS opened above");
        kata_core::store::CasStore::read_verified(database, &blobs, &address.hash(), size, maximum)
            .map_err(|_| refused("authoritative output CAS bytes are missing or invalid"))
    };
    // Non-effect outputs also carry authoritative references. Validate them all
    // before restricting the VCS receipt census to checked effect stages.
    kata_core::operational::verify_authoritative_output_references(
        connection,
        reader.deadline,
        usize::MAX,
        &mut read_output,
    )?;
    // The verifier owns a temporary SQLite progress handler. Reinstall the
    // census handler for the remaining program and receipt queries.
    let _deadline = kata_core::operational::RecoveryReadDeadline::new(connection, reader.deadline)?;
    let mut programs = BTreeMap::new();
    let mut statement = connection
        .prepare(&format!("SELECT execution_id, CASE WHEN length(program_json) <= {MAX_RECORD_BYTES} THEN program_json END FROM programs"))
        .map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let bytes = row_bytes(row, 1)?;
        reader.charge(bytes.len())?;
        refuse_noncurrent_program_schema(bytes)?;
        let program: kata_program::execution_program::ExecutionProgram = reader.decode(bytes)?;
        program
            .validate_carried_stage_execution_classes()
            .map_err(|_| refused("unhonourable checked program"))?;
        if program.summary.worktree_isolated {
            reader
                .isolated_executions
                .insert(row_bytes(row, 0)?.to_vec());
        }
        programs.insert(row_bytes(row, 0)?.to_vec(), program);
    }
    let mut authorities = BTreeMap::new();
    let mut statement = connection
        .prepare(&format!("SELECT execution_id, stage_id, CASE WHEN length(assignment_json) <= {MAX_RECORD_BYTES} THEN assignment_json END FROM attempts WHERE executor = 'worker' UNION ALL SELECT execution_id, stage_id, CASE WHEN length(payload_json) <= {MAX_RECORD_BYTES} THEN json_extract(payload_json, '$.assignment') END FROM transitions WHERE kind = 'undispatched_stage_admitted'"))
        .map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        // THE AT-REST FORM IS A TAGGED `DispatchFrame` with one arm left —
        // `{"capsule": {…}}`. A capsule frame carries occurrence + capsule
        // identity, not the checked stage authority (that lives behind the
        // durable command), so this census attributes each attempt to its
        // stage through the program's own stage table: `stage_id` on the row
        // names the stage, the program names its executor kind, and a frame
        // that does not decode as a capsule attempt is refused by name.
        let kata_transport::types::DispatchFrame::Capsule(capsule) =
            reader.decode(row_bytes(row, 2)?)?;
        let execution = row_bytes(row, 0)?.to_vec();
        if capsule.execution_id.to_bytes().as_slice() != execution.as_slice() {
            return Err(refused("attempt capsule execution identity mismatch"));
        }
        let program = programs
            .get(&execution)
            .ok_or_else(|| refused("attempt missing checked program"))?;
        let stage_id_key = row.get::<_, String>(1).map_err(sql)?;
        let stage = program
            .stages
            .iter()
            .find(|(id, _)| id.0.as_str() == stage_id_key)
            .map(|(_, stage)| stage)
            .ok_or_else(|| refused("attempt missing checked stage"))?;
        let key = (execution, stage_id_key);
        let effect = stage.is_workspace_effect_executor();
        if authorities
            .insert(key, effect)
            .is_some_and(|old| old != effect)
        {
            return Err(refused("conflicting retained stage authority"));
        }
    }
    let mut statement = connection.prepare(&format!("SELECT execution_id, stage_id, scope, kind, CASE WHEN length(payload_json) <= {MAX_RECORD_BYTES} THEN payload_json END FROM transitions WHERE scope IN ('stage', 'attempt')")).map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        reader.charge(1)?;
        let execution = row_bytes(row, 0)?.to_vec();
        let stage_id: String = row.get(1).map_err(sql)?;
        let program = programs
            .get(&execution)
            .ok_or_else(|| refused("transition missing checked program"))?;
        let effect = match authorities.get(&(execution.clone(), stage_id.clone())) {
            Some(effect) => *effect,
            // A derived `/work` apply (`#apply/<stage>`, the stage possibly a loop member
            // or topology child spelling) is owned by the capsule stage whose delta it
            // lands — never a workspace effect. Its stage must still be the program's.
            None => match kata_types::execution_contract::work_apply_stage(&stage_id) {
                Some(applied) => {
                    program
                        .checked_stage_id_for_runtime_stage(applied)
                        .ok_or_else(|| refused("work apply names no checked stage"))?;
                    false
                }
                None => program
                    .checked_stage_id_for_runtime_stage(&stage_id)
                    .and_then(|id| program.stages.get(&id))
                    .map(kata_program::execution_program::ExecutionProgramStage::is_workspace_effect_executor)
                    .ok_or_else(|| refused("transition missing checked stage authority"))?,
            },
        };
        if !effect {
            continue;
        }
        let kind: String = row.get(3).map_err(sql)?;
        let execution_id = Ulid::from_bytes(
            execution
                .as_slice()
                .try_into()
                .map_err(|_| refused("malformed output execution identity"))?,
        );
        let resolved = kata_core::operational::resolve_authoritative_output_payload(
            connection,
            execution_id,
            &kind,
            row_bytes(row, 4)?,
            &mut read_output,
        )?;
        let payload: serde_json::Value = reader.decode(&resolved)?;
        if kind == "completed" && payload.get("output").is_none_or(serde_json::Value::is_null) {
            return Err(refused("completed workspace effect lacks receipt"));
        }
        if kind == "outcome_amended" {
            if reader.output(&payload)? {
                reader.durable_candidates.insert(execution);
            }
        } else if kind == "undispatched_stage_recorded" {
            let record: kata_core::operational::UndispatchedStageRecordPayload =
                serde_json::from_value(payload)
                    .map_err(|_| refused("malformed undispatched metadata"))?;
            let kata_core::operational::UndispatchedStageRecord::OutcomeAmended(output) =
                record.record;
            if reader.output(&output)? {
                reader.durable_candidates.insert(execution);
            }
        } else if let Some(output) = payload.get("output")
            && reader.output(output)?
        {
            reader.durable_candidates.insert(execution);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let operational = Connection::open(directory.path().join("operational.db")).unwrap();
        // `execution_evidence` IS IN THIS FILE: the census reads one database,
        // never a two-file snapshot it would have to reconcile.
        operational.execute_batch("CREATE TABLE cas_roots(object_digest BLOB); CREATE TABLE programs(execution_id BLOB, program_json BLOB); CREATE TABLE attempts(execution_id BLOB, stage_id TEXT, assignment_json BLOB, executor TEXT NOT NULL DEFAULT 'worker'); CREATE TABLE transitions(execution_id BLOB, stage_id TEXT, scope TEXT, kind TEXT, payload_json BLOB); CREATE TABLE event_inbox(accepted INTEGER, execution_id BLOB, payload_json BLOB); CREATE TABLE execution_evidence(evidence_json BLOB);").unwrap();
        directory
    }

    /// Generous on purpose: a census reads sqlite on disk, which a loaded gate host
    /// stalls past seconds; the expired-deadline refusal is its own cell (the
    /// `census_source(.., Instant::now())` assertion below).
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn recovery_reference_census_only_incomplete_promotion_claim_requires_paired_base_name() {
        let mut value = serde_json::json!({"controller_applications": [{
            "schema_version": 1, "application_id": "claim", "decision_id": "decision", "decision": "promote", "action": "promote", "applied": false, "applied_at_ms": 0,
            "promotion": {"available": true, "safe_to_promote": true, "status": "pending", "identity": {
                "schema_version": 1, "execution_id": "execution", "backend": "jj",
                "workspace_ref": "historical-workspace-label", "workspace_commit_sha": "a".repeat(40),
                "base_ref": "main", "base_commit_sha": "b".repeat(40)
            }}
        }]});
        let read = |value: &serde_json::Value| {
            let mut reader = Reader {
                deadline: deadline(),
                commits: BTreeSet::new(),
                names: BTreeSet::new(),
                isolated_executions: BTreeSet::new(),
                durable_candidates: BTreeSet::new(),
            };
            reader
                .evidence(&serde_json::from_value(value.clone()).unwrap())
                .unwrap();
            reader.names
        };
        assert_eq!(
            read(&value),
            BTreeSet::from([RecoveryNamedReference::LocalBookmark("main".into())])
        );
        value["controller_applications"][0]["applied"] = true.into();
        assert!(read(&value).is_empty());
        value["controller_applications"][0]["applied"] = false.into();
        value["controller_applications"][0]["promotion"]["promoted_ref"] =
            "historical-complete-ref".into();
        value["controller_applications"][0]["promotion"]["promoted_commit_sha"] =
            "c".repeat(40).into();
        assert!(read(&value).is_empty());
    }

    fn evidence(directory: &Path, commit: &str) {
        let record = kata_core::ExecutionEvidenceRecord {
            id: ulid::Ulid::new(),
            execution_id: ulid::Ulid::new(),
            created_at_ms: 1,
            evidence: ExecutionEvidence {
                parked_candidate: Some(ParkedExecution {
                    status: "parked".into(),
                    parked_ref: "historical-deleted-name".into(),
                    commit_sha: commit.into(),
                    identity: None,
                }),
                ..Default::default()
            },
        };
        Connection::open(directory.join("operational.db"))
            .unwrap()
            .execute(
                "INSERT INTO execution_evidence VALUES (?)",
                [serde_json::to_vec(&record).unwrap()],
            )
            .unwrap();
    }

    #[test]
    fn recovery_reference_census_reads_all_receipts_and_preserves_source_bytes() {
        let directory = fixture();
        evidence(directory.path(), &"a".repeat(40));
        evidence(directory.path(), &"b".repeat(40));
        let operational = Connection::open(directory.path().join("operational.db")).unwrap();
        operational
            .execute("INSERT INTO cas_roots VALUES (?)", [&[7u8; 32][..]])
            .unwrap();
        drop(operational);
        // ONE file to hash, since the evidence table moved into it.
        let before: Vec<_> = ["operational.db"]
            .map(|name| std::fs::read(directory.path().join(name)).unwrap())
            .into();
        let census = census_source(directory.path(), deadline()).unwrap();
        assert_eq!(census.commits(), &["a".repeat(40), "b".repeat(40)]);
        assert!(
            census.named_refs().is_empty(),
            "an object root names content, never a VCS reference"
        );
        let after: Vec<_> = ["operational.db"]
            .map(|name| std::fs::read(directory.path().join(name)).unwrap())
            .into();
        assert_eq!(before, after);
        // ONE entry: the census must not create a sidecar beside the fixture's single
        // database.
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    /// Schema 24 — a MAIN-RESOLVED attempt's row (executor `main`, blob `{"main": …}`) is
    /// EXCLUDED BY NAME from the stage-authority census rather than decoded: it carries no
    /// checked stage authority and authorizes no workspace effect, and a decode of it
    /// would refuse the whole census — every capture and restore of its data directory.
    #[test]
    fn recovery_reference_census_excludes_a_main_resolved_attempt_by_name() {
        let directory = fixture();
        Connection::open(directory.path().join("operational.db"))
            .unwrap()
            .execute(
                "INSERT INTO attempts VALUES (?1, 'join', ?2, 'main')",
                rusqlite::params![
                    ulid::Ulid::new().to_bytes().as_slice(),
                    br#"{"main":{"operation":"join"}}"#.as_slice()
                ],
            )
            .unwrap();
        census_source(directory.path(), deadline())
            .expect("the census reads past a main-resolved attempt");
    }

    #[test]
    fn recovery_reference_census_snapshot_requires_exact_captured_population() {
        use kata_types::recovery::RecoveryReference;
        let directory = fixture();
        let commit = "a".repeat(40);
        evidence(directory.path(), &commit);
        let reference = |kind, name: &str| RecoveryReference {
            kind,
            name_digest: blake3::hash(name.as_bytes()).to_hex().to_string(),
            remote_name_digest: None,
            tracked: None,
            removes: Vec::new(),
            adds: vec![Some(commit.clone())],
        };
        let mut snapshot = RecoveryReferenceSnapshot {
            operation_id: "f".repeat(128),
            references: vec![
                reference(RecoveryReferenceKind::Head, ""),
                reference(RecoveryReferenceKind::DurableCommit, &commit),
            ],
            required_commits: vec![commit.clone()],
            resolved_changes: BTreeMap::new(),
            reference_set_digest: String::new(),
        };
        snapshot.reference_set_digest = snapshot.computed_digest();
        census_source(directory.path(), deadline())
            .unwrap()
            .validate_snapshot(&snapshot)
            .unwrap();
        evidence(directory.path(), &"b".repeat(40));
        assert!(
            census_source(directory.path(), deadline())
                .unwrap()
                .validate_snapshot(&snapshot)
                .is_err()
        );
        snapshot
            .references
            .retain(|reference| reference.kind != RecoveryReferenceKind::DurableCommit);
        snapshot.reference_set_digest = snapshot.computed_digest();
        assert!(
            census_source(directory.path(), deadline())
                .unwrap()
                .validate_snapshot(&snapshot)
                .is_err()
        );
    }

    #[test]
    fn recovery_reference_census_source_reads_committed_wal_and_captured_uses_own_bytes() {
        let directory = fixture();
        let connection = Connection::open(directory.path().join("operational.db")).unwrap();
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        // A receipt committed to the WAL only, on the connection held open below.
        let record = kata_core::ExecutionEvidenceRecord {
            id: ulid::Ulid::new(),
            execution_id: ulid::Ulid::new(),
            created_at_ms: 1,
            evidence: ExecutionEvidence {
                parked_candidate: Some(ParkedExecution {
                    status: "parked".into(),
                    parked_ref: "wal-candidate".into(),
                    commit_sha: "d".repeat(40),
                    identity: None,
                }),
                ..Default::default()
            },
        };
        connection
            .execute(
                "INSERT INTO execution_evidence VALUES (?)",
                [serde_json::to_vec(&record).unwrap()],
            )
            .unwrap();
        let captured = tempfile::tempdir().unwrap();
        // Copying the database file deliberately excludes the committed WAL.
        // This independent control catches accidentally using immutable=1 live.
        std::fs::copy(
            directory.path().join("operational.db"),
            captured.path().join("operational.db"),
        )
        .unwrap();
        assert_eq!(
            census_source(directory.path(), deadline())
                .unwrap()
                .commits()
                .len(),
            1
        );
        assert!(
            census(captured.path(), true, deadline())
                .unwrap()
                .commits()
                .is_empty()
        );
    }

    #[test]
    fn recovery_reference_census_refuses_missing_malformed_and_buffered_authority() {
        let directory = fixture();
        evidence(directory.path(), "not-a-commit");
        assert!(census_source(directory.path(), deadline()).is_err());
        assert!(census_source(&directory.path().join("missing"), deadline()).is_err());
        let directory = fixture();
        Connection::open(directory.path().join("operational.db"))
            .unwrap()
            .execute("INSERT INTO event_inbox(accepted) VALUES (0)", [])
            .unwrap();
        assert!(
            census_source(directory.path(), deadline())
                .unwrap_err()
                .to_string()
                .contains("unadjudicated")
        );
        assert!(census_source(directory.path(), Instant::now()).is_err());
    }

    /// A retained checked program another build wrote is refused BY ITS
    /// SCHEMA, before any decode. The fixture is a schema-7 row whose payload
    /// this build cannot decode (`{"kind":"bwrap"}`); a decode-first census
    /// would fail it as the generic "malformed typed retained metadata" and the
    /// operator would learn nothing about which format they held.
    #[test]
    fn recovery_reference_census_refuses_a_retired_program_schema_by_name() {
        let directory = fixture();
        let program = serde_json::json!({
            "schema_version": 7,
            "workflow_name": "pre-rename",
            "sandbox_profiles": {"confined": {"exec": {"kind": "bwrap"}}},
        });
        Connection::open(directory.path().join("operational.db"))
            .unwrap()
            .execute(
                "INSERT INTO programs VALUES (?1, ?2)",
                rusqlite::params![
                    ulid::Ulid::new().to_bytes().as_slice(),
                    serde_json::to_vec(&program).unwrap()
                ],
            )
            .unwrap();
        let error = census_source(directory.path(), deadline())
            .unwrap_err()
            .to_string();
        let current = kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION;
        assert!(
            error.contains(&format!(
                "checked program schema 7 is not the supported schema {current}"
            )),
            "{error}"
        );
        assert!(
            !error.contains("bwrap"),
            "the schema alone is named: {error}"
        );
        assert!(
            !error.contains("malformed typed retained metadata"),
            "{error}"
        );
    }

    #[test]
    fn recovery_reference_census_refuses_oversized_sql_value_before_json_decode() {
        let directory = fixture();
        Connection::open(directory.path().join("operational.db"))
            .unwrap()
            .execute(
                "INSERT INTO execution_evidence VALUES (zeroblob(?))",
                [MAX_RECORD_BYTES + 1],
            )
            .unwrap();
        let error = census_source(directory.path(), deadline())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("oversized or malformed retained metadata column"),
            "{error}"
        );
        assert!(
            !error.contains("malformed typed retained metadata"),
            "oversized bytes must never reach serde"
        );
    }

    #[test]
    fn recovery_reference_census_history_larger_than_proof_bound_is_not_truncated() {
        let directory = fixture();
        let ledger = Connection::open(directory.path().join("operational.db")).unwrap();
        for _ in 0..12 {
            let mut record = serde_json::to_value(kata_core::ExecutionEvidenceRecord {
                id: ulid::Ulid::new(),
                execution_id: ulid::Ulid::new(),
                created_at_ms: 0,
                evidence: ExecutionEvidence::default(),
            })
            .unwrap();
            // Opaque prose is deliberately not interpreted as VCS authority.
            record["opaque_test_extension"] = serde_json::Value::String("f".repeat(100_000));
            ledger
                .execute(
                    "INSERT INTO execution_evidence VALUES (?)",
                    [serde_json::to_vec(&record).unwrap()],
                )
                .unwrap();
        }
        evidence(directory.path(), &"c".repeat(40));
        assert_eq!(
            census_source(directory.path(), deadline())
                .unwrap()
                .commits(),
            &["c".repeat(40)]
        );
    }

    #[test]
    fn recovery_reference_census_checked_effect_receipts_include_amendment_history_not_agent_hex() {
        let directory = fixture();
        let program = kata_program::execution_program::compile_starlark_execution_program(
            r#"
seed = stage(id = "seed", agent = "shell", run = "true")
park = stage(id = "park", agent = "workspace_effect", op = "park", depends_on = ["seed"])
workflow("recovery-census", root = [seed, park], worktree_isolated = True)
"#,
            "recovery-census.star",
            &[],
        )
        .unwrap();
        let execution = ulid::Ulid::new();
        let connection = Connection::open(directory.path().join("operational.db")).unwrap();
        connection
            .execute(
                "INSERT INTO programs VALUES (?, ?)",
                rusqlite::params![
                    execution.to_bytes().as_slice(),
                    serde_json::to_vec(&program).unwrap()
                ],
            )
            .unwrap();
        let receipt = |commit: &str| serde_json::json!({"parsed": {"operation": "park", "ref_name": "historical-name", "commit_sha": commit}});
        for (stage, kind, payload) in [
            (
                "park",
                "completed",
                serde_json::json!({"output": receipt(&"a".repeat(40))}),
            ),
            (
                "park",
                "outcome_amended",
                serde_json::json!({"output": receipt(&"b".repeat(40))}),
            ),
            (
                "seed",
                "completed",
                serde_json::json!({"output": receipt(&"f".repeat(40))}),
            ),
        ] {
            connection
                .execute(
                    "INSERT INTO transitions VALUES (?, ?, 'stage', ?, ?)",
                    rusqlite::params![
                        execution.to_bytes().as_slice(),
                        stage,
                        kind,
                        serde_json::to_vec(&payload).unwrap()
                    ],
                )
                .unwrap();
        }
        assert_eq!(
            census_source(directory.path(), deadline())
                .unwrap()
                .commits(),
            &["a".repeat(40), "b".repeat(40)]
        );
        connection.execute("UPDATE transitions SET payload_json = '{}' WHERE stage_id = 'park' AND kind = 'outcome_amended'", []).unwrap();
        assert!(census_source(directory.path(), deadline()).is_err());
    }

    fn file_inventory(root: &Path) -> BTreeMap<std::path::PathBuf, Option<blake3::Hash>> {
        fn visit(
            root: &Path,
            directory: &Path,
            result: &mut BTreeMap<std::path::PathBuf, Option<blake3::Hash>>,
        ) {
            for entry in std::fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_owned();
                if entry.file_type().unwrap().is_dir() {
                    result.insert(relative, None);
                    visit(root, &path, result);
                } else {
                    assert!(entry.file_type().unwrap().is_file());
                    result.insert(relative, Some(blake3::hash(&std::fs::read(path).unwrap())));
                }
            }
        }
        let mut result = BTreeMap::new();
        visit(root, root, &mut result);
        result
    }

    #[test]
    fn recovery_reference_census_resolves_large_effect_receipts_without_mutating_artifact() {
        use kata_core::operational::{CasRootOwner, CasRootSpec};
        use kata_types::cache::CasAddress;
        let directory = fixture();
        let program = kata_program::execution_program::compile_starlark_execution_program(
            "seed = stage(id = 'seed', agent = 'shell', run = 'true')\npark = stage(id = 'park', agent = 'workspace_effect', op = 'park', depends_on = [seed])\nworkflow('offloaded-receipt', root = [seed, park], worktree_isolated = True)\n",
            "offloaded-receipt.star", &[],
        ).unwrap();
        let execution = Ulid::new();
        let commit = "a".repeat(40);
        let output = serde_json::json!({"parsed":{"operation":"park","ref_name":"retained","commit_sha":commit},"content":"x".repeat(120_000)});
        let bytes = kata_types::idempotency::canonicalize_args(&output);
        let cas = kata_core::store::CasStore::open(
            directory.path().join("cas.db"),
            directory.path().join("cas"),
        )
        .unwrap();
        let durable = cas.put_durable(&bytes).unwrap();
        let blob = cas.__test_blob_path(&durable.object_id());
        let root = CasRootSpec::for_object(
            &durable,
            CasRootOwner::Execution(execution),
            "operational_output",
        );
        let descriptor = serde_json::json!({"output_ref": {
            "root_id":hex::encode(root.root_id()),
            "address":CasAddress::blake3(durable.object_id()).to_string(),
            "size_bytes":bytes.len(),
        }});
        assert!(descriptor.get("output").is_none());
        let operational = Connection::open(directory.path().join("operational.db")).unwrap();
        operational.execute_batch("ALTER TABLE cas_roots ADD COLUMN root_id BLOB; ALTER TABLE cas_roots ADD COLUMN owner_kind TEXT; ALTER TABLE cas_roots ADD COLUMN owner_execution_id BLOB; ALTER TABLE cas_roots ADD COLUMN purpose TEXT;").unwrap();
        operational
            .execute(
                "INSERT INTO programs VALUES (?,?)",
                rusqlite::params![
                    execution.to_bytes().as_slice(),
                    serde_json::to_vec(&program).unwrap()
                ],
            )
            .unwrap();
        operational.execute("INSERT INTO cas_roots(object_digest,root_id,owner_kind,owner_execution_id,purpose) VALUES (?1,?2,'execution',?3,'operational_output')", rusqlite::params![durable.object_id().0.as_slice(),root.root_id().as_slice(),execution.to_bytes().as_slice()]).unwrap();
        operational
            .execute(
                "INSERT INTO transitions VALUES (?1,'park','attempt','outcome_amended',?2)",
                rusqlite::params![
                    execution.to_bytes().as_slice(),
                    serde_json::to_vec(&descriptor).unwrap()
                ],
            )
            .unwrap();
        let (stored_digest, stored_root): (Vec<u8>, Vec<u8>) = operational
            .query_row("SELECT object_digest,root_id FROM cas_roots", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        // Independent documented CAS preimage, not the producer's address helper.
        let mut address = blake3::Hasher::new();
        address.update(b"kata.cas.object\0");
        address.update(&[1]);
        address.update(&(bytes.len() as u64).to_le_bytes());
        address.update(&bytes);
        assert_eq!(stored_digest.as_slice(), address.finalize().as_bytes());
        assert_eq!(
            hex::encode(stored_root),
            descriptor["output_ref"]["root_id"]
        );
        drop(operational);
        drop(cas);
        let before = file_inventory(directory.path());
        assert_eq!(
            census_source(directory.path(), deadline())
                .unwrap()
                .commits(),
            std::slice::from_ref(&commit)
        );
        // A live READ_ONLY WAL reader may materialize SQLite coordination
        // sidecars. It must see committed WAL, unlike an immutable artifact
        // reader; creating an empty WAL/SHM pair is not an authority write.
        let mut after_source = file_inventory(directory.path());
        for sidecar in ["cas.db-wal", "cas.db-shm"] {
            if !before.contains_key(Path::new(sidecar)) {
                after_source.remove(Path::new(sidecar));
            }
        }
        if let Ok(wal) = std::fs::metadata(directory.path().join("cas.db-wal")) {
            assert_eq!(
                wal.len(),
                0,
                "source census must not append WAL transactions"
            );
        }
        assert_eq!(after_source, before);

        let artifact = tempfile::tempdir().unwrap();
        let stores = artifact.path().join(STORES_SUBDIR);
        let trees = artifact.path().join(TREES_SUBDIR).join("cas");
        std::fs::create_dir(&stores).unwrap();
        for name in ["operational.db", "cas.db"] {
            std::fs::copy(directory.path().join(name), stores.join(name)).unwrap();
        }
        let captured_blob = trees.join(blob.strip_prefix(directory.path().join("cas")).unwrap());
        std::fs::create_dir_all(captured_blob.parent().unwrap()).unwrap();
        std::fs::copy(&blob, &captured_blob).unwrap();
        // Copy only retained blob content: there is no CAS tmp/lock directory
        // in this artifact. A writable CAS open would therefore be observable.
        assert!(!trees.join("tmp").exists());
        let before = file_inventory(artifact.path());
        assert_eq!(
            census(&stores, true, deadline()).unwrap().commits(),
            &[commit]
        );
        assert_eq!(file_inventory(artifact.path()), before);

        let missing = artifact.path().join("detached-blob");
        std::fs::rename(&captured_blob, &missing).unwrap();
        let before_missing = file_inventory(artifact.path());
        assert!(
            census(&stores, true, deadline())
                .unwrap_err()
                .to_string()
                .contains("CAS bytes are missing or invalid")
        );
        assert_eq!(file_inventory(artifact.path()), before_missing);
        std::fs::rename(missing, &captured_blob).unwrap();
        let detached_database = artifact.path().join("detached-cas.db");
        std::fs::rename(stores.join("cas.db"), &detached_database).unwrap();
        let before_database_missing = file_inventory(artifact.path());
        assert!(census(&stores, true, deadline()).is_err());
        assert_eq!(file_inventory(artifact.path()), before_database_missing);
        std::fs::rename(detached_database, stores.join("cas.db")).unwrap();
        let mut corrupt = bytes.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        std::fs::write(&captured_blob, corrupt).unwrap();
        let before_corrupt = file_inventory(artifact.path());
        assert!(
            census(&stores, true, deadline())
                .unwrap_err()
                .to_string()
                .contains("CAS bytes are missing or invalid")
        );
        assert_eq!(file_inventory(artifact.path()), before_corrupt);

        // Root authority is independent of valid content: reassigning the root
        // cannot make the same verified bytes another execution's output.
        let operational = Connection::open(directory.path().join("operational.db")).unwrap();
        operational
            .execute(
                "UPDATE cas_roots SET owner_execution_id=?",
                [Ulid::new().to_bytes().as_slice()],
            )
            .unwrap();
        drop(operational);
        assert!(census_source(directory.path(), deadline()).is_err());
        let operational = Connection::open(directory.path().join("operational.db")).unwrap();
        operational
            .execute(
                "UPDATE cas_roots SET owner_execution_id=?",
                [execution.to_bytes().as_slice()],
            )
            .unwrap();
        operational
            .execute("UPDATE transitions SET stage_id='seed'", [])
            .unwrap();
        drop(operational);
        std::fs::write(blob, b"corrupt ordinary shell output").unwrap();
        assert!(
            census_source(directory.path(), deadline())
                .unwrap_err()
                .to_string()
                .contains("CAS bytes are missing or invalid"),
            "non-effect output references must also be verified"
        );
    }
}
