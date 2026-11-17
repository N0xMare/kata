//! The CAPSULE REUSE DOOR
//! (`OperationalDb::reuse_accepted_capsule_result`), observed through a SECOND raw
//! rusqlite handle.
//!
//! # Invariant
//!
//! Every durable assertion reads `operational.db` through a read-only connection this
//! file opens itself; every "nothing was written" counts rows on it. A reuse is
//! established by the rows it leaves — the adopting occurrence accepted by an
//! `executor = 'main'` attempt, the adopter's own `cas_roots` row, no capsule, no
//! command — never by the verdict the door returns.
//!
//! The SOURCE is built through the production verbs a worker's completion takes
//! (`declare_capsule`, `claim_attempt`, `adopt_and_accept_capsule_completion`), so the
//! door reads a plane a real acceptance wrote.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use kata_core::operational::{
    ArtifactDeclaration, AttemptClaimSpec, AttemptLifecycle, CapsuleDeclaration,
    CapsuleResultAdoption, CapsuleReuse, CapsuleReuseMiss, CapsuleReuseVerdict, CasRootOwner,
    MainSideTransition, OccurrenceBinding,
};
use kata_core::store::cas::CasStore;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork,
    CapsuleProcess, EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId,
    OccurrenceRef, OperationContractId, OperationPath, PlatformId, PreparedActionId,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_types::tree_delta::TreeDelta;
use kata_types::workflow::{ExecutionId, ShellExitPolicy};
use rusqlite::params;
use ulid::Ulid;

const STAGE: &str = "digest";
const ENVIRONMENT_ID: [u8; 32] = [0x5A; 32];
const STAGE_ULID: &str = "01JZZZZZZZZZZZZZZZZZZZZZE1";
const PROGRAM_HASH: [u8; 32] = [0xB1; 32];
const WORK: &[u8] = b"capsule-reuse-fixture-work-tree";
const MEMBER: &[u8] = b"digest of /work\n";

const CHILD_MARKER: &str = "KATA_CAPSULE_REUSE_CRASH_CHILD";
const CHILD_DIR: &str = "KATA_CAPSULE_REUSE_CRASH_DIR";

// ---------------------------------------------------------------------------
// Planes
// ---------------------------------------------------------------------------

struct Planes {
    op_path: std::path::PathBuf,
    db: Arc<OperationalDb>,
    cas: Arc<CasStore>,
}

fn open_planes(dir: &Path) -> Planes {
    let op_path = dir.join("operational.db");
    let cas = Arc::new(CasStore::open(dir.join("cas.db"), dir.join("cas")).unwrap());
    let db = Arc::new(OperationalDb::open_with_cas(&op_path, Arc::clone(&cas)).unwrap());
    Planes { op_path, db, cas }
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn count(path: &Path, sql: &str) -> i64 {
    raw(path).query_row(sql, [], |row| row.get(0)).unwrap()
}

/// `(occurrences, attempts, capsules, commands, cas_roots, transitions)`,
/// raw — the whole footprint a reuse could leave.
fn footprint(path: &Path) -> [i64; 6] {
    [
        "occurrences",
        "attempts",
        "capsules",
        "attempt_commands",
        "cas_roots",
        "transitions",
    ]
    .map(|table| count(path, &format!("SELECT count(*) FROM {table}")))
}

fn program() -> ProgramRecord {
    let program_hash = ContentHash::new(PROGRAM_HASH);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
        })),
    }
}

fn invocation() -> InvocationRecord {
    let invocation_json = canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
    }));
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

fn occurrence_ref(execution_id: Ulid) -> OccurrenceRef {
    OccurrenceRef::new(
        ExecutionId(execution_id),
        ContentHash::new(PROGRAM_HASH),
        OperationContractId(ContentHash::new([0x6C; 32])),
        OperationPath(vec![0]),
    )
}

/// The one capsule body every execution in this file assembles, at its own occurrence,
/// over its own `/work` bytes.
fn capsule(occurrence: OccurrenceId, work: ArtifactId) -> Capsule {
    Capsule::new(
        occurrence,
        PreparedActionId(ContentHash::new([0x02; 32])),
        EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
        PlatformId(ContentHash::new([0x04; 32])),
        vec![GuestMapping {
            artifact: work,
            guest_path: GuestPath::new("/work").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command {
            argv: vec![
                "sh".into(),
                "-c".into(),
                "sha256sum /work/* > /out/r".into(),
            ],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 1 << 20,
            result_entries: 16,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap()
}

/// The AGENT arm of the same capsule (`model_reuse` is capsule reuse of an agent
/// capsule): one `nanocode_openai` turn over the same
/// `/work`. The prompt is a durable CAS blob like the submit door's; its
/// artifact id is deterministic over the bytes, so `target_capsule_agent`
/// re-derives the same id in the armed child.
const AGENT_PROMPT: &[u8] = b"inspect the diff and return a verdict";
const AGENT_RESPONSE: &[u8] = b"{\"verdict\": \"ship\"}\n";
const AGENT_EVIDENCE: &[u8] = b"{\"events\":[],\"events_dropped\":0,\"scratch_commits\":[]}";

fn agent_prompt_id() -> ArtifactId {
    ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(AGENT_PROMPT),
        AGENT_PROMPT.len() as u64,
        ArtifactPrivacy::Private,
    )
    .id()
}

fn agent_capsule(occurrence: OccurrenceId, work: ArtifactId) -> Capsule {
    Capsule::new(
        occurrence,
        PreparedActionId(ContentHash::new([0x02; 32])),
        EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
        PlatformId(ContentHash::new([0x04; 32])),
        vec![GuestMapping {
            artifact: work,
            guest_path: GuestPath::new("/work").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Agent(kata_types::execution_contract::AgentTurnSpec {
            adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
            model: Some("gpt-5-codex".into()),
            reasoning_effort: None,
            output_schema: None,
            prompt: agent_prompt_id(),
            credential: None,
            env: std::collections::BTreeMap::new(),
        }),
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 1 << 20,
            result_entries: 16,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap()
}

/// The `/work` TREE an execution maps: `work` is ONE regular file `w`'s bytes —
/// the member blob, not the manifest — because a `/work` delta's base must
/// decode as a [`TreeManifest`]. Deterministic in `work`, so a second process
/// re-derives the same artifact (`target_capsule` does, unarmed).
fn work_tree(work: &[u8]) -> (ArtifactRef, TreeManifest) {
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("w").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: kata_types::cache::object_id_for_canonical_bytes(work),
            size_bytes: work.len() as u64,
        },
    }])
    .unwrap();
    let bytes = manifest.manifest_bytes().unwrap();
    (
        ArtifactRef::new(
            kata_types::cache::object_id_for_canonical_bytes(&bytes),
            bytes.len() as u64,
            ArtifactPrivacy::Private,
        ),
        manifest,
    )
}

/// Submit and run an execution, and declare its `/work` tree as an artifact it owns.
fn execution_over(planes: &Planes, work: &[u8]) -> (Ulid, ArtifactRef) {
    let execution_id = Ulid::new();
    assert!(matches!(
        planes
            .db
            .submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    planes.db.mark_running(execution_id).unwrap();
    planes.cas.put_durable(work).unwrap();
    let (input_ref, manifest) = work_tree(work);
    let input = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    planes
        .db
        .declare_artifact(
            &ArtifactDeclaration::for_durable_tree(
                &manifest,
                input_ref.privacy(),
                CasRootOwner::Execution(execution_id),
                &input,
            )
            .unwrap(),
        )
        .unwrap();
    (execution_id, input_ref)
}

fn declare_environment(planes: &Planes) {
    if planes.db.environment(ENVIRONMENT_ID).unwrap().is_some() {
        return;
    }
    let manifest = planes
        .cas
        .put_durable(b"capsule-reuse-fixture-environment-manifest")
        .unwrap();
    planes
        .db
        .declare_environment(
            &kata_core::operational::EnvironmentDeclaration::for_staged_root(
                ENVIRONMENT_ID,
                &manifest,
                [0x5C; 32],
                "capsule-reuse-fixture",
                [0x04; 32],
                STAGE_ULID,
            )
            .unwrap(),
        )
        .unwrap();
}

/// The accepted SOURCE: one execution's capsule declared, its attempt claimed, running,
/// and its `/out` tree adopted and accepted through the production door.
#[derive(Clone, Copy)]
struct Source {
    execution_id: Ulid,
    occurrence_id: OccurrenceId,
    result: [u8; 32],
    member: [u8; 32],
}

fn source(planes: &Planes, output_extra: Option<(&str, serde_json::Value)>) -> Source {
    source_with_stderr(planes, b"", output_extra)
}

/// The same source, with its stderr capture carrying real bytes — the
/// re-judgement's miss reason tails THAT blob.
fn source_with_stderr(
    planes: &Planes,
    stderr_bytes: &[u8],
    output_extra: Option<(&str, serde_json::Value)>,
) -> Source {
    declare_environment(planes);
    let (execution_id, work) = execution_over(planes, WORK);
    let occurrence = occurrence_ref(execution_id);
    let capsule = capsule(occurrence.id(), work.id());
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    planes
        .db
        .declare_capsule(
            &CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap(),
        )
        .unwrap();
    let attempt_id = Ulid::new();
    let claimed = planes
        .db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"digest\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(capsule.action()),
                    Some(capsule.id()),
                )
                // The worker-side claim carries the walked /work tree, so the
                // reuse door's binding converges on the stored row rather than
                // being refused as a different work tree under the same
                // coordinates.
                .with_work_tree(work.id().0.0),
            },
        )
        .unwrap();
    planes
        .db
        .record_main_side_transition(
            attempt_id,
            &kata_core::operational::MainSideTransition {
                worker_id: Some("w-1"),
                ..kata_core::operational::MainSideTransition::bare("running")
            },
        )
        .unwrap();
    let member = planes.cas.put_durable(MEMBER).unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("r").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let result = ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    );
    // A capture is a published BLOB the ref names — the same shape the worker
    // publishes off the provider's spool.
    let capture = |bytes: &[u8]| {
        let receipt = planes.cas.put_durable(bytes).unwrap();
        ArtifactRef::new(
            receipt.object_id(),
            receipt.size(),
            ArtifactPrivacy::Private,
        )
    };
    let stdout = capture(b"{\"work_files\": 1}\n");
    let stderr = capture(stderr_bytes);
    let (adopted, _) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                // The stage changed nothing under `/work` — the EMPTY delta over
                // the mapped tree, published the way the worker publishes it.
                work_delta: Some({
                    let delta = TreeDelta::new(work.clone(), Vec::new()).unwrap();
                    let receipt = planes
                        .cas
                        .put_durable(&delta.delta_bytes().unwrap())
                        .unwrap();
                    ArtifactRef::new(
                        receipt.object_id(),
                        receipt.size(),
                        ArtifactPrivacy::Private,
                    )
                }),
                capture_exceeded: false,
                agent: None,
                egress_refusals: vec![],
            },
            |adopted| {
                let mut output = kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    Some(0),
                    &stdout,
                    &stderr,
                    false,
                    Some(fixture_executor_term().digest()),
                );
                if let Some((field, value)) = output_extra {
                    output
                        .as_object_mut()
                        .unwrap()
                        .insert(field.to_owned(), value);
                }
                kata_core::operational::WorkerCompletionInput {
                    execution_id,
                    attempt_id,
                    attempt_ordinal: claimed.attempt_ordinal,
                    lease_epoch: 0,
                    worker_id: "w-1".to_string(),
                    output,
                }
            },
        )
        .unwrap();
    Source {
        execution_id,
        occurrence_id: occurrence.id(),
        result: adopted.artifact_id,
        member: member.object_id().0,
    }
}

/// The bytes the agent source WROTE under `/work` — the delta's one `Write`
/// change's member blob.
const AGENT_WRITTEN: &[u8] = b"the patch the turn left under /work\n";

/// The delta the agent source's completion reported, deterministically
/// re-derivable (`TreeDelta`'s canonical bytes) so the test asserts against the
/// same artifact the builder published.
fn agent_work_delta(work: &ArtifactRef) -> TreeDelta {
    let written = kata_types::cache::object_id_for_canonical_bytes(AGENT_WRITTEN);
    TreeDelta::new(
        work.clone(),
        vec![kata_types::tree_delta::TreeChange {
            path: TreePath::new("written").unwrap(),
            change: kata_types::tree_delta::TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: written,
                    size_bytes: AGENT_WRITTEN.len() as u64,
                },
            },
        }],
    )
    .unwrap()
}

/// The accepted SOURCE, AGENT arm: an agent capsule declared, its attempt
/// claimed, running, and its `/out` tree, captures, RESPONSE blob, session
/// EVIDENCE and a one-file `/work` DELTA adopted through the same production
/// door. The turn's usage is a real metered charge — the adoption cells prove
/// the reuser reports zero, never re-claims the source's spend.
fn source_agent(planes: &Planes) -> Source {
    declare_environment(planes);
    planes.cas.put_durable(AGENT_PROMPT).unwrap();
    planes.cas.put_durable(AGENT_WRITTEN).unwrap();
    let (execution_id, work) = execution_over(planes, WORK);
    let occurrence = occurrence_ref(execution_id);
    let capsule = agent_capsule(occurrence.id(), work.id());
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    planes
        .db
        .declare_capsule(
            &CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap(),
        )
        .unwrap();
    let attempt_id = Ulid::new();
    let claimed = planes
        .db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"digest\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(capsule.action()),
                    Some(capsule.id()),
                )
                .with_work_tree(work.id().0.0),
            },
        )
        .unwrap();
    planes
        .db
        .record_main_side_transition(
            attempt_id,
            &kata_core::operational::MainSideTransition {
                worker_id: Some("w-1"),
                ..kata_core::operational::MainSideTransition::bare("running")
            },
        )
        .unwrap();
    let member = planes.cas.put_durable(MEMBER).unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("r").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let result = ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    );
    let capture = |bytes: &[u8]| {
        let receipt = planes.cas.put_durable(bytes).unwrap();
        ArtifactRef::new(
            receipt.object_id(),
            receipt.size(),
            ArtifactPrivacy::Private,
        )
    };
    let stdout = capture(b"the vendor's protocol stream\n");
    let stderr = capture(b"");
    let response = planes.cas.put_durable(AGENT_RESPONSE).unwrap();
    let evidence = planes.cas.put_durable(AGENT_EVIDENCE).unwrap();
    let delta = agent_work_delta(&work);
    let delta_receipt = planes
        .cas
        .put_durable(&delta.delta_bytes().unwrap())
        .unwrap();
    let (adopted, _) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(ArtifactRef::new(
                    delta_receipt.object_id(),
                    delta_receipt.size(),
                    ArtifactPrivacy::Private,
                )),
                capture_exceeded: false,
                agent: Some(kata_types::agent::AgentTurnReport {
                    response: ArtifactRef::new(
                        response.object_id(),
                        response.size(),
                        ArtifactPrivacy::Private,
                    ),
                    usage: Some(kata_types::metering::StageUsage::metered(
                        &kata_types::cache::TokenUsage {
                            input: 900,
                            output: 40,
                            ..Default::default()
                        },
                        kata_types::metering::MeteredCost::Authoritative { micro_usd: 41 },
                        0,
                    )),
                    adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
                    model_reported: Some("gpt-5-codex".into()),
                    session_evidence: Some(ArtifactRef::new(
                        evidence.object_id(),
                        evidence.size(),
                        ArtifactPrivacy::Private,
                    )),
                    stop_reason: None,
                }),
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id,
                attempt_id,
                attempt_ordinal: claimed.attempt_ordinal,
                lease_epoch: 0,
                worker_id: "w-1".to_string(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    Some(0),
                    &stdout,
                    &stderr,
                    false,
                    Some(fixture_executor_term().digest()),
                ),
            },
        )
        .unwrap();
    Source {
        execution_id,
        occurrence_id: occurrence.id(),
        result: adopted.artifact_id,
        member: member.object_id().0,
    }
}

/// An ADOPTING execution over `work`, and the AGENT capsule it assembled — never
/// declared.
fn target_agent(planes: &Planes, work: &[u8]) -> (OccurrenceRef, Capsule) {
    let (execution_id, work) = execution_over(planes, work);
    let occurrence = occurrence_ref(execution_id);
    let capsule = agent_capsule(occurrence.id(), work.id());
    (occurrence, capsule)
}

/// An ADOPTING execution over `work`, and the capsule it assembled — never declared.
fn target(planes: &Planes, work: &[u8]) -> (OccurrenceRef, Capsule) {
    let (execution_id, work) = execution_over(planes, work);
    let occurrence = occurrence_ref(execution_id);
    let capsule = capsule(occurrence.id(), work.id());
    (occurrence, capsule)
}

fn reuse(
    planes: &Planes,
    attempt_id: Ulid,
    occurrence: &OccurrenceRef,
    capsule: &Capsule,
    source: OccurrenceId,
) -> CapsuleReuseVerdict {
    reuse_under(
        planes,
        attempt_id,
        occurrence,
        capsule,
        source,
        ShellExitPolicy::default(),
    )
}

/// The executor term every source here is stamped with and every reuse is keyed under —
/// a fixed stand-in for the main's.
fn fixture_executor_term() -> kata_types::execution_platform::ExecutorTerm {
    kata_types::execution_platform::ExecutorTerm::derive(&[("operational_capsule_reuse", b"main")])
        .unwrap()
}

fn reuse_under(
    planes: &Planes,
    attempt_id: Ulid,
    occurrence: &OccurrenceRef,
    capsule: &Capsule,
    source: OccurrenceId,
    exit_policy: ShellExitPolicy,
) -> CapsuleReuseVerdict {
    planes
        .db
        .reuse_accepted_capsule_result(&CapsuleReuse {
            attempt_id,
            stage_id: STAGE,
            occurrence,
            capsule,
            source,
            exit_policy,
            executor_term: &fixture_executor_term(),
        })
        .expect("the door answers a verdict")
}

fn expect_miss(verdict: CapsuleReuseVerdict) -> CapsuleReuseMiss {
    match verdict {
        CapsuleReuseVerdict::Miss(miss) => miss,
        CapsuleReuseVerdict::Adopted(adopted) => panic!("expected a miss, adopted {adopted:?}"),
    }
}

/// `(accepted_attempt_id, executor of that attempt, capsule_id, work_tree_artifact_id,
/// prepared_action_id)` of one occurrence, raw.
type OccurrenceFacts = (
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn occurrence_facts(path: &Path, occurrence: OccurrenceId) -> Option<OccurrenceFacts> {
    use rusqlite::OptionalExtension as _;
    raw(path)
        .query_row(
            "SELECT o.accepted_attempt_id, a.executor, o.capsule_id, o.work_tree_artifact_id, \
                    o.prepared_action_id \
               FROM occurrences o LEFT JOIN attempts a ON a.attempt_id = o.accepted_attempt_id \
              WHERE o.occurrence_id = ?1",
            params![occurrence.0.0.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .unwrap()
}

/// Live `artifact_object` roots over `object` owned by `execution`, raw.
fn roots_owned_by(path: &Path, execution: Ulid, object: [u8; 32]) -> i64 {
    raw(path)
        .query_row(
            "SELECT count(*) FROM cas_roots WHERE purpose = 'artifact_object' \
               AND object_digest = ?1 AND owner_execution_id = ?2 AND released_at_ms IS NULL",
            params![object.as_slice(), execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

fn result_object(path: &Path, artifact: [u8; 32]) -> [u8; 32] {
    let object: Vec<u8> = raw(path)
        .query_row(
            "SELECT object_id FROM artifacts WHERE artifact_id = ?1",
            params![artifact.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    object.try_into().unwrap()
}

// ---------------------------------------------------------------------------
// The adopting path
// ---------------------------------------------------------------------------

/// **A SECOND EXECUTION WITH EQUAL INPUTS ADOPTS, IN ONE TRANSACTION, AND RUNS NOTHING.**
///
/// Read raw: the adopting occurrence is accepted by an `executor = 'main'` attempt and
/// bound to the prepared action and the walked `/work` tree with NO capsule; no capsule
/// or command was added; the accepting payload names the SOURCE's result
/// artifact and says where it came from; and the adopter holds its OWN live root over the
/// result, beside the source's.
///
/// **Would red if:** the door accepted without claiming (no main attempt), declared the
/// capsule, dispatched, re-used the source's root instead of adding the adopter's, or
/// adopted a different artifact.
#[test]
fn a_second_execution_with_equal_inputs_adopts_in_one_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source(&planes, None);
    let (occurrence, capsule) = target(&planes, WORK);
    let adopting_execution = occurrence.execution.0;
    let before = footprint(&planes.op_path);

    let attempt_id = Ulid::new();
    let CapsuleReuseVerdict::Adopted(adopted) = reuse(
        &planes,
        attempt_id,
        &occurrence,
        &capsule,
        source.occurrence_id,
    ) else {
        panic!("equal inputs over an accepted, live source adopt");
    };
    assert_eq!(adopted.artifact_id, source.result, "the SOURCE's artifact");
    assert_eq!(adopted.source_execution, source.execution_id);

    let (accepted, executor, capsule_id, work_tree, prepared) =
        occurrence_facts(&planes.op_path, occurrence.id()).expect("the occurrence is minted");
    assert_eq!(accepted, Some(attempt_id.to_bytes().to_vec()));
    assert_eq!(executor.as_deref(), Some("main"), "accepted MAIN-side");
    assert_eq!(capsule_id, None, "no capsule is bound: none ran");
    assert_eq!(
        work_tree,
        Some(capsule.inputs()[0].artifact.0.0.to_vec()),
        "bound to the walked /work tree, so a divergent re-presentation is still refused"
    );
    assert_eq!(prepared, Some(capsule.action().0.0.to_vec()));

    let after = footprint(&planes.op_path);
    assert_eq!(after[0], before[0] + 1, "one occurrence");
    assert_eq!(after[1], before[1] + 1, "one attempt");
    assert_eq!(after[2], before[2], "NO capsule declared");
    assert_eq!(after[3], before[3], "NO command");
    assert_eq!(
        after[4],
        before[4] + 4,
        "four roots — the result's, the /work delta's and the two capture blobs', \
         execution-owned like /out"
    );
    assert_eq!(after[5], before[5] + 2, "the claim and the acceptance");

    let object = result_object(&planes.op_path, source.result);
    assert_eq!(
        roots_owned_by(&planes.op_path, adopting_execution, object),
        1
    );
    assert_eq!(
        roots_owned_by(&planes.op_path, source.execution_id, object),
        1,
        "the source keeps its own"
    );

    let payload: String = raw(&planes.op_path)
        .query_row(
            "SELECT CAST(payload_json AS TEXT) FROM transitions \
              WHERE attempt_id = ?1 AND resulting_state = 'completed'",
            params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let output = &payload["output"];
    assert_eq!(
        output["result_artifact_id"],
        ContentHash::new(source.result).to_string(),
        "the accepted outcome names the adopted artifact"
    );
    assert_eq!(output["content"], "{\"work_files\": 1}\n");
    assert_eq!(
        output["reused_from"]["occurrence"],
        source.occurrence_id.0.to_string()
    );
    assert_eq!(
        output["reused_from"]["execution"],
        source.execution_id.to_string()
    );

    // A re-presentation writes nothing.
    let settled = footprint(&planes.op_path);
    assert!(matches!(
        expect_miss(reuse(
            &planes,
            Ulid::new(),
            &occurrence,
            &capsule,
            source.occurrence_id
        )),
        CapsuleReuseMiss::TargetAccepted { attempt_id: holder } if holder == attempt_id
    ));
    assert_eq!(footprint(&planes.op_path), settled);
}

/// **AN AGENT SOURCE'S HIT ADOPTS THE RESPONSE, THE `/work` DELTA AND ZERO SPEND.**
///
/// `model_reuse` is THIS door over an agent capsule. Read raw —
/// the adopting occurrence is accepted by an `executor = 'main'` attempt with no
/// capsule row, and its accepted payload carries the SOURCE'S response as its
/// `content`, the source's recorded `work_delta_*` triple verbatim, and the
/// `agent` band naming the source's response and session-evidence artifacts. The
/// metered `token_usage` the source's turn billed is NOT carried over: the
/// adopter's envelope holds `StageUsage::unbilled()` — `authoritative` zero, zero
/// counters — because the model call was already charged to the source and a
/// reuse that re-claimed it would bill the provider's work twice. Six roots join
/// the plane (result, delta, two captures, response, evidence), all owned by the
/// ADOPTER's execution.
///
/// **Would red if:** the unbilled rewrite in `reuse_accepted_capsule_result`
/// were dropped — `cost_micro_usd` would adopt the source's `41`; or the door
/// skipped the agent band — `agent` would be `null`; or the delta were not
/// adopted — `work_delta_artifact_id` would name another artifact or `null`.
#[test]
fn an_agent_source_s_hit_adopts_the_response_the_delta_and_zero_spend() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source_agent(&planes);
    let (occurrence, capsule) = target_agent(&planes, WORK);
    let before = footprint(&planes.op_path);

    let attempt_id = Ulid::new();
    let CapsuleReuseVerdict::Adopted(adopted) = reuse(
        &planes,
        attempt_id,
        &occurrence,
        &capsule,
        source.occurrence_id,
    ) else {
        panic!("equal agent capsules over an accepted source adopt");
    };
    assert_eq!(adopted.artifact_id, source.result, "the SOURCE's artifact");

    let (accepted, executor, capsule_id, bound_work, prepared) =
        occurrence_facts(&planes.op_path, occurrence.id()).expect("the occurrence is minted");
    assert_eq!(accepted, Some(attempt_id.to_bytes().to_vec()));
    assert_eq!(executor.as_deref(), Some("main"), "accepted MAIN-side");
    assert_eq!(capsule_id, None, "no capsule is bound: none ran");
    assert_eq!(
        bound_work,
        Some(capsule.inputs()[0].artifact.0.0.to_vec()),
        "bound to the walked /work tree"
    );
    assert_eq!(prepared, Some(capsule.action().0.0.to_vec()));

    let after = footprint(&planes.op_path);
    assert_eq!(after[0], before[0] + 1, "one occurrence");
    assert_eq!(after[1], before[1] + 1, "one attempt");
    assert_eq!(after[2], before[2], "NO capsule declared");
    assert_eq!(after[3], before[3], "NO command");
    assert_eq!(
        after[4],
        before[4] + 6,
        "six roots — the result's, the /work delta's, the two captures', the \
         response's and the session evidence's"
    );
    assert_eq!(after[5], before[5] + 2, "the claim and the acceptance");

    // The ids the payload must name — every one re-derived from fixture bytes,
    // never read back through the door.
    let (work_ref, _) = work_tree(WORK);
    let delta_bytes = agent_work_delta(&work_ref).delta_bytes().unwrap();
    let delta_ref = ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(&delta_bytes),
        delta_bytes.len() as u64,
        ArtifactPrivacy::Private,
    );
    let response_ref = ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(AGENT_RESPONSE),
        AGENT_RESPONSE.len() as u64,
        ArtifactPrivacy::Private,
    );

    let payload: String = raw(&planes.op_path)
        .query_row(
            "SELECT CAST(payload_json AS TEXT) FROM transitions \
              WHERE attempt_id = ?1 AND resulting_state = 'completed'",
            params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let output = &payload["output"];
    assert_eq!(
        output["result_artifact_id"],
        ContentHash::new(source.result).to_string(),
        "the accepted outcome names the adopted artifact"
    );
    assert_eq!(
        output["content"],
        std::str::from_utf8(AGENT_RESPONSE).unwrap(),
        "the stage envelope's content is the source turn's response"
    );
    assert_eq!(
        output["work_delta_artifact_id"],
        delta_ref.id().0.to_string(),
        "the recorded /work delta is adopted, verbatim"
    );
    assert_eq!(
        output["work_delta_entries"], 1,
        "the source wrote one file under /work"
    );
    assert_eq!(
        output["agent"]["adapter"], "nanocode_openai",
        "the agent band survives — the turn's own record"
    );
    assert_eq!(output["agent"]["model_reported"], "gpt-5-codex");
    assert_eq!(
        output["agent"]["response_artifact_id"],
        response_ref.id().0.to_string()
    );
    let usage = &output["token_usage"];
    assert_eq!(
        usage["cost_micro_usd"], 0,
        "the adopter reports ZERO spend — the source's turn was already billed"
    );
    assert_eq!(usage["input"], 0);
    assert_eq!(usage["output"], 0);
    assert_eq!(
        usage["cost"]["quality"], "authoritative",
        "zero is a FACT here, not an estimate"
    );
    assert_eq!(
        output["reused_from"]["occurrence"],
        source.occurrence_id.0.to_string()
    );
    assert_eq!(
        output["reused_from"]["execution"],
        source.execution_id.to_string()
    );
}

/// **ONE CHANGED `/work` BYTE MISSES**, writing nothing — the key folds the walked tree.
///
/// **Would red if:** the door's re-check (`Capsule::has_reuse_inputs_of`) omitted the
/// mappings, or answered equal regardless: the adopter would be handed a result
/// computed over other bytes.
#[test]
fn one_changed_work_byte_misses() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source(&planes, None);
    let mut changed = WORK.to_vec();
    changed[0] ^= 1;
    let (occurrence, capsule) = target(&planes, &changed);
    let before = footprint(&planes.op_path);
    let miss = expect_miss(reuse(
        &planes,
        Ulid::new(),
        &occurrence,
        &capsule,
        source.occurrence_id,
    ));
    assert_eq!(miss, CapsuleReuseMiss::SourceKeyDiverges);
    assert!(miss.hint_is_stale());
    assert_eq!(footprint(&planes.op_path), before);
    assert!(occurrence_facts(&planes.op_path, occurrence.id()).is_none());
}

/// **AN ABSENT SOURCE MEMBER IS A MISS.** The result's manifest is present, one member's
/// `cas_objects` row is gone (kata deletes no CAS object, so this is a store damaged or
/// edited outside kata) — the adoption's member presence check refuses it.
///
/// **Would red if:** `prepare_adoption` skipped `refuse_absent_or_mismeasured_member`:
/// the adopter would root a tree whose bytes are not there.
#[test]
fn an_absent_source_member_is_a_miss() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source(&planes, None);
    // THE DAMAGE: the member's `cas_objects` row gone.
    rusqlite::Connection::open(dir.path().join("cas.db"))
        .unwrap()
        .execute(
            "DELETE FROM cas_objects WHERE object_id = ?1",
            params![source.member.as_slice()],
        )
        .unwrap();
    let (occurrence, capsule) = target(&planes, WORK);
    let before = footprint(&planes.op_path);
    let miss = expect_miss(reuse(
        &planes,
        Ulid::new(),
        &occurrence,
        &capsule,
        source.occurrence_id,
    ));
    let CapsuleReuseMiss::SourceResultUnverifiable { reason } = &miss else {
        panic!("an absent member is unverifiable: {miss:?}");
    };
    assert!(reason.contains("tree member absent"), "{reason}");
    assert_eq!(footprint(&planes.op_path), before);
}

/// **A REUSE AT AN OCCURRENCE WITH A LIVE ATTEMPT IS REFUSED** — a miss, nothing
/// written, the live attempt the only one there.
///
/// **Would red if:** the door dropped its live-attempt check: a main attempt would be
/// claimed and accepted beside a live worker attempt — two attempts at one occurrence.
#[test]
fn a_reuse_at_an_occurrence_with_a_live_attempt_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source(&planes, None);
    let (occurrence, capsule) = target(&planes, WORK);
    // A LIVE worker attempt at the adopting occurrence, as an earlier submit's
    // authorization leaves it.
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    planes
        .db
        .declare_capsule(
            &CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap(),
        )
        .unwrap();
    let live = Ulid::new();
    planes
        .db
        .claim_attempt(
            occurrence.execution.0,
            live,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"digest\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                // Bound as `authorize_attempt` binds it: the capsule AND the walked tree.
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(capsule.action()),
                    Some(capsule.id()),
                )
                .with_work_tree(capsule.inputs()[0].artifact.0.0),
            },
        )
        .unwrap();
    let before = footprint(&planes.op_path);
    let miss = expect_miss(reuse(
        &planes,
        Ulid::new(),
        &occurrence,
        &capsule,
        source.occurrence_id,
    ));
    assert_eq!(miss, CapsuleReuseMiss::TargetLive { attempt_id: live });
    assert!(!miss.hint_is_stale(), "the source is fine; the hint stays");
    assert_eq!(footprint(&planes.op_path), before);
    assert_eq!(
        count(
            &planes.op_path,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0
    );
}

/// **A SOURCE OUTCOME WITH AN UNKNOWN FIELD IS A MISS** — the forward guard: an outcome
/// carrying something this build does not adopt (a later `/work` diff) is not reused.
///
/// **Would red if:** `AcceptedCapsuleOutcome` decoded leniently: the adopter would take
/// the half of the outcome this build understands.
#[test]
fn a_source_outcome_with_an_unknown_field_is_a_miss() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source(
        &planes,
        Some(("work_diff", serde_json::json!({"changed": ["a"]}))),
    );
    let (occurrence, capsule) = target(&planes, WORK);
    let before = footprint(&planes.op_path);
    let miss = expect_miss(reuse(
        &planes,
        Ulid::new(),
        &occurrence,
        &capsule,
        source.occurrence_id,
    ));
    let CapsuleReuseMiss::SourceOutcomeUndecodable { reason } = &miss else {
        panic!("an unknown outcome field is a miss: {miss:?}");
    };
    assert!(reason.contains("work_diff"), "{reason}");
    assert_eq!(footprint(&planes.op_path), before);
}

/// **A SOURCE THAT RAN UNDER ANOTHER EXECUTOR TERM IS A STALE MISS THAT WRITES
/// NOTHING** — two sources equal in every reuse input, one stamped at acceptance
/// with a standalone worker's term other than the key's and one stamped `null` (a
/// registration that stated none): the door misses `SourceExecutorTermDiffers` naming
/// what each ran under, the hint is stale, and the raw footprint does not move. The
/// same source stamped with the key's own term adopts (`a_second_execution_with_equal_
/// inputs_adopts_in_one_transaction`).
///
/// **Watched red:** with the executor-term comparison removed from
/// `OperationalDb::reusable_source`, both sources ADOPT.
#[test]
fn a_source_that_ran_under_another_executor_term_is_a_stale_miss() {
    let skewed = kata_types::execution_platform::ExecutorTerm::derive(&[(
        "operational_capsule_reuse",
        b"a worker of another build",
    )])
    .unwrap();
    assert_ne!(skewed, fixture_executor_term());
    for (stamped, expected) in [
        (
            serde_json::json!(skewed.digest().to_string()),
            Some(*skewed.digest()),
        ),
        (serde_json::Value::Null, None),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let planes = open_planes(dir.path());
        let source = source(&planes, Some(("executor_term", stamped)));
        let (occurrence, capsule) = target(&planes, WORK);
        let before = footprint(&planes.op_path);
        let miss = expect_miss(reuse(
            &planes,
            Ulid::new(),
            &occurrence,
            &capsule,
            source.occurrence_id,
        ));
        assert_eq!(
            miss,
            CapsuleReuseMiss::SourceExecutorTermDiffers {
                ran_under: expected
            }
        );
        assert!(miss.hint_is_stale(), "the source's fault: forget the hint");
        assert_eq!(footprint(&planes.op_path), before, "nothing is written");
    }
}

/// **A SOURCE WHOSE RECORDED `/work` DELTA DOES NOT DERIVE FROM ITS ROW IS A MISS** —
/// the outcome names the delta artifact by id AND records its object and size; a row
/// that derives the id but not the recorded object (or size) is an outcome that does
/// not describe itself, so it misses `SourceOutcomeUndecodable` and writes nothing.
///
/// **Would red if:** `delta_reference` required ALL three to disagree before refusing
/// (the nightly mutation sample's `||` → `&&` survivor) — the adopter would take a
/// delta whose recorded bytes are not the ones it names.
#[test]
fn a_source_whose_recorded_delta_does_not_derive_from_its_row_is_a_miss() {
    for (field, wrong) in [
        ("work_delta_object_id", serde_json::json!("ab".repeat(32))),
        ("work_delta_size_bytes", serde_json::json!(1_u64 << 40)),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let planes = open_planes(dir.path());
        let source = source(&planes, Some((field, wrong)));
        let (occurrence, capsule) = target(&planes, WORK);
        let before = footprint(&planes.op_path);
        let miss = expect_miss(reuse(
            &planes,
            Ulid::new(),
            &occurrence,
            &capsule,
            source.occurrence_id,
        ));
        let CapsuleReuseMiss::SourceOutcomeUndecodable { reason } = &miss else {
            panic!("{field}: a delta the row does not derive is a miss: {miss:?}");
        };
        assert!(reason.contains("does not derive"), "{field}: {reason}");
        assert_eq!(
            footprint(&planes.op_path),
            before,
            "{field}: nothing written"
        );
    }
}

/// A source accepted BEFORE the main judged capsule completions, whose provider reported
/// its capture TRUNCATED, is a stale miss that writes nothing — under either exit policy,
/// as the reactor fails a fresh truncated completion under either. The source is written
/// through the production acceptance door, which does not judge (the reactor does), so it
/// is exactly the row a pre-judgement main left in a schema-24 data directory.
///
/// **Watched red:** with `reusable_source`'s re-judgement removed, the adopter ADOPTS the
/// truncated source.
#[test]
fn a_pre_judgement_source_with_a_truncated_capture_is_a_stale_miss() {
    for policy in [ShellExitPolicy::ZeroSuccess, ShellExitPolicy::Content] {
        let dir = tempfile::tempdir().unwrap();
        let planes = open_planes(dir.path());
        let source = source(&planes, Some(("capture_exceeded", serde_json::json!(true))));
        let (occurrence, capsule) = target(&planes, WORK);
        let before = footprint(&planes.op_path);
        let miss = expect_miss(reuse_under(
            &planes,
            Ulid::new(),
            &occurrence,
            &capsule,
            source.occurrence_id,
            policy,
        ));
        let CapsuleReuseMiss::SourceOutcomeFailsStage { reason } = &miss else {
            panic!("{policy:?}: a truncated source is not reused: {miss:?}");
        };
        assert!(
            reason.contains(kata_types::workflow::SHELL_CAPTURE_TRUNCATED_MARKER),
            "{policy:?}: {reason}"
        );
        assert!(miss.hint_is_stale(), "{policy:?}");
        assert_eq!(footprint(&planes.op_path), before, "{policy:?}");
    }
}

/// A pre-judgement source that EXITED 3 is a stale miss under the default `zero_success`
/// policy, with the `ShellNonzeroExit` reason, and writes nothing; under a declared
/// `content` policy the same source is ADOPTED — the exit code is content there, as on a
/// fresh completion.
///
/// **Watched red:** with `reusable_source`'s re-judgement removed, the `zero_success`
/// adopter ADOPTS the source that exited 3.
#[test]
fn a_pre_judgement_source_that_exited_nonzero_is_judged_by_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source(&planes, Some(("exit_code", serde_json::json!(3))));
    let (occurrence, capsule) = target(&planes, WORK);
    let before = footprint(&planes.op_path);
    let miss = expect_miss(reuse_under(
        &planes,
        Ulid::new(),
        &occurrence,
        &capsule,
        source.occurrence_id,
        ShellExitPolicy::ZeroSuccess,
    ));
    let CapsuleReuseMiss::SourceOutcomeFailsStage { reason } = &miss else {
        panic!("a source that exited 3 is not reused under zero_success: {miss:?}");
    };
    assert!(
        reason.contains(kata_types::workflow::SHELL_NONZERO_EXIT_ERROR_PREFIX)
            && reason.contains("exit_code=3"),
        "{reason}"
    );
    assert_eq!(footprint(&planes.op_path), before);

    let verdict = reuse_under(
        &planes,
        Ulid::new(),
        &occurrence,
        &capsule,
        source.occurrence_id,
        ShellExitPolicy::Content,
    );
    assert!(
        matches!(verdict, CapsuleReuseVerdict::Adopted(_)),
        "under `content` the exit code is content: {verdict:?}"
    );
    let accepted: i64 = count(
        &planes.op_path,
        "SELECT count(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL",
    );
    assert_eq!(accepted, 2, "the source and the adopter are accepted");
}

/// A source that is not accepted — here, an occurrence with no row at all — is a miss
/// that forgets the hint.
#[test]
fn an_unaccepted_source_is_a_stale_hint() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    declare_environment(&planes);
    let (occurrence, capsule) = target(&planes, WORK);
    let before = footprint(&planes.op_path);
    let miss = expect_miss(reuse(
        &planes,
        Ulid::new(),
        &occurrence,
        &capsule,
        OccurrenceId(ContentHash::new([0x77; 32])),
    ));
    assert_eq!(miss, CapsuleReuseMiss::SourceNotAccepted);
    assert!(miss.hint_is_stale());
    assert_eq!(footprint(&planes.op_path), before);
}

// ---------------------------------------------------------------------------
// K3 / K4 on the reuse transaction
// ---------------------------------------------------------------------------

/// The facts the armed child needs to re-present the prepared reuse.
fn write_fixture(dir: &Path, source: Source, occurrence: &OccurrenceRef, attempt: Ulid) {
    std::fs::write(
        dir.join("reuse"),
        format!(
            "{} {} {}",
            source.occurrence_id.0, occurrence.execution.0, attempt
        ),
    )
    .unwrap();
}

fn read_fixture(dir: &Path) -> (OccurrenceId, Ulid, Ulid) {
    let recorded = std::fs::read_to_string(dir.join("reuse")).unwrap();
    let fields: Vec<&str> = recorded.split(' ').collect();
    (
        OccurrenceId(fields[0].parse().unwrap()),
        fields[1].parse().unwrap(),
        fields[2].parse().unwrap(),
    )
}

/// The adopting capsule, re-derived from the target execution's `/work` artifact.
fn target_capsule(adopter: Ulid) -> (OccurrenceRef, Capsule) {
    let occurrence = occurrence_ref(adopter);
    let (work, _) = work_tree(WORK);
    let capsule = capsule(occurrence.id(), work.id());
    (occurrence, capsule)
}

/// The adopting AGENT capsule, re-derived the same way — every field in
/// `agent_capsule` is a fixture constant or derives from `work`, so the armed
/// child rebuilds it byte-for-byte.
fn target_capsule_agent(adopter: Ulid) -> (OccurrenceRef, Capsule) {
    let occurrence = occurrence_ref(adopter);
    let (work, _) = work_tree(WORK);
    let capsule = agent_capsule(occurrence.id(), work.id());
    (occurrence, capsule)
}

const CHILD_CAPSULE_ARM: &str = "KATA_CAPSULE_REUSE_CRASH_ARM";

/// The armed child: re-open the prepared planes and run ONLY the reuse door.
fn crash_child(dir: &Path) {
    let planes = open_planes(dir);
    let (source, adopter, attempt) = read_fixture(dir);
    let (occurrence, capsule) = match std::env::var(CHILD_CAPSULE_ARM).as_deref() {
        Ok("agent") => target_capsule_agent(adopter),
        _ => target_capsule(adopter),
    };
    let verdict = reuse(&planes, attempt, &occurrence, &capsule, source);
    panic!("the armed fault point was never reached; the door answered {verdict:?}");
}

/// Prepare the source and the adopting execution UNARMED, then run the door in a child
/// armed at `boundary`, and hand back what the parent needs to read the plane.
fn crash_at(
    cell: &str,
    boundary: &str,
) -> (tempfile::TempDir, Source, OccurrenceRef, Capsule, Ulid) {
    crash_at_with(cell, boundary, false)
}

/// `crash_at` over the capsule arm the cell names: `agent` builds the source and
/// the adopting capsule on [`source_agent`]/[`agent_capsule`] instead.
fn crash_at_with(
    cell: &str,
    boundary: &str,
    agent: bool,
) -> (tempfile::TempDir, Source, OccurrenceRef, Capsule, Ulid) {
    let dir = tempfile::tempdir().unwrap();
    let (source, occurrence, capsule, attempt) = {
        let planes = open_planes(dir.path());
        let (source, occurrence, capsule) = if agent {
            let source = source_agent(&planes);
            let (occurrence, capsule) = target_agent(&planes, WORK);
            (source, occurrence, capsule)
        } else {
            let source = source(&planes, None);
            let (occurrence, capsule) = target(&planes, WORK);
            (source, occurrence, capsule)
        };
        let attempt = Ulid::new();
        let rederived = if agent {
            target_capsule_agent(occurrence.execution.0)
        } else {
            target_capsule(occurrence.execution.0)
        };
        assert_eq!(
            (occurrence.clone(), capsule.clone()),
            rederived,
            "the child re-derives the same adopting capsule"
        );
        write_fixture(dir.path(), source, &occurrence, attempt);
        (source, occurrence, capsule, attempt)
    };
    let output = Command::new(std::env::current_exe().unwrap())
        .arg(cell)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir.path())
        .env(CHILD_CAPSULE_ARM, if agent { "agent" } else { "command" })
        .env("KATA_FAULT_INJECT", format!("operational.{boundary}"))
        .output()
        .expect("spawn the armed child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the armed child must abort:\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(&format!("crash point reached: operational.{boundary}")),
        "the child must die IN the window:\nstderr:\n{stderr}"
    );
    (dir, source, occurrence, capsule, attempt)
}

/// **K3 — a crash BEFORE the reuse transaction commits leaves NOTHING of it**, and the
/// re-presented reuse then adopts exactly once.
///
/// **Would red if:** any of the reuse's writes (the occurrence, the claim, the adopter's
/// root, the acceptance) committed outside the one transaction.
#[test]
fn a_crash_before_the_reuse_commit_leaves_nothing_and_a_retry_adopts_once() {
    const CELL: &str = "a_crash_before_the_reuse_commit_leaves_nothing_and_a_retry_adopts_once";
    if std::env::var(CHILD_MARKER).is_ok() {
        crash_child(Path::new(&std::env::var(CHILD_DIR).unwrap()));
        return;
    }
    let (dir, source, occurrence, capsule, attempt) = crash_at(CELL, "before_txn_commit");
    let op_path = dir.path().join("operational.db");
    let adopter = occurrence.execution.0;
    let object = result_object(&op_path, source.result);
    assert!(
        occurrence_facts(&op_path, occurrence.id()).is_none(),
        "no occurrence"
    );
    assert_eq!(
        count(
            &op_path,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0,
        "no main attempt"
    );
    assert_eq!(
        roots_owned_by(&op_path, adopter, object),
        0,
        "no adopter root"
    );

    let planes = open_planes(dir.path());
    assert!(matches!(
        reuse(
            &planes,
            attempt,
            &occurrence,
            &capsule,
            source.occurrence_id
        ),
        CapsuleReuseVerdict::Adopted(_)
    ));
    let (accepted, executor, ..) = occurrence_facts(&op_path, occurrence.id()).unwrap();
    assert_eq!(accepted, Some(attempt.to_bytes().to_vec()));
    assert_eq!(executor.as_deref(), Some("main"));
    assert_eq!(roots_owned_by(&op_path, adopter, object), 1);
}

/// **K4 — a crash AFTER the reuse transaction commits leaves it WHOLE**: the adopting
/// occurrence accepted by the main attempt, the adopter's root, one accepting
/// transition; the re-presentation converges and writes nothing.
///
/// **Would red if:** the acceptance and the root were split across transactions (one
/// would be missing here), or a re-presentation did not recognise its own acceptance.
#[test]
fn a_crash_after_the_reuse_commit_leaves_it_whole_and_a_retry_writes_nothing() {
    const CELL: &str = "a_crash_after_the_reuse_commit_leaves_it_whole_and_a_retry_writes_nothing";
    if std::env::var(CHILD_MARKER).is_ok() {
        crash_child(Path::new(&std::env::var(CHILD_DIR).unwrap()));
        return;
    }
    let (dir, source, occurrence, capsule, attempt) = crash_at(CELL, "after_txn_commit");
    let op_path = dir.path().join("operational.db");
    let adopter = occurrence.execution.0;
    let object = result_object(&op_path, source.result);
    let (accepted, executor, ..) = occurrence_facts(&op_path, occurrence.id()).unwrap();
    assert_eq!(accepted, Some(attempt.to_bytes().to_vec()));
    assert_eq!(executor.as_deref(), Some("main"));
    assert_eq!(roots_owned_by(&op_path, adopter, object), 1);
    let completed = |path: &Path| {
        raw(path)
            .query_row(
                "SELECT count(*) FROM transitions WHERE attempt_id = ?1 \
                   AND resulting_state = 'completed'",
                params![attempt.to_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    assert_eq!(completed(&op_path), 1);

    let planes = open_planes(dir.path());
    let before = footprint(&op_path);
    assert_eq!(
        expect_miss(reuse(
            &planes,
            Ulid::new(),
            &occurrence,
            &capsule,
            source.occurrence_id
        )),
        CapsuleReuseMiss::TargetAccepted {
            attempt_id: attempt
        }
    );
    assert_eq!(footprint(&op_path), before);
    assert_eq!(completed(&op_path), 1);
}

/// **K3, AGENT arm** — the `model_reuse` crash window is the same transaction:
/// a crash between the adoption's writes and the commit leaves NOTHING durable,
/// and the retried reuse adopts the agent source exactly once.
///
/// **Would red if:** the agent outcome's extra roots (response, evidence, the
/// delta) sat in a second transaction — one half would survive the crash.
#[test]
fn a_crash_before_an_agent_reuse_commit_leaves_nothing_and_a_retry_adopts_once() {
    const CELL: &str =
        "a_crash_before_an_agent_reuse_commit_leaves_nothing_and_a_retry_adopts_once";
    if std::env::var(CHILD_MARKER).is_ok() {
        crash_child(Path::new(&std::env::var(CHILD_DIR).unwrap()));
        return;
    }
    let (dir, source, occurrence, capsule, attempt) =
        crash_at_with(CELL, "before_txn_commit", true);
    let op_path = dir.path().join("operational.db");
    let adopter = occurrence.execution.0;
    let object = result_object(&op_path, source.result);
    assert!(
        occurrence_facts(&op_path, occurrence.id()).is_none(),
        "no occurrence"
    );
    assert_eq!(
        count(
            &op_path,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0,
        "no main attempt"
    );
    assert_eq!(
        roots_owned_by(&op_path, adopter, object),
        0,
        "no adopter root"
    );

    let planes = open_planes(dir.path());
    assert!(matches!(
        reuse(
            &planes,
            attempt,
            &occurrence,
            &capsule,
            source.occurrence_id
        ),
        CapsuleReuseVerdict::Adopted(_)
    ));
    let (accepted, executor, ..) = occurrence_facts(&op_path, occurrence.id()).unwrap();
    assert_eq!(accepted, Some(attempt.to_bytes().to_vec()));
    assert_eq!(executor.as_deref(), Some("main"));
    assert_eq!(roots_owned_by(&op_path, adopter, object), 1);
}

/// **The executor column is the whole answer** — `main_attempts_at_occurrence` must
/// return the MAIN attempts at an occurrence and no other. The capsule-reuse door is the
/// ONE production path that binds a main attempt to an occurrence a worker attempt
/// already sits on (a failed or cancelled worker generation may precede the adoption),
/// so this occurrence is built exactly that way: a worker generation claimed and then
/// failed terminally, then `reuse_accepted_capsule_result` claiming its `executor =
/// 'main'` row at the same `occurrence_id`. Every durable fact is read through a second
/// raw handle; the function's return is compared to BOTH the raw executor columns and
/// the ids the doors handed back.
///
/// **Would red if:** the filter inverted — `executor != 'main'` would return the failed
/// worker attempt and drop the main one (the mutation cargo-mutants planted, and the
/// reason this cell exists); or the filter dropped to nothing — the main attempt would
/// be missed.
#[test]
fn a_mixed_executor_occurrence_names_only_its_main_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source(&planes, None);

    // The ADOPTING execution's occurrence, first held by a WORKER generation that
    // claimed it and then failed — terminal, never accepted, exactly the prior state
    // the reuse door tolerates.
    let (execution_id, work) = execution_over(&planes, WORK);
    let occurrence = occurrence_ref(execution_id);
    let capsule = capsule(occurrence.id(), work.id());
    let capsule_bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = planes.cas.put_durable(&capsule_bytes).unwrap();
    planes
        .db
        .declare_capsule(
            &CapsuleDeclaration::for_durable_object(&capsule, &capsule_bytes, &durable).unwrap(),
        )
        .unwrap();
    let worker_attempt = Ulid::new();
    planes
        .db
        .claim_attempt(
            execution_id,
            worker_attempt,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"digest\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(capsule.action()),
                    Some(capsule.id()),
                )
                // The worker-side claim carries the walked /work tree, so the
                // reuse door's binding converges on the stored row rather than
                // being refused as a different work tree under the same
                // coordinates.
                .with_work_tree(work.id().0.0),
            },
        )
        .unwrap();
    planes
        .db
        .record_main_side_transition(
            worker_attempt,
            &MainSideTransition {
                reason: Some("the worker generation failed before the reuse was judged"),
                terminal_charge: Some(&kata_types::metering::TerminalCharge {
                    token_usage: Some(kata_types::metering::StageUsage::unbilled()),
                    child_invocation_summary: None,
                }),
                ..MainSideTransition::bare("failed")
            },
        )
        .unwrap();

    // The main-resolved adoption claims `executor = 'main'` at the SAME occurrence.
    let main_attempt = Ulid::new();
    assert!(matches!(
        reuse(
            &planes,
            main_attempt,
            &occurrence,
            &capsule,
            source.occurrence_id
        ),
        CapsuleReuseVerdict::Adopted(_)
    ));

    // The oracle: the raw `attempts` rows at the occurrence — two rows, one per
    // executor, neither id invented by the function under test.
    let raw_rows: Vec<(String, Vec<u8>)> = {
        let conn = raw(&planes.op_path);
        let mut statement = conn
            .prepare(
                "SELECT executor, attempt_id FROM attempts WHERE occurrence_id = ?1                    ORDER BY executor",
            )
            .unwrap();
        statement
            .query_map(params![occurrence.id().0.0.as_slice()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(
        raw_rows,
        vec![
            ("main".to_string(), main_attempt.to_bytes().to_vec()),
            ("worker".to_string(), worker_attempt.to_bytes().to_vec()),
        ],
        "the fixture owes the mixed state: one terminal worker generation and the adopting main attempt, bound to one occurrence"
    );

    let mains = planes
        .db
        .main_attempts_at_occurrence(occurrence.id().0.0)
        .unwrap();
    assert_eq!(
        mains,
        vec![(main_attempt, AttemptLifecycle::Completed)],
        "only the executor = 'main' row answers — the failed worker generation beside it is another executor's history, not this door's"
    );

    // And a sibling occurrence holding ONLY a worker attempt answers EMPTY — the
    // filter is not "every attempt at the occurrence", it is the main ones.
    let (other_execution, _) = execution_over(&planes, WORK);
    let other = occurrence_ref(other_execution);
    planes
        .db
        .claim_attempt(
            other_execution,
            Ulid::new(),
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"digest\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(other.clone(), None, None),
            },
        )
        .unwrap();
    assert_eq!(
        planes
            .db
            .main_attempts_at_occurrence(other.id().0.0)
            .unwrap(),
        Vec::new()
    );
}

/// A stale source's miss reason carries the stderr TAIL the outcome's stderr
/// artifact holds — `capture_tail_in`'s whole observable: with the artifact
/// folded to `Some(String::new())` the tail the failure reason names is
/// empty, and the reason loses the source's own failure text.
#[test]
fn a_stale_source_s_miss_reason_carries_the_stderr_tail() {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    let source = source_with_stderr(
        &planes,
        b"the real failure text lives here",
        Some(("exit_code", serde_json::json!(1))),
    );
    let (occurrence, capsule) = target(&planes, WORK);
    let miss = expect_miss(reuse_under(
        &planes,
        Ulid::new(),
        &occurrence,
        &capsule,
        source.occurrence_id,
        ShellExitPolicy::ZeroSuccess,
    ));
    let CapsuleReuseMiss::SourceOutcomeFailsStage { reason } = &miss else {
        panic!("a source that exited 1 is not reused under zero_success: {miss:?}");
    };
    assert!(
        reason.contains("the real failure text lives here"),
        "the miss reason tails the stored stderr artifact: {reason}"
    );
}
