//! ADOPTING one capsule attempt's RESULT TREE, observed
//! through a SECOND raw rusqlite handle and through the CAS's own files.
//!
//! # Invariant
//!
//! Every durable assertion here reads `operational.db` through a connection this file
//! opens itself, and every "nothing was written" assertion counts rows on that handle
//! rather than asking `OperationalDb` whether `OperationalDb` declined to write. Asking
//! the subject whether the subject worked is the shape that has let every composition
//! defect in this tree ship green.
//!
//! # What each cell is the witness for
//!
//! The property is *"the bound is enforced BEFORE anything is declared"*, and the only
//! way to see the difference between that and *"the bound is enforced and then the row
//! is removed"* is to observe the plane after a refusal. So the two bound cells assert
//! `count(*) FROM artifacts = 0` off the raw handle, which a declare-then-rollback
//! implementation would also satisfy — and are therefore paired with a NON-VACUITY twin
//! that adopts the same tree inside the bound and requires the row, so a cell that
//! refused everything could not pass.
//!
//! # THE CRASH CELL
//!
//! The production door declares a result in the transaction that accepts it, so there is
//! no registered boundary between the two. The crash cell here arms
//! `operational.after_accept_event` — whose home is
//! `operational_crash_matrix.rs` — through the CAPSULE door, and redelivers.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use kata_core::operational::{
    ArtifactDeclaration, AttemptClaimSpec, CapsuleDeclaration, CapsuleResultAdoption, CasRootOwner,
    OccurrenceBinding,
};
use kata_core::store::cas::CasStore;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork,
    CapsuleProcess, EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceRef,
    OperationContractId, OperationPath, PlatformId, PreparedActionId,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::{ContentHash, FixedBytes};
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};
use kata_types::workflow::ExecutionId;
use rusqlite::params;
use ulid::Ulid;

const STAGE: &str = "probe";
/// The declared environment every fixture capsule binds, and the ULID-shaped stage id
/// `EnvironmentDeclaration` requires.
const ENVIRONMENT_ID: [u8; 32] = [0x5A; 32];
const STAGE_ULID: &str = "01JZZZZZZZZZZZZZZZZZZZZZE1";
const PROGRAM_HASH: [u8; 32] = [0xB1; 32];

/// The RESULT BOUNDS every capsule in this file promises: small enough that a
/// three-member tree is over the byte bound and a three-member tree is over the entry
/// bound, each on its own.
///
/// Deliberately tiny rather than production's 64 MiB / 10 000: the property is that the
/// CAPSULE's promise is what a result is held to, and a cell that had to write 64 MiB to
/// trip it would be a slow test proving the same thing.
const BOUND_BYTES: u64 = 32;
const BOUND_ENTRIES: u32 = 2;

/// The environment variable the crash cell's child reads, and the one that tells it
/// which directory to adopt.
const CHILD_MARKER: &str = "KATA_CAPSULE_RESULT_CRASH_CHILD";
const CHILD_DIR: &str = "KATA_CAPSULE_RESULT_CRASH_DIR";

// ---------------------------------------------------------------------------
// Planes
// ---------------------------------------------------------------------------

/// The two planes. It does NOT own the temporary directory: the crash cell's child
/// adopts a directory the parent owns, so a `Planes` that dropped one would delete the
/// plane the parent is about to read.
struct Planes {
    op_path: std::path::PathBuf,
    db: Arc<OperationalDb>,
    cas: Arc<CasStore>,
}

/// The two planes, with the CAS BOUND to the nucleus.
///
/// `open_with_cas` and not `open`: `adopt_capsule_result` reads the node's one content
/// store off the database rather than taking a handle, so the store a result is verified
/// against is the one the node's offloaded output already publishes into. A plane opened
/// without one is its own named refusal, asserted in [`an_unbound_content_store_is_refused_by_name`].
fn planes() -> (tempfile::TempDir, Planes) {
    let dir = tempfile::tempdir().unwrap();
    let planes = open_planes(dir.path());
    (dir, planes)
}

fn open_planes(dir: &Path) -> Planes {
    let op_path = dir.join("operational.db");
    let cas = Arc::new(CasStore::open(dir.join("cas.db"), dir.join("cas")).unwrap());
    let db = Arc::new(OperationalDb::open_with_cas(&op_path, Arc::clone(&cas)).unwrap());
    Planes { op_path, db, cas }
}

/// The SECOND handle. Read-only: an observer that can write is an observer that can
/// repair what it was meant to catch.
fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn artifact_rows(path: &Path) -> i64 {
    raw(path)
        .query_row("SELECT count(*) FROM artifacts", [], |row| row.get(0))
        .unwrap()
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

fn occurrence_ref(execution_id: Ulid, path: Vec<u32>) -> OccurrenceRef {
    OccurrenceRef::new(
        ExecutionId(execution_id),
        ContentHash::new(PROGRAM_HASH),
        OperationContractId(ContentHash::new([0x6C; 32])),
        OperationPath(path),
    )
}

// ---------------------------------------------------------------------------
// One authorized occurrence, end to end through the production verbs
// ---------------------------------------------------------------------------

/// Everything one adoption needs, already durable.
#[derive(Clone)]
struct Authorized {
    execution_id: Ulid,
    attempt_id: Ulid,
    attempt_ordinal: i64,
    occurrence_id: kata_types::execution_contract::OccurrenceId,
    /// The `/work` mapping's own TREE artifact — the base every delta the
    /// fixture publishes must name, because `verify_work_delta` refuses a
    /// delta whose `base` is not exactly the mapped artifact.
    work_tree: ArtifactRef,
}

/// Submit an execution, declare a `/work` input artifact, publish and declare a capsule
/// with [`BOUND_BYTES`]/[`BOUND_ENTRIES`], and claim one attempt BOUND to the occurrence.
///
/// Every step goes through the production verb, not through a raw insert: the point of
/// the fixture is that the adoption reads a plane the AUTHORIZATION built, so a fixture
/// that wrote the rows itself could satisfy a reader that the production writer would
/// not.
fn authorize(planes: &Planes) -> Authorized {
    authorize_at(planes, vec![0])
}

/// [`authorize`] at a caller-chosen operation path, so one plane can hold TWO authorized
/// occurrences in TWO executions — the precondition for the shared-content cell.
fn authorize_at(planes: &Planes, path: Vec<u32>) -> Authorized {
    authorize_shaped(planes, path, capsule)
}

/// [`authorize_at`] with a caller-chosen capsule SHAPE — a delta cell's capsule
/// maps no `/work`, or carries its own `work_delta_*` bounds — while the
/// execution, work artifact, environment and occurrence all stay the production
/// fixture's.
fn authorize_shaped(
    planes: &Planes,
    path: Vec<u32>,
    build: impl FnOnce(kata_types::execution_contract::OccurrenceId, ArtifactId) -> Capsule,
) -> Authorized {
    let execution_id = Ulid::new();
    assert!(matches!(
        planes
            .db
            .submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    planes.db.mark_running(execution_id).unwrap();

    // The `/work` input: a real TREE artifact with a real `kind='tree'` row — the
    // base a `/work` delta is verified against, so a `Delete` cell has a subject
    // (`seed.txt`) and a file↔symlink cell has one too (`shared-link`).
    let seed = planes
        .cas
        .put_durable(b"capsule-result-fixture-work-tree")
        .unwrap();
    let work_manifest = TreeManifest::new(vec![
        TreeEntry {
            path: TreePath::new("seed.txt").unwrap(),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: seed.object_id(),
                size_bytes: seed.size(),
            },
        },
        link_entry("shared-link", "seed.txt"),
    ])
    .unwrap();
    let work_durable = planes
        .cas
        .put_durable(&work_manifest.manifest_bytes().unwrap())
        .unwrap();
    let input_ref = ArtifactRef::new(
        work_durable.object_id(),
        work_durable.size(),
        ArtifactPrivacy::Private,
    );
    planes
        .db
        .declare_artifact(
            &ArtifactDeclaration::for_durable_tree(
                &work_manifest,
                input_ref.privacy(),
                CasRootOwner::Execution(execution_id),
                &work_durable,
            )
            .unwrap(),
        )
        .unwrap();

    // A DECLARED environment: `declare_capsule` refuses a capsule naming one this plane
    // never authorized, which is the immutability of the binding rather than a
    // convenience. The manifest's bytes are arbitrary here — the adoption reads the
    // capsule's budgets, never the environment.
    let manifest = planes
        .cas
        .put_durable(b"capsule-result-fixture-environment-manifest")
        .unwrap();
    planes
        .db
        .declare_environment(
            &kata_core::operational::EnvironmentDeclaration::for_staged_root(
                ENVIRONMENT_ID,
                &manifest,
                [0x5C; 32],
                "capsule-result-fixture",
                [0x04; 32],
                STAGE_ULID,
            )
            .unwrap(),
        )
        .unwrap();

    let occurrence = occurrence_ref(execution_id, path);
    authorize_capsule(planes, execution_id, &occurrence, input_ref, build)
}

/// [`authorize_at`]'s second half, factored so a delta cell can declare a capsule
/// of its own shape (no `/work` mapping, or its own `work_delta_*` bounds) while
/// the claim and the `Authorized` it feeds stay the production path's.
fn authorize_capsule(
    planes: &Planes,
    execution_id: Ulid,
    occurrence: &OccurrenceRef,
    work_tree: ArtifactRef,
    build: impl FnOnce(kata_types::execution_contract::OccurrenceId, ArtifactId) -> Capsule,
) -> Authorized {
    let capsule = build(occurrence.id(), work_tree.id());
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
                assignment_json: b"{\"capsule\":{\"stage_name\":\"probe\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(capsule.action()),
                    Some(capsule.id()),
                ),
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
    Authorized {
        execution_id,
        attempt_id,
        attempt_ordinal: claimed.attempt_ordinal,
        occurrence_id: occurrence.id(),
        work_tree,
    }
}

/// A fixture capsule with NO `/work` mapping — the shape the `None` half of the
/// mapped-vs-reported delta law needs.
fn capsule_without_work(occurrence: kata_types::execution_contract::OccurrenceId) -> Capsule {
    Capsule::new(
        occurrence,
        PreparedActionId(ContentHash::new([0x02; 32])),
        EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
        PlatformId(ContentHash::new([0x04; 32])),
        Vec::new(),
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "echo hi > /out/hi".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: BOUND_BYTES,
            result_entries: BOUND_ENTRIES,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap()
}

/// The fixture capsule with the `/work` delta's own bounds set — the refusal a
/// delta budget cell needs without forging a frame.
fn capsule_with_delta_bounds(
    occurrence: kata_types::execution_contract::OccurrenceId,
    work: ArtifactId,
    work_delta_entries: u32,
    work_delta_bytes: u64,
) -> Capsule {
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
            argv: vec!["sh".into(), "-c".into(), "echo hi > /out/hi".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: BOUND_BYTES,
            result_entries: BOUND_ENTRIES,
            work_delta_bytes,
            work_delta_entries,
        },
        None,
    )
    .unwrap()
}

/// The fixture capsule: one `/work` mapping and the two tiny result bounds.
fn capsule(occurrence: kata_types::execution_contract::OccurrenceId, work: ArtifactId) -> Capsule {
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
            argv: vec!["sh".into(), "-c".into(), "echo hi > /out/hi".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: BOUND_BYTES,
            result_entries: BOUND_ENTRIES,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap()
}

/// Publish a result tree of `members` — THROUGH the CAS, members first then the manifest,
/// exactly as `kata_worker::result_publication` does — and hand back the reference the
/// worker would put on its frame.
fn publish_result(cas: &CasStore, members: &[(&str, &[u8])]) -> ArtifactRef {
    let mut entries = Vec::new();
    for (path, bytes) in members {
        let member = cas.put_durable(bytes).unwrap();
        entries.push(TreeEntry {
            path: TreePath::new(*path).unwrap(),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        });
    }
    let manifest = TreeManifest::new(entries).unwrap();
    let receipt = cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        kata_worker_result_privacy(&manifest),
    )
}

/// Publish a `/work` DELTA over `base` — `Write` member bytes first, then the
/// delta's own encoding, the order `kata_worker::work_delta::publish_work_delta`
/// publishes in — and hand back the reference a `CompletedCapsule` frame's
/// `work_delta` carries. The delta is `Private` always: its bytes embed the
/// base reference, so even an empty one is stage-produced content.
fn publish_delta(
    cas: &CasStore,
    base: &ArtifactRef,
    writes: &[(&str, &[u8])],
    deletes: &[&str],
) -> ArtifactRef {
    publish_delta_with_links(cas, base, writes, &[], deletes)
}

/// [`publish_delta`] with SYMLINK writes too — a created or retargeted link is a
/// `Write { Symlink }`, the node's content living inside the delta.
fn publish_delta_with_links(
    cas: &CasStore,
    base: &ArtifactRef,
    writes: &[(&str, &[u8])],
    links: &[(&str, &str)],
    deletes: &[&str],
) -> ArtifactRef {
    let mut changes = Vec::new();
    for (path, bytes) in writes {
        let member = cas.put_durable(bytes).unwrap();
        changes.push(TreeChange {
            path: TreePath::new(*path).unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: member.object_id(),
                    size_bytes: member.size(),
                },
            },
        });
    }
    for (path, target) in links {
        changes.push(TreeChange {
            path: TreePath::new(*path).unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::Symlink {
                    target: kata_types::tree_artifact::SymlinkTarget::new(*target).unwrap(),
                },
            },
        });
    }
    for path in deletes {
        changes.push(TreeChange {
            path: TreePath::new(*path).unwrap(),
            change: TreeChangeKind::Delete,
        });
    }
    changes.sort_by(|left, right| left.path.as_str().cmp(right.path.as_str()));
    let delta = TreeDelta::new(base.clone(), changes).unwrap();
    let receipt = cas.put_durable(&delta.delta_bytes().unwrap()).unwrap();
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    )
}

/// The EMPTY delta over `base` — the frame's honest report of "the stage changed
/// nothing under `/work`", which the fixture's adoptions carry so only the
/// verdict under test can refuse.
fn unchanged_delta(cas: &CasStore, base: &ArtifactRef) -> ArtifactRef {
    publish_delta(cas, base, &[], &[])
}

/// Publish `bytes` as one capture BLOB and return its `ArtifactRef` — the shape a
/// `CompletedCapsule` frame's `stdout`/`stderr` carry since provider protocol v6:
/// captures are spool files the worker publishes, never inline frame strings.
fn publish_capture(cas: &CasStore, bytes: &[u8]) -> ArtifactRef {
    let receipt = cas.put_durable(bytes).unwrap();
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    )
}

/// A schema-2 SYMLINK member — its content is the target inside the manifest, so
/// publishing one touches the CAS only for the manifest itself.
fn link_entry(path: &str, target: &str) -> TreeEntry {
    TreeEntry {
        path: TreePath::new(path).unwrap(),
        node: TreeNode::Symlink {
            target: kata_types::tree_artifact::SymlinkTarget::new(target).unwrap(),
        },
    }
}

/// [`publish_result`] over caller-built entries, so a result tree can carry a
/// symlink. The member files are still expected to have been published first —
/// `members` publishes them and builds the entries.
fn publish_result_entries(
    cas: &CasStore,
    members: &[(&str, &[u8])],
    links: &[(&str, &str)],
) -> (ArtifactRef, TreeManifest) {
    let mut entries = Vec::new();
    for (path, bytes) in members {
        let member = cas.put_durable(bytes).unwrap();
        entries.push(TreeEntry {
            path: TreePath::new(*path).unwrap(),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        });
    }
    for (path, target) in links {
        entries.push(link_entry(path, target));
    }
    let manifest = TreeManifest::new(entries).unwrap();
    let receipt = cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    (
        ArtifactRef::new(
            receipt.object_id(),
            receipt.size(),
            kata_worker_result_privacy(&manifest),
        ),
        manifest,
    )
}

/// The privacy a published result carries, spelled here rather than imported: `kata-core`
/// does not depend on `kata-worker`, so the function the worker mints with
/// (`result_publication::privacy_for`) cannot be referenced. Written as one function so a
/// divergence is one edit away from being found — and the two refusal cells below assert
/// the WRONG arm is refused by name in both directions, which is what makes this a pinned
/// agreement rather than a shared guess.
///
/// The EMPTY tree is `Public`: it is the object every capsule already maps at `/out`, so a
/// `Private` twin over those bytes would collide on `idx_artifacts_object`.
fn kata_worker_result_privacy(manifest: &TreeManifest) -> ArtifactPrivacy {
    if manifest.entries().is_empty() {
        ArtifactPrivacy::Public
    } else {
        ArtifactPrivacy::Private
    }
}

/// Publish a result tree and hand back BOTH halves, for the cells that need the manifest.
fn publish_result_with_manifest(
    cas: &CasStore,
    members: &[(&str, &[u8])],
) -> (ArtifactRef, TreeManifest) {
    let reference = publish_result(cas, members);
    let bytes = cas
        .get_verified(&reference.object_id(), reference.size_bytes(), 1 << 20)
        .unwrap();
    (reference, serde_json::from_slice(&bytes).unwrap())
}

// ---------------------------------------------------------------------------
// The accepting path
// ---------------------------------------------------------------------------

/// **One published tree is adopted, then accepted exactly once — and the raw handle sees
/// both.**
///
/// **Would red if:** adoption declared no row, declared it against the wrong execution,
/// or the acceptance failed to latch `accepted_attempt_id`. It is also the NON-VACUITY
/// twin for both bound cells: they assert that nothing was declared, and a reader that
/// refused everything would pass them and fail here.
#[test]
fn a_result_inside_its_bounds_is_adopted_and_accepted_once() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let result = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect("a result inside the capsule's promise is adopted");

    assert_eq!(adopted.artifact_id, result.id().0.0);
    assert_eq!(adopted.manifest.entries().len(), 1);
    assert_eq!(adopted.member_bytes, 3);
    assert_eq!(
        artifact_rows(&planes.op_path),
        before + 4,
        "four artifacts rows are added — the result tree's, the /work delta's, and the \
         two CAPTURES', which adopt execution-owned and retained exactly as /out does \
         (protocol v6)"
    );

    // The row is a TREE and carries NO OWNER — it is a node-level content claim — and
    // the EXECUTION's ownership is the `cas_roots` row beside it.
    let (kind, object): (String, Vec<u8>) = raw(&planes.op_path)
        .query_row(
            "SELECT kind, object_id FROM artifacts WHERE artifact_id = ?1",
            params![adopted.artifact_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        kind, "tree",
        "a result is a tree, and collection expands its members"
    );
    assert_eq!(object, result.object_id().0.to_vec());
    let root_owner: Option<Vec<u8>> = raw(&planes.op_path)
        .query_row(
            "SELECT owner_execution_id FROM cas_roots
              WHERE purpose = 'artifact_object' AND object_digest = ?1
                AND released_at_ms IS NULL",
            params![result.object_id().0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        root_owner,
        Some(authorized.execution_id.to_bytes().to_vec()),
        "the retaining ROOT belongs to the EXECUTION, so the execution's own retention \
         boundary reclaims the bytes — and it is the only place ownership is \
         recorded"
    );

    // Then the ONE acceptance door, with the adopted artifact in its payload.
    let input = kata_core::operational::WorkerCompletionInput {
        execution_id: authorized.execution_id,
        attempt_id: authorized.attempt_id,
        attempt_ordinal: authorized.attempt_ordinal,
        lease_epoch: 0,
        worker_id: "w-1".to_string(),
        output: kata_core::operational::capsule_result_output(
            &adopted,
            &result,
            Some(0),
            &stdout,
            &stderr,
            false,
            None,
        ),
    };
    assert!(matches!(
        planes.db.accept_worker_completion(&input).unwrap(),
        kata_core::operational::CompletionVerdict::Accepted { .. }
    ));

    let (accepted_attempt, accepted_at): (Option<Vec<u8>>, Option<i64>) = raw(&planes.op_path)
        .query_row(
            "SELECT accepted_attempt_id, accepted_at_ms FROM occurrences WHERE occurrence_id = ?1",
            params![authorized.occurrence_id.0.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        accepted_attempt,
        Some(authorized.attempt_id.to_bytes().to_vec()),
        "the occurrence's accepted outcome is this attempt's"
    );
    assert!(accepted_at.is_some());

    // The RESULT ARTIFACT IS RECORDED, and this is where — the accepting transition's
    // payload, rather than a column. Read off the raw handle rather than off the typed
    // reader, so the claim is about the bytes that are durable.
    let payload: Vec<u8> = raw(&planes.op_path)
        .query_row(
            "SELECT payload_json FROM transitions WHERE execution_id = ?1 \
               AND resulting_state = 'completed' ORDER BY seq DESC LIMIT 1",
            params![authorized.execution_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    let text = String::from_utf8_lossy(&payload);
    assert!(
        text.contains(&ContentHash::new(adopted.artifact_id).to_string()),
        "the accepting transition's payload must NAME the adopted result artifact — it is the \
         durable record of what the acceptance accepted, and the reason no column was added: \
         {text}"
    );

    // A SECOND adoption of the same result is idempotent: one id, one row.
    planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect("re-adopting one result is idempotent, which is what makes crash recovery re-do");
    assert_eq!(artifact_rows(&planes.op_path), before + 4);
    drop(dir);
}

// ---------------------------------------------------------------------------
// The bounds, each on its own, each observed as "nothing was declared"
// ---------------------------------------------------------------------------

/// **A result over the capsule's `result_bytes` is refused BEFORE any row exists.**
///
/// The two bounds are asserted separately because they are folded separately and neither
/// implies the other: this tree has ONE entry (inside `BOUND_ENTRIES`) and 40 member
/// bytes (outside `BOUND_BYTES`), so only the byte bound can refuse it.
#[test]
fn a_result_over_its_byte_bound_is_refused_with_no_artifacts_row() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let oversized = vec![b'x'; usize::try_from(BOUND_BYTES).unwrap() + 8];
    let result = publish_result(&planes.cas, &[("big", &oversized)]);
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a result over the capsule's byte promise must be refused");
    assert!(
        error.to_string().contains("members total")
            && error.to_string().contains("promised at most"),
        "the refusal must name the bound, and it must be the MEMBER bound rather than the \
         manifest ceiling — a cell that accepted either could pass while the two were \
         conflated: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared. Read off a raw handle rather than by asking the writer, because \
         the property is about the plane and not about the return value"
    );
    drop(dir);
}

/// **A result over the capsule's `result_entries` is refused BEFORE any row exists.**
///
/// Three one-byte entries: three total member bytes, well inside `BOUND_BYTES`, so only
/// the ENTRY bound can refuse it. Together with its sibling this is what makes "two
/// bounds, folded separately" a measured claim rather than a comment on the struct.
#[test]
fn a_result_over_its_entry_bound_is_refused_with_no_artifacts_row() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let result = publish_result(&planes.cas, &[("a", b"1"), ("b", b"2"), ("c", b"3")]);
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a result over the capsule's entry promise must be refused");
    assert!(
        error.to_string().contains("holds 3 entries") && error.to_string().contains("at most 2"),
        "the refusal must name the ENTRY bound and the count that broke it: {error}"
    );
    assert_eq!(artifact_rows(&planes.op_path), before);
    drop(dir);
}

/// **A schema-2 result carrying a SYMLINK is adopted: the link is an entry, names no
/// CAS member, and its target is the bytes it charges.**
///
/// The member presence-and-length check asks `cas_objects` about the link's object —
/// there IS none (the arm carries no `object`), so the check skipping it is the type's
/// own shape; what this cell pins is the ADOPTED arithmetic: `member_bytes` is the
/// file's length plus the target's length, and the artifacts row still declares.
#[test]
fn a_result_carrying_a_symlink_is_adopted_with_its_target_as_carried_bytes() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let (result, _) =
        publish_result_entries(&planes.cas, &[("hi", b"hi\n")], &[("link", "/etc/passwd")]);
    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect("a result tree carrying a symlink is adoptable — the link names no member");

    assert_eq!(adopted.manifest.entries().len(), 2);
    assert!(
        adopted.manifest.entries().iter().any(|entry| matches!(
            &entry.node,
            TreeNode::Symlink { target } if target.as_str() == "/etc/passwd"
        )),
        "the adopted manifest carries the link verbatim"
    );
    assert_eq!(
        adopted.member_bytes,
        3 + "/etc/passwd".len() as u64,
        "carried bytes = the file's length + the target's length"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before + 4,
        "the result tree's row declares, exactly once — and the /work delta's and \
         the two capture blobs' beside it, execution-owned like it"
    );
    drop(dir);
}

/// **A symlink's target is CHARGED to `result_bytes`, not free.**
///
/// One link whose 40-byte target is over `BOUND_BYTES` on its own — a manifest could
/// otherwise carry an entry the capsule never promised bytes for. The refusal is the
/// same member-bytes door a file trips.
#[test]
fn a_symlink_result_over_the_byte_bound_is_refused_with_no_artifacts_row() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let long_target = "t".repeat(usize::try_from(BOUND_BYTES).unwrap() + 8);
    let (result, _) = publish_result_entries(&planes.cas, &[], &[("link", long_target.as_str())]);
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a link whose target is over the byte promise must be refused");
    assert!(
        error.to_string().contains("members total") && error.to_string().contains("at most"),
        "the refusal is the byte bound, measured over the target: {error}"
    );
    assert_eq!(artifact_rows(&planes.op_path), before);
    drop(dir);
}

/// **The PRIVACY a worker may claim for a result is exactly one value, and the other arm
/// is refused by name.**
///
/// This is what turns the `kata_worker_result_privacy` agreement above from a shared
/// guess into a pinned one: privacy is folded into `ArtifactId`, so a `Public` result
/// would mint a SECOND identity over one tree's bytes — the permissive one.
#[test]
fn a_result_claiming_the_wrong_privacy_is_refused_before_any_byte_is_read() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let published = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let public = ArtifactRef::new(
        published.object_id(),
        published.size_bytes(),
        ArtifactPrivacy::Public,
    );
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: public,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a result classified public must be refused");
    assert!(error.to_string().contains("classified public"), "{error}");
    assert_eq!(artifact_rows(&planes.op_path), before);
    drop(dir);
}

/// **An occurrence that names NO CAPSULE has no bound, so its result is refused rather
/// than adopted against a default.**
///
/// The refusal is the whole reason the bound lives in the capsule: a reader that fell
/// back to a node-configured ceiling would be holding the result to a value the
/// authorization never promised, which is exactly the wider-than-its-mechanism shape.
#[test]
fn an_occurrence_with_no_capsule_has_no_bound_and_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let execution_id = Ulid::new();
    assert!(matches!(
        planes
            .db
            .submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    planes.db.mark_running(execution_id).unwrap();
    let occurrence = occurrence_ref(execution_id, vec![0]);
    planes
        .db
        .claim_attempt(
            execution_id,
            Ulid::new(),
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"probe\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                // NO capsule on the binding — which is the state every attempt claimed
                // before the authorization path existed.
                occurrence: OccurrenceBinding::new(occurrence.clone(), None, None),
            },
        )
        .unwrap();

    let result = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id,
            occurrence_id: occurrence.id(),
            result,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: None,
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("an occurrence with no capsule has no promised bound");
    assert!(error.to_string().contains("names no capsule"), "{error}");
    assert_eq!(artifact_rows(&planes.op_path), 0);
    drop(dir);
}

/// **A nucleus opened with no content store refuses by name rather than adopting
/// nothing.**
#[test]
fn an_unbound_content_store_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
    let error = db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: Ulid::new(),
            occurrence_id: kata_types::execution_contract::OccurrenceId(ContentHash::new(
                [0x11; 32],
            )),
            result: ArtifactRef::new(FixedBytes([0x22; 32]), 8, ArtifactPrivacy::Private),
            stdout: ArtifactRef::new(FixedBytes([0x33; 32]), 0, ArtifactPrivacy::Private),
            stderr: ArtifactRef::new(FixedBytes([0x44; 32]), 0, ArtifactPrivacy::Private),
            work_delta: None,
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a plane with no CAS cannot verify or retain a result");
    assert!(
        error.to_string().contains("NO content store bound"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// The crash cell
// ---------------------------------------------------------------------------

/// The completion the production door accepts for `authorized`'s attempt, over `result`.
fn completion_for(
    authorized: &Authorized,
    result: &ArtifactRef,
    stdout: &ArtifactRef,
    stderr: &ArtifactRef,
) -> impl FnOnce(&kata_core::operational::AdoptedResult) -> kata_core::operational::WorkerCompletionInput
{
    let authorized = authorized.clone();
    let result = result.clone();
    let stdout = stdout.clone();
    let stderr = stderr.clone();
    move |adopted| kata_core::operational::WorkerCompletionInput {
        execution_id: authorized.execution_id,
        attempt_id: authorized.attempt_id,
        attempt_ordinal: authorized.attempt_ordinal,
        lease_epoch: 0,
        worker_id: "w-1".to_string(),
        output: kata_core::operational::capsule_result_output(
            adopted,
            &result,
            Some(0),
            &stdout,
            &stderr,
            false,
            None,
        ),
    }
}

/// The armed child: build the fixture, adopt-and-accept the result through the
/// PRODUCTION door, and die just past the accepting commit. The authorization is left on
/// disk for the parent's redelivery.
fn crash_child(dir: &Path) {
    let planes = open_planes(dir);
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    std::fs::write(
        dir.join("authorized"),
        format!(
            "{} {} {} {} {} {} {}",
            authorized.execution_id,
            authorized.attempt_id,
            authorized.attempt_ordinal,
            authorized.occurrence_id.0,
            authorized.work_tree.object_id(),
            authorized.work_tree.size_bytes(),
            authorized.work_tree.privacy().as_tag(),
        ),
    )
    .unwrap();
    let result = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let (_, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id: authorized.execution_id,
                occurrence_id: authorized.occurrence_id,
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
                capture_exceeded: false,
                agent: None,
                egress_refusals: vec![],
            },
            completion_for(&authorized, &result, &stdout, &stderr),
        )
        .expect("the door reaches its crash point");
    panic!("the armed fault point was never reached; the door answered {verdict:?}");
}

/// **A CAPSULE COMPLETION REDELIVERED AFTER A CRASH PAST ITS ACCEPTANCE IS ACCEPTED
/// ONCE.**
///
/// The production door declares the result in the accepting transaction, so the first
/// durable edge after a `CompletedCapsule` arrives is `after_accept_event`: the result
/// row, its root and the acceptance all committed, the handler never returned. A child
/// dies there (a real abort at the registered boundary); the parent reopens the plane and
/// REDELIVERS the same frame through the same door.
///
/// **Would red if:** the declaration left the accepting transaction (the reopened plane
/// would hold a row beside no acceptance, or an acceptance beside no row), or the door
/// stopped recognising its own earlier acceptance (the redelivery would answer
/// `Superseded` off the completed attempt's fence, or write a second transition).
#[test]
fn a_capsule_completion_redelivered_after_a_crash_past_its_acceptance_is_accepted_once() {
    if std::env::var(CHILD_MARKER).is_ok() {
        crash_child(Path::new(&std::env::var(CHILD_DIR).unwrap()));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("a_capsule_completion_redelivered_after_a_crash_past_its_acceptance_is_accepted_once")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir.path())
        .env("KATA_FAULT_INJECT", "operational.after_accept_event")
        .output()
        .expect("spawn the armed child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the armed child must abort, not exit cleanly:\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("crash point reached: operational.after_accept_event"),
        "the child must die IN the window, not incidentally:\nstderr:\n{stderr}"
    );
    let recorded = std::fs::read_to_string(dir.path().join("authorized")).unwrap();
    let fields: Vec<&str> = recorded.split(' ').collect();
    let authorized = Authorized {
        execution_id: fields[0].parse().unwrap(),
        attempt_id: fields[1].parse().unwrap(),
        attempt_ordinal: fields[2].parse().unwrap(),
        occurrence_id: kata_types::execution_contract::OccurrenceId(
            fields[3].parse().expect("the occurrence id round-trips"),
        ),
        work_tree: ArtifactRef::new(
            FixedBytes(
                fields[4]
                    .parse::<ContentHash>()
                    .expect("the work-tree object id round-trips")
                    .0,
            ),
            fields[5].parse().expect("the work-tree size round-trips"),
            match fields[6] {
                "public" => ArtifactPrivacy::Public,
                "private" => ArtifactPrivacy::Private,
                other => panic!("a privacy tag that is not one: {other}"),
            },
        ),
    };

    // The plane the crash left, and after the redelivery, read through a raw handle.
    // `kind='tree'` counts TWO rows: the `/work` input the authorization declared
    // AND the adopted result — the delta row is counted on its own, because the
    // point is that all three commit in the ONE accepting transaction.
    let op_path = dir.path().join("operational.db");
    let observe = || -> (i64, i64, Option<Vec<u8>>, i64) {
        raw(&op_path)
            .query_row(
                "SELECT (SELECT count(*) FROM artifacts WHERE kind = 'tree'), \
                        (SELECT count(*) FROM artifacts WHERE kind = 'tree_delta'), \
                        (SELECT accepted_attempt_id FROM occurrences WHERE occurrence_id = ?1), \
                        (SELECT count(*) FROM transitions \
                          WHERE attempt_id = ?2 AND resulting_state = 'completed')",
                params![
                    authorized.occurrence_id.0.0.as_slice(),
                    authorized.attempt_id.to_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    };
    let accepted_by = Some(authorized.attempt_id.to_bytes().to_vec());
    assert_eq!(
        observe(),
        (2, 1, accepted_by.clone(), 1),
        "the crash left the result row, the delta row, the acceptance and ONE completed \
         transition — all of them commit together or not at all"
    );

    // THE REDELIVERY, through the production door, on a fresh process's planes.
    let planes = open_planes(dir.path());
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let result = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let (_, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id: authorized.execution_id,
                occurrence_id: authorized.occurrence_id,
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
                capture_exceeded: false,
                agent: None,
                egress_refusals: vec![],
            },
            completion_for(&authorized, &result, &stdout, &stderr),
        )
        .expect("a redelivered completion is an answer, not an error");
    assert_eq!(
        verdict,
        kata_core::operational::CompletionVerdict::AlreadyAccepted,
        "the redelivery recognises the acceptance the crash left"
    );
    assert_eq!(
        observe(),
        (2, 1, accepted_by, 1),
        "and writes nothing: one result row, one delta row, one acceptance, one \
         completed transition"
    );
}

// ---------------------------------------------------------------------------
// Shared content, the empty tree, and member soundness
// ---------------------------------------------------------------------------

/// **An EMPTY `/out` IS ADOPTED, as the canonical `Public` empty tree.**
///
/// **Would red if:** the adoption required `Private` for every result (the empty tree
/// would be refused, and a stage that legitimately writes nothing could never report), or
/// admitted `Private` for it (a second artifact id over bytes every capsule already maps
/// as `Public`, colliding on `idx_artifacts_object` the moment either arrives
/// second).
#[test]
fn an_empty_result_is_adopted_as_the_canonical_public_empty_tree() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);

    let (result, manifest) = publish_result_with_manifest(&planes.cas, &[]);
    assert!(manifest.entries().is_empty(), "premise: the tree is empty");
    assert_eq!(
        result.privacy(),
        ArtifactPrivacy::Public,
        "premise: the worker publishes the empty tree as Public, or this cell is about a \
         different reference than production produces"
    );

    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect("a stage that writes nothing to /out has a result, and it is the empty tree");
    assert_eq!(adopted.member_bytes, 0);
    assert_eq!(adopted.manifest.entries().len(), 0);

    let (kind, privacy): (String, String) = raw(&planes.op_path)
        .query_row(
            "SELECT kind, privacy FROM artifacts WHERE artifact_id = ?1",
            params![adopted.artifact_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((kind.as_str(), privacy.as_str()), ("tree", "public"));

    // AND THE ADOPTION COEXISTS WITH THE CAPSULE PLANE's own claim on those bytes: a
    // second declaration of the same reference, node-owned this time, is one row and a
    // second root — which is what every capsule mapping /out needs and what an owner
    // column on the row would refuse.
    let same = ArtifactDeclaration::for_durable_tree(
        &adopted.manifest,
        ArtifactPrivacy::Public,
        CasRootOwner::Node,
        &planes
            .cas
            .put_durable(&adopted.manifest.manifest_bytes().unwrap())
            .unwrap(),
    )
    .unwrap();
    planes
        .db
        .declare_artifact(&same)
        .expect("the empty tree is also node-owned, by every capsule that maps it at /out");
    assert_eq!(
        artifact_rows(&planes.op_path),
        5,
        "the /work input, the empty tree, the /work delta, and the two capture blobs — \
         execution-owned and declared the same way"
    );
    drop(dir);
}

/// **TWO EXECUTIONS WHOSE `/out` TREES ARE BYTE-IDENTICAL BOTH ADOPT: one `artifacts`
/// row, two `cas_roots` roots.**
///
/// # Why this cell matters
///
/// `ArtifactId` is `H(object, size, privacy)` and folds no owner, so two stages that
/// wrote the same bytes produce ONE id — and with an owner on the row the second
/// execution's adoption would be refused as a "divergent re-declaration" for
/// having a different owner. Two runs of one deterministic stage is not an exotic input;
/// it is the case the content-addressed plane exists to make cheap.
///
/// **Would red if:** the row carried an owner again (the second adoption refuses), or the
/// second adoption were made idempotent by SKIPPING the root (one root for two owners,
/// and the second execution's ownership goes unrecorded).
#[test]
fn two_executions_with_byte_identical_results_share_one_row_and_hold_two_roots() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let first = authorize(&planes);
    let second = authorize_at(&planes, vec![1]);

    // ONE published tree; both executions report it, which is exactly what two
    // deterministic stages writing the same bytes produce.
    let result = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let before = artifact_rows(&planes.op_path);

    let a = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: first.execution_id,
            occurrence_id: first.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &first.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect("the first execution adopts");
    let b = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: second.execution_id,
            occurrence_id: second.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &second.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect(
            "the SECOND execution adopts the same content. A refusal here would mean a content \
             address carries one owner's retention obligation, which it cannot",
        );
    assert_eq!(
        a.artifact_id, b.artifact_id,
        "premise: byte-identical results are ONE artifact id, or this cell is about two \
         artifacts"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before + 4,
        "FOUR rows for the two adoptions — the shared result, the two shared \
         captures, and the ONE shared delta, each declared once under ONE \
         content id: identical bases make identical delta bytes"
    );

    let conn = raw(&planes.op_path);
    let (roots, owners): (i64, i64) = conn
        .query_row(
            "SELECT count(*), count(DISTINCT hex(owner_execution_id)) FROM cas_roots
              WHERE purpose = 'artifact_object' AND object_digest = ?1
                AND released_at_ms IS NULL",
            params![result.object_id().0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (roots, owners),
        (2, 2),
        "TWO roots, one per execution: each execution asserts the bytes its own \
         accepted outcome names"
    );

    drop(dir);
}

/// **A NON-EMPTY result claiming `Public` is refused, and nothing is declared.**
///
/// The other half of [`an_empty_result_is_adopted_as_the_canonical_public_empty_tree`]:
/// the exception is exactly one object id, and a stage's actual output is not it.
#[test]
fn a_non_empty_result_claiming_public_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let published = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let public = ArtifactRef::new(
        published.object_id(),
        published.size_bytes(),
        ArtifactPrivacy::Public,
    );
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: public,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a stage's own output is not the canonical empty tree");
    assert!(
        error.to_string().contains("must be declared private"),
        "{error}"
    );
    assert_eq!(artifact_rows(&planes.op_path), before);
    drop(dir);
}

/// **A manifest naming an ABSENT member is refused, and nothing is declared.**
///
/// A tree row makes its members reachable for retention, so a row over an absent member
/// retains a promise about bytes that are not there — and every bound this adoption
/// enforces is computed over the manifest's own numbers, which an absent member satisfies
/// perfectly.
#[test]
fn a_result_naming_an_absent_member_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    // A manifest published WITHOUT its member: the entry names an object this store has
    // never held.
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("ghost").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: FixedBytes([0x5E; 32]),
            size_bytes: 3,
        },
    }])
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: ArtifactRef::new(
                receipt.object_id(),
                receipt.size(),
                ArtifactPrivacy::Private,
            ),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a member the store does not hold must be refused");
    assert!(
        error.to_string().contains("content store does not hold"),
        "{error}"
    );
    assert_eq!(artifact_rows(&planes.op_path), before);
    drop(dir);
}

/// **A manifest that LIES ABOUT A MEMBER'S LENGTH is refused, and nothing is declared.**
///
/// # Why the bounds cannot catch this and this cell is not redundant
///
/// `result_bytes` and `result_entries` are both computed over the MANIFEST's numbers. A
/// manifest declaring three bytes for an object the store holds a megabyte of is inside
/// every bound the capsule promised while occupying whatever it likes — so the check has
/// to compare the declared length against the store's recorded one, which is what this
/// asserts.
///
/// It is PRESENCE AND LENGTH and not integrity: the member's digest is checked where it is
/// read. The lie here is therefore in the length alone, which is the part a reader
/// downstream would not question.
#[test]
fn a_result_whose_member_lies_about_its_length_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let member = planes.cas.put_durable(b"a much longer member").unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("liar").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            // THREE, against twenty real bytes: inside `BOUND_BYTES`, so every bound passes.
            size_bytes: 3,
        },
    }])
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: ArtifactRef::new(
                receipt.object_id(),
                receipt.size(),
                ArtifactPrivacy::Private,
            ),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a member that misreports its length must be refused");
    let message = error.to_string();
    assert!(
        message.contains("declares member liar as 3 bytes"),
        "{message}"
    );
    assert!(
        message.contains(&format!("holds {} at object", member.size())),
        "the refusal must name what the store actually holds: {message}"
    );
    assert_eq!(artifact_rows(&planes.op_path), before);
    drop(dir);
}

/// **A CURRENT-EPOCH DUPLICATE of one `CompletedCapsule` changes nothing, and
/// `accepted_attempt_id` does not move.**
///
/// # What this is the witness for, and which mechanism it reaches
///
/// The fence refuses a STALE epoch before a byte of the result is read, so a CURRENT-epoch
/// redelivery is the only duplicate that reaches the acceptance door — the redelivery a
/// crash between the acceptance and the ack produces. This cell drives the SAME frame
/// twice and asserts three things, because "the second call did not error" is a much
/// weaker claim than any of them:
///
/// * the ADOPTION is idempotent over one artifact id — the row is re-acquired and no
///   second row or root appears;
/// * the acceptance returns `AlreadyAccepted`: it converges through
///   `dedupe_accepted_event`, which is the SAME-DIGEST path, and appends NO transition;
/// * `accepted_attempt_id` and `accepted_at_ms` are byte-identical across the two calls.
///
/// # What it deliberately does NOT cover
///
/// A current-epoch frame from a DIFFERENT attempt at an already-accepted occurrence. That
/// is the typed divergence, it is record-only (a transition IS appended), and its
/// mechanism is `refuse_second_occurrence_acceptance` — falsified in its own named cell,
/// `refuse_second_occurrence_acceptance_refuses_a_second_attempts_completion`
/// (`crates/core/tests/operational_occurrences.rs`). Naming it here rather than asserting
/// it twice: the two duplicates reach two different mechanisms, and a cell that tripped
/// both would prove only that SOME mechanism fired.
///
/// **Would red if:** the second adjudication latched a second acceptance (the pair would
/// move), or the write-once UPDATE were a plain UPDATE (the instant would re-stamp).
#[test]
fn a_current_epoch_duplicate_completion_is_record_only_and_moves_no_acceptance() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let result = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .unwrap();
    let input = kata_core::operational::WorkerCompletionInput {
        execution_id: authorized.execution_id,
        attempt_id: authorized.attempt_id,
        attempt_ordinal: authorized.attempt_ordinal,
        lease_epoch: 0,
        worker_id: "w-1".to_string(),
        output: kata_core::operational::capsule_result_output(
            &adopted,
            &result,
            Some(0),
            &stdout,
            &stderr,
            false,
            None,
        ),
    };

    // FIRST delivery: accepted.
    assert!(matches!(
        planes.db.accept_worker_completion(&input).unwrap(),
        kata_core::operational::CompletionVerdict::Accepted { .. }
    ));
    let conn = raw(&planes.op_path);
    let accepted_after_first: (Option<Vec<u8>>, Option<i64>) = conn
        .query_row(
            "SELECT accepted_attempt_id, accepted_at_ms FROM occurrences WHERE occurrence_id = ?1",
            params![authorized.occurrence_id.0.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        accepted_after_first.0,
        Some(authorized.attempt_id.to_bytes().to_vec())
    );
    let transitions_after_first: i64 = conn
        .query_row("SELECT count(*) FROM transitions", [], |row| row.get(0))
        .unwrap();

    // SECOND delivery, SAME generation and same bytes — the redelivery a crash between
    // the acceptance and the ack produces.
    let re_adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect(
            "re-adoption is idempotent over one artifact id, which is what makes a \
                 redelivery safe",
        );
    assert_eq!(re_adopted.artifact_id, adopted.artifact_id);
    let second = planes
        .db
        .accept_worker_completion(&input)
        .expect("a current-epoch duplicate is adjudicated, not refused");
    assert_eq!(
        second,
        kata_core::operational::CompletionVerdict::AlreadyAccepted,
        "the second acceptance must CONVERGE on the recorded acceptance as an idempotent \
         ACK, not mint a second one"
    );

    // THE PROPERTY: the acceptance pair is byte-identical, and no second accepting
    // transition was appended.
    let accepted_after_second: (Option<Vec<u8>>, Option<i64>) = conn
        .query_row(
            "SELECT accepted_attempt_id, accepted_at_ms FROM occurrences WHERE occurrence_id = ?1",
            params![authorized.occurrence_id.0.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        accepted_after_second, accepted_after_first,
        "the duplicate is RECORD-ONLY: `accepted_attempt_id` and the acceptance instant are \
         both unchanged. A moved instant would mean the write-once UPDATE is a plain one"
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM transitions", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        transitions_after_first,
        "and no second accepting transition was appended"
    );
    drop(dir);
}

/// **`kata run show`'s capsule half: the ACCEPTED attempt's stage output, keyed by stage,
/// read off the accepting transition and overlaid by a later amendment.**
///
/// The status projection's assignment population excludes capsule attempts by name, so this
/// reader is the only way a capsule stage's output reaches an operator.
///
/// **Would red if:** the reader answered before acceptance (an unaccepted result is not
/// an outcome), keyed by anything but the stage, dropped the envelope's `content`, or
/// ignored the runner's `outcome_amended` frame (the envelope with `parsed` injected).
#[test]
fn the_accepted_capsule_output_is_read_by_stage_and_the_amendment_wins() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"{\"dns_failed\":true}\n");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    assert!(
        planes
            .db
            .accepted_occurrence_outputs(authorized.execution_id)
            .unwrap()
            .is_empty(),
        "no acceptance, no output"
    );

    let result = publish_result(&planes.cas, &[]);
    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .unwrap();
    let output = kata_core::operational::capsule_result_output(
        &adopted,
        &result,
        Some(0),
        &stdout,
        &stderr,
        false,
        None,
    );
    let input = kata_core::operational::WorkerCompletionInput {
        execution_id: authorized.execution_id,
        attempt_id: authorized.attempt_id,
        attempt_ordinal: authorized.attempt_ordinal,
        lease_epoch: 0,
        worker_id: "w-1".to_string(),
        output: output.clone(),
    };
    assert!(matches!(
        planes.db.accept_worker_completion(&input).unwrap(),
        kata_core::operational::CompletionVerdict::Accepted { .. }
    ));
    let read = planes
        .db
        .accepted_occurrence_outputs(authorized.execution_id)
        .unwrap();
    assert_eq!(read, vec![(STAGE.to_string(), output.clone())]);
    assert_eq!(read[0].1["content"], "{\"dns_failed\":true}\n");

    let mut amended = output;
    amended["parsed"] = serde_json::json!({"dns_failed": true});
    planes
        .db
        .amend_attempt_outcome(
            authorized.attempt_id,
            &kata_types::idempotency::canonicalize_args(&amended),
        )
        .unwrap();
    assert_eq!(
        planes
            .db
            .accepted_occurrence_outputs(authorized.execution_id)
            .unwrap(),
        vec![(STAGE.to_string(), amended)],
        "the runner's amendment is the output an operator reads"
    );
    drop(dir);
}

/// **The runner's amendment of a capsule stage lands on the chain once the occurrence
/// ACCEPTED the attempt — and only then, and only once.**
///
/// **Would red if:** the door amended an attempt no occurrence accepted (such an attempt
/// must fall through to the assignment-population gate), refused an accepted one (the
/// `parsed` envelope would never reach `run show`), or appended a second frame for bytes
/// already effective.
#[test]
fn the_capsule_amendment_door_amends_only_an_accepted_attempt_and_is_idempotent() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let amendments = |planes: &Planes| -> i64 {
        raw(&planes.op_path)
            .query_row(
                "SELECT count(*) FROM transitions WHERE kind = 'outcome_amended'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };
    let augmented = serde_json::json!({"content": "{}", "parsed": {}});
    assert!(
        !planes
            .db
            .amend_accepted_capsule_output(authorized.attempt_id, &augmented)
            .unwrap(),
        "an unaccepted attempt falls through"
    );
    assert_eq!(amendments(&planes), 0, "and nothing is written");

    let result = publish_result(&planes.cas, &[]);
    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .unwrap();
    let input = kata_core::operational::WorkerCompletionInput {
        execution_id: authorized.execution_id,
        attempt_id: authorized.attempt_id,
        attempt_ordinal: authorized.attempt_ordinal,
        lease_epoch: 0,
        worker_id: "w-1".to_string(),
        output: kata_core::operational::capsule_result_output(
            &adopted,
            &result,
            Some(0),
            &stdout,
            &stderr,
            false,
            None,
        ),
    };
    planes.db.accept_worker_completion(&input).unwrap();

    for _ in 0..2 {
        assert!(
            planes
                .db
                .amend_accepted_capsule_output(authorized.attempt_id, &augmented)
                .unwrap()
        );
    }
    assert_eq!(amendments(&planes), 1, "ONE frame for one effective output");
    assert_eq!(
        planes
            .db
            .accepted_occurrence_outputs(authorized.execution_id)
            .unwrap(),
        vec![(STAGE.to_string(), augmented)]
    );
    drop(dir);
}

/// **ACCEPT AND SETTLE RACED ON TWO THREADS: exactly one wins, every time.**
///
/// ONE plane shared by two threads — as the main's reactor and its sweeps share one
/// `OperationalDb` — released together by a barrier: one adopts-and-accepts a result, the
/// other settles the attempt `failed` only-if-live. The writer lock decides the order;
/// the property is that neither order leaves the plane half-decided. Two leading rounds
/// FORCE each order (the settle side waits for the accept side to finish, then the
/// reverse), so both orders are exercised however the box is loaded; the sixteen racing
/// rounds after them start the settle side a little later each round (0 to 45 ms) and
/// require only that each round holds exactly one outcome. Whichever order the writer lock grants, the plane holds exactly one outcome: accepted (the result's `artifacts` row
/// exists, the occurrence names the attempt, the attempt is `completed`) or settled (no
/// row for the result, no acceptance, the attempt `failed`) — never a declared result
/// beside a settled attempt, and never both verdicts claiming the win.
///
/// **Would red if:** the declaration left the accepting transaction (a settle committing
/// between the two leaves a retained result for an outcome nobody accepted), or either
/// side stopped re-reading liveness under the lock.
#[test]
fn accept_and_settle_raced_on_two_threads_leave_exactly_one_outcome() {
    const RACING_ROUNDS: u32 = 16;
    // Round 0 forces accept-then-settle, round 1 settle-then-accept; the rest race.
    const ROUNDS: u32 = RACING_ROUNDS + 2;
    let mut outcomes = (0_u32, 0_u32);
    for round in 0..ROUNDS {
        let (accept_first, settle_first) = (
            std::sync::Arc::new(std::sync::Barrier::new(if round == 0 { 2 } else { 1 })),
            std::sync::Arc::new(std::sync::Barrier::new(if round == 1 { 2 } else { 1 })),
        );
        let dir = tempfile::tempdir().unwrap();
        let first = open_planes(dir.path());
        let stdout = publish_capture(&first.cas, b"the stdout bytes");
        let stderr = publish_capture(&first.cas, b"the stderr bytes");
        let authorized = authorize(&first);
        let result = publish_result(&first.cas, &[("race", b"race\n")]);
        let work_delta = unchanged_delta(&first.cas, &authorized.work_tree);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let accept = {
            let db = Arc::clone(&first.db);
            let barrier = Arc::clone(&barrier);
            let authorized = authorized.clone();
            let (accept_first, settle_first) =
                (Arc::clone(&accept_first), Arc::clone(&settle_first));
            let result = result.clone();
            std::thread::spawn(move || {
                barrier.wait();
                settle_first.wait();
                let verdict = db.adopt_and_accept_capsule_completion(
                    &CapsuleResultAdoption {
                        execution_id: authorized.execution_id,
                        occurrence_id: authorized.occurrence_id,
                        result: result.clone(),
                        stdout: stdout.clone(),
                        stderr: stderr.clone(),
                        work_delta: Some(work_delta.clone()),
                        capture_exceeded: false,
                        agent: None,
                        egress_refusals: vec![],
                    },
                    |adopted| kata_core::operational::WorkerCompletionInput {
                        execution_id: authorized.execution_id,
                        attempt_id: authorized.attempt_id,
                        attempt_ordinal: authorized.attempt_ordinal,
                        lease_epoch: 0,
                        worker_id: "w-1".to_string(),
                        output: kata_core::operational::capsule_result_output(
                            adopted,
                            &result,
                            Some(0),
                            &stdout,
                            &stderr,
                            false,
                            None,
                        ),
                    },
                );
                accept_first.wait();
                verdict.map(|(_, verdict)| verdict)
            })
        };
        let settle = {
            let db = Arc::clone(&first.db);
            let barrier = Arc::clone(&barrier);
            let (accept_first, settle_first) =
                (Arc::clone(&accept_first), Arc::clone(&settle_first));
            std::thread::spawn(move || {
                barrier.wait();
                accept_first.wait();
                std::thread::sleep(std::time::Duration::from_millis(
                    u64::from(round.saturating_sub(2)) * 3,
                ));
                let settled = db.record_main_side_transition_if_live(
                    authorized.attempt_id,
                    &kata_core::operational::MainSideTransition {
                        reason: Some("a racing sweep"),
                        ..kata_core::operational::MainSideTransition::bare("failed")
                    },
                );
                settle_first.wait();
                settled
            })
        };
        let accepted = accept.join().unwrap().expect("the accept side answers");
        let settled = settle.join().unwrap().expect("the settle side answers");

        let conn = raw(&first.op_path);
        let (state, accepted_attempt, result_rows): (String, Option<Vec<u8>>, i64) = conn
            .query_row(
                "SELECT (SELECT p.state FROM attempts a JOIN attempt_projection p \
                           ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
                          AND p.attempt_ordinal = a.attempt_ordinal WHERE a.attempt_id = ?1), \
                        (SELECT accepted_attempt_id FROM occurrences WHERE occurrence_id = ?2), \
                        (SELECT count(*) FROM artifacts WHERE object_id = ?3)",
                params![
                    authorized.attempt_id.to_bytes().as_slice(),
                    authorized.occurrence_id.0.0.as_slice(),
                    result.object_id().0.as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        match accepted {
            kata_core::operational::CompletionVerdict::Accepted { .. } => {
                assert!(settled.is_none(), "the settle side must not also win");
                assert_eq!(state, "completed");
                assert_eq!(
                    accepted_attempt,
                    Some(authorized.attempt_id.to_bytes().to_vec())
                );
                assert_eq!(result_rows, 1, "the accepted result is declared");
                outcomes.0 += 1;
            }
            kata_core::operational::CompletionVerdict::Superseded => {
                assert!(
                    settled.is_some(),
                    "a superseded accept means the settle won"
                );
                assert_eq!(state, "failed");
                assert_eq!(accepted_attempt, None);
                assert_eq!(
                    result_rows, 0,
                    "a result is declared only by the transaction that accepts it"
                );
                outcomes.1 += 1;
            }
            kata_core::operational::CompletionVerdict::AlreadyAccepted => {
                panic!("neither side can see an earlier acceptance")
            }
        }
        drop((first, dir));
    }
    assert_eq!(outcomes.0 + outcomes.1, ROUNDS, "{outcomes:?}");
    assert!(
        outcomes.0 > 0 && outcomes.1 > 0,
        "the two forced rounds make each order win at least once: (accepted, settled) = \
         {outcomes:?}"
    );
    eprintln!("race outcomes (accepted, settled): {outcomes:?}");
}

/// **A completion whose two capture blobs sum PAST the capsule's `output_bytes` is
/// refused before any adoption — the claim the provider was supposedly held to.**
///
/// The provider is held to the COMBINED bound at its spool
/// (`CaptureSpec::limit_bytes`) and kills the stage for exceeding it; a frame
/// whose captures pass the bound is a frame whose bound was NOT enforced, so the
/// main-side check is the honest reading rather than a second enforcement. The
/// cell forges it exactly: two REAL blobs in the rig's CAS — both verifiable —
/// whose sizes together beat the fixture capsule's `output_bytes` (1 MiB).
///
/// **Watched red:** remove the combined-size check from `adopt_capsule_result` and
/// this cell ADOPTS — the spool's own bound is on the provider's side, and nothing
/// on the wire can stop a worker reporting a larger capture than the capsule's.
#[test]
fn a_completion_whose_captures_pass_the_combined_bound_is_refused() {
    let (dir, planes) = planes();
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    // Two VERIFIED blobs — each inside nothing the ref can lie about — whose sum
    // is over the fixture's 1 MiB `output_bytes`.
    let half_plus = usize::try_from(1_u64 << 19).unwrap() + 8;
    let stdout = publish_capture(&planes.cas, &vec![b'o'; half_plus]);
    let stderr = publish_capture(&planes.cas, &vec![b'e'; half_plus]);
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("ok", b"1")]),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("captures over the combined bound must be refused");
    assert!(
        error.to_string().contains("combined") && error.to_string().contains("output_bytes"),
        "the refusal names the bound it was measured against: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "nothing was declared — the refused frame left no artifact rows either"
    );
    drop(dir);
}

/// **An agent report whose response is under `output_bytes` but whose
/// response-plus-stderr passes it is refused — the pair shares the ONE bound
/// the worker's capture rule enforces.** A per-capture check alone would let a
/// small answer ride a large stderr; the combined check is the honest reading
/// of the worker-side rule, and a frame that violates it is a frame whose
/// bound was not enforced.
///
/// **Watched red:** check `response ≤ output_bytes` alone and this cell ADOPTS —
/// each half passes its own bound while the pair exceeds it.
#[test]
fn an_agent_response_and_stderr_over_the_shared_bound_is_refused() {
    let (dir, planes) = planes();
    let authorized = authorize_shaped(&planes, vec![0], agent_capsule);
    let before = artifact_rows(&planes.op_path);

    // Response 600 KiB — under the 1 MiB bound alone — and stderr 500 KiB,
    // pushing the sum 1_148_000 bytes past it. Both blobs are REAL and
    // verifiable: the refusal is on the arithmetic, not the bytes.
    let response = vec![b'r'; 600 * 1024];
    let stderr = publish_capture(&planes.cas, &vec![b'e'; 500 * 1024]);
    let stdout = publish_capture(&planes.cas, b"protocol chatter");
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("ok", b"1")]),
            stdout,
            stderr,
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: Some(turn_report(&planes.cas, &response, None)),
            egress_refusals: vec![],
        })
        .expect_err("response under the bound but over it WITH stderr must refuse");
    assert!(
        error.to_string().contains("combined") && error.to_string().contains("output_bytes"),
        "the refusal names the shared bound it was measured against: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "nothing was declared — the refused frame left no artifact rows either"
    );
    drop(dir);
}

// ---------------------------------------------------------------------------
// The `/work` DELTA's own set — what adoption verifies, declares, and refuses
// ---------------------------------------------------------------------------

/// **A delta of REAL CHANGES is adopted, declared `tree_delta`, and recorded.**
///
/// The fixture's `/work` base is `{seed.txt: file, shared-link: ->seed.txt}`; this
/// delta writes a new file, deletes the seed, and retargets the link. Adoption
/// must take all three kinds through `TreeDelta::apply` against the base, carry
/// the adopted delta into the output payload, and leave one `kind='tree_delta'`
/// artifacts row — read off the raw handle, like every other row claim here.
#[test]
fn a_work_delta_of_writes_deletes_and_links_is_adopted_and_recorded() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let result = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let delta = publish_delta_with_links(
        &planes.cas,
        &authorized.work_tree,
        &[("new.txt", b"new\n")],
        &[("shared-link", "new.txt")],
        &["seed.txt"],
    );

    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout,
            stderr,
            work_delta: Some(delta.clone()),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect("a delta of writes, a delete and a retargeted link applies to the base");

    let adopted_delta = adopted
        .work_delta
        .as_ref()
        .expect("the adopted result carries the delta it verified");
    assert_eq!(
        adopted_delta.entries, 3,
        "three changes: write, write, delete"
    );
    assert_eq!(adopted_delta.reference.id().0.0, delta.id().0.0);

    let kind: String = raw(&planes.op_path)
        .query_row(
            "SELECT kind FROM artifacts WHERE artifact_id = ?1",
            params![delta.id().0.0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(kind, "tree_delta", "the delta's row declares its own kind");

    // And the RECORD: the accepting output's four `work_delta_*` fields name the
    // adopted delta — the durable record of which delta this acceptance took.
    let output = kata_core::operational::capsule_result_output(
        &adopted,
        &result,
        Some(0),
        &adopted_delta.reference,
        &adopted_delta.reference,
        false,
        None,
    );
    assert_eq!(
        output["work_delta_artifact_id"],
        serde_json::json!(kata_types::primitives::ContentHash::new(delta.id().0.0).to_string())
    );
    assert_eq!(output["work_delta_entries"], serde_json::json!(3));
    drop(dir);
}

/// **A delta built over ANOTHER tree is refused — `base` is exact.**
///
/// A delta applies to exactly one base, and a delta over another tree is a
/// report of a different stage's `/work`. The refused delta is otherwise valid
/// — published, canonical, private — so the refusal names the base mismatch and
/// nothing it could have been confused with.
#[test]
fn a_delta_over_another_base_is_refused_with_nothing_declared() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let other = publish_result(&planes.cas, &[("other", b"not the /work base\n")]);
    let delta = publish_delta(&planes.cas, &other, &[], &[]);
    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(delta),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a delta over another base must be refused");
    assert!(
        error.to_string().contains("built over base artifact")
            && error
                .to_string()
                .contains(&ContentHash::new(authorized.work_tree.id().0.0).to_string()),
        "the refusal names the delta's base and the capsule's mapping: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A delta reported against a capsule that maps NO `/work` is refused.**
///
/// `None` on the frame and an absent mapping is the only honest pair; a delta
/// against no base is an invented answer.
#[test]
fn a_delta_reported_when_no_work_is_mapped_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize_shaped(&planes, vec![0], |occurrence, _| {
        capsule_without_work(occurrence)
    });
    let before = artifact_rows(&planes.op_path);

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a delta against no /work mapping is an invented answer");
    assert!(
        error.to_string().contains("maps no /work"),
        "the refusal names the missing mapping: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A capsule that maps `/work` and a frame reporting NO delta is refused.**
///
/// A mapped `/work` always produces a delta — empty when the stage changed
/// nothing — so `None` here is a frame that lost it, not a stage that made none.
#[test]
fn a_mapped_work_with_no_delta_reported_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: None,
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a mapped /work and no reported delta must be refused");
    assert!(
        error.to_string().contains("reports NO delta"),
        "the refusal names the missing delta: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A delta claimed `Public` is refused before a byte is read.**
///
/// The result's privacy rule without the empty-tree carve-out: a delta's bytes
/// embed their base reference, so even an empty delta is stage-produced
/// content, and a `Public` claim mints the second identity the plane forbids.
#[test]
fn a_public_work_delta_is_refused_before_any_byte_is_read() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);
    let delta = unchanged_delta(&planes.cas, &authorized.work_tree);
    // The SAME object claimed Public — the frame's misclassification, not a
    // different publication.
    let public_claim = ArtifactRef::new(
        delta.object_id(),
        delta.size_bytes(),
        ArtifactPrivacy::Public,
    );

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(public_claim),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a public delta must be refused");
    assert!(
        error.to_string().contains("a work delta is declared"),
        "the refusal names the privacy rule: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A delta object the store does NOT HOLD is refused.**
///
/// The frame names an object id computed over bytes never published — the
/// claim's first check, `recorded_size`, answers `None`.
#[test]
fn a_delta_object_the_store_does_not_hold_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);
    let phantom = ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(b"a delta never published"),
        42,
        ArtifactPrivacy::Private,
    );

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(phantom),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a delta naming bytes the store does not hold must be refused");
    assert!(
        error
            .to_string()
            .contains("is not held by this node's content store"),
        "the refusal names the absent object: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **Bytes that are not a `TreeDelta` are refused** — the store holds them, the
/// length is honest, and the decode fails.
#[test]
fn a_delta_object_that_does_not_decode_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);
    let not_a_delta = planes.cas.put_durable(b"{\"not\": \"a delta\"}").unwrap();
    let reference = ArtifactRef::new(
        not_a_delta.object_id(),
        not_a_delta.size(),
        ArtifactPrivacy::Private,
    );

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(reference),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("bytes that are not a tree delta must be refused");
    assert!(
        error
            .to_string()
            .contains("does not decode as a tree delta"),
        "the refusal names the decode: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A delta whose `Write` member the store does not hold is refused** — the
/// member check: declaring a delta over an absent member would record a promise
/// about bytes that are not there.
#[test]
fn a_delta_member_the_store_does_not_hold_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);
    // A delta naming a member object never published — built by hand so the
    // member publication is the thing that did not happen.
    let absent = kata_types::cache::object_id_for_canonical_bytes(b"absent member bytes");
    let delta = TreeDelta::new(
        authorized.work_tree.clone(),
        vec![TreeChange {
            path: TreePath::new("ghost.txt").unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: absent,
                    size_bytes: 7,
                },
            },
        }],
    )
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&delta.delta_bytes().unwrap())
        .unwrap();
    let reference = ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    );

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(reference),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a delta over an absent member must be refused");
    assert!(
        error.to_string().contains("delta member absent"),
        "the refusal names the absent member: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A delta member whose declared length disagrees with the store is refused**
/// — every bound is computed over the delta's own numbers, so a member that lies
/// about its length passes `work_delta_bytes` while occupying whatever it likes.
#[test]
fn a_mismeasured_delta_member_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);
    let member = planes.cas.put_durable(b"six").unwrap();
    let delta = TreeDelta::new(
        authorized.work_tree.clone(),
        vec![TreeChange {
            path: TreePath::new("lied.txt").unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: member.object_id(),
                    // The store holds 3 bytes; the delta claims 9 — inside every
                    // bound, over the truth.
                    size_bytes: 9,
                },
            },
        }],
    )
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&delta.delta_bytes().unwrap())
        .unwrap();
    let reference = ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    );

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(reference),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a mis-measured delta member must be refused");
    assert!(
        error.to_string().contains("delta member mis-measured"),
        "the refusal names the measurement: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A delta that does not APPLY to the mapped base is refused** — `Delete` of
/// an absent path is `TreeDelta::apply`'s own verdict, relayed verbatim.
#[test]
fn a_delta_that_does_not_apply_to_the_base_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize(&planes);
    let before = artifact_rows(&planes.op_path);
    // `gone.txt` is not in the base — the delta is canonical, decodable, over
    // the right base, and still unadoptable.
    let delta = publish_delta(&planes.cas, &authorized.work_tree, &[], &["gone.txt"]);

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(delta),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a delta that does not apply must be refused");
    assert!(
        error
            .to_string()
            .contains("does not apply to the tree the capsule mapped"),
        "the refusal relays apply's verdict: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A delta over the capsule's `work_delta_entries` promise is refused** — the
/// bound read off the AUTHORIZED CAPSULE's bytes, as every capsule bound is.
#[test]
fn a_delta_over_its_entries_bound_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize_shaped(&planes, vec![0], |occurrence, work| {
        capsule_with_delta_bounds(occurrence, work, 0, 1 << 20)
    });
    let before = artifact_rows(&planes.op_path);
    let delta = publish_delta(
        &planes.cas,
        &authorized.work_tree,
        &[("new.txt", b"new\n")],
        &[],
    );

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(delta),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a delta over the promised change count must be refused");
    assert!(
        error.to_string().contains("carries 1 changes")
            && error.to_string().contains("promised at most 0"),
        "the refusal names the count and the bound: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

/// **A delta over the capsule's `work_delta_bytes` promise is refused** — the
/// `Write`-carried bytes measured against the capsule's own bound.
#[test]
fn a_delta_over_its_bytes_bound_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize_shaped(&planes, vec![0], |occurrence, work| {
        capsule_with_delta_bounds(occurrence, work, 64, 4)
    });
    let before = artifact_rows(&planes.op_path);
    let delta = publish_delta(
        &planes.cas,
        &authorized.work_tree,
        &[("big.txt", b"this write is over the four-byte promise")],
        &[],
    );

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(delta),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a delta over the promised bytes must be refused");
    assert!(
        error.to_string().contains("written members total")
            && error.to_string().contains("promised at most 4"),
        "the refusal names the measurement and the bound: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

// ---------------------------------------------------------------------------
// The agent turn's settlement
// ---------------------------------------------------------------------------

/// An `Agent` capsule shape for `authorize_shaped` — the turn spec's adapter,
/// argv, model and prompt are arbitrary; the adoption's own checks verify the
/// REPORT echoes them.
fn agent_capsule(
    occurrence: kata_types::execution_contract::OccurrenceId,
    work: ArtifactId,
) -> Capsule {
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
            model: Some("vendor/small".into()),
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(ContentHash::new([0x51; 32])),
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
            result_bytes: BOUND_BYTES,
            result_entries: BOUND_ENTRIES,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap()
}

/// A turn report over a published response blob — the worker's frame band —
/// with a published (empty) session-evidence blob, which a completed agent
/// turn always carries.
fn turn_report(
    cas: &CasStore,
    response: &[u8],
    usage: Option<kata_types::metering::StageUsage>,
) -> kata_types::agent::AgentTurnReport {
    let durable = cas.put_durable(response).unwrap();
    let evidence = cas
        .put_durable(
            &serde_json::to_vec(&kata_types::agent::SessionEvidence {
                events: vec![],
                events_dropped: 0,
                scratch_commits: vec![],
            })
            .unwrap(),
        )
        .unwrap();
    kata_types::agent::AgentTurnReport {
        response: ArtifactRef::new(
            durable.object_id(),
            durable.size(),
            ArtifactPrivacy::Private,
        ),
        adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
        model_reported: Some(smol_str::SmolStr::new("vendor/small")),
        usage,
        session_evidence: Some(ArtifactRef::new(
            evidence.object_id(),
            evidence.size(),
            ArtifactPrivacy::Private,
        )),
        stop_reason: None,
    }
}

/// **An agent capsule's completion is adopted with the RESPONSE as its
/// content, the usage folded, and the adapter/model echoed through the
/// `agent` band** — and the response blob is declared execution-owned beside
/// the result, read raw.
#[test]
fn an_agent_capsule_completion_is_adopted_with_the_response_as_its_content() {
    let (dir, planes) = planes();
    let authorized = authorize_shaped(&planes, vec![0], agent_capsule);
    let stdout = publish_capture(&planes.cas, b"protocol chatter");
    let stderr = publish_capture(&planes.cas, b"vendor stderr");
    let usage = kata_types::metering::StageUsage {
        input: 1200,
        output: 80,
        cache_read: 0,
        cache_write: 0,
        cache_savings_micro_usd: 0,
        cost: kata_types::metering::MeteredCost::Estimated {
            micro_usd: 4_200,
            basis: kata_types::metering::EstimateBasis::OperatorOverride,
        },
        cost_micro_usd: Some(4_200),
    };
    let report = turn_report(&planes.cas, b"done", Some(usage.clone()));
    let result = publish_result(&planes.cas, &[("note", b"written by the turn")]);
    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: Some(report.clone()),
            egress_refusals: vec![],
        })
        .expect("an agent capsule's completion is adopted");

    // THE TURN — the adopted band carries the verified response bytes, the
    // usage facts, and the adapter/model echo.
    let agent = adopted
        .agent
        .as_ref()
        .expect("an Agent capsule's adoption carries its turn");
    assert_eq!(agent.response, b"done");
    assert_eq!(
        agent.adapter,
        kata_types::agent::AdapterKind::NanocodeOpenai
    );
    assert_eq!(agent.model_reported.as_deref(), Some("vendor/small"));
    assert_eq!(agent.usage, Some(usage));
    assert_eq!(agent.reference, report.response);

    // THE ENVELOPE — `content` is the RESPONSE's bytes, `token_usage` the
    // metered fold, `agent` the band's echo.
    let output = kata_core::operational::capsule_result_output(
        &adopted,
        &result,
        Some(0),
        &stdout,
        &stderr,
        false,
        None,
    );
    assert_eq!(output["content"], "done");
    assert_eq!(output["token_usage"]["input"], 1200);
    assert_eq!(output["token_usage"]["output"], 80);
    assert_eq!(output["agent"]["adapter"], "nanocode_openai");
    assert_eq!(output["agent"]["model_reported"], "vendor/small");

    // The response blob is DECLARED execution-owned — the response's retention
    // is the stage's, not a worker claim's.
    let owner: Option<Vec<u8>> = raw(&planes.op_path)
        .query_row(
            "SELECT owner_execution_id FROM cas_roots
              WHERE purpose = 'artifact_object' AND object_digest = ?1
                AND released_at_ms IS NULL",
            params![report.response.object_id().0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        owner,
        Some(authorized.execution_id.to_bytes().to_vec()),
        "the response is retained under the execution's own cas_root"
    );
    drop(dir);
}

/// **A vendor that reported no usage still adopts** — the `usage` band is
/// `None`, and the envelope's `token_usage` is the UNMETERED shape naming the
/// adapter, never an invented zero.
#[test]
fn an_agent_capsule_with_no_reported_usage_adopts_unmetered_never_zero() {
    let (dir, planes) = planes();
    let authorized = authorize_shaped(&planes, vec![0], agent_capsule);
    let stdout = publish_capture(&planes.cas, b"");
    let stderr = publish_capture(&planes.cas, b"");
    let report = turn_report(&planes.cas, b"done", None);
    let result = publish_result(&planes.cas, &[]);
    let adopted = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: Some(report),
            egress_refusals: vec![],
        })
        .expect("a report without usage is still a report");

    let agent = adopted.agent.as_ref().expect("the turn is carried");
    assert!(agent.usage.is_none());
    let output = kata_core::operational::capsule_result_output(
        &adopted,
        &result,
        Some(0),
        &stdout,
        &stderr,
        false,
        None,
    );
    let token_usage = &output["token_usage"];
    assert_eq!(
        token_usage["cost"]["quality"], "unavailable",
        "an unmeasured turn is `Unavailable`, never an estimated zero: {token_usage}"
    );
    assert_eq!(
        token_usage["cost"]["backend"], "nanocode_openai",
        "the unpriced call still names its backend: {token_usage}"
    );
    assert!(
        token_usage.get("cost_micro_usd").is_none() || token_usage["cost_micro_usd"].is_null(),
        "an unavailable cost has no micro-USD figure to sum: {token_usage}"
    );
    assert_eq!(token_usage["input"], 0);
    drop(dir);
}

/// **The refused set at the adoption door:** an agent report on a `Command`
/// capsule, a missing report on an `Agent` capsule, and a report echoing an
/// adapter or model the capsule never declared — each refused by its own
/// reason before anything declares.
#[test]
fn the_agent_band_is_refused_unless_it_echoes_the_capsules_own_turn() {
    // Command capsule + a report — a claim no command can produce.
    let (dir1, planes1) = planes();
    let authorized = authorize(&planes1);
    let stdout = publish_capture(&planes1.cas, b"");
    let stderr = publish_capture(&planes1.cas, b"");
    let result = publish_result(&planes1.cas, &[]);
    let refusal = planes1
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: result.clone(),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            work_delta: Some(unchanged_delta(&planes1.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: Some(turn_report(&planes1.cas, b"done", None)),
            egress_refusals: vec![],
        })
        .expect_err("a report on a Command capsule is refused")
        .to_string();
    assert!(
        refusal.contains("no command capsule can produce"),
        "refused by its own reason: {refusal}"
    );
    drop(dir1);

    // Agent capsule + NO report — a completion it cannot describe.
    let (dir2, planes2) = planes();
    let authorized = authorize_shaped(&planes2, vec![0], agent_capsule);
    let refusal = planes2
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes2.cas, &[]),
            stdout: publish_capture(&planes2.cas, b""),
            stderr: publish_capture(&planes2.cas, b""),
            work_delta: Some(unchanged_delta(&planes2.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a missing report on an Agent capsule is refused")
        .to_string();
    assert!(
        refusal.contains("no agent report"),
        "refused by its own reason: {refusal}"
    );

    // An agent report naming ANOTHER adapter is refused — the adapter is
    // kata's own claim about which protocol ran the turn.
    let refusal = planes2
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes2.cas, &[]),
            stdout: publish_capture(&planes2.cas, b""),
            stderr: publish_capture(&planes2.cas, b""),
            work_delta: Some(unchanged_delta(&planes2.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: Some(kata_types::agent::AgentTurnReport {
                adapter: kata_types::agent::AdapterKind::NanocodeAnthropic,
                ..turn_report(&planes2.cas, b"done", None)
            }),
            egress_refusals: vec![],
        })
        .expect_err("a report echoing a different adapter is refused")
        .to_string();
    assert!(
        refusal.contains("adapter") && refusal.contains("a claim nobody made"),
        "adapter: refused by its own reason: {refusal}"
    );

    // A `model_reported` DIFFERENT from the requested one is adopted — the
    // field is the vendor's own wire statement, and a vendor that rerouted
    // the model is reporting evidence, not minting a claim. The requested
    // model lives in capsule identity; the report answers "what actually ran".
    let adopted = planes2
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes2.cas, &[]),
            stdout: publish_capture(&planes2.cas, b""),
            stderr: publish_capture(&planes2.cas, b""),
            work_delta: Some(unchanged_delta(&planes2.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: Some(kata_types::agent::AgentTurnReport {
                model_reported: Some(smol_str::SmolStr::new("vendor/other")),
                ..turn_report(&planes2.cas, b"done", None)
            }),
            egress_refusals: vec![],
        })
        .expect("a vendor-reported model that differs from the request is adopted");
    assert_eq!(
        adopted
            .agent
            .as_ref()
            .and_then(|agent| agent.model_reported.as_deref()),
        Some("vendor/other"),
        "the band records the vendor's report verbatim"
    );
    drop(dir2);
}

/// **An agent report without session evidence is refused** — the grant and
/// refusal record cannot die with the session — and an evidence ref the CAS
/// cannot verify is refused the same way the response's is.
#[test]
fn an_agent_report_without_session_evidence_is_refused() {
    let (dir2, planes2) = planes();
    let authorized = authorize_shaped(&planes2, vec![0], agent_capsule);

    // `None` on the field — the report claims a completed turn whose record
    // died with the session.
    let refusal = planes2
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes2.cas, &[]),
            stdout: publish_capture(&planes2.cas, b""),
            stderr: publish_capture(&planes2.cas, b""),
            work_delta: Some(unchanged_delta(&planes2.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: Some(kata_types::agent::AgentTurnReport {
                session_evidence: None,
                stop_reason: None,
                ..turn_report(&planes2.cas, b"done", None)
            }),
            egress_refusals: vec![],
        })
        .expect_err("a report naming no evidence is refused")
        .to_string();
    assert!(
        refusal.contains("session evidence"),
        "refused by its own reason: {refusal}"
    );

    // An evidence ref no CAS object verifies against — same verdict as a
    // response the store cannot derive.
    let refusal = planes2
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes2.cas, &[]),
            stdout: publish_capture(&planes2.cas, b""),
            stderr: publish_capture(&planes2.cas, b""),
            work_delta: Some(unchanged_delta(&planes2.cas, &authorized.work_tree)),
            capture_exceeded: false,
            agent: Some(kata_types::agent::AgentTurnReport {
                session_evidence: Some(ArtifactRef::new(
                    kata_types::primitives::FixedBytes([0xee; 32]),
                    4,
                    ArtifactPrivacy::Private,
                )),
                ..turn_report(&planes2.cas, b"done", None)
            }),
            egress_refusals: vec![],
        })
        .expect_err("an evidence ref the store cannot verify is refused")
        .to_string();
    assert!(
        refusal.contains("session evidence"),
        "refused by its own reason: {refusal}"
    );
    drop(dir2);
}

/// **The session-evidence claim is written INSIDE the accepting transaction,
/// and the row the operator surfaces project is read back off this plane's own
/// evidence store** — the durable half of "the operator can find the blob".
///
/// The row names the stage off THIS node's `attempts` row (never the frame),
/// the adapter and vendor-reported model verbatim, and the Private-CAS triple
/// `capsule_result_output` spells — and the object it names is read back off
/// the CAS and parsed as `SessionEvidence`, so the claim is a name for bytes
/// that exist, not a label for a hole.
#[test]
fn an_accepted_agent_turn_names_its_session_evidence_on_the_evidence_rows() {
    let (dir, planes) = planes();
    let authorized = authorize_shaped(&planes, vec![0], agent_capsule);
    let stdout = publish_capture(&planes.cas, b"protocol chatter");
    let stderr = publish_capture(&planes.cas, b"vendor stderr");
    let report = turn_report(&planes.cas, b"done", None);
    let result = publish_result(&planes.cas, &[("note", b"written by the turn")]);
    let (_, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id: authorized.execution_id,
                occurrence_id: authorized.occurrence_id,
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
                capture_exceeded: false,
                agent: Some(report.clone()),
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id: authorized.execution_id,
                attempt_id: authorized.attempt_id,
                attempt_ordinal: authorized.attempt_ordinal,
                lease_epoch: 0,
                worker_id: "w-1".to_string(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    Some(0),
                    &stdout,
                    &stderr,
                    false,
                    None,
                ),
            },
        )
        .expect("the agent turn's completion is accepted");
    assert!(matches!(
        verdict,
        kata_core::operational::CompletionVerdict::Accepted { .. }
    ));

    // The durable row, read back through the plane's own evidence reader — the
    // SAME rows `execution_evidence_records` serves the record projection.
    let rows = planes
        .db
        .execution_evidence_for(authorized.execution_id)
        .expect("the evidence rows read");
    let turns: Vec<_> = rows
        .iter()
        .flat_map(|row| row.evidence.agent_turns.iter())
        .collect();
    assert_eq!(turns.len(), 1, "one accepted turn names one row");
    let turn = turns[0];
    assert_eq!(turn.stage_id, STAGE, "the stage comes off the attempts row");
    assert_eq!(turn.attempt_id, authorized.attempt_id.to_string());
    assert_eq!(turn.adapter, "nanocode_openai");
    assert_eq!(turn.model_reported.as_deref(), Some("vendor/small"));
    let evidence_ref = report
        .session_evidence
        .as_ref()
        .expect("the report names its evidence blob");
    assert_eq!(
        turn.session_evidence_artifact_id,
        ContentHash::new(evidence_ref.id().0.0).to_string(),
    );
    assert_eq!(
        turn.session_evidence_object_id,
        evidence_ref.object_id().to_string(),
    );
    assert_eq!(turn.session_evidence_size_bytes, evidence_ref.size_bytes());

    // The name is for bytes that EXIST: the object the row names is read off
    // the CAS and parses as the session's own record — the blob an operator
    // fetching `session_evidence_object_id` would get.
    let blob = planes
        .cas
        .get(&evidence_ref.object_id())
        .expect("the CAS reads")
        .expect("the named object is held");
    let record: kata_types::agent::SessionEvidence =
        serde_json::from_slice(&blob).expect("the named blob is the session's record");
    assert!(record.events.is_empty());
    assert_eq!(record.events_dropped, 0);
    drop(dir);
}

/// **No reader kata runs decodes a stored session-evidence blob**: the
/// adoption verifies the blob's privacy, size and hash and stores its bytes,
/// and the evidence row names it by its CAS triple — nothing parses its
/// events. So a blob in the retired vocabulary — the bytes a worker built
/// before the `auth_status` event left [`kata_types::agent::SessionEvidenceEvent`]
/// wrote for a claude-agent-acp turn, which today's type refuses at decode — is
/// adopted, accepted and named exactly as a current one, its bytes held
/// unchanged. Read through the second raw handle on `operational.db` and on
/// `cas.db`, not through the plane's readers.
///
/// **Would red if:** the adoption or the evidence-row write decoded the blob
/// as `SessionEvidence` (the completion is refused, or no row names it).
#[test]
fn a_session_evidence_blob_in_a_retired_vocabulary_is_adopted_and_named_undecoded() {
    let (dir, planes) = planes();
    let authorized = authorize_shaped(&planes, vec![0], agent_capsule);
    let stdout = publish_capture(&planes.cas, b"protocol chatter");
    let stderr = publish_capture(&planes.cas, b"vendor stderr");
    let retired: &[u8] = br#"{"events":[{"event":"auth_status","kind":"none"}],"events_dropped":0,"scratch_commits":[],"credential_refreshes":[]}"#;
    let refusal = serde_json::from_slice::<kata_types::agent::SessionEvidence>(retired)
        .expect_err("today's vocabulary refuses the retired event")
        .to_string();
    assert!(
        refusal.contains("unknown variant `auth_status`"),
        "{refusal}"
    );
    let held = planes.cas.put_durable(retired).unwrap();
    let evidence_ref = ArtifactRef::new(held.object_id(), held.size(), ArtifactPrivacy::Private);
    let mut report = turn_report(&planes.cas, b"done", None);
    report.session_evidence = Some(evidence_ref.clone());
    let result = publish_result(&planes.cas, &[("note", b"written by the turn")]);
    let (_, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id: authorized.execution_id,
                occurrence_id: authorized.occurrence_id,
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
                capture_exceeded: false,
                agent: Some(report.clone()),
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id: authorized.execution_id,
                attempt_id: authorized.attempt_id,
                attempt_ordinal: authorized.attempt_ordinal,
                lease_epoch: 0,
                worker_id: "w-1".to_string(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    Some(0),
                    &stdout,
                    &stderr,
                    false,
                    None,
                ),
            },
        )
        .expect("a blob in the retired vocabulary is adopted: nothing decodes it");
    assert!(matches!(
        verdict,
        kata_core::operational::CompletionVerdict::Accepted { .. }
    ));

    let object_id = evidence_ref.object_id().to_string();
    let rows: Vec<Vec<u8>> = raw(&planes.op_path)
        .prepare("SELECT evidence_json FROM execution_evidence WHERE execution_id = ?1")
        .unwrap()
        .query_map(
            params![authorized.execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let named: Vec<String> = rows
        .iter()
        .flat_map(|json| {
            let row: serde_json::Value = serde_json::from_slice(json).unwrap();
            row["evidence"]["agent_turns"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|turn| {
                    turn["session_evidence_object_id"]
                        .as_str()
                        .map(str::to_owned)
                })
        })
        .collect();
    assert_eq!(named, vec![object_id], "the row names the blob by its id");
    let (storage, bytes): (String, Option<Vec<u8>>) = raw(&dir.path().join("cas.db"))
        .query_row(
            "SELECT storage, blob FROM cas_objects WHERE object_id = ?1",
            params![evidence_ref.object_id().0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(storage, "inline", "a blob this small is held inline");
    assert_eq!(
        bytes.as_deref(),
        Some(retired),
        "the bytes are held unchanged"
    );
    drop(dir);
}

/// **The other half of the door's claim:** a completion a settlement beat to
/// the lock records NO agent-turn row — the name is a fact about an accepted
/// turn, never a name that survives its attempt being declined.
#[test]
fn a_superseded_agent_completion_names_no_session_evidence() {
    let (dir, planes) = planes();
    let authorized = authorize_shaped(&planes, vec![0], agent_capsule);
    // The settlement wins first — the attempt is terminal before the frame's
    // result is ever read.
    planes
        .db
        .record_main_side_transition_if_live(
            authorized.attempt_id,
            &kata_core::operational::MainSideTransition {
                reason: Some("a racing sweep"),
                ..kata_core::operational::MainSideTransition::bare("failed")
            },
        )
        .unwrap()
        .expect("the settlement lands while the attempt is live");
    let stdout = publish_capture(&planes.cas, b"");
    let stderr = publish_capture(&planes.cas, b"");
    let result = publish_result(&planes.cas, &[]);
    let verdict = planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id: authorized.execution_id,
                occurrence_id: authorized.occurrence_id,
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(unchanged_delta(&planes.cas, &authorized.work_tree)),
                capture_exceeded: false,
                agent: Some(turn_report(&planes.cas, b"done", None)),
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id: authorized.execution_id,
                attempt_id: authorized.attempt_id,
                attempt_ordinal: authorized.attempt_ordinal,
                lease_epoch: 0,
                worker_id: "w-1".to_string(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    Some(0),
                    &stdout,
                    &stderr,
                    false,
                    None,
                ),
            },
        )
        .map(|(_, verdict)| verdict)
        .expect("the door answers, adopting nothing");
    assert!(matches!(
        verdict,
        kata_core::operational::CompletionVerdict::Superseded
    ));
    let rows = planes
        .db
        .execution_evidence_for(authorized.execution_id)
        .expect("the evidence rows read");
    assert!(
        rows.iter().all(|row| row.evidence.agent_turns.is_empty()),
        "a completion nobody accepted names no turn's evidence"
    );
    drop(dir);
}

/// **A SCRATCH `/work` delta is EVIDENCE, never an applied mutation.**
///
/// A `read_write_scratch` `/work` maps an ephemeral root: the delta the stage
/// wrote is verified against the mapped artifact exactly as a workspace delta
/// is — but the adopted record binds it under `scratch_delta_*`, `work_delta_*`
/// stays null, and `pending_work_apply_for_stage` never schedules it: there is
/// no durable head behind an ephemeral tree for an apply to land on. The
/// positive arm — a `read_write` delta DOES surface to the sweep — is the
/// `crates/core/tests/work_apply.rs` cells'; this cell is the scratch twin.
#[test]
fn a_scratch_work_delta_is_evidence_and_is_never_scheduled() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    // The SCRATCH capsule: `capsule()`'s shape with `ReadWriteScratch` access
    // at /work. The fixture's declared seed tree stands in for the canonical
    // empty tree production maps at a scratch /work — the disposition this
    // cell proves is the access TAG's, and the delta's `base` is the mapped
    // artifact either way.
    let authorized = authorize_shaped(&planes, vec![0], |occurrence, work| {
        Capsule::new(
            occurrence,
            PreparedActionId(ContentHash::new([0x02; 32])),
            EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
            PlatformId(ContentHash::new([0x04; 32])),
            vec![GuestMapping {
                artifact: work,
                guest_path: GuestPath::new("/work").unwrap(),
                access: GuestAccess::ReadWriteScratch,
            }],
            CapsuleProcess::Command {
                argv: vec!["sh".into(), "-c".into(), "echo hi > /out/hi".into()],
            },
            CapsuleNetwork::Offline,
            None,
            CapsuleBudgets {
                wall_time_ms: 30_000,
                output_bytes: 1 << 20,
                memory_bytes: 512 * 1024 * 1024,
                process_count: 64,
                result_bytes: BOUND_BYTES,
                result_entries: BOUND_ENTRIES,
                work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
                work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
            },
            None,
        )
        .unwrap()
    });
    let result = publish_result(&planes.cas, &[("hi", b"hi\n")]);
    let delta = publish_delta(
        &planes.cas,
        &authorized.work_tree,
        &[("new.txt", b"new\n")],
        &[],
    );

    let (adopted, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id: authorized.execution_id,
                occurrence_id: authorized.occurrence_id,
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(delta.clone()),
                capture_exceeded: false,
                agent: None,
                egress_refusals: vec![],
            },
            completion_for(&authorized, &result, &stdout, &stderr),
        )
        .expect("a scratch capsule's completion adopts and accepts");
    assert!(
        matches!(
            verdict,
            kata_core::operational::CompletionVerdict::Accepted { .. }
        ),
        "the first completion is accepted: {verdict:?}"
    );

    // THE DISPOSITION — read off the adopted delta, not the output keys.
    let adopted_delta = adopted
        .work_delta
        .as_ref()
        .expect("the adopted result carries the delta it verified");
    assert_eq!(
        adopted_delta.disposition,
        kata_core::operational::WorkDeltaDisposition::Scratch,
        "a read_write_scratch /work binds its delta as scratch evidence"
    );

    // THE RECORD — `scratch_delta_*` names the delta; `work_delta_*` stays null.
    let output = kata_core::operational::capsule_result_output(
        &adopted,
        &result,
        Some(0),
        &stdout,
        &stderr,
        false,
        None,
    );
    assert_eq!(
        output["scratch_delta_artifact_id"],
        serde_json::json!(kata_types::primitives::ContentHash::new(delta.id().0.0).to_string())
    );
    assert_eq!(output["scratch_delta_entries"], serde_json::json!(1));
    assert!(
        output["work_delta_artifact_id"].is_null() && output["work_delta_entries"].is_null(),
        "no work_delta_* key is minted for a scratch root: {output}"
    );

    // THE SWEEP — the committed transition's payload carries no
    // `work_delta_artifact_id`, so the apply question answers false for this
    // stage forever.
    assert!(
        !planes
            .db
            .pending_work_apply_for_stage(authorized.execution_id, STAGE)
            .unwrap(),
        "a scratch delta is never scheduled for application"
    );
    drop(dir);
}

/// **A `ReadOnly` /work reporting a delta is refused by name.**
///
/// The capsule contract's only /work forms are the writable workspace
/// (`ReadWrite`) and the writable scratch (`ReadWriteScratch`) — assembly mints
/// no other. A `ReadOnly` /work is a mount the stage cannot write, so a delta
/// reported against it is neither a workspace mutation the apply sweep may land
/// nor the scratch evidence a `read_write_scratch` mapping declares: the
/// disposition arm refuses it, after the delta itself has passed every byte
/// check. The refused set is exactly `{ReadOnly /work, Some(delta)}` — the
/// `None` arm is caught earlier by the missing-delta refusal.
#[test]
fn a_read_only_work_reporting_a_delta_is_refused() {
    let (dir, planes) = planes();
    let stdout = publish_capture(&planes.cas, b"the stdout bytes");
    let stderr = publish_capture(&planes.cas, b"the stderr bytes");
    let authorized = authorize_shaped(&planes, vec![0], |occurrence, work| {
        Capsule::new(
            occurrence,
            PreparedActionId(ContentHash::new([0x02; 32])),
            EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
            PlatformId(ContentHash::new([0x04; 32])),
            vec![GuestMapping {
                artifact: work,
                guest_path: GuestPath::new("/work").unwrap(),
                access: GuestAccess::ReadOnly,
            }],
            CapsuleProcess::Command {
                argv: vec!["sh".into(), "-c".into(), "echo hi > /out/hi".into()],
            },
            CapsuleNetwork::Offline,
            None,
            CapsuleBudgets {
                wall_time_ms: 30_000,
                output_bytes: 1 << 20,
                memory_bytes: 512 * 1024 * 1024,
                process_count: 64,
                result_bytes: BOUND_BYTES,
                result_entries: BOUND_ENTRIES,
                work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
                work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
            },
            None,
        )
        .unwrap()
    });
    let before = artifact_rows(&planes.op_path);
    let delta = publish_delta(
        &planes.cas,
        &authorized.work_tree,
        &[("new.txt", b"new\n")],
        &[],
    );

    let error = planes
        .db
        .adopt_capsule_result(&CapsuleResultAdoption {
            execution_id: authorized.execution_id,
            occurrence_id: authorized.occurrence_id,
            result: publish_result(&planes.cas, &[("hi", b"hi\n")]),
            stdout,
            stderr,
            work_delta: Some(delta),
            capture_exceeded: false,
            agent: None,
            egress_refusals: vec![],
        })
        .expect_err("a delta against a read-only /work must be refused");
    assert!(
        error.to_string().contains("maps /work READ-ONLY"),
        "the refusal names the access the capsule claimed: {error}"
    );
    assert_eq!(
        artifact_rows(&planes.op_path),
        before,
        "NOTHING was declared"
    );
    drop(dir);
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "operational_capsule_result/capsule_result_envelope.rs"]
mod capsule_result_envelope;
