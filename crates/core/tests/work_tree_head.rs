//! The `execution_work_tree_heads` plane and
//! [`publish_base_tree_head`]'s publish-declare-record shape, observed through
//! a SECOND raw rusqlite handle and the CAS's own `cas_objects`/`cas_roots`
//! rows, never through the plane under test.
//!
//! # Invariant
//!
//! The head is write-once by PRIMARY KEY plus `record_work_tree_head`'s
//! converge-or-refuse: an identical re-record is re-admission converging, a
//! divergent one is `work_tree_head_divergent`. Publication puts the members
//! into CAS, publishes the manifest after them, and declares
//! the tree execution-retained BEFORE the head row commits — the
//! `after_base_tree_published_before_head_recorded` window's near edge. The
//! crash half of that window lives in `cas_root_liveness.rs` (K16), which owns
//! the CAS/nucleus join; this file owns the row semantics and the re-drive.

use std::path::Path;
use std::sync::Arc;

use kata_core::operational::{
    JoinFanIn, JoinFanInInput, MainAttemptSpec, MainClaimAndResolveOutcome, MainOperation,
    MainResolution, OccurrenceBinding, WORK_FANIN_CONFLICT, WORK_TREE_HEAD_DIVERGENT,
    WORK_TREE_HEAD_UNRECORDED, WorkApplyClaimOutcome, WorkTreeHeadAdvance,
};
use kata_core::store::cas::CasStore;
use kata_core::work_tree::publish_base_tree_head;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::execution_contract::{
    OccurrenceRef, OperationContractId, OperationPath, work_apply_operation_contract,
    work_apply_stage_id,
};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::tree_artifact::{
    CommittedBaseTree, SymlinkTarget, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
};
use kata_types::tree_delta::TreeDelta;
use kata_types::work_tree_head::WorkTreeHeadCoordinate;
use ulid::Ulid;

/// THE SECOND HANDLE. Read-only on purpose: an observer that can write is an
/// observer that can repair what it was meant to catch.
fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

fn program() -> ProgramRecord {
    let program_hash = ContentHash::new([0xD1; 32]);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
            "program": 1,
        })),
    }
}

fn invocation() -> InvocationRecord {
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
        "inputs": [1],
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

struct Rig {
    dir: tempfile::TempDir,
    db: OperationalDb,
    cas: Arc<CasStore>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap());
    // The fan-in reads head manifests through the bound store: bind it at open,
    // the way the node's db is opened.
    let db =
        OperationalDb::open_with_cas(dir.path().join("operational.db"), Arc::clone(&cas)).unwrap();
    Rig { dir, db, cas }
}

fn submit(rig: &Rig, execution: Ulid) {
    match rig
        .db
        .submit_execution(execution, &program(), &invocation())
        .unwrap()
    {
        SubmitOutcome::Submitted { .. } | SubmitOutcome::AlreadySubmitted => {}
    }
}

/// Declare a REAL `kind='tree'` artifact for `execution` and return its id —
/// `execution_work_tree_heads.work_tree_artifact_id` references `artifacts`,
/// so a head may only ever name a declared row.
fn declare_tree(rig: &Rig, execution: Ulid) -> [u8; 32] {
    let manifest = TreeManifest::new(Vec::new()).unwrap();
    let bytes = manifest.manifest_bytes().unwrap();
    let durable = rig.cas.put_durable(&bytes).unwrap();
    let declaration = kata_core::operational::ArtifactDeclaration::for_durable_tree(
        &manifest,
        kata_types::execution_contract::ArtifactPrivacy::Public,
        kata_core::operational::CasRootOwner::Execution(execution),
        &durable,
    )
    .unwrap();
    rig.db.declare_artifact(&declaration).unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        kata_types::execution_contract::ArtifactPrivacy::Public,
    )
    .id()
    .0
    .0
}

/// The head row's columns through the RAW handle — the cell's witness is the
/// row itself, not `execution_work_tree_head`'s reading of it.
fn raw_head(path: &Path, execution: Ulid) -> Option<(String, Vec<u8>, i64, String)> {
    use rusqlite::OptionalExtension as _;
    raw(path)
        .query_row(
            "SELECT base_commit, work_tree_artifact_id, recorded_at_ms, candidate_commit_id \
             FROM execution_work_tree_heads WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .expect("a head row read")
}

/// The member/object counts the publish produced, through the raw handle.
fn raw_counts(path: &Path, execution: Ulid) -> (i64, i64, i64) {
    let conn = raw(path);
    let heads: i64 = conn
        .query_row("SELECT count(*) FROM execution_work_tree_heads", [], |r| {
            r.get(0)
        })
        .unwrap();
    let artifacts: i64 = conn
        .query_row(
            "SELECT count(*) FROM artifacts WHERE kind = 'tree'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let roots: i64 = conn
        .query_row(
            "SELECT count(*) FROM cas_roots WHERE owner_execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    (heads, artifacts, roots)
}

/// The `put_member` callback shape `publish_base_tree_head` hands the
/// conversion — the VCS provider trait's exact signature, spelled once.
type PutMember<'a> =
    dyn FnMut(&[u8]) -> kata_types::KataResult<kata_types::primitives::ObjectId> + 'a;

/// A synthetic committed-base conversion — the shape `kata_vcs`'s provider
/// returns — over one regular file, one executable, one symlink. The members
/// are streamed through `put_member`, whose return IS the object the manifest
/// declares, exactly as the production publish wires it.
fn synthetic_convert(
    base_commit: &str,
    files: &[(&str, &[u8], bool)],
    links: &[(&str, &str)],
) -> impl FnOnce(&mut PutMember<'_>) -> kata_types::KataResult<CommittedBaseTree> {
    let files: Vec<(String, Vec<u8>, bool)> = files
        .iter()
        .map(|(p, b, x)| ((*p).to_owned(), b.to_vec(), *x))
        .collect();
    let links: Vec<(String, String)> = links
        .iter()
        .map(|(p, t)| ((*p).to_owned(), (*t).to_owned()))
        .collect();
    let base_commit = base_commit.to_owned();
    move |put_member| {
        let mut entries = Vec::new();
        for (path, bytes, executable) in &files {
            let object = put_member(bytes)?;
            entries.push(TreeEntry {
                path: TreePath::new(path).unwrap(),
                node: TreeNode::File {
                    mode: if *executable {
                        TreeEntryMode::Executable
                    } else {
                        TreeEntryMode::Regular
                    },
                    object,
                    size_bytes: bytes.len() as u64,
                },
            });
        }
        for (path, target) in &links {
            entries.push(TreeEntry {
                path: TreePath::new(path).unwrap(),
                node: TreeNode::Symlink {
                    target: SymlinkTarget::new(target.clone()).unwrap(),
                },
            });
        }
        let manifest = TreeManifest::new(entries).unwrap();
        let manifest_bytes = manifest.manifest_bytes().unwrap();
        let candidate_commit_id = format!("{base_commit}wc");
        Ok(CommittedBaseTree {
            base_commit,
            manifest,
            manifest_bytes,
            candidate_commit_id,
        })
    }
}

/// Record → read → re-record. The row is what was written, verbatim, and an
/// IDENTICAL restatement converges to the stored row rather than a second row —
/// the idempotent half of re-admission.
#[test]
fn a_recorded_head_reads_back_and_an_identical_restatement_converges() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let artifact = declare_tree(&rig, execution);

    let head = rig
        .db
        .record_work_tree_head(execution, "abc123", artifact, "wc111")
        .expect("the first record lands");

    // Read through the RAW handle: the row is the execution's, its commit and
    // artifact as recorded, and exactly one of it.
    let (commit, stored_artifact, _, candidate) =
        raw_head(&rig.dir.path().join("operational.db"), execution).expect("the head row exists");
    assert_eq!(commit, "abc123");
    assert_eq!(stored_artifact, artifact.to_vec());
    assert_eq!(
        candidate, "wc111",
        "the apply effect's expected commit is on the row"
    );
    let count: i64 = raw(&rig.dir.path().join("operational.db"))
        .query_row("SELECT count(*) FROM execution_work_tree_heads", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 1, "one row, write-once by primary key");

    // The typed reader agrees — it is the caller the capsule path uses.
    let read = rig
        .db
        .execution_work_tree_head(execution)
        .unwrap()
        .expect("the head reads back");
    assert_eq!(read, head);

    // Re-admission: the SAME restatement returns the stored row — including
    // its original recorded_at_ms — rather than writing or minting anew.
    let again = rig
        .db
        .record_work_tree_head(execution, "abc123", artifact, "wc111")
        .expect("an identical restatement converges");
    assert_eq!(again, head, "converged re-record returns the stored row");
    assert_eq!(
        raw_head(&rig.dir.path().join("operational.db"), execution).map(|(_, _, ms, _)| ms),
        Some(head.recorded_at_ms),
        "the stored row is untouched"
    );
}

/// `work_tree_head_divergent`: a second record naming a DIFFERENT artifact or
/// a DIFFERENT base commit is refused by name, and the stored row stands.
#[test]
fn a_divergent_re_record_is_refused_and_the_stored_row_stands() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let artifact = declare_tree(&rig, execution);
    rig.db
        .record_work_tree_head(execution, "abc123", artifact, "wc111")
        .unwrap();

    // Divergent ARTIFACT, same commit — refused at the compare, before the
    // undeclared `[0xBB;32]` could ever reach the insert.
    let error = rig
        .db
        .record_work_tree_head(execution, "abc123", [0xBB; 32], "wc111")
        .expect_err("a second artifact under one execution is refused");
    let message = error.to_string();
    assert!(
        message.contains(WORK_TREE_HEAD_DIVERGENT),
        "the refusal is named: {message}"
    );
    assert!(matches!(error, kata_types::KataError::Validation(_)));

    // Divergent COMMIT, same artifact.
    let error = rig
        .db
        .record_work_tree_head(execution, "def456", artifact, "wc111")
        .expect_err("a second base commit under one execution is refused");
    assert!(
        error.to_string().contains(WORK_TREE_HEAD_DIVERGENT),
        "the refusal is named: {error}"
    );

    assert_eq!(
        raw_head(&rig.dir.path().join("operational.db"), execution)
            .map(|(commit, artifact, _, _)| (commit, artifact)),
        Some(("abc123".to_owned(), artifact.to_vec())),
        "the recorded head survives both refusals unchanged"
    );
}

/// The row's identity key is `execution_id`: a SECOND execution may record the
/// SAME artifact — two executions over the same base content share the content
/// address — while an execution with no `programs` row cannot record at all.
#[test]
fn a_head_is_keyed_by_execution_and_requires_the_execution() {
    let rig = rig();
    let first = Ulid::new();
    let second = Ulid::new();
    submit(&rig, first);
    submit(&rig, second);
    let artifact = declare_tree(&rig, first);
    rig.db
        .record_work_tree_head(first, "abc123", artifact, "wc111")
        .unwrap();
    let head = rig
        .db
        .record_work_tree_head(second, "abc123", artifact, "wc222")
        .expect("a shared artifact id is a shared base, not a collision");
    assert_eq!(head.execution_id, second);
    assert_eq!(
        raw(&rig.dir.path().join("operational.db"))
            .query_row("SELECT count(*) FROM execution_work_tree_heads", [], |r| r
                .get(0),)
            .unwrap_or(0),
        2i64
    );

    let orphan = Ulid::new();
    let error = rig
        .db
        .record_work_tree_head(orphan, "abc123", artifact, "wc111")
        .expect_err("no programs row — the foreign key refuses");
    assert!(
        matches!(error, kata_types::KataError::Storage(_)),
        "a foreign-key refusal is Storage, not a head-plane refusal: {error:?}"
    );
    assert!(rig.db.execution_work_tree_head(orphan).unwrap().is_none());
}

/// The production publish shape end to end — synthetic conversion standing in
/// for `kata_vcs`'s provider walk — publishes every member into CAS, publishes
/// the manifest after them, declares the tree execution-retained, and records
/// the head LAST. Read through raw handles: the artifact row, its owner root,
/// the members' objects, and the head row naming the declared artifact.
#[test]
fn publish_base_tree_head_publishes_members_declares_and_records() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);

    let head = publish_base_tree_head(
        &rig.db,
        &rig.cas,
        execution,
        synthetic_convert(
            "f00dbabe",
            &[
                ("src/lib.rs", b"pub fn x() {}\n", false),
                ("run.sh", b"#!/bin/sh\n", true),
            ],
            &[("latest", "src/lib.rs")],
        ),
    )
    .expect("the committed base publishes");

    let op = rig.dir.path().join("operational.db");
    let conn = raw(&op);

    // The head row names the declared artifact and the conversion's commit.
    let (commit, artifact, _, _) = raw_head(&op, execution).expect("the head row exists");
    assert_eq!(commit, "f00dbabe");
    assert_eq!(
        artifact,
        head.work_tree_artifact_id.to_vec(),
        "the head row names the artifact the return value carried"
    );

    // The declared artifact is a `kind='tree'` row pointing at the manifest's
    // object in CAS — and the manifest blob resolves.
    let (object_id, size_bytes): (Vec<u8>, i64) = conn
        .query_row(
            "SELECT object_id, size_bytes FROM artifacts WHERE artifact_id = ?1 AND kind = 'tree'",
            [head.work_tree_artifact_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the tree artifact row exists");
    let manifest_object = kata_types::cache::object_id_for_canonical_bytes(
        &TreeManifest::new(
            // Rebuild the expected manifest shape — same entries the convert
            // built, so the manifest's own canonical bytes are the witness.
            vec![
                TreeEntry {
                    path: TreePath::new("latest").unwrap(),
                    node: TreeNode::Symlink {
                        target: SymlinkTarget::new("src/lib.rs".to_owned()).unwrap(),
                    },
                },
                TreeEntry {
                    path: TreePath::new("run.sh").unwrap(),
                    node: TreeNode::File {
                        mode: TreeEntryMode::Executable,
                        object: kata_types::cache::object_id_for_canonical_bytes(b"#!/bin/sh\n"),
                        size_bytes: 10,
                    },
                },
                TreeEntry {
                    path: TreePath::new("src/lib.rs").unwrap(),
                    node: TreeNode::File {
                        mode: TreeEntryMode::Regular,
                        object: kata_types::cache::object_id_for_canonical_bytes(
                            b"pub fn x() {}\n",
                        ),
                        size_bytes: 14,
                    },
                },
            ],
        )
        .unwrap()
        .manifest_bytes()
        .unwrap(),
    );
    assert_eq!(object_id, manifest_object.as_bytes().to_vec());
    assert!(size_bytes > 0);
    assert!(
        rig.cas.resolves(&manifest_object).unwrap(),
        "the manifest blob is in CAS"
    );

    // Every FILE member's bytes are durable and content-addressed; the symlink
    // carries no member (its content is the target inside the manifest).
    for bytes in [&b"pub fn x() {}\n"[..], &b"#!/bin/sh\n"[..]] {
        assert!(
            rig.cas
                .resolves(&kata_types::cache::object_id_for_canonical_bytes(bytes))
                .unwrap(),
            "the member blob is in CAS"
        );
    }

    // The retention claim: one execution-owner root row holds the manifest.
    let (heads, artifacts, roots) = raw_counts(&op, execution);
    assert_eq!((heads, artifacts, roots), (1, 1, 1));
}

/// Re-admission over the SAME committed content converges: the second drive
/// dedups every object, declares no second artifact, and returns the stored
/// head. A drive over DIFFERENT content reaches `record_work_tree_head`'s
/// divergent refusal.
#[test]
fn republishing_converges_and_a_divergent_republish_is_refused() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let op = rig.dir.path().join("operational.db");

    let first = publish_base_tree_head(
        &rig.db,
        &rig.cas,
        execution,
        synthetic_convert("f00dbabe", &[("a.txt", b"alpha\n", false)], &[]),
    )
    .unwrap();
    let second = publish_base_tree_head(
        &rig.db,
        &rig.cas,
        execution,
        synthetic_convert("f00dbabe", &[("a.txt", b"alpha\n", false)], &[]),
    )
    .expect("an identical re-drive converges");
    assert_eq!(
        second, first,
        "re-admission returns the recorded head, not a second one"
    );
    assert_eq!(
        raw_counts(&op, execution),
        (1, 1, 1),
        "CAS dedup + converge-or-refuse: no second artifact, no second root, one head"
    );

    // A divergent re-drive — same commit spelled, different tree content — is
    // refused at the record, and the recorded head stands.
    let error = publish_base_tree_head(
        &rig.db,
        &rig.cas,
        execution,
        synthetic_convert("f00dbabe", &[("a.txt", b"DIFFERENT\n", false)], &[]),
    )
    .expect_err("a second content under one execution is refused");
    let message = error.to_string();
    assert!(
        message.contains(WORK_TREE_HEAD_DIVERGENT),
        "the refusal is named: {message}"
    );
    assert_eq!(
        raw_head(&op, execution).map(|(_, artifact, _, _)| artifact),
        Some(first.work_tree_artifact_id.to_vec()),
        "the recorded head is untouched by the refused re-drive"
    );

    // A divergent COMMIT SPELLING at identical content is also refused — the
    // provenance is part of the head's identity, not decoration.
    let error = publish_base_tree_head(
        &rig.db,
        &rig.cas,
        execution,
        synthetic_convert("cafebabe", &[("a.txt", b"alpha\n", false)], &[]),
    )
    .expect_err("the same tree under a different base commit is refused");
    assert!(
        error.to_string().contains(WORK_TREE_HEAD_DIVERGENT),
        "the refusal is named: {error}"
    );
}

/// No head is the DISTINCT state — for an isolated execution it is the crash
/// window before the row, for a non-isolated one it is the normal state — and
/// the reader answers `None`, never a synthesized head.
#[test]
fn an_unrecorded_head_reads_as_absent_not_as_a_default() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    assert!(
        rig.db
            .execution_work_tree_head(execution)
            .unwrap()
            .is_none()
    );
    assert!(raw_head(&rig.dir.path().join("operational.db"), execution).is_none());
}

// ---------------------------------------------------------------------------
// Branch coordinates: lazy forks, one frozen base per
// barrier, and CAS-only advancement.
// ---------------------------------------------------------------------------

/// Declare `manifest` for `execution` and return its artifact id — the branch
/// cells' trees are real `kind='tree'` rows because the head table's foreign
/// key refuses anything else.
fn declare_manifest(rig: &Rig, execution: Ulid, entries: Vec<TreeEntry>) -> [u8; 32] {
    let manifest = TreeManifest::new(entries).unwrap();
    let bytes = manifest.manifest_bytes().unwrap();
    let durable = rig.cas.put_durable(&bytes).unwrap();
    let declaration = kata_core::operational::ArtifactDeclaration::for_durable_tree(
        &manifest,
        kata_types::execution_contract::ArtifactPrivacy::Public,
        kata_core::operational::CasRootOwner::Execution(execution),
        &durable,
    )
    .unwrap();
    rig.db.declare_artifact(&declaration).unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        kata_types::execution_contract::ArtifactPrivacy::Public,
    )
    .id()
    .0
    .0
}

/// One member file's entry — `path` = `bytes`.
fn member(rig: &Rig, path: &str, bytes: &[u8]) -> TreeEntry {
    let stored = rig.cas.put_durable(bytes).unwrap();
    TreeEntry {
        path: TreePath::new(path).unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: stored.object_id(),
            size_bytes: stored.size(),
        },
    }
}

/// The `#apply/<stage>` spec a claim binds — the same shape the dispatcher's
/// drive builds, at operation path `path`.
fn apply_spec(execution: Ulid, stage: &str, path: Vec<u32>) -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: work_apply_stage_id(stage),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                ContentHash::new([0xA7; 32]),
                work_apply_operation_contract(OperationContractId(ContentHash::new([0x6C; 32]))),
                OperationPath(path),
            ),
            None,
            None,
        ),
    }
}

/// Claim an apply against the head row at `branch` and resolve it with the
/// advance to `to` — the CAS-only verb pair the dispatcher's non-jj leg calls.
/// `path` keys the apply occurrence, so each advance carries its own.
fn advance_head(
    rig: &Rig,
    execution: Ulid,
    branch: &str,
    path: Vec<u32>,
    to: [u8; 32],
    expected_seq: i64,
    expected_artifact: [u8; 32],
) {
    let spec = apply_spec(execution, &format!("stage{}", path[0]), path);
    let attempt = Ulid::new();
    let claimed = rig
        .db
        .claim_work_apply_attempt(attempt, &spec, branch, expected_artifact)
        .expect("the apply claim");
    let head = match claimed {
        WorkApplyClaimOutcome::Claimed { head, .. } => head,
        other => panic!("the apply claims against the current head: {other:?}"),
    };
    assert_eq!(head.head_seq, expected_seq);
    let advance = WorkTreeHeadAdvance {
        work_tree_artifact_id: to,
        candidate_commit_id: String::new(),
        expected_head_seq: expected_seq,
        expected_artifact_id: expected_artifact,
    };
    rig.db
        .resolve_work_apply_attempt(
            attempt,
            branch,
            Some(&advance),
            &serde_json::json!({"work_apply": {"applied": true}}),
        )
        .expect("the advance resolves");
}

/// `execution_work_tree_heads`' columns as the RAW row hands them back —
/// `(base_commit, candidate_commit_id, work_tree_artifact_id, head_seq,
/// join_stage, forked_from, fork_base_artifact_id)`.
type RawHeadRow = (
    String,
    String,
    Vec<u8>,
    i64,
    String,
    String,
    Option<Vec<u8>>,
);

/// The full branch row through the RAW handle — `ensure_work_tree_head`'s
/// column-by-column witness, not the typed reader's decode of it.
fn raw_branch(path: &Path, execution: Ulid, branch: &str) -> Option<RawHeadRow> {
    use rusqlite::OptionalExtension as _;
    raw(path)
        .query_row(
            "SELECT base_commit, candidate_commit_id, work_tree_artifact_id, head_seq,                     join_stage, forked_from, fork_base_artifact_id              FROM execution_work_tree_heads WHERE execution_id = ?1 AND branch = ?2",
            rusqlite::params![execution.to_bytes().as_slice(), branch],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .expect("a branch head row read")
}

/// A BRANCH coordinate's row is forked LAZILY: the first `ensure` at
/// `root.pushed(join, exit)` writes a row forked off the parent's CURRENT
/// artifact — `join_stage`/`forked_from`/`fork_base_artifact_id` naming the
/// barrier and the point — and a second `ensure` returns the stored row
/// rather than a second row.
#[test]
fn a_branch_head_forks_lazily_off_the_parent_and_a_re_ensure_converges() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let root_artifact =
        declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    rig.db
        .record_work_tree_head(execution, "", root_artifact, "")
        .unwrap();
    let coordinate = WorkTreeHeadCoordinate::root().pushed("join", "left");

    let branch = rig
        .db
        .ensure_work_tree_head(execution, &coordinate)
        .expect("the first ensure forks the branch row");
    assert_eq!(branch.join_stage, "join");
    assert_eq!(branch.forked_from, "");
    assert_eq!(branch.work_tree_artifact_id, root_artifact);
    assert_eq!(branch.fork_base_artifact_id, Some(root_artifact));
    assert_eq!(branch.base_commit, "");
    assert_eq!(branch.candidate_commit_id, "");
    assert_eq!(branch.head_seq, 0);
    assert_eq!(branch.branch, coordinate.spelling());

    let raw_row = raw_branch(
        &rig.dir.path().join("operational.db"),
        execution,
        &coordinate.spelling(),
    )
    .expect("the row exists through the raw handle");
    assert_eq!(
        (raw_row.0.as_str(), raw_row.1.as_str()),
        ("", ""),
        "a branch head has no jj checkout behind it"
    );
    assert_eq!(raw_row.2, root_artifact.to_vec());
    assert_eq!((raw_row.4.as_str(), raw_row.5.as_str()), ("join", ""));
    assert_eq!(raw_row.6, Some(root_artifact.to_vec()));

    let again = rig
        .db
        .ensure_work_tree_head(execution, &coordinate)
        .expect("the second ensure converges");
    assert_eq!(again, branch, "one row, never a second fork");
    let count: i64 = raw(&rig.dir.path().join("operational.db"))
        .query_row("SELECT count(*) FROM execution_work_tree_heads", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 2, "one root row and one branch row");
}

/// ONE fork point per barrier: the second sibling's ensure takes the FIRST
/// row's frozen `fork_base_artifact_id`, not the parent's moved artifact — so
/// both branches' deltas are computed against the same base at the join.
#[test]
fn a_sibling_forks_at_the_first_siblings_frozen_base_not_the_moved_parent() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    let moved = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "parent.txt", b"the parent moved\n"),
        ],
    );
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();

    let left = WorkTreeHeadCoordinate::root().pushed("join", "left");
    let right = WorkTreeHeadCoordinate::root().pushed("join", "right");
    let left_head = rig.db.ensure_work_tree_head(execution, &left).unwrap();
    assert_eq!(left_head.fork_base_artifact_id, Some(base));

    // The parent head advances between the two forks — the case the frozen
    // base exists for.
    advance_head(&rig, execution, "", vec![90], moved, 0, base);

    let right_head = rig.db.ensure_work_tree_head(execution, &right).unwrap();
    assert_eq!(
        right_head.fork_base_artifact_id,
        Some(base),
        "the sibling pins the frozen base, not the parent's moved artifact"
    );
    assert_eq!(
        right_head.work_tree_artifact_id, base,
        "the fork's own content is the frozen base"
    );
    let raw_row = raw_branch(
        &rig.dir.path().join("operational.db"),
        execution,
        &right.spelling(),
    )
    .expect("the right sibling row exists");
    assert_eq!(raw_row.6, Some(base.to_vec()));
}

/// The recursion's base case is the refusal: a coordinate on an execution
/// that never recorded its root head is `work_tree_head_unrecorded` — at the
/// root AND beneath it, where the recursion reaches the absent root.
#[test]
fn an_unrecorded_root_is_refused_at_the_root_and_below_it() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let error = rig
        .db
        .ensure_work_tree_head(execution, &WorkTreeHeadCoordinate::root())
        .expect_err("an unrecorded root is refused");
    let message = error.to_string();
    assert!(
        message.contains(WORK_TREE_HEAD_UNRECORDED),
        "refused by name: {message}"
    );

    let branch = WorkTreeHeadCoordinate::root().pushed("join", "left");
    let error = rig
        .db
        .ensure_work_tree_head(execution, &branch)
        .expect_err("a branch on an unrecorded execution reaches the same refusal");
    assert!(
        error.to_string().contains(WORK_TREE_HEAD_UNRECORDED),
        "refused by name: {error}"
    );
    let count: i64 = raw(&rig.dir.path().join("operational.db"))
        .query_row("SELECT count(*) FROM execution_work_tree_heads", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0, "a refused ensure forks nothing");
}

/// A NESTED branch forks off its outer branch's row — `forked_from` is the
/// outer coordinate's spelling, `join_stage` the inner barrier — so an inner
/// `parallel()`'s deltas sit over its branch's own head.
#[test]
fn a_nested_branch_forks_off_its_outer_branch_row() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    let outer_moved = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "outer.txt", b"outer edit\n"),
        ],
    );
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();

    let outer = WorkTreeHeadCoordinate::root().pushed("outer_join", "outer_left");
    rig.db.ensure_work_tree_head(execution, &outer).unwrap();
    advance_head(
        &rig,
        execution,
        &outer.spelling(),
        vec![91],
        outer_moved,
        0,
        base,
    );

    let inner = outer.pushed("inner_join", "inner_left");
    let inner_head = rig.db.ensure_work_tree_head(execution, &inner).unwrap();
    assert_eq!(inner_head.join_stage, "inner_join");
    assert_eq!(inner_head.forked_from, outer.spelling());
    assert_eq!(
        inner_head.fork_base_artifact_id,
        Some(outer_moved),
        "the inner branch forks off the outer branch's CURRENT artifact"
    );
    assert_eq!(inner_head.work_tree_artifact_id, outer_moved);
}

/// The stored spelling is canonical JSON — `''` at the root, one `[join,
/// exit]` pair per fork, outermost first — and `from_spelling` round-trips
/// what `spelling` mints while refusing a hand-edited row.
#[test]
fn a_coordinate_spelling_round_trips_and_a_hand_edit_is_refused() {
    let root = WorkTreeHeadCoordinate::root();
    assert_eq!(root.spelling(), "");
    let one = root.pushed("join", "left");
    assert_eq!(one.spelling(), "[[\"join\",\"left\"]]");
    let two = one.pushed("inner", "nested");
    assert_eq!(
        two.spelling(),
        "[[\"join\",\"left\"],[\"inner\",\"nested\"]]"
    );
    for coordinate in [&root, &one, &two] {
        let decoded = WorkTreeHeadCoordinate::from_spelling(&coordinate.spelling())
            .expect("the minted spelling decodes");
        assert_eq!(&decoded, coordinate);
    }
    for bad in [
        "not json",
        "{\"join\":\"left\"}",
        "[[\"join\",\"left\",\"extra\"]]",
        "[[\"join\"]]",
        // Parsed but not canonical — the re-mint comparison owns this refusal:
        // serde accepts the spaced form and `spelling()` never produces it.
        "[[ \"join\",\"left\" ]]",
    ] {
        WorkTreeHeadCoordinate::from_spelling(bad)
            .expect_err("a non-canonical spelling is refused");
    }
}

/// THE SEQUENCING HALF: a branch row's apply advances ITS row only — seq
/// bumps, the parent's row and the sibling's row are untouched — and an
/// advance whose expected base is spent is `work_delta_base_stale` by name.
#[test]
fn a_branch_head_advances_its_own_row_and_a_stale_base_is_refused() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    let landed = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "left.txt", b"the branch's write\n"),
        ],
    );
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();
    let left = WorkTreeHeadCoordinate::root().pushed("join", "left");
    let right = WorkTreeHeadCoordinate::root().pushed("join", "right");
    rig.db.ensure_work_tree_head(execution, &left).unwrap();
    rig.db.ensure_work_tree_head(execution, &right).unwrap();

    advance_head(&rig, execution, &left.spelling(), vec![1], landed, 0, base);

    let op = rig.dir.path().join("operational.db");
    let left_row = raw_branch(&op, execution, &left.spelling()).unwrap();
    assert_eq!((left_row.2, left_row.3), (landed.to_vec(), 1));
    // The sibling and the parent did not move.
    let right_row = raw_branch(&op, execution, &right.spelling()).unwrap();
    assert_eq!((right_row.2, right_row.3), (base.to_vec(), 0));
    let root_row = raw_branch(&op, execution, "").unwrap();
    assert_eq!((root_row.2, root_row.3), (base.to_vec(), 0));

    // A claim whose delta base is the SPENT artifact resolves failed
    // (`work_delta_base_stale`) in the claim transaction, and the row stands.
    let stale_spec = apply_spec(execution, "stale", vec![7]);
    let claimed = rig
        .db
        .claim_work_apply_attempt(Ulid::new(), &stale_spec, &left.spelling(), base)
        .expect("the stale claim resolves failed rather than erroring");
    match claimed {
        WorkApplyClaimOutcome::StaleBase { reason, .. } => {
            assert!(
                reason.contains("work_delta_base_stale"),
                "the refusal is named: {reason}"
            );
        }
        other => panic!("a stale base is refused at the claim: {other:?}"),
    }
    let left_row = raw_branch(&op, execution, &left.spelling()).unwrap();
    assert_eq!((left_row.2, left_row.3), (landed.to_vec(), 1));
}

// ---------------------------------------------------------------------------
// The join FAN-IN: `resolve_join` merges the branches'
// deltas off their frozen fork base and names the union's apply delta in the
// accepted output, inside the join's one claim-and-resolve transaction. The
// witnesses are the raw rows and the CAS bytes, never the plane's own types.
// ---------------------------------------------------------------------------

/// Accept an occurrence the join fans in — minted through the same
/// claim-and-resolve door a completed input takes, because the precondition
/// reads exactly this acceptance.
fn accept_input(rig: &Rig, execution: Ulid, path: Vec<u32>) -> [u8; 32] {
    let spec = MainAttemptSpec {
        stage_id: "input".to_string(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                ContentHash::new([0xD1; 32]),
                OperationContractId(ContentHash::new([0x3C; 32])),
                OperationPath(path),
            ),
            None,
            None,
        ),
    };
    rig.db
        .claim_and_resolve_main_attempt(
            Ulid::new(),
            &spec,
            MainOperation::Join,
            &MainResolution::Complete {
                output: &serde_json::json!({"input": true}),
            },
        )
        .expect("the input accepts");
    spec.occurrence.occurrence_id()
}

/// The join attempt's spec — `stage_id` IS the barrier name the fan-in checks
/// every input's innermost fork against.
fn join_spec(execution: Ulid, join_stage: &str, path: Vec<u32>) -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: join_stage.to_string(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                ContentHash::new([0xD1; 32]),
                OperationContractId(ContentHash::new([0x5E; 32])),
                OperationPath(path),
            ),
            None,
            None,
        ),
    }
}

/// One input line of the fan-in — `label` is what a conflict report names it.
fn fan_input(occurrence: [u8; 32], branch: &WorkTreeHeadCoordinate, label: &str) -> JoinFanInInput {
    JoinFanInInput {
        occurrence,
        branch: branch.clone(),
        label: label.to_string(),
    }
}

/// The resolving transition's payload, read raw — `output` for a completed
/// join, `reason` for the recorded failure.
fn resolved_payload(rig: &Rig, seq: i64) -> serde_json::Value {
    let payload: Vec<u8> = raw(&rig.dir.path().join("operational.db"))
        .query_row(
            "SELECT payload_json FROM transitions WHERE seq = ?1",
            rusqlite::params![seq],
            |row| row.get(0),
        )
        .expect("the resolving transition's payload");
    serde_json::from_slice(&payload).expect("the payload decodes")
}

/// The declared `kind='tree_delta'` artifact's content — the merge's output
/// verified as stored bytes, not through the plane's own decode.
fn read_delta_artifact(rig: &Rig, artifact_id: [u8; 32]) -> TreeDelta {
    let (object_id, size): (Vec<u8>, i64) = raw(&rig.dir.path().join("operational.db"))
        .query_row(
            "SELECT object_id, size_bytes FROM artifacts \
             WHERE artifact_id = ?1 AND kind = 'tree_delta'",
            rusqlite::params![artifact_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the declared delta artifact's row");
    let bytes = rig
        .cas
        .get_verified(
            &ObjectId::new(object_id.as_slice().try_into().unwrap()),
            size.cast_unsigned(),
            TreeDelta::MAXIMUM_ENCODED_BYTES,
        )
        .expect("the delta's bytes verify");
    serde_json::from_slice(&bytes).expect("the stored delta decodes")
}

/// The count of declared delta artifacts — the conflict cells' "nothing was
/// published" witness.
fn tree_delta_count(rig: &Rig) -> i64 {
    raw(&rig.dir.path().join("operational.db"))
        .query_row(
            "SELECT count(*) FROM artifacts WHERE kind = 'tree_delta'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

/// THE MERGE, disjoint: two branches write different paths off the one frozen
/// fork base and the join's accepted output carries the APPLY delta — base the
/// parent's CURRENT artifact, changes the union of the two branches' — while
/// the parent head itself stands (the `#apply/<join>` sweep lands it). A third
/// input whose branch was never ensured forks lazily at the base inside the
/// join and contributes the empty delta.
#[test]
fn a_join_fans_disjoint_branch_deltas_into_one_apply_delta() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();

    let left = WorkTreeHeadCoordinate::root().pushed("join", "left");
    let right = WorkTreeHeadCoordinate::root().pushed("join", "right");
    let idle = WorkTreeHeadCoordinate::root().pushed("join", "idle");
    rig.db.ensure_work_tree_head(execution, &left).unwrap();
    rig.db.ensure_work_tree_head(execution, &right).unwrap();
    let left_tree = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "left.txt", b"the left branch's write\n"),
        ],
    );
    let right_tree = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "right.txt", b"the right branch's write\n"),
        ],
    );
    advance_head(
        &rig,
        execution,
        &left.spelling(),
        vec![1],
        left_tree,
        0,
        base,
    );
    advance_head(
        &rig,
        execution,
        &right.spelling(),
        vec![2],
        right_tree,
        0,
        base,
    );
    // `idle` is ensured by NOBODY — the join's own ensure must fork it.

    let inputs = [
        (accept_input(&rig, execution, vec![11]), &left, "left"),
        (accept_input(&rig, execution, vec![12]), &right, "right"),
        (accept_input(&rig, execution, vec![13]), &idle, "idle"),
    ];
    let outcome = rig
        .db
        .resolve_join(
            Ulid::new(),
            &join_spec(execution, "join", vec![9]),
            &JoinFanIn {
                parent: WorkTreeHeadCoordinate::root(),
                inputs: inputs
                    .iter()
                    .map(|(occurrence, branch, label)| fan_input(*occurrence, branch, label))
                    .collect(),
            },
        )
        .expect("the disjoint merge resolves");
    let MainClaimAndResolveOutcome::Resolved { resolve_seq, .. } = outcome else {
        panic!("the disjoint merge resolves completed: {outcome:?}");
    };

    let output = &resolved_payload(&rig, resolve_seq)["output"];
    let delta_hex = output["work_delta_artifact_id"]
        .as_str()
        .expect("the join's output carries the apply delta artifact");
    let delta_id: [u8; 32] = hex::decode(delta_hex)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    let delta = read_delta_artifact(&rig, delta_id);
    assert_eq!(
        delta.base().id().0.0,
        base,
        "the apply delta's base is the parent's CURRENT artifact"
    );
    let mut paths: Vec<&str> = delta
        .changes()
        .iter()
        .map(|change| change.path.as_str())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        ["left.txt", "right.txt"],
        "the union of the two deltas"
    );

    // The parent head stands at the fork base — applying the delta is the
    // sweep's, not the join's, transaction.
    let root_row = raw_branch(&rig.dir.path().join("operational.db"), execution, "").unwrap();
    assert_eq!(
        (root_row.2, root_row.3),
        (base.to_vec(), 0),
        "the join does not advance the parent head"
    );
    // The lazily-ensured idle branch forked at the frozen base and advanced
    // nothing.
    let idle_row = raw_branch(
        &rig.dir.path().join("operational.db"),
        execution,
        &idle.spelling(),
    )
    .expect("the join ensured the idle branch's row");
    assert_eq!(
        (idle_row.2, idle_row.6),
        (base.to_vec(), Some(base.to_vec())),
        "the untouched branch contributes the empty delta off the frozen base"
    );
}

/// IDENTICAL writes to one path COLLAPSE rather than conflict, and the parent
/// head's own move since the fork is ambient input: the union folds onto it,
/// so the apply delta carries only what the branches added.
#[test]
fn a_join_merge_collapses_identical_writes_onto_the_moved_parent() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();

    let left = WorkTreeHeadCoordinate::root().pushed("join", "left");
    let right = WorkTreeHeadCoordinate::root().pushed("join", "right");
    rig.db.ensure_work_tree_head(execution, &left).unwrap();
    rig.db.ensure_work_tree_head(execution, &right).unwrap();
    // Both branches write `same.txt` with the SAME content — one change in the
    // merge, not a conflict.
    for (branch, path) in [(&left, vec![1]), (&right, vec![2])] {
        let tree = declare_manifest(
            &rig,
            execution,
            vec![
                member(&rig, "base.txt", b"base\n"),
                member(&rig, "same.txt", b"both branches wrote this\n"),
            ],
        );
        advance_head(&rig, execution, &branch.spelling(), path, tree, 0, base);
    }
    // The parent moved ambiently after the forks: the union lands ON it.
    let moved = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "ambient.txt", b"the parent's own write\n"),
        ],
    );
    advance_head(&rig, execution, "", vec![90], moved, 0, base);

    let inputs = [
        (accept_input(&rig, execution, vec![11]), "left"),
        (accept_input(&rig, execution, vec![12]), "right"),
    ];
    let branches = [left, right];
    let outcome = rig
        .db
        .resolve_join(
            Ulid::new(),
            &join_spec(execution, "join", vec![9]),
            &JoinFanIn {
                parent: WorkTreeHeadCoordinate::root(),
                inputs: inputs
                    .iter()
                    .zip(branches.iter())
                    .map(|((occurrence, label), branch)| fan_input(*occurrence, branch, label))
                    .collect(),
            },
        )
        .expect("the collapsing merge resolves");
    let MainClaimAndResolveOutcome::Resolved { resolve_seq, .. } = outcome else {
        panic!("the collapsing merge resolves completed: {outcome:?}");
    };
    let output = &resolved_payload(&rig, resolve_seq)["output"];
    let delta_id: [u8; 32] = hex::decode(
        output["work_delta_artifact_id"]
            .as_str()
            .expect("the union differs from the moved parent, so a delta exists"),
    )
    .unwrap()
    .as_slice()
    .try_into()
    .unwrap();
    let delta = read_delta_artifact(&rig, delta_id);
    assert_eq!(
        delta.base().id().0.0,
        moved,
        "the apply delta is expressed over the parent's MOVED artifact"
    );
    assert_eq!(
        delta.changes().len(),
        1,
        "the identical writes collapsed to one change"
    );
    assert_eq!(delta.changes()[0].path.as_str(), "same.txt");

    // And the union really is base+ambient+same: apply the recorded delta to
    // the moved manifest and read the entries back.
    let (moved_object, moved_size): (Vec<u8>, i64) = raw(&rig.dir.path().join("operational.db"))
        .query_row(
            "SELECT object_id, size_bytes FROM artifacts WHERE artifact_id = ?1",
            rusqlite::params![moved.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let moved_bytes = rig
        .cas
        .get_verified(
            &ObjectId::new(moved_object.as_slice().try_into().unwrap()),
            moved_size.cast_unsigned(),
            TreeManifest::MAXIMUM_ENCODED_BYTES,
        )
        .unwrap();
    let moved_manifest: TreeManifest = serde_json::from_slice(&moved_bytes).unwrap();
    let union = delta.apply(&moved_manifest).unwrap();
    let mut union_paths: Vec<&str> = union
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    union_paths.sort_unstable();
    assert_eq!(
        union_paths,
        ["ambient.txt", "base.txt", "same.txt"],
        "the union folds the branches' change onto the moved parent"
    );
}

/// Two branches writing one path DIFFERENTLY is the typed verdict: the join
/// resolves `failed` with `work_fanin_conflict` naming the path and both
/// branch labels; the parent head, the branch rows and the artifact plane are
/// untouched; and a re-presented join converges on the recorded verdict
/// instead of re-running the merge.
#[test]
fn a_fanin_conflict_fails_the_join_naming_paths_and_branches_and_moves_nothing() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "hot.txt", b"the base content\n"),
        ],
    );
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();

    let left = WorkTreeHeadCoordinate::root().pushed("join", "left");
    let right = WorkTreeHeadCoordinate::root().pushed("join", "right");
    rig.db.ensure_work_tree_head(execution, &left).unwrap();
    rig.db.ensure_work_tree_head(execution, &right).unwrap();
    for (branch, path, bytes) in [
        (&left, vec![1], b"the LEFT branch's hot.txt\n".as_slice()),
        (&right, vec![2], b"the RIGHT branch's hot.txt\n".as_slice()),
    ] {
        let tree = declare_manifest(
            &rig,
            execution,
            vec![
                member(&rig, "base.txt", b"base\n"),
                member(&rig, "hot.txt", bytes),
            ],
        );
        advance_head(&rig, execution, &branch.spelling(), path, tree, 0, base);
    }

    let deltas_before = tree_delta_count(&rig);
    let inputs = [
        (accept_input(&rig, execution, vec![11]), "left"),
        (accept_input(&rig, execution, vec![12]), "right"),
    ];
    let branches = [left, right];
    let join = join_spec(execution, "join", vec![9]);
    let fanin = JoinFanIn {
        parent: WorkTreeHeadCoordinate::root(),
        inputs: inputs
            .iter()
            .zip(branches.iter())
            .map(|((occurrence, label), branch)| fan_input(*occurrence, branch, label))
            .collect(),
    };
    let outcome = rig
        .db
        .resolve_join(Ulid::new(), &join, &fanin)
        .expect("a conflict is a recorded verdict, not an error");
    let MainClaimAndResolveOutcome::ResolvedFailed { resolve_seq, .. } = outcome else {
        panic!("a contested merge resolves failed: {outcome:?}");
    };
    let reason = resolved_payload(&rig, resolve_seq)["reason"]
        .as_str()
        .expect("the failed resolution carries the reason")
        .to_string();
    assert!(reason.contains(WORK_FANIN_CONFLICT), "named: {reason}");
    assert!(reason.contains("hot.txt"), "the path is named: {reason}");
    assert!(reason.contains("left"), "the left label is named: {reason}");
    assert!(
        reason.contains("right"),
        "the right label is named: {reason}"
    );

    // NOTHING moved: the parent head stands at the fork base, the branch rows
    // keep their trees, and no apply delta was published.
    let op = rig.dir.path().join("operational.db");
    let root_row = raw_branch(&op, execution, "").unwrap();
    assert_eq!((root_row.2, root_row.3), (base.to_vec(), 0));
    assert_eq!(
        tree_delta_count(&rig),
        deltas_before,
        "a conflict declares no apply delta"
    );

    // A re-presented join converges on the recorded verdict — the merge is not
    // re-run.
    let again = rig
        .db
        .resolve_join(Ulid::new(), &join, &fanin)
        .expect("the recorded verdict converges");
    assert!(
        matches!(
            again,
            MainClaimAndResolveOutcome::AlreadyResolvedTerminal { ref state, .. }
                if state.as_str() == "failed"
        ),
        "the recorded failure answers the re-presentation: {again:?}"
    );
}

/// A path the PARENT moved and a branch rewrote differently is contested by
/// the same rule as branch-vs-branch — the reason names the path, the branch,
/// and the parent head's ambient label.
#[test]
fn a_parents_own_move_contesting_a_branch_write_is_the_ambient_conflict() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "hot.txt", b"the base content\n"),
        ],
    );
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();

    let left = WorkTreeHeadCoordinate::root().pushed("join", "left");
    let right = WorkTreeHeadCoordinate::root().pushed("join", "right");
    rig.db.ensure_work_tree_head(execution, &left).unwrap();
    rig.db.ensure_work_tree_head(execution, &right).unwrap();
    // Only `left` touches hot.txt; `right` carries it UNCHANGED and writes a
    // disjoint path — omitting it would read as the branch DELETING the path.
    let left_tree = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "hot.txt", b"the LEFT branch's hot.txt\n"),
        ],
    );
    advance_head(
        &rig,
        execution,
        &left.spelling(),
        vec![1],
        left_tree,
        0,
        base,
    );
    let right_tree = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "hot.txt", b"the base content\n"),
            member(&rig, "right.txt", b"the right branch's write\n"),
        ],
    );
    advance_head(
        &rig,
        execution,
        &right.spelling(),
        vec![2],
        right_tree,
        0,
        base,
    );
    // The PARENT moved hot.txt differently after both forks — the ambient arm.
    let moved = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "hot.txt", b"the PARENT's own hot.txt\n"),
        ],
    );
    advance_head(&rig, execution, "", vec![90], moved, 0, base);

    let inputs = [
        (accept_input(&rig, execution, vec![11]), "left"),
        (accept_input(&rig, execution, vec![12]), "right"),
    ];
    let branches = [left, right];
    let outcome = rig
        .db
        .resolve_join(
            Ulid::new(),
            &join_spec(execution, "join", vec![9]),
            &JoinFanIn {
                parent: WorkTreeHeadCoordinate::root(),
                inputs: inputs
                    .iter()
                    .zip(branches.iter())
                    .map(|((occurrence, label), branch)| fan_input(*occurrence, branch, label))
                    .collect(),
            },
        )
        .expect("an ambient conflict is a recorded verdict, not an error");
    let MainClaimAndResolveOutcome::ResolvedFailed { resolve_seq, .. } = outcome else {
        panic!("the ambient-contested merge resolves failed: {outcome:?}");
    };
    let reason = resolved_payload(&rig, resolve_seq)["reason"]
        .as_str()
        .expect("the failed resolution carries the reason")
        .to_string();
    assert!(reason.contains(WORK_FANIN_CONFLICT), "named: {reason}");
    assert!(reason.contains("hot.txt"), "the path is named: {reason}");
    assert!(reason.contains("left"), "the branch is named: {reason}");
    assert!(
        reason.contains("the parent head"),
        "the ambient label is named: {reason}"
    );
    // The parent's own move stands — a conflict rewinds nothing.
    let root_row = raw_branch(&rig.dir.path().join("operational.db"), execution, "").unwrap();
    assert_eq!((root_row.2, root_row.3), (moved.to_vec(), 1));
}

/// Branches that advanced nothing fold to the parent's own tree: the join
/// resolves `completed`, its output names NO delta artifact, and no
/// `tree_delta` row exists — the `#apply/<join>` sweep never runs for it.
#[test]
fn a_join_whose_branches_changed_nothing_carries_no_apply_delta() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();

    let left = WorkTreeHeadCoordinate::root().pushed("join", "left");
    let right = WorkTreeHeadCoordinate::root().pushed("join", "right");
    // Neither branch is even ensured — the join forks both lazily.
    let inputs = [
        (accept_input(&rig, execution, vec![11]), "left"),
        (accept_input(&rig, execution, vec![12]), "right"),
    ];
    let branches = [left, right];
    let outcome = rig
        .db
        .resolve_join(
            Ulid::new(),
            &join_spec(execution, "join", vec![9]),
            &JoinFanIn {
                parent: WorkTreeHeadCoordinate::root(),
                inputs: inputs
                    .iter()
                    .zip(branches.iter())
                    .map(|((occurrence, label), branch)| fan_input(*occurrence, branch, label))
                    .collect(),
            },
        )
        .expect("the empty merge resolves");
    let MainClaimAndResolveOutcome::Resolved { resolve_seq, .. } = outcome else {
        panic!("the empty merge resolves completed: {outcome:?}");
    };
    let output = &resolved_payload(&rig, resolve_seq)["output"];
    assert!(
        output.get("work_delta_artifact_id").is_none(),
        "nothing to apply carries no delta: {output}"
    );
    assert_eq!(tree_delta_count(&rig), 0, "no delta artifact was declared");
}

/// The ambient STRUCTURAL conflict: the parent head moved since the fork
/// to carry FILE `x`, while the branch wrote `x/y` — no same-path overlap for
/// the ambient check to contest, but the union of moved-parent + branch delta
/// is a tree that cannot exist. The join must record `work_fanin_conflict`
/// failed — never propagate `Err` and wedge the runner.
#[test]
fn a_fanin_ambient_structural_conflict_is_a_recorded_verdict_not_an_err() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();
    let branch = WorkTreeHeadCoordinate::root().pushed("join", "only");
    rig.db.ensure_work_tree_head(execution, &branch).unwrap();
    // The branch writes `x/y` — a file beneath a path the parent will hold as
    // a FILE by the time the join runs.
    let branch_tree = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "x/y", b"the branch's nested write\n"),
        ],
    );
    advance_head(
        &rig,
        execution,
        &branch.spelling(),
        vec![1],
        branch_tree,
        0,
        base,
    );
    // The ambient move: the parent head advances past the fork carrying FILE
    // `x` — a stage at the barrier's own coordinate applied in between.
    let moved = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "x", b"the parent's file\n"),
        ],
    );
    advance_head(&rig, execution, "", vec![2], moved, 0, base);

    let input = accept_input(&rig, execution, vec![11]);
    let join = join_spec(execution, "join", vec![9]);
    let fanin = JoinFanIn {
        parent: WorkTreeHeadCoordinate::root(),
        inputs: vec![fan_input(input, &branch, "only")],
    };
    let deltas_before = tree_delta_count(&rig);
    let outcome = rig
        .db
        .resolve_join(Ulid::new(), &join, &fanin)
        .expect("a structural conflict is a recorded verdict, not an Err");
    let MainClaimAndResolveOutcome::ResolvedFailed { resolve_seq, .. } = outcome else {
        panic!("an ambient structural conflict resolves failed: {outcome:?}");
    };
    let reason = resolved_payload(&rig, resolve_seq)["reason"]
        .as_str()
        .expect("the failed resolution carries the reason")
        .to_string();
    assert!(reason.contains(WORK_FANIN_CONFLICT), "named: {reason}");
    assert!(reason.contains("\"x\""), "the ambient file named: {reason}");
    assert!(reason.contains("x/y"), "the branch path named: {reason}");
    assert_eq!(
        tree_delta_count(&rig),
        deltas_before,
        "a conflict declares no apply delta"
    );
}

/// **The ambient-structural verdict names the PAIRS, with their labels** — the
/// manifest error alone names the paths; only `ambient_structural_pairs` puts
/// `<the parent head>` on the ambient side and the writer on the branch side.
/// The branch writes `x/y/z` against a parent file `x`: `x/y` is a prefix the
/// parent does NOT carry, so a prefix lookup that answers on non-membership
/// invents a `<the parent head>` pair for it — and the dedup, the write-only
/// arm, and the writers computation each change the pair list this verdict
/// is built from.
#[test]
fn an_ambient_structural_verdict_names_the_pairs_and_their_labels() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();
    let branch = WorkTreeHeadCoordinate::root().pushed("join", "only");
    rig.db.ensure_work_tree_head(execution, &branch).unwrap();
    let branch_tree = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "x/y/z", b"the branch's deep write\n"),
        ],
    );
    advance_head(
        &rig,
        execution,
        &branch.spelling(),
        vec![1],
        branch_tree,
        0,
        base,
    );
    let moved = declare_manifest(
        &rig,
        execution,
        vec![
            member(&rig, "base.txt", b"base\n"),
            member(&rig, "x", b"the parent's file\n"),
        ],
    );
    advance_head(&rig, execution, "", vec![2], moved, 0, base);

    let input = accept_input(&rig, execution, vec![11]);
    let join = join_spec(execution, "join", vec![9]);
    let fanin = JoinFanIn {
        parent: WorkTreeHeadCoordinate::root(),
        inputs: vec![fan_input(input, &branch, "only")],
    };
    let outcome = rig
        .db
        .resolve_join(Ulid::new(), &join, &fanin)
        .expect("a structural conflict is a recorded verdict, not an Err");
    let MainClaimAndResolveOutcome::ResolvedFailed { resolve_seq, .. } = outcome else {
        panic!("an ambient structural conflict resolves failed: {outcome:?}");
    };
    let reason = resolved_payload(&rig, resolve_seq)["reason"]
        .as_str()
        .expect("the failed resolution carries the reason")
        .to_string();
    assert!(reason.contains(WORK_FANIN_CONFLICT), "named: {reason}");
    // The pair list — not just the structural sentence — is the verdict: the
    // ambient entry carries `<the parent head>`, the written path its writer.
    assert!(
        reason.contains("TreePath(\"x\") touched by [<the parent head>]"),
        "the ambient entry is labeled: {reason}"
    );
    assert!(
        reason.contains("TreePath(\"x/y/z\") touched by [only]"),
        "the branch path carries its writer: {reason}"
    );
    assert!(
        !reason.contains("TreePath(\"x/y\")"),
        "a prefix the parent does NOT carry invents no pair: {reason}"
    );
}

/// **A fan-in input whose fork names a DIFFERENT barrier refuses, one half of
/// the guard being enough** — `parent != barrier` OR `fork.join != join` is a
/// head this join does not own the merge of, and neither operand may stand in
/// for the other. A coordinate `root().pushed("other", "stray")` has the right
/// parent and the wrong join: only the second operand is true.
#[test]
fn a_fanin_input_forked_by_a_different_join_is_refused_and_writes_nothing() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let base = declare_manifest(&rig, execution, vec![member(&rig, "base.txt", b"base\n")]);
    rig.db
        .record_work_tree_head(execution, "", base, "")
        .unwrap();
    let stray = WorkTreeHeadCoordinate::root().pushed("other", "stray");
    let input = accept_input(&rig, execution, vec![11]);
    let join = join_spec(execution, "join", vec![9]);
    let fanin = JoinFanIn {
        parent: WorkTreeHeadCoordinate::root(),
        inputs: vec![fan_input(input, &stray, "stray")],
    };
    let deltas_before = tree_delta_count(&rig);
    let error = rig
        .db
        .resolve_join(Ulid::new(), &join, &fanin)
        .expect_err("a branch coordinate forked by another barrier is not this join's input");
    assert!(
        error
            .to_string()
            .contains("neither the barrier's own coordinate"),
        "the refusal names the shape: {error}"
    );
    assert!(
        raw_branch(
            &rig.dir.path().join("operational.db"),
            execution,
            &stray.spelling()
        )
        .is_none(),
        "a refused input gets no head row forked"
    );
    assert_eq!(
        tree_delta_count(&rig),
        deltas_before,
        "a refused input declares no apply delta"
    );
}
