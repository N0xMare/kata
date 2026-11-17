//! The `execution_git_views` plane and
//! [`publish_execution_git_view`]'s publish-declare-record shape, observed
//! through a SECOND raw rusqlite handle and the CAS's own rows, never through
//! the plane under test.
//!
//! # Invariant
//!
//! The view is write-once by PRIMARY KEY plus `record_execution_git_view`'s
//! converge-or-refuse: an identical re-record is re-admission converging, a
//! divergent one is `git_view_divergent`. Publication puts the history
//! members into CAS, publishes the manifest after
//! them, declares the artifact execution-retained BEFORE the view row
//! commits — the `after_git_view_published_before_recorded` window's near
//! edge. The crash half of that window lives in `cas_root_liveness.rs`
//! (K17), which owns the CAS/nucleus join; this file owns the row semantics
//! and the re-drive — the same split `work_tree_head.rs` states for the
//! `/work` head one plane over.

use std::path::Path;
use std::sync::Arc;

use kata_core::operational::GIT_VIEW_DIVERGENT;
use kata_core::store::cas::CasStore;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::execution_contract::GitViewRef;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::tree_artifact::{
    CommittedBaseGitView, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
};
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
    let program_hash = ContentHash::new([0xD9; 32]);
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
/// `execution_git_views.history_artifact_id` references `artifacts`, so a view
/// may only ever name a declared row. `label` names the manifest's one member:
/// two labels are two DIFFERENT artifacts, which is what the divergent
/// restatement case needs — an empty manifest declares the same id every call
/// and a "divergent" record over it would converge instead of refusing.
fn declare_tree(rig: &Rig, execution: Ulid, label: &str) -> [u8; 32] {
    let member_bytes = format!("{label} member bytes\n").into_bytes();
    let member_durable = rig.cas.put_durable(&member_bytes).unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new(format!("objects/pack/{label}.pack")).unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member_durable.object_id(),
            size_bytes: member_durable.size(),
        },
    }])
    .unwrap();
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

/// The view tuple this suite's fixtures record — forty hex characters of base
/// commit, the trunk's short name at that commit, the inherited identity — so
/// the row checks read the same values the producer would spell.
const BASE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const BASE_BRANCH: &str = "main";

/// The fixtures' branch ref: trunk's name at the base commit, the shape a
/// trunk target's view records.
fn base_branch() -> GitViewRef {
    GitViewRef {
        name: BASE_BRANCH.into(),
        commit: BASE_COMMIT.into(),
    }
}
const IDENTITY_NAME: &str = "kata tests";
const IDENTITY_EMAIL: &str = "kata-tests@localhost";

fn record_view(rig: &Rig, execution: Ulid, artifact: [u8; 32]) {
    rig.db
        .record_execution_git_view(
            execution,
            BASE_COMMIT,
            Some(&base_branch()),
            IDENTITY_NAME,
            IDENTITY_EMAIL,
            artifact,
        )
        .expect("the view records");
}

/// **The row writes and reads back through its own reader, and the SECOND raw
/// handle agrees on every column** — the row is the join `capsule_submit` makes,
/// so the durable shape is what a late dispatch sees, not what the writer
/// remembers.
#[test]
fn a_recorded_view_reads_back_off_the_row_and_the_reader() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let artifact = declare_tree(&rig, execution, "first");

    record_view(&rig, execution, artifact);

    // The SECOND handle reads the row back — every column, as stored.
    let (exec, commit, branch, branch_commit, name, email, hist): (
        Vec<u8>,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
    ) = raw(&rig.dir.path().join("operational.db"))
        .query_row(
            "SELECT execution_id, base_commit, branch_name, branch_commit, identity_name, \
                    identity_email, history_artifact_id \
             FROM execution_git_views WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
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
        .unwrap();
    assert_eq!(exec, execution.to_bytes().to_vec());
    assert_eq!(commit, BASE_COMMIT);
    assert_eq!(branch, BASE_BRANCH);
    assert_eq!(branch_commit, BASE_COMMIT);
    assert_eq!(name, IDENTITY_NAME);
    assert_eq!(email, IDENTITY_EMAIL);
    assert_eq!(hist, artifact.to_vec());

    // And the plane's own reader decodes the same facts.
    let view = rig
        .db
        .execution_git_view(execution)
        .expect("the read resolves")
        .expect("the row exists");
    assert_eq!(view.execution_id, execution);
    assert_eq!(view.base_commit, BASE_COMMIT);
    assert_eq!(view.branch, Some(base_branch()));
    assert_eq!(view.identity_name, IDENTITY_NAME);
    assert_eq!(view.identity_email, IDENTITY_EMAIL);
    assert_eq!(view.history_artifact_id, artifact);
    assert!(view.recorded_at_ms > 0);

    // An execution with no row reads `None` — the absent case the capsule
    // submit's non-isolated arm relies on.
    let other = Ulid::new();
    submit(&rig, other);
    assert!(
        rig.db
            .execution_git_view(other)
            .expect("the read resolves")
            .is_none(),
        "no row means no view, not an error"
    );
}

/// **Converge-or-refuse, both arms.** An identical restatement is re-admission
/// converging — one row, unchanged. A divergent one — a second artifact, or a
/// second base, under one execution — is `git_view_divergent`, and the stored
/// row keeps its first value: the window is not a route to a second input.
#[test]
fn an_identical_restate_converges_and_a_divergent_one_is_refused_by_name() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let artifact = declare_tree(&rig, execution, "first");
    record_view(&rig, execution, artifact);

    // Identical restatement — converges, still ONE row.
    record_view(&rig, execution, artifact);
    let rows: i64 = raw(&rig.dir.path().join("operational.db"))
        .query_row(
            "SELECT count(*) FROM execution_git_views WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1, "re-admission converges — never a second row");

    // A second ARTIFACT under the same view metadata refuses.
    let second = declare_tree(&rig, execution, "second");
    let refusal = rig
        .db
        .record_execution_git_view(
            execution,
            BASE_COMMIT,
            Some(&base_branch()),
            IDENTITY_NAME,
            IDENTITY_EMAIL,
            second,
        )
        .expect_err("a second history artifact under one execution is refused");
    assert!(
        refusal.to_string().contains(GIT_VIEW_DIVERGENT),
        "the refusal is named: {refusal}"
    );

    // A second BASE COMMIT refuses the same way — even naming the first
    // artifact, a different base is a different view.
    let refusal = rig
        .db
        .record_execution_git_view(
            execution,
            "fedcba9876543210fedcba9876543210fedcba98",
            Some(&base_branch()),
            IDENTITY_NAME,
            IDENTITY_EMAIL,
            artifact,
        )
        .expect_err("a second base commit under one execution is refused");
    assert!(
        refusal.to_string().contains(GIT_VIEW_DIVERGENT),
        "the refusal is named: {refusal}"
    );

    // And the stored row still names the FIRST pair — nothing half-wrote.
    let (commit, hist): (String, Vec<u8>) = raw(&rig.dir.path().join("operational.db"))
        .query_row(
            "SELECT base_commit, history_artifact_id FROM execution_git_views \
             WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(commit, BASE_COMMIT, "the first view stands, unmutated");
    assert_eq!(hist, artifact.to_vec());
}

/// **The referential edges the row owes.** A view names an execution and an
/// artifact — a row over an artifact no `artifacts` row carries, or an
/// execution no `programs` row carries, is a FOREIGN KEY refusal, not a
/// nullable hole.
#[test]
fn a_view_over_an_undeclared_artifact_or_execution_is_refused() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);

    // The artifact half: a plausible 32-byte id nothing declared.
    let refusal = rig
        .db
        .record_execution_git_view(
            execution,
            BASE_COMMIT,
            Some(&base_branch()),
            IDENTITY_NAME,
            IDENTITY_EMAIL,
            [0xAA; 32],
        )
        .expect_err("a view over an artifact row that does not exist is refused");
    assert!(
        refusal.to_string().contains("git view"),
        "the refusal names the write: {refusal}"
    );

    // The execution half: a view for an execution no `programs` row carries.
    let artifact = declare_tree(&rig, execution, "first");
    let ghost = Ulid::new();
    let refusal = rig
        .db
        .record_execution_git_view(
            ghost,
            BASE_COMMIT,
            Some(&base_branch()),
            IDENTITY_NAME,
            IDENTITY_EMAIL,
            artifact,
        )
        .expect_err("a view over an execution row that does not exist is refused");
    assert!(
        refusal.to_string().contains("git view"),
        "the refusal names the write: {refusal}"
    );

    let rows: i64 = raw(&rig.dir.path().join("operational.db"))
        .query_row("SELECT count(*) FROM execution_git_views", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0, "a refused insert leaves no row behind");
}

/// **The publish shape end to end at this plane**: members through the guard,
/// manifest declared, artifact + owner root durable, THEN the row — and the
/// decoded view carries the conversion's metadata, so the capsule submit's
/// join reads exactly what admission produced.
#[test]
fn publish_execution_git_view_declares_then_records() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);

    // The fixture conversion — the shape `kata_vcs`'s producer returns: one
    // pack member and an index member streamed through `put_member`, then the
    // manifest over them plus the view's metadata.
    let pack_bytes: &[u8] = b"pack-bytes-the-history-artifact-carries\n";
    let index_bytes: &[u8] = b"git-index-for-the-base-tree\n";
    let convert = move |put: &mut dyn FnMut(&[u8]) -> kata_types::KataResult<ObjectId>| {
        let pack = put(pack_bytes)?;
        let index = put(index_bytes)?;
        let manifest = TreeManifest::new(vec![
            TreeEntry {
                path: TreePath::new("objects/pack/pack-deadbeef.pack").unwrap(),
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: pack,
                    size_bytes: pack_bytes.len() as u64,
                },
            },
            TreeEntry {
                path: TreePath::new("index").unwrap(),
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: index,
                    size_bytes: index_bytes.len() as u64,
                },
            },
        ])
        .unwrap();
        let manifest_bytes = manifest.manifest_bytes().unwrap();
        Ok(CommittedBaseGitView {
            base_commit: BASE_COMMIT.to_owned(),
            branch: Some(base_branch()),
            identity: kata_types::execution_contract::GitIdentity {
                name: IDENTITY_NAME.into(),
                email: IDENTITY_EMAIL.into(),
            },
            manifest,
            manifest_bytes,
        })
    };

    let view =
        kata_core::git_view::publish_execution_git_view(&rig.db, &rig.cas, execution, convert)
            .expect("the publish records the view");
    assert_eq!(view.base_commit, BASE_COMMIT);
    assert_eq!(view.branch, Some(base_branch()));

    // The order the window is named for: the artifact row and its owner root
    // AND the view row all exist together once the call returns — the row is
    // LAST, so a view row can never name an undeclared artifact.
    let op = rig.dir.path().join("operational.db");
    let (views, trees, roots): (i64, i64, i64) = raw(&op)
        .query_row(
            "SELECT (SELECT count(*) FROM execution_git_views),
                    (SELECT count(*) FROM artifacts WHERE kind = 'tree'),
                    (SELECT count(*) FROM cas_roots WHERE owner_execution_id = ?1)",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((views, trees, roots), (1, 1, 1));

    // The member objects RESOLVE off the CAS — the artifact the row names is
    // content, not a label for a hole.
    assert!(
        rig.cas
            .resolves(&kata_types::cache::object_id_for_canonical_bytes(
                pack_bytes
            ))
            .unwrap(),
        "the pack member is durable"
    );
    assert!(
        rig.cas
            .resolves(&kata_types::cache::object_id_for_canonical_bytes(
                index_bytes
            ))
            .unwrap(),
        "the index member is durable"
    );

    // And the same conversion re-driven converges — CAS dedup gives the same
    // artifact id, the record re-states identically: the recovery drive.
    let again =
        kata_core::git_view::publish_execution_git_view(&rig.db, &rig.cas, execution, convert)
            .expect("re-admission converges");
    assert_eq!(again.history_artifact_id, view.history_artifact_id);
    let views: i64 = raw(&op)
        .query_row("SELECT count(*) FROM execution_git_views", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(views, 1, "convergent re-drive writes nothing new");
}

/// **The view plane is the booted shape** — the `user_version` stamp and the
/// `execution_git_views` table with its exact column set, read off
/// `sqlite_master`/`PRAGMA table_info` by the second handle: a fresh open
/// carries the view plane, not a label for it.
#[test]
fn schema_32_boots_with_the_execution_git_views_table() {
    let rig = rig();
    let conn = raw(&rig.dir.path().join("operational.db"));

    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(
        version,
        kata_core::OPERATIONAL_SCHEMA_VERSION,
        "the fresh nucleus stamps the current version — the table arrived at 32 and every later \
         stamp keeps it"
    );

    // The table's own column set, in declaration order — the shape the stamp
    // identifies. `validate_schema` asserts this on every open; the assertion
    // here is that a SECOND handle agrees, so the check is not the plane
    // asking itself.
    let mut columns = conn
        .prepare("PRAGMA table_info(execution_git_views)")
        .unwrap();
    let names: Vec<String> = columns
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        names,
        [
            "execution_id",
            "base_commit",
            "branch_name",
            "branch_commit",
            "identity_name",
            "identity_email",
            "history_artifact_id",
            "recorded_at_ms",
        ],
        "the table's column set is exactly what the schema declares"
    );

    // And its artifact-side index exists — the ON DELETE NO ACTION child scan
    // is planned, not table-scanned.
    let index: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'index' \
             AND tbl_name = 'execution_git_views' \
             AND name = 'idx_execution_git_views_artifact'",
            [],
            |row| row.get(0),
        )
        .ok();
    assert_eq!(
        index.as_deref(),
        Some("idx_execution_git_views_artifact"),
        "the artifact-side index exists"
    );
}
