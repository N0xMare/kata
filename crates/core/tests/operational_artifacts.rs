//! The portable artifacts and capsules, observed through a SECOND raw rusqlite
//! handle rather than through the API under test.
//!
//! # Invariant
//!
//! EVERY assertion about durable state here reads `operational.db` (or `cas.db`, or the
//! blob tree on disk) through a connection this file opens itself. Asking
//! `OperationalDb` whether `OperationalDb` wrote the row is the shape that has let every
//! composition defect in this tree ship green; the typed readers (`artifact`,
//! `active_artifacts_for`, `capsule`) are asserted AGAINST the raw handle, not trusted in
//! place of it.
//!
//! # What it covers
//!
//! The artifact declaration and its refused sets, the capsule declaration's three
//! cross-plane refusals (unknown artifact, unasserted artifact, inactive environment) and
//! its tampered-bytes refusal, and the partial index the active read actually uses under
//! `EXPLAIN QUERY PLAN`.

use std::path::Path;
use std::sync::Arc;

use kata_core::store::cas::CasStore;
use kata_core::{
    ArtifactDeclaration, ArtifactKind, CapsuleDeclaration, CasRootOwner, EnvironmentDeclaration,
    InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::execution_contract::{
    ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess,
    EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId, PlatformId,
    PreparedActionId,
};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use rusqlite::params;
use ulid::Ulid;

/// One `artifacts` row as the raw handle reads it: `(object_id, size_bytes, privacy,
/// kind)` — NO OWNER; see the module's Identity note.
type RawArtifactRow = (Vec<u8>, i64, String, String);

/// One `capsules` row's five identity columns as the raw handle reads them:
/// `(occurrence_id, prepared_action_id, environment_id, platform_id,
/// capsule_object_id)`.
type RawCapsuleRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

const ENVIRONMENT_LABEL: &str = "pkgs-static-busybox";
const STAGE_ID: &str = "01JZZZZZZZZZZZZZZZZZZZZZE1";

struct Planes {
    _dir: tempfile::TempDir,
    op_path: std::path::PathBuf,
    db: Arc<OperationalDb>,
    cas: CasStore,
}

fn planes() -> Planes {
    let dir = tempfile::tempdir().unwrap();
    let op_path = dir.path().join("operational.db");
    let db = Arc::new(OperationalDb::open(&op_path).unwrap());
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();
    Planes {
        _dir: dir,
        op_path,
        db,
        cas,
    }
}

/// The SECOND handle. Read-only on purpose: an observer that can write is an observer
/// that can repair what it was meant to catch.
fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// A payload deliberately OVER `INLINE_THRESHOLD`, so the object is FILE-backed rather
/// than a column inside `cas.db`.
fn file_backed_bytes(tag: &str) -> Vec<u8> {
    kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "tag": tag,
        "filler": "p".repeat(kata_core::store::INLINE_THRESHOLD + 2_048),
    }))
}

fn after_declaration(offset: i64) -> i64 {
    chrono::Utc::now().timestamp_millis() + offset
}

/// Publish `bytes` and declare a node-owned artifact over them. Returns the reference
/// and the declaration so a caller can assert against both halves.
fn declare_blob(planes: &Planes, tag: &str, privacy: ArtifactPrivacy) -> ArtifactDeclaration {
    let bytes = file_backed_bytes(tag);
    let durable = planes.cas.put_durable(&bytes).unwrap();
    let reference = ArtifactRef::new(durable.object_id(), durable.size(), privacy);
    let declaration =
        ArtifactDeclaration::for_durable_object(&reference, CasRootOwner::Node, &durable).unwrap();
    planes.db.declare_artifact(&declaration).unwrap();
    declaration
}

// -- artifacts ---------------------------------------------------------------

/// DECLARE commits exactly two rows: the artifact and the AUTHORITATIVE object root
/// that retains its bytes.
///
/// Both counts come off the raw handle in ONE statement, so a torn declare is a value
/// mismatch rather than a missing assertion.
#[test]
fn declare_commits_the_artifact_row_and_its_object_root() {
    let planes = planes();
    let declaration = declare_blob(&planes, "one", ArtifactPrivacy::Private);
    let conn = raw(&planes.op_path);

    let (artifacts, roots): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM artifacts), (SELECT count(*) FROM cas_roots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (artifacts, roots),
        (1, 1),
        "one declare commits one artifact row and one object root, never one of the two"
    );

    let (object, size, privacy, kind): RawArtifactRow = conn
        .query_row(
            "SELECT object_id, size_bytes, privacy, kind FROM artifacts WHERE artifact_id = ?1",
            params![declaration.artifact_id().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(object, declaration.object_id().to_vec());
    assert_eq!(
        u64::try_from(size).unwrap(),
        file_backed_bytes("one").len() as u64,
        "size_bytes is the object's real length, which the receipt proved"
    );
    assert_eq!((privacy.as_str(), kind.as_str()), ("private", "blob"));

    let (owner_kind, purpose, digest): (String, String, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT owner_kind, purpose, object_digest FROM cas_roots",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (owner_kind.as_str(), purpose.as_str()),
        ("node", "artifact_object")
    );
    assert_eq!(
        digest,
        Some(declaration.object_id().to_vec()),
        "the root must name the object the row names, or one of the two is unverifiable"
    );

    // And the typed readers agree with what the raw handle just showed.
    let row = planes
        .db
        .artifact(declaration.artifact_id())
        .unwrap()
        .expect("the declared artifact is readable");
    assert_eq!(row.object_id, declaration.object_id());
    assert_eq!(row.kind, ArtifactKind::Blob);
    assert_eq!(
        planes
            .db
            .active_artifacts_for(CasRootOwner::Node)
            .unwrap()
            .len(),
        1
    );
}

/// An EXECUTION-OWNED artifact's ROOT cascades with the execution; the ROW SURVIVES as a
/// node-level content claim, and `declare_capsule` then refuses to map it.
///
/// # Why the survival is correct rather than a leak
///
/// The row does NOT cascade with the root, and must not: it carries no owner. `artifact_id`
/// folds no owner, so two executions that produced byte-identical results share ONE row —
/// cascading it on one execution's delete would erase the other's content claim while its
/// root is still live.
///
/// So a live row with ZERO live roots is REACHABLE, through a path with no Rust in it
/// (the `cas_roots` FK to `programs` is `ON DELETE CASCADE`, so the roots are DELETED
/// rather than released). That is exactly why `declare_capsule` checks the ROOT and not
/// the row, and the second half of this cell is that refusal — the state and the door
/// that refuses it, in one place.
#[test]
fn an_execution_owned_artifacts_root_cascades_and_the_row_survives_unretained() {
    let planes = planes();
    let execution = Ulid::new();
    submit(&planes.db, execution);
    let bytes = file_backed_bytes("owned");
    let durable = planes.cas.put_durable(&bytes).unwrap();
    let reference = ArtifactRef::new(durable.object_id(), durable.size(), ArtifactPrivacy::Public);
    let declaration = ArtifactDeclaration::for_durable_object(
        &reference,
        CasRootOwner::Execution(execution),
        &durable,
    )
    .unwrap();
    planes.db.declare_artifact(&declaration).unwrap();

    let conn = raw(&planes.op_path);
    let root_owner: Option<Vec<u8>> = conn
        .query_row(
            "SELECT owner_execution_id FROM cas_roots WHERE purpose = 'artifact_object'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        root_owner,
        Some(execution.to_bytes().to_vec()),
        "the ROOT carries the owner, and it is the only place that does"
    );
    assert_eq!(
        planes
            .db
            .active_artifacts_for(CasRootOwner::Execution(execution))
            .unwrap()
            .len(),
        1
    );
    assert!(
        planes
            .db
            .active_artifacts_for(CasRootOwner::Node)
            .unwrap()
            .is_empty(),
        "the node-owned read must not see an execution's artifacts"
    );

    // The CASCADE is the SCHEMA's, so it is proven by deleting the parent through a raw
    // writer handle — the typed API has no execution-delete verb to ask.
    let writer = rusqlite::Connection::open(&planes.op_path).unwrap();
    writer.pragma_update(None, "foreign_keys", "ON").unwrap();
    writer
        .execute(
            "DELETE FROM programs WHERE execution_id = ?1",
            params![execution.to_bytes().as_slice()],
        )
        .unwrap();
    let (artifacts, roots): (i64, i64) = writer
        .query_row(
            "SELECT (SELECT count(*) FROM artifacts), (SELECT count(*) FROM cas_roots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (artifacts, roots),
        (1, 0),
        "the ROOT cascaded and the ROW survived. The row is a node-level content claim \
         shared across owners, so cascading it on one execution's delete would erase a \
         claim another execution's live root may still be holding"
    );

    // AND THE DOOR THAT MATTERS REFUSES. The surviving row is unasserted, so a capsule
    // mapping it is refused — which is why `declare_capsule` reads `cas_roots` rather
    // than trusting the row the cascade left behind.
    let environment = declare_environment(&planes);
    let (capsule, bytes, capsule_object) = publish_capsule(
        &planes,
        environment,
        vec![mapping(declaration.artifact_id(), "/work")],
    );
    let error = planes
        .db
        .declare_capsule(
            &CapsuleDeclaration::for_durable_object(&capsule, &bytes, &capsule_object).unwrap(),
        )
        .expect_err("a surviving row with no live root retains nothing a worker could read");
    assert!(
        error.to_string().contains("no live root asserts its bytes"),
        "{error}"
    );
}

/// The constructor refuses a reference whose object or size disagrees with the receipt.
#[test]
fn a_declaration_refuses_a_reference_that_disagrees_with_the_receipt() {
    let planes = planes();
    let durable = planes.cas.put_durable(&file_backed_bytes("two")).unwrap();

    let wrong_object = ArtifactRef::new(
        ObjectId::from([0x77; 32]),
        durable.size(),
        ArtifactPrivacy::Public,
    );
    let error =
        ArtifactDeclaration::for_durable_object(&wrong_object, CasRootOwner::Node, &durable)
            .expect_err("a reference naming another object must be refused");
    assert!(error.to_string().contains("durability receipt"), "{error}");

    let wrong_size = ArtifactRef::new(
        durable.object_id(),
        durable.size() + 1,
        ArtifactPrivacy::Public,
    );
    let error = ArtifactDeclaration::for_durable_object(&wrong_size, CasRootOwner::Node, &durable)
        .expect_err("a reference claiming another length must be refused");
    assert!(error.to_string().contains("size is folded"), "{error}");
}

/// An IDENTICAL re-declare is a no-op; a divergent one is a typed conflict naming the
/// field, and neither writes a second row.
#[test]
fn redeclare_is_idempotent_when_identical_and_refuses_when_divergent() {
    let planes = planes();
    let bytes = file_backed_bytes("three");
    let durable = planes.cas.put_durable(&bytes).unwrap();
    let reference = ArtifactRef::new(durable.object_id(), durable.size(), ArtifactPrivacy::Public);
    let blob =
        ArtifactDeclaration::for_durable_object(&reference, CasRootOwner::Node, &durable).unwrap();
    planes.db.declare_artifact(&blob).unwrap();
    planes
        .db
        .declare_artifact(&blob)
        .expect("an identical re-declare is an idempotent no-op");

    // Same OBJECT, different KIND: one object cannot be both bytes and a manifest. The
    // tree declaration has to come from a real manifest whose canonical bytes ARE this
    // object — there is no `kind` parameter to flip — so the fixture publishes a manifest
    // and then declares a BLOB over it first.
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("a").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: durable.object_id(),
            size_bytes: durable.size(),
        },
    }])
    .unwrap();
    let manifest_bytes = manifest.manifest_bytes().unwrap();
    let manifest_object = planes.cas.put_durable(&manifest_bytes).unwrap();
    let as_blob = ArtifactDeclaration::for_durable_object(
        &ArtifactRef::new(
            manifest_object.object_id(),
            manifest_object.size(),
            ArtifactPrivacy::Public,
        ),
        CasRootOwner::Node,
        &manifest_object,
    )
    .unwrap();
    planes.db.declare_artifact(&as_blob).unwrap();
    let as_tree = ArtifactDeclaration::for_durable_tree(
        &manifest,
        ArtifactPrivacy::Public,
        CasRootOwner::Node,
        &manifest_object,
    )
    .unwrap();
    assert_eq!(
        as_tree.artifact_id(),
        as_blob.artifact_id(),
        "the artifact id folds object, size and privacy — not kind — so these are ONE id"
    );
    let error = planes
        .db
        .declare_artifact(&as_tree)
        .expect_err("a divergent kind must be refused");
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");
    assert!(error.to_string().contains("kind"), "{error}");

    // SAME REFERENCE, DIFFERENT OWNER: ONE ROW, TWO ROOTS. A refusal ("a divergent owner
    // must be refused") would be the defect: `artifact_id` folds `(object, size, privacy)`
    // and no owner, so two executions whose stages produce byte-identical results — or two
    // capsules mapping the canonical empty tree — are the SAME artifact, and the second was
    // rejected for being a different execution.
    let execution = Ulid::new();
    submit(&planes.db, execution);
    let owned = ArtifactDeclaration::for_durable_object(
        &reference,
        CasRootOwner::Execution(execution),
        &durable,
    )
    .unwrap();
    planes
        .db
        .declare_artifact(&owned)
        .expect("a second OWNER of one content address is the normal case, not a conflict");
    assert_eq!(
        owned.artifact_id(),
        blob.artifact_id(),
        "premise: the two declarations name ONE artifact id, or this cell is about two \
         artifacts and proves nothing"
    );

    let conn = raw(&planes.op_path);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM artifacts", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        2,
        "ONE ROW PER ARTIFACT ID: the two rows are the blob and the manifest published \
         above. The identical re-declare added none, the refused kind conflict added none, \
         and the SECOND OWNER added none — it added a ROOT"
    );
    // TWO ROOTS, one per owner, which is where ownership lives.
    let (roots, owners): (i64, i64) = conn
        .query_row(
            "SELECT count(*), count(DISTINCT COALESCE(hex(owner_execution_id), 'node'))
               FROM cas_roots
              WHERE purpose = 'artifact_object' AND object_digest = ?1
                AND released_at_ms IS NULL",
            params![blob.object_id().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (roots, owners),
        (2, 2),
        "one content claim, TWO owners — the node's root and the execution's. A single root \
         here would record only one of them, which is the state an owner column would make \
         unrepresentable by refusing the second owner outright"
    );
    // And each owner sees the artifact in its OWN active set.
    for owner in [CasRootOwner::Node, CasRootOwner::Execution(execution)] {
        assert!(
            planes
                .db
                .active_artifacts_for(owner)
                .unwrap()
                .iter()
                .any(|row| row.artifact_id == blob.artifact_id()),
            "{owner:?} retains the artifact, so its own active read must list it"
        );
    }
}

/// TWO ARTIFACTS OVER ONE OBJECT ARE REFUSED — which means exactly TWO PRIVACY CLASSES
/// over one object, because the id folds `(object, size, privacy)` and the first two
/// are fixed by the bytes.
///
/// The refusal names both artifacts; the UNIQUE index is what makes it total, and the
/// second half of this cell proves the index is really there by reaching around the
/// typed writer.
#[test]
fn a_second_artifact_over_one_object_is_refused_by_name_and_by_index() {
    let planes = planes();
    let public = declare_blob(&planes, "shared", ArtifactPrivacy::Public);
    let durable = planes
        .cas
        .put_durable(&file_backed_bytes("shared"))
        .unwrap();
    let private = ArtifactDeclaration::for_durable_object(
        &ArtifactRef::new(
            durable.object_id(),
            durable.size(),
            ArtifactPrivacy::Private,
        ),
        CasRootOwner::Node,
        &durable,
    )
    .unwrap();
    assert_ne!(
        private.artifact_id(),
        public.artifact_id(),
        "privacy is folded into the artifact id, so these are two ids over one object"
    );
    let error = planes
        .db
        .declare_artifact(&private)
        .expect_err("a second artifact over one object must be refused");
    let message = error.to_string();
    assert!(
        message.contains(&hex::encode(public.artifact_id())),
        "{message}"
    );
    assert!(
        message.contains(&hex::encode(private.artifact_id())),
        "{message}"
    );

    // The index, not the check: a raw writer that skipped the typed refusal still
    // cannot commit the second row.
    let writer = rusqlite::Connection::open(&planes.op_path).unwrap();
    let forged = writer.execute(
        "INSERT INTO artifacts
             (artifact_id, object_id, size_bytes, privacy, kind, created_at_ms)
         VALUES (?1, ?2, 1, 'private', 'blob', 1)",
        params![
            private.artifact_id().as_slice(),
            public.object_id().as_slice()
        ],
    );
    let forged = forged
        .expect_err("a second row over one object must be refused")
        .to_string();
    // SQLite names the UNIQUE index by its INDEXED COLUMN rather than by the index name,
    // and `idx_artifacts_object` is the only UNIQUE over `artifacts.object_id` — so
    // this string identifies that index and nothing else. Asserted rather than left at
    // `is_err`, because a CHECK or the primary key would also make this INSERT fail and
    // the cell would then be green without the index existing at all.
    assert!(
        forged.contains("UNIQUE constraint failed: artifacts.object_id"),
        "the refusal must come from idx_artifacts_object, the one UNIQUE over that \
         column: {forged}"
    );
}

/// The ACTIVE read really uses its partial index, over the PRODUCTION projection.
#[test]
fn the_active_artifact_read_uses_its_partial_index() {
    let planes = planes();
    for tag in ["a", "b", "c"] {
        declare_blob(&planes, tag, ArtifactPrivacy::Public);
    }
    let conn = raw(&planes.op_path);
    // The column list is the PRODUCTION reader's, re-derived from the one const every
    // artifact read is built from rather than retyped here: a plan proved over a
    // narrower projection than the reader issues is a plan for a different statement.
    let columns = kata_core::operational::debug_artifact_columns()
        .strip_prefix("SELECT ")
        .and_then(|rest| rest.split_once(" FROM artifacts"))
        .map(|(columns, _)| columns.to_string())
        .expect("the artifact read projection is `SELECT <columns> FROM artifacts`");
    let mut stmt = conn
        .prepare(&format!(
            "EXPLAIN QUERY PLAN SELECT {columns} FROM artifacts \
             WHERE object_id IN ( \
                 SELECT object_digest FROM cas_roots \
                  WHERE purpose = 'artifact_object' \
                    AND owner_execution_id IS NULL) \
             ORDER BY artifact_id"
        ))
        .unwrap();
    let plan = stmt
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" | ");
    // The index is over `cas_roots`, not over an `artifacts` owner column: the
    // OWNER side of the read is what must be indexed, because it is the equality (or IS
    // NULL) term and the one that would otherwise scan every artifact root on the node.
    assert!(
        plan.contains("idx_cas_roots_owner_artifact"),
        "the owner's-roots half of the active read must use its index: {plan}"
    );
    assert_eq!(
        planes
            .db
            .active_artifacts_for(CasRootOwner::Node)
            .unwrap()
            .len(),
        3
    );
}

/// A TREE declaration is only constructible from the MANIFEST, and the address is
/// re-derived from it.
#[test]
fn a_tree_declaration_refuses_a_receipt_that_is_not_its_manifests_bytes() {
    let planes = planes();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("README.md").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: ObjectId::from([0xA1; 32]),
            size_bytes: 2_048,
        },
    }])
    .unwrap();
    // A receipt for OTHER bytes: the only way a `kind='tree'` row could ever name an
    // object that does not parse as a manifest.
    let other = planes
        .cas
        .put_durable(&file_backed_bytes("not-a-tree"))
        .unwrap();
    let error = ArtifactDeclaration::for_durable_tree(
        &manifest,
        ArtifactPrivacy::Public,
        CasRootOwner::Node,
        &other,
    )
    .expect_err("a tree declaration over bytes that are not this manifest must be refused");
    assert!(
        error.to_string().contains("PARSES as a tree manifest"),
        "{error}"
    );

    // The honest path, for contrast: the same manifest, published.
    let bytes = manifest.manifest_bytes().unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    let declaration = ArtifactDeclaration::for_durable_tree(
        &manifest,
        ArtifactPrivacy::Public,
        CasRootOwner::Node,
        &durable,
    )
    .unwrap();
    assert_eq!(declaration.kind(), ArtifactKind::Tree);
    assert_eq!(declaration.object_id(), durable.object_id().0);
}

// -- capsules ----------------------------------------------------------------

/// DECLARE a capsule: the row, and its node-owned authoritative object root.
#[test]
fn declare_capsule_commits_the_row_and_its_node_owned_object_root() {
    let planes = planes();
    let environment = declare_environment(&planes);
    let artifact = declare_blob(&planes, "mapped", ArtifactPrivacy::Private);
    let (capsule, bytes, durable) = publish_capsule(
        &planes,
        environment,
        vec![mapping(artifact.artifact_id(), "/work")],
    );
    let declaration = CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap();
    planes.db.declare_capsule(&declaration).unwrap();

    let conn = raw(&planes.op_path);
    let (occurrence, action, environment_id, platform, object): RawCapsuleRow = conn
        .query_row(
            "SELECT occurrence_id, prepared_action_id, environment_id, platform_id,
                    capsule_object_id
               FROM capsules WHERE capsule_id = ?1",
            params![declaration.capsule_id().as_slice()],
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
        .unwrap();
    assert_eq!(occurrence, capsule.occurrence().0.0.to_vec());
    assert_eq!(action, capsule.action().0.0.to_vec());
    assert_eq!(environment_id, capsule.environment().0.0.to_vec());
    assert_eq!(platform, capsule.platform().0.0.to_vec());
    assert_eq!(object, declaration.capsule_object_id().to_vec());

    let purposes: Vec<String> = conn
        .prepare("SELECT purpose FROM cas_roots ORDER BY purpose")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        purposes,
        vec![
            "artifact_object".to_string(),
            "capsule_object".to_string(),
            "nix_environment_manifest".to_string()
        ],
        "the capsule's bytes are retained by their own node-owned root"
    );

    let row = planes
        .db
        .capsule(declaration.capsule_id())
        .unwrap()
        .expect("the declared capsule is readable");
    assert_eq!(row.capsule_object_id, declaration.capsule_object_id());

    // An identical re-declare is an idempotent no-op.
    planes.db.declare_capsule(&declaration).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM capsules", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

/// A capsule mapping an artifact this plane never declared is refused, and the message
/// names the guest path as well as the artifact.
#[test]
fn declare_capsule_refuses_a_mapping_whose_artifact_is_not_declared() {
    let planes = planes();
    let environment = declare_environment(&planes);

    let (capsule, bytes, durable) =
        publish_capsule(&planes, environment, vec![mapping([0x99; 32], "/work")]);
    let unknown = CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap();
    let error = planes
        .db
        .declare_capsule(&unknown)
        .expect_err("a mapping naming an undeclared artifact must be refused");
    let message = error.to_string();
    assert!(
        message.contains("is not declared on this node"),
        "{message}"
    );
    assert!(message.contains("/work"), "{message}");
    // The other refusal — a declared row no live root asserts — is
    // `an_execution_owned_artifacts_root_cascades_and_the_row_survives_unretained`'s.

    let conn = raw(&planes.op_path);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM capsules", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "a refused capsule declaration writes nothing"
    );
}

/// A capsule naming an environment this plane never declared, or one it released, is
/// refused — the first also being what the foreign key makes structural.
#[test]
fn declare_capsule_refuses_an_environment_that_is_not_active() {
    let planes = planes();
    let artifact = declare_blob(&planes, "mapped", ArtifactPrivacy::Public);
    let undeclared = EnvironmentId(ContentHash::new([0x5B; 32]));
    let (capsule, bytes, durable) = publish_capsule(
        &planes,
        undeclared,
        vec![mapping(artifact.artifact_id(), "/work")],
    );
    let declaration = CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap();
    let error = planes
        .db
        .declare_capsule(&declaration)
        .expect_err("a capsule naming an undeclared environment must be refused");
    assert!(
        error.to_string().contains("not declared on this node"),
        "{error}"
    );

    let environment = declare_environment(&planes);
    let promoted = after_declaration(5);
    planes
        .db
        .promote_environment_root(environment.0.0, promoted)
        .unwrap();
    planes
        .db
        .release_environment(environment.0.0, promoted + 10)
        .unwrap();
    let (capsule, bytes, durable) = publish_capsule(
        &planes,
        environment,
        vec![mapping(artifact.artifact_id(), "/work")],
    );
    let declaration = CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap();
    let error = planes
        .db
        .declare_capsule(&declaration)
        .expect_err("a capsule naming a released environment must be refused");
    assert!(error.to_string().contains("was released at"), "{error}");
}

/// TAMPERED BYTES ARE REFUSED AT THE DECLARATION, by `Capsule`'s own `Deserialize`
/// recomputing the id — not by a re-implementation of the derivation here.
#[test]
fn a_capsule_declaration_refuses_tampered_bytes() {
    let planes = planes();
    let environment = declare_environment(&planes);
    let artifact = declare_blob(&planes, "mapped", ArtifactPrivacy::Private);
    let (capsule, bytes, _) = publish_capsule(
        &planes,
        environment,
        vec![mapping(artifact.artifact_id(), "/work")],
    );

    // Flip one nibble of the SERIALIZED capsule id and re-publish: the bytes are
    // durable and the receipt is honest about them, so the only thing that can refuse
    // is the decode.
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut tampered_id = capsule.id().0.0;
    tampered_id[0] ^= 0x01;
    value["id"] = serde_json::json!(hex::encode(tampered_id));
    let tampered_bytes = serde_json::to_vec(&value).unwrap();
    let tampered = planes.cas.put_durable(&tampered_bytes).unwrap();
    let error = CapsuleDeclaration::for_durable_object(&capsule, &tampered_bytes, &tampered)
        .expect_err("bytes whose embedded capsule id was tampered with must be refused");
    assert!(
        error.to_string().contains("do not decode as a capsule"),
        "{error}"
    );

    // And a receipt for OTHER bytes is refused before the decode is even attempted.
    let other = planes.cas.put_durable(b"not this capsule").unwrap();
    let error = CapsuleDeclaration::for_durable_object(&capsule, &bytes, &other)
        .expect_err("a receipt for other bytes must be refused");
    assert!(
        error.to_string().contains("durability receipt is for"),
        "{error}"
    );
}

// -- fixtures ----------------------------------------------------------------

fn submit(db: &OperationalDb, execution: Ulid) {
    let program_hash = ContentHash::new([0x11; 32]);
    let program_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 4,
        "program_hash": program_hash.to_string(),
        "program": 1,
    }));
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
        "inputs": [1],
    }));
    let outcome = db
        .submit_execution(
            execution,
            &ProgramRecord {
                program_hash,
                schema_version: 4,
                program_json,
            },
            &InvocationRecord {
                schema_version: 1,
                kind: InvocationKind::Workflow,
                admission_digest: AdmissionDigest(ContentHash::new(
                    *blake3::hash(&invocation_json).as_bytes(),
                )),
                invocation_json,
            },
        )
        .unwrap();
    assert!(matches!(outcome, SubmitOutcome::Submitted { .. }));
}

/// A declared Nix environment, so a capsule has something real to bind. The capsule
/// plane checks `nix_environments` rows, not a type, so the fixture has to write one.
fn declare_environment(planes: &Planes) -> EnvironmentId {
    let manifest = planes
        .cas
        .put_durable(&file_backed_bytes("environment-manifest"))
        .unwrap();
    let environment_id = [0x5A; 32];
    let declaration = EnvironmentDeclaration::for_staged_root(
        environment_id,
        &manifest,
        [0x5C; 32],
        ENVIRONMENT_LABEL,
        [0x33; 32],
        STAGE_ID,
    )
    .unwrap();
    planes.db.declare_environment(&declaration).unwrap();
    EnvironmentId(ContentHash::new(environment_id))
}

fn mapping(artifact: [u8; 32], guest_path: &str) -> GuestMapping {
    GuestMapping {
        artifact: kata_types::execution_contract::ArtifactId(ContentHash::new(artifact)),
        guest_path: GuestPath::new(guest_path).unwrap(),
        access: GuestAccess::ReadOnly,
    }
}

/// Build a capsule, publish its canonical serialization, and hand back all three
/// halves a declaration needs.
fn publish_capsule(
    planes: &Planes,
    environment: EnvironmentId,
    inputs: Vec<GuestMapping>,
) -> (Capsule, Vec<u8>, kata_core::store::cas::DurableObject) {
    let capsule = Capsule::new(
        OccurrenceId(ContentHash::new([0x01; 32])),
        PreparedActionId(ContentHash::new([0x02; 32])),
        environment,
        PlatformId(ContentHash::new([0x33; 32])),
        inputs,
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 60_000,
            output_bytes: 1_048_576,
            memory_bytes: 268_435_456,
            process_count: 64,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap();
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    (capsule, bytes, durable)
}
