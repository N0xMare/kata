//! `LocalPlaneIndex` over a REAL `operational.db` and `cas.db`, through its real SQL.
//!
//! # Why these cells exist
//!
//! The worker's resolvers were proven against in-memory doubles of `EnvironmentIndex` /
//! `TreeResolver`, so the SQL that production actually runs — the `released_at_ms IS NULL`
//! predicate, the row-versus-bytes identity recomputation — is covered by nothing else:
//! dropping each predicate in production leaves the whole four-crate suite green
//! without these cells. Every row here is written by the production plane (`OperationalDb`) or, for the
//! forged row, by a second raw writable handle, and every verdict is the reader's refusal
//! token.

use std::path::Path;

use kata_core::store::cas::CasStore;
use kata_core::{ArtifactDeclaration, CasRootOwner, EnvironmentDeclaration, OperationalDb};
use kata_types::execution_contract::{ArtifactId, ArtifactPrivacy, EnvironmentId};
use kata_types::primitives::FixedBytes;
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_worker::materialize::TreeResolver;
use kata_worker::plane_index::{LocalPlaneIndex, resolve_environment};

struct Planes {
    _dir: tempfile::TempDir,
    data_dir: std::path::PathBuf,
    db: OperationalDb,
    cas: CasStore,
}

fn planes() -> Planes {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let db = OperationalDb::open(data_dir.join("operational.db")).unwrap();
    let cas = CasStore::open(data_dir.join("cas.db"), data_dir.join("cas")).unwrap();
    Planes {
        _dir: dir,
        data_dir,
        db,
        cas,
    }
}

/// Publish a one-member tree and declare it NODE-retained; return its id and object.
fn declare_tree(planes: &Planes, payload: &[u8]) -> (ArtifactId, [u8; 32]) {
    let member = planes.cas.put_durable(payload).unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("a.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    let durable = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let declaration = ArtifactDeclaration::for_durable_tree(
        &manifest,
        ArtifactPrivacy::Private,
        CasRootOwner::Node,
        &durable,
    )
    .unwrap();
    planes.db.declare_artifact(&declaration).unwrap();
    (
        ArtifactId(FixedBytes(declaration.artifact_id())),
        declaration.object_id(),
    )
}

fn writable(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

#[test]
fn a_row_pointing_at_other_bytes_is_refused_as_an_identity_mismatch() {
    let planes = planes();
    let (artifact, _) = declare_tree(&planes, b"the declared bytes\n");
    // Another VALID tree manifest, published but never declared.
    let other_member = planes.cas.put_durable(b"other bytes\n").unwrap();
    let other = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("b.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: other_member.object_id(),
            size_bytes: other_member.size(),
        },
    }])
    .unwrap();
    let other_durable = planes
        .cas
        .put_durable(&other.manifest_bytes().unwrap())
        .unwrap();
    // FORGE the row through a second handle: the id stays, the object and length move.
    let changed = writable(&planes.data_dir.join("operational.db"))
        .execute(
            "UPDATE artifacts SET object_id = ?1, size_bytes = ?2 WHERE artifact_id = ?3",
            rusqlite::params![
                other_durable.object_id().0.as_slice(),
                i64::try_from(other_durable.size()).unwrap(),
                artifact.0.0.as_slice()
            ],
        )
        .unwrap();
    assert_eq!(changed, 1, "the forged row is in place — the premise");
    let index = LocalPlaneIndex::open(&planes.data_dir).unwrap();
    let refusal = index
        .tree_manifest(artifact)
        .expect_err("the row's bytes are not the ones the id names")
        .to_string();
    assert!(
        refusal.contains("artifact_identity_mismatch"),
        "refused by name: {refusal}"
    );
}

fn declare_environment_row(planes: &Planes, environment: [u8; 32]) {
    let manifest = planes
        .cas
        .put_durable(b"{\"manifest\":\"fixture\"}")
        .unwrap();
    planes
        .db
        .declare_environment(
            &EnvironmentDeclaration::for_staged_root(
                environment,
                &manifest,
                [0x5C; 32],
                "fixture",
                [0x33; 32],
                "01JZZZZZZZZZZZZZZZZZZZZZE1",
            )
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn an_unpromoted_environment_is_refused_through_the_real_row() {
    let planes = planes();
    declare_environment_row(&planes, [0x5A; 32]);
    let index = LocalPlaneIndex::open(&planes.data_dir).unwrap();
    let refusal = resolve_environment(&index, &index, EnvironmentId(FixedBytes([0x5A; 32])))
        .expect_err("an unpromoted root is not bindable")
        .to_string();
    assert!(
        refusal.contains("environment_root_unpromoted"),
        "refused by name: {refusal}"
    );
}

#[test]
fn a_released_environment_is_refused_through_the_real_row() {
    let planes = planes();
    declare_environment_row(&planes, [0x5B; 32]);
    let now = chrono::Utc::now().timestamp_millis();
    planes.db.promote_environment_root([0x5B; 32], now).unwrap();
    planes.db.release_environment([0x5B; 32], now + 1).unwrap();
    let index = LocalPlaneIndex::open(&planes.data_dir).unwrap();
    let refusal = resolve_environment(&index, &index, EnvironmentId(FixedBytes([0x5B; 32])))
        .expect_err("a released environment's bytes may already be collected")
        .to_string();
    assert!(
        refusal.contains("environment_released"),
        "refused by name: {refusal}"
    );
}
