//! The `/work` PRODUCER (`kata_core::work_tree`): walk, bound, publish,
//! declare. Every refusal by name, each with nothing published, read through a SECOND raw
//! handle on `cas.db` / `operational.db` — never the plane's own readers.

use std::path::Path;

use kata_core::store::cas::CasStore;
use kata_core::work_tree::{
    WORK_TREE_BOUND_EXCEEDED, WORK_TREE_MAX_BYTES, WORK_TREE_MAX_ENTRIES,
    WORK_TREE_MEMBER_UNVERIFIED, WORK_TREE_SPECIAL_FILE, WORK_TREE_SYMLINK,
    WORK_TREE_UNACCEPTABLE_PATH, WORK_TREE_UNMATERIALIZED, WORK_TREE_UNREADABLE, declare_work_tree,
    publish_scratch_tree_head, walk_work_tree,
};
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::idempotency::canonicalize_args;
use kata_types::primitives::ContentHash;
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use ulid::Ulid;

struct Planes {
    dir: tempfile::TempDir,
    db: OperationalDb,
    cas: CasStore,
}

fn planes() -> Planes {
    let dir = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();
    Planes { dir, db, cas }
}

fn execution(planes: &Planes) -> Ulid {
    let program_hash = ContentHash::new([0x42; 32]);
    let invocation_json = canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
    }));
    let execution_id = Ulid::new();
    assert!(matches!(
        planes
            .db
            .submit_execution(
                execution_id,
                &ProgramRecord {
                    program_hash,
                    schema_version: 4,
                    program_json: canonicalize_args(&serde_json::json!({
                        "schema_version": 4,
                        "program_hash": program_hash.to_string(),
                    })),
                },
                &InvocationRecord {
                    schema_version: 1,
                    kind: InvocationKind::Workflow,
                    admission_digest: kata_types::identity_algebra::AdmissionDigest(
                        ContentHash::new(*blake3::hash(&invocation_json).as_bytes(),)
                    ),
                    invocation_json,
                },
            )
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    execution_id
}

/// `cas_objects` row count, through a second read-only handle.
fn cas_objects(planes: &Planes) -> i64 {
    rusqlite::Connection::open_with_flags(
        planes.dir.path().join("cas.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
    .query_row("SELECT count(*) FROM cas_objects", [], |row| row.get(0))
    .unwrap()
}

fn workspace(planes: &Planes) -> std::path::PathBuf {
    let root = planes.dir.path().join("workspace");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.txt"), b"source\n").unwrap();
    root
}

fn refused(root: &Path, token: &str) {
    let refusal = walk_work_tree(root)
        .expect_err("the walk must refuse")
        .to_string();
    assert!(
        refusal.contains(token),
        "refused by name ({token}): {refusal}"
    );
}

#[test]
fn an_unmaterialized_workspace_is_refused_rather_than_mapped_empty() {
    let planes = planes();
    refused(
        &planes.dir.path().join("never-created"),
        WORK_TREE_UNMATERIALIZED,
    );
    let file = planes.dir.path().join("a-file");
    std::fs::write(&file, b"x").unwrap();
    refused(&file, WORK_TREE_UNMATERIALIZED);
}

#[test]
fn a_symlink_anywhere_is_refused_and_nothing_is_published() {
    let planes = planes();
    let root = workspace(&planes);
    std::fs::create_dir_all(root.join("deep/er")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("deep/er/link")).unwrap();
    let before = cas_objects(&planes);
    refused(&root, WORK_TREE_SYMLINK);
    assert_eq!(cas_objects(&planes), before, "the walk publishes nothing");

    // A symlinked ROOT is refused too: the root is opened O_NOFOLLOW.
    let linked_root = planes.dir.path().join("linked-root");
    std::os::unix::fs::symlink(&root, &linked_root).unwrap();
    refused(&linked_root, WORK_TREE_UNMATERIALIZED);
}

#[test]
fn a_fifo_or_a_socket_is_refused_as_a_special_file() {
    let planes = planes();
    let root = workspace(&planes);
    let fifo = root.join("pipe");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    refused(&root, WORK_TREE_SPECIAL_FILE);
    std::fs::remove_file(&fifo).unwrap();
    let _socket = kata_transport::unix_socket::bind_std(&root.join("sock")).unwrap();
    refused(&root, WORK_TREE_SPECIAL_FILE);
}

#[test]
fn a_walk_past_either_bound_is_refused_and_nothing_is_published() {
    let planes = planes();
    let entries = workspace(&planes);
    for index in 0..WORK_TREE_MAX_ENTRIES {
        std::fs::write(entries.join(format!("f{index}")), b"").unwrap();
    }
    let before = cas_objects(&planes);
    refused(&entries, WORK_TREE_BOUND_EXCEEDED);

    let bytes = planes.dir.path().join("bytes");
    std::fs::create_dir_all(&bytes).unwrap();
    // SPARSE: one byte past the bound costs no disk.
    std::fs::File::create(bytes.join("big"))
        .unwrap()
        .set_len(WORK_TREE_MAX_BYTES + 1)
        .unwrap();
    refused(&bytes, WORK_TREE_BOUND_EXCEEDED);
    assert_eq!(cas_objects(&planes), before, "nothing was published");
}

#[test]
fn a_walked_scratch_seed_publishes_and_records_retained_by_the_execution() {
    let planes = planes();
    let execution_id = execution(&planes);
    let root = workspace(&planes);
    let walked = walk_work_tree(&root).unwrap();
    assert_eq!(
        walked
            .manifest()
            .entries()
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/a.txt"]
    );
    let head = publish_scratch_tree_head(&planes.db, &planes.cas, execution_id, &root).unwrap();
    assert_eq!(head.branch, "");
    assert_eq!(head.work_tree_artifact_id, walked.reference().id().0.0);
    assert_eq!(head.base_commit, "");
    assert_eq!(head.candidate_commit_id, "");
    let conn = rusqlite::Connection::open_with_flags(
        planes.dir.path().join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let (kind, owner): (String, Vec<u8>) = conn
        .query_row(
            "SELECT a.kind, r.owner_execution_id FROM artifacts a JOIN cas_roots r \
               ON r.object_digest = a.object_id AND r.purpose = 'artifact_object' \
              WHERE a.artifact_id = ?1",
            [head.work_tree_artifact_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "tree");
    assert_eq!(
        owner,
        execution_id.to_bytes().to_vec(),
        "retained BY THE EXECUTION"
    );
}

#[test]
fn a_member_absent_or_mismeasured_in_the_store_is_refused_at_declaration() {
    let planes = planes();
    let execution_id = execution(&planes);
    let present = planes.cas.put_durable(b"present").unwrap();
    for (case, entry) in [
        (
            "absent",
            TreeEntry {
                path: TreePath::new("absent.txt").unwrap(),
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: kata_types::cache::object_id_for_canonical_bytes(b"never published"),
                    size_bytes: 15,
                },
            },
        ),
        (
            "mis-measured",
            TreeEntry {
                path: TreePath::new("lies.txt").unwrap(),
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: present.object_id(),
                    size_bytes: present.size() + 1,
                },
            },
        ),
    ] {
        let manifest = TreeManifest::new(vec![entry]).unwrap();
        let durable = planes
            .cas
            .put_durable(&manifest.manifest_bytes().unwrap())
            .unwrap();
        let refusal = declare_work_tree(&planes.db, &planes.cas, execution_id, &manifest, &durable)
            .expect_err("a tree row over a member the store does not hold as named")
            .to_string();
        assert!(
            refusal.contains(WORK_TREE_MEMBER_UNVERIFIED),
            "{case}: refused by name: {refusal}"
        );
    }
    let artifacts: i64 = rusqlite::Connection::open_with_flags(
        planes.dir.path().join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
    .query_row("SELECT count(*) FROM artifacts", [], |row| row.get(0))
    .unwrap();
    assert_eq!(artifacts, 0, "no row was written");
}

/// The ENTRIES bound at its exact edge: a workspace of exactly WORK_TREE_MAX_ENTRIES
/// files walks, and one more is refused.
#[test]
fn the_entries_bound_admits_exactly_its_maximum() {
    let planes = planes();
    let root = planes.dir.path().join("edge");
    std::fs::create_dir_all(&root).unwrap();
    for index in 0..WORK_TREE_MAX_ENTRIES {
        std::fs::write(root.join(format!("f{index}")), b"").unwrap();
    }
    let walked = walk_work_tree(&root).expect("exactly the maximum walks");
    assert_eq!(
        walked.manifest().entries().len(),
        usize::try_from(WORK_TREE_MAX_ENTRIES).unwrap()
    );
    std::fs::write(root.join("one-more"), b"").unwrap();
    refused(&root, WORK_TREE_BOUND_EXCEEDED);
}

/// A name a tree path cannot carry is refused `work_tree_unacceptable_path`, at any depth,
/// and nothing is published — at BOTH of its sites: a NON-UTF-8 name (which Linux permits
/// and a `TreePath`, a string, cannot hold), refused while the relative path is built;
/// and a UTF-8 name `TreePath::new` refuses (an ASCII control byte), refused when the
/// member's entry is made.
#[test]
fn a_name_a_tree_path_cannot_carry_is_refused_and_nothing_is_published() {
    use std::os::unix::ffi::OsStrExt;
    for name in [
        std::ffi::OsStr::from_bytes(b"not-utf8-\xff\xfe"),
        std::ffi::OsStr::from_bytes(b"control-\x01-byte"),
    ] {
        let planes = planes();
        let root = workspace(&planes);
        std::fs::create_dir_all(root.join("deep")).unwrap();
        std::fs::write(root.join("deep").join(name), b"x").unwrap();
        let before = cas_objects(&planes);
        refused(&root, WORK_TREE_UNACCEPTABLE_PATH);
        assert_eq!(cas_objects(&planes), before, "the walk publishes nothing");
    }
}

/// A member this process cannot READ — a regular file with no permission bits, which the
/// listing classifies and the open then fails with `EACCES` — is refused
/// `work_tree_unreadable`: not a symlink, not a changed entry, and not skipped.
#[test]
fn an_unreadable_member_is_refused_by_name() {
    use std::os::unix::fs::PermissionsExt;
    let planes = planes();
    let root = workspace(&planes);
    let locked = root.join("src/locked.txt");
    std::fs::write(&locked, b"secret\n").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert!(
        std::fs::File::open(&locked).is_err(),
        "the premise: this process cannot open a mode-000 file (a root test runner can, and \
         would prove nothing here)"
    );
    refused(&root, WORK_TREE_UNREADABLE);
}
