//! The `/work` delta walk and publish, with every verdict read
//! off the FILESYSTEM and off a second raw rusqlite handle.
//!
//! # Invariant
//!
//! The subject is asked nothing it could shade. The published delta's BYTES are
//! read back out of the CAS through a handle this file opens itself and applied
//! to the base — the result must be exactly the manifest of what the test wrote
//! to disk, where "what the test wrote" is a second, independent statement of
//! the post-run tree. And every "nothing was published" refusal counts
//! `cas_objects` on the raw handle, because *"the bound is enforced BEFORE any
//! byte is published"* and *"the bound is enforced and the bytes are left
//! behind"* return the same `Err` and differ only in the store.
//!
//! # CRASH CELL HOME
//!
//! This file is the home `operational_crash_matrix.rs`'s `ELSEWHERE` table
//! credits with `operational.after_work_delta_published_before_completion`, so
//! the boundary name and the `KATA_FAULT_INJECT` arming below are load-bearing
//! rather than decorative.

use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use kata_core::store::cas::CasStore;
use kata_types::cache::object_id_for_canonical_bytes;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, CapsuleBudgets, CapsuleWorkView,
};
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_types::tree_delta::{TreeChangeKind, TreeDelta};
use kata_worker::materialize::TreeResolver;
use kata_worker::result_publication::CasBlobSink;
use kata_worker::work_delta::{MaterializationSnapshot, WorkDeltaRefusal, publish_work_delta};

/// Bounds a delta is outside in ONE dimension each, so the two refusals are
/// reachable separately — the sibling result-publication tests' argument.
fn budgets(work_delta_bytes: u64, work_delta_entries: u32) -> CapsuleBudgets {
    CapsuleBudgets {
        wall_time_ms: 30_000,
        output_bytes: 1 << 20,
        memory_bytes: 512 * 1024 * 1024,
        process_count: 64,
        result_bytes: 1 << 20,
        result_entries: 128,
        work_delta_bytes,
        work_delta_entries,
    }
}

/// A generous bound, for the cells whose subject is not the bound.
fn ample() -> CapsuleBudgets {
    budgets(
        kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
        128,
    )
}

/// A [`TreeResolver`] carrying the one base artifact the fixture's capsule
/// mapped — the same shape [`DeclaredTreeResolver`] has in production, minus
/// the CAS read: the reference AND the manifest are held, because a resolver
/// answers both.
///
/// [`DeclaredTreeResolver`]: kata_worker::materialize::DeclaredTreeResolver
struct OneTree {
    reference: ArtifactRef,
    manifest: TreeManifest,
}

impl TreeResolver for OneTree {
    fn tree_manifest(&self, artifact: ArtifactId) -> KataResult<TreeManifest> {
        self.reference_for(artifact)?;
        Ok(self.manifest.clone())
    }

    fn tree_reference(&self, artifact: ArtifactId) -> KataResult<ArtifactRef> {
        self.reference_for(artifact)
    }
}

impl OneTree {
    /// The resolver's refusal for an id it was not handed — the same shape
    /// [`DeclaredTreeResolver`]'s, because the publisher must not be able to
    /// tell the fixture from the real lookup.
    fn reference_for(&self, artifact: ArtifactId) -> KataResult<ArtifactRef> {
        if artifact == self.reference.id() {
            Ok(self.reference.clone())
        } else {
            Err(KataError::Validation(format!(
                "the fixture's assignment carries no reference for artifact {}",
                artifact.0
            )))
        }
    }
}

/// The CAS this test publishes into, with the raw handle path kept beside it.
struct Rig {
    dir: tempfile::TempDir,
    cas: CasStore,
    cas_db: PathBuf,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let cas_db = dir.path().join("cas.db");
    let cas = CasStore::open(&cas_db, dir.path().join("cas")).unwrap();
    Rig { dir, cas, cas_db }
}

/// The artifact reference `manifest`'s canonical bytes publish to — the same
/// derivation the publisher mints, reached through the store's own receipt so
/// the fixture's claim about the base is the store's claim.
fn publish_base(rig: &Rig, manifest: &TreeManifest, privacy: ArtifactPrivacy) -> OneTree {
    let bytes = manifest.manifest_bytes().unwrap();
    let receipt = rig.cas.put_durable(&bytes).unwrap();
    OneTree {
        reference: ArtifactRef::new(receipt.object_id(), receipt.size(), privacy),
        manifest: manifest.clone(),
    }
}

fn manifest(entries: Vec<TreeEntry>) -> TreeManifest {
    TreeManifest::new(entries).expect("a valid manifest")
}

fn file(path: &str, content: &[u8]) -> TreeEntry {
    TreeEntry {
        path: TreePath::new(path).unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: object_id_for_canonical_bytes(content),
            size_bytes: content.len() as u64,
        },
    }
}

fn exe(path: &str, content: &[u8]) -> TreeEntry {
    let TreeNode::File {
        object, size_bytes, ..
    } = file(path, content).node
    else {
        unreachable!()
    };
    TreeEntry {
        path: TreePath::new(path).unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Executable,
            object,
            size_bytes,
        },
    }
}

fn link(path: &str, target: &str) -> TreeEntry {
    TreeEntry {
        path: TreePath::new(path).unwrap(),
        node: TreeNode::Symlink {
            target: kata_types::tree_artifact::SymlinkTarget::new(target).unwrap(),
        },
    }
}

/// Write the POST-RUN `/work` the scenario describes: `files` as regular files,
/// `execs` as executable ones, `links` as symlinks whose targets are verbatim.
/// The test's own spelling of the tree — which is what makes "the delta says
/// the same thing" an assertion rather than a tautology.
fn write_work(
    root: &Path,
    files: &[(&str, &[u8])],
    execs: &[(&str, &[u8])],
    links: &[(&str, &str)],
) -> PathBuf {
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let write_file = |path: &str, content: &[u8], mode: u32| {
        let target = work.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&target, content).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    for (path, content) in files {
        write_file(path, content, 0o644);
    }
    for (path, content) in execs {
        write_file(path, content, 0o755);
    }
    for (path, target) in links {
        let at = work.join(path);
        if let Some(parent) = at.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::os::unix::fs::symlink(target, &at).unwrap();
    }
    work
}

/// The SECOND handle onto `cas.db`. Read-only: an observer that can write is an
/// observer that can repair what it was meant to catch.
fn raw(cas_db: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        cas_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn object_count(cas_db: &Path) -> i64 {
    raw(cas_db)
        .query_row("SELECT count(*) FROM cas_objects", [], |row| row.get(0))
        .unwrap()
}

/// Whether the store holds an object at `hex`, asked of the raw handle.
fn holds(cas_db: &Path, hex: &str) -> bool {
    raw(cas_db)
        .query_row(
            "SELECT count(*) FROM cas_objects WHERE lower(hex(object_id)) = ?1",
            rusqlite::params![hex],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
        > 0
}

fn hex_of(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// Read the published delta's bytes OUT OF THE STORE and decode them — the
/// artifact is the bytes, so the bytes are what the cell reads.
fn read_delta(rig: &Rig, reference: &ArtifactRef) -> TreeDelta {
    let bytes = rig
        .cas
        .get_verified(
            &reference.object_id(),
            reference.size_bytes(),
            TreeDelta::MAXIMUM_ENCODED_BYTES,
        )
        .expect("the delta object is in the store and verifies");
    serde_json::from_slice::<TreeDelta>(&bytes).expect("the bytes decode as a delta")
}

/// The shape of one change, for assertions that care about kind and target and
/// not about the whole node body.
fn kind(change: &TreeChangeKind) -> &'static str {
    match change {
        TreeChangeKind::Write {
            node: TreeNode::File { .. },
        } => "write(file)",
        TreeChangeKind::Write {
            node: TreeNode::Symlink { .. },
        } => "write(symlink)",
        TreeChangeKind::Delete => "delete",
    }
}

/// Publish the delta for a scenario and return its reference.
fn publish(
    rig: &Rig,
    work: &Path,
    base: &OneTree,
    budgets: CapsuleBudgets,
) -> Result<ArtifactRef, WorkDeltaRefusal> {
    let sink = CasBlobSink(&rig.cas);
    publish_work_delta(work, base.reference.id(), base, budgets, &sink, None, None)
}

/// Publish with the materializer's stamp record attached — the shape the real
/// route produces.
fn publish_stamped(
    rig: &Rig,
    work: &Path,
    base: &OneTree,
    budgets: CapsuleBudgets,
    snapshot: &MaterializationSnapshot,
) -> Result<ArtifactRef, WorkDeltaRefusal> {
    let sink = CasBlobSink(&rig.cas);
    publish_work_delta(
        work,
        base.reference.id(),
        base,
        budgets,
        &sink,
        Some(snapshot),
        None,
    )
}

/// [`publish`], with the capsule's declared `/work` view attached — the shape
/// the confined route produces.
fn publish_viewed(
    rig: &Rig,
    work: &Path,
    base: &OneTree,
    budgets: CapsuleBudgets,
    view: &CapsuleWorkView,
) -> Result<ArtifactRef, WorkDeltaRefusal> {
    let sink = CasBlobSink(&rig.cas);
    publish_work_delta(
        work,
        base.reference.id(),
        base,
        budgets,
        &sink,
        None,
        Some(view),
    )
}

/// Bytes this PROCESS has read, off `/proc/self/io`'s `rchar` — the kernel's
/// count, which page-cache hits do not dodge: `read(2)` of a cached page still
/// counts. "The file was not read" is therefore measurable without
/// instrumenting the subject.
fn bytes_read_this_process() -> u64 {
    let io = std::fs::read_to_string("/proc/self/io").unwrap();
    io.lines()
        .find(|line| line.starts_with("rchar:"))
        .and_then(|line| line[6..].trim().parse::<u64>().ok())
        .expect("rchar is in /proc/self/io on Linux")
}

/// **An unchanged member is reused from the base WITHOUT its bytes being
/// read.** A 48 MiB member plus a one-byte change: the published delta names
/// only the change, and `rchar` across the publish moves by far less than the
/// member — the file's content was never touched.
///
/// **Would red if:** the fast path were removed or skipped — the same delta
/// would still publish (the assertion that it is right is the SECOND one), but
/// `rchar` would count all 48 MiB.
#[test]
fn an_unchanged_members_bytes_are_never_read() {
    let rig = rig();
    let big = vec![b'z'; 48 * 1024 * 1024];
    let base = publish_base(
        &rig,
        &manifest(vec![
            file("big.bin", &big),
            file(
                "pin.txt", b"a
",
            ),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[
            ("big.bin", &big),
            (
                "pin.txt", b"a
",
            ),
        ],
        &[],
        &[],
    );
    let snapshot = MaterializationSnapshot::take(&work).unwrap();
    assert_eq!(snapshot.len(), 2);

    // The stage's whole edit: one byte in the small file.
    std::fs::write(
        work.join("pin.txt"),
        b"b
",
    )
    .unwrap();

    let before = bytes_read_this_process();
    let reference = publish_stamped(&rig, &work, &base, ample(), &snapshot).unwrap();
    let read = bytes_read_this_process() - before;

    assert!(
        read < 4 * 1024 * 1024,
        "an untouched 48 MiB member must not be read back: rchar moved {read} bytes"
    );
    // And the delta is still RIGHT — the fast path cannot trade correctness.
    let delta = read_delta(&rig, &reference);
    assert_eq!(delta.changes().len(), 1);
    assert_eq!(delta.changes()[0].path.as_str(), "pin.txt");
    assert_eq!(kind(&delta.changes()[0].change), "write(file)");
}

/// **A guest that rewrites a member and rewinds `mtime` is still caught.** The
/// tuple includes `st_ctime` — the kernel's metadata stamp, which `utimensat`
/// (and therefore `touch -d`, and `File::set_modified`) cannot reach — so the
/// forgery misses on ctime and the member is hashed and reported.
///
/// **Would red if:** the tuple were `(ino, size, mtime)` — the falsification
/// this cell exists for.
#[test]
fn a_rewound_mtime_does_not_hide_a_rewrite() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![file("victim.txt", b"a")]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(rig.dir.path(), &[("victim.txt", b"a")], &[], &[]);
    let snapshot = MaterializationSnapshot::take(&work).unwrap();
    let original_mtime = std::fs::metadata(work.join("victim.txt"))
        .unwrap()
        .modified()
        .unwrap();

    // Same-size rewrite, then the mtime wound back — the forgery an inode+size
    // +mtime check would call unchanged.
    std::fs::write(work.join("victim.txt"), b"b").unwrap();
    std::fs::File::options()
        .write(true)
        .open(work.join("victim.txt"))
        .unwrap()
        .set_modified(original_mtime)
        .unwrap();

    let reference = publish_stamped(&rig, &work, &base, ample(), &snapshot).unwrap();
    let delta = read_delta(&rig, &reference);
    assert_eq!(
        delta.changes().len(),
        1,
        "the rewritten byte must be reported even with mtime forged back"
    );
    assert_eq!(delta.changes()[0].path.as_str(), "victim.txt");
    match &delta.changes()[0].change {
        TreeChangeKind::Write {
            node: TreeNode::File { object, .. },
        } => assert_eq!(
            *object,
            object_id_for_canonical_bytes(b"b"),
            "the reported object is the NEW bytes, hashed after the fast path missed"
        ),
        other => panic!("expected a file write, got {}", kind(other)),
    }
}

/// **A chmod lands through the same miss** — an exec-bit flip moves ctime.
#[test]
fn an_exec_flip_is_detected_through_the_snapshot() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![file(
            "run.sh",
            b"#!/bin/sh
",
        )]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[(
            "run.sh",
            b"#!/bin/sh
",
        )],
        &[],
        &[],
    );
    let snapshot = MaterializationSnapshot::take(&work).unwrap();
    std::fs::set_permissions(work.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();

    let reference = publish_stamped(&rig, &work, &base, ample(), &snapshot).unwrap();
    let delta = read_delta(&rig, &reference);
    assert_eq!(delta.changes().len(), 1);
    match &delta.changes()[0].change {
        TreeChangeKind::Write {
            node: TreeNode::File { mode, .. },
        } => assert_eq!(*mode, TreeEntryMode::Executable),
        other => panic!("expected a file write, got {}", kind(other)),
    }
}

/// **An unchanged `/work` produces an EMPTY delta — `Some`, not `None`** — and
/// the delta's bytes, read back out of the store, apply to the base as itself.
///
/// The rule this carries: a mapped `/work` the stage did not touch is a
/// DIFFERENT answer from a capsule that mapped none — the wire's `None`/`Some`
/// distinction is what keeps the adopting side from inventing a workspace.
#[test]
fn an_unchanged_work_publishes_an_empty_delta() {
    let rig = rig();
    let base_entries = vec![
        file("kept.txt", b"kept\n"),
        file("nested/also.txt", b"also\n"),
        link("link", "kept.txt"),
    ];
    let base = publish_base(
        &rig,
        &manifest(base_entries.clone()),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[("kept.txt", b"kept\n"), ("nested/also.txt", b"also\n")],
        &[],
        &[("link", "kept.txt")],
    );
    let before = object_count(&rig.cas_db);

    let reference = publish(&rig, &work, &base, ample()).expect("an unchanged /work publishes");

    assert_eq!(
        reference.privacy(),
        ArtifactPrivacy::Private,
        "a delta embeds its base reference — stage-produced bytes, never the canonical \
         public empty tree"
    );
    let delta = read_delta(&rig, &reference);
    assert!(
        delta.changes().is_empty(),
        "an unchanged tree is an EMPTY delta — no changes, not a refusal"
    );
    assert_eq!(
        delta.base().id(),
        base.reference.id(),
        "the delta names the very artifact the mapping carried"
    );
    assert_eq!(
        delta.apply(&base.manifest).unwrap(),
        base.manifest,
        "applying the empty delta reproduces the base"
    );
    // The CAS grew by exactly ONE object — the delta itself. An unchanged
    // member is already retained by the input declaration; re-publishing it
    // would be a second copy of bytes the store already addresses.
    assert_eq!(object_count(&rig.cas_db), before + 1);
    assert!(holds(&rig.cas_db, &hex_of(reference.object_id().0)));
    drop(rig.dir);
}

/// **Every change kind lands: created files, edited files, a file→link flip, a
/// link→file flip, a retargeted link, a deleted file, a mode flip — and an
/// unchanged link is NOT one.**
///
/// **Would red if:** any of the seven dispositions were misread (a retargeted
/// link dropped, a transition read as two changes, an unchanged link written),
/// or a member's bytes never reached the store — each written member's object
/// is read back and compared against the CONTENT the test wrote, which is a
/// fact about the bytes and not about the walker.
#[test]
fn every_change_kind_lands_and_unchanged_links_are_absent() {
    let rig = rig();
    // The base pairs `flip/file_to_link` with a FILE and `flip/link_to_file`
    // with a LINK — the two transition directions are both under test.
    let base_entries = vec![
        file("edited.txt", b"before\n"),
        file("flip/file_to_link", b"was a file\n"),
        file("gone.txt", b"gone\n"),
        file("kept.txt", b"kept\n"),
        file("mode.txt", b"#!/bin/sh\n"),
        link("flip/link_to_file", "was/a/link"),
        link("kept_link", "kept.txt"),
        link("retargeted", "old-target"),
    ];
    let base = publish_base(&rig, &manifest(base_entries), ArtifactPrivacy::Private);

    let work = write_work(
        rig.dir.path(),
        &[
            ("edited.txt", b"after\n"),
            ("flip/link_to_file", b"now a file\n"),
            ("kept.txt", b"kept\n"),
            ("added/nested/new.txt", b"new\n"),
        ],
        // `mode.txt` — same bytes, now executable: a mode flip is a write.
        &[("mode.txt", b"#!/bin/sh\n")],
        &[
            ("flip/file_to_link", "now/a/link"),
            ("kept_link", "kept.txt"),
            ("retargeted", "new-target"),
        ],
    );

    let before = object_count(&rig.cas_db);
    let reference = publish(&rig, &work, &base, ample()).expect("a mutated /work publishes");

    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![
            ("added/nested/new.txt", "write(file)"),
            ("edited.txt", "write(file)"),
            ("flip/file_to_link", "write(symlink)"),
            ("flip/link_to_file", "write(file)"),
            ("gone.txt", "delete"),
            ("mode.txt", "write(file)"),
            ("retargeted", "write(symlink)"),
        ],
        "the minimal delta — sorted by path bytes, nothing for kept.txt or kept_link"
    );

    // The VERBATIM target, asserted off the delta's own bytes.
    let retargeted = delta
        .changes()
        .iter()
        .find(|change| change.path.as_str() == "retargeted")
        .unwrap();
    let TreeChangeKind::Write {
        node: TreeNode::Symlink { target },
    } = &retargeted.change
    else {
        panic!("the retargeted link is a write")
    };
    assert_eq!(target.as_str(), "new-target");

    // THE RESULT the delta encodes is the disk's truth: apply it to the base
    // and compare to the manifest of what the test wrote — the test's own
    // statement of the post-run tree.
    let expected = manifest(vec![
        file("added/nested/new.txt", b"new\n"),
        file("edited.txt", b"after\n"),
        link("flip/file_to_link", "now/a/link"),
        file("flip/link_to_file", b"now a file\n"),
        file("kept.txt", b"kept\n"),
        link("kept_link", "kept.txt"),
        exe("mode.txt", b"#!/bin/sh\n"),
        link("retargeted", "new-target"),
    ]);
    assert_eq!(
        delta.apply(&base.manifest).unwrap(),
        expected,
        "base + delta must be exactly the post-run tree"
    );

    // Members in the store, read back and compared to the bytes the test wrote.
    for (path, content) in [
        ("added/nested/new.txt", b"new\n".as_slice()),
        ("edited.txt", b"after\n".as_slice()),
        ("flip/link_to_file", b"now a file\n".as_slice()),
        ("mode.txt", b"#!/bin/sh\n".as_slice()),
    ] {
        let node = expected
            .entries()
            .iter()
            .find(|entry| entry.path.as_str() == path)
            .unwrap();
        let object = node.node.object().unwrap();
        assert!(
            holds(&rig.cas_db, &hex_of(object.0)),
            "member {path} must be in the store"
        );
        assert_eq!(
            rig.cas
                .get_verified(&object, node.node.size_bytes(), 1 << 20)
                .unwrap(),
            content,
            "the published member's bytes are the file's bytes"
        );
    }

    // The store grew by exactly: 4 changed members + 1 delta object. `kept.txt`
    // and the links carry no new bytes — a delta is not a second copy of the
    // base.
    assert_eq!(object_count(&rig.cas_db), before + 5);
    drop(rig.dir);
}

/// **A fifo under `/work` is refused BY NAME and nothing is published.** Sockets,
/// devices and fifos have no `TreeNode` arm, so a delta that dropped one would
/// record a `/work` that never existed.
#[cfg(unix)]
#[test]
fn a_fifo_is_refused_and_nothing_is_published() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[("a.txt", b"a\n")], &[], &[]);
    nix::unistd::mkfifo(
        &work.join("pipe"),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    let before = object_count(&rig.cas_db);

    let refusal = publish(&rig, &work, &base, ample()).expect_err("a fifo is not a tree entry");
    assert_eq!(refusal.label(), "work_delta_special_file", "{refusal}");
    assert!(refusal.to_string().contains("fifo"), "{refusal}");
    assert_eq!(object_count(&rig.cas_db), before);
    drop(rig.dir);
}

/// **A socket under `/work` is refused BY NAME** — the same arm, through the
/// entry kind a unix listener leaves.
#[cfg(unix)]
#[test]
fn a_socket_is_refused_and_nothing_is_published() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[], &[], &[]);
    let _listener = kata_transport::unix_socket::bind_std(&work.join("sock")).unwrap();
    let before = object_count(&rig.cas_db);

    let refusal = publish(&rig, &work, &base, ample()).expect_err("a socket is not a tree entry");
    assert_eq!(refusal.label(), "work_delta_special_file", "{refusal}");
    assert!(refusal.to_string().contains("socket"), "{refusal}");
    assert_eq!(object_count(&rig.cas_db), before);
    drop(rig.dir);
}

/// **A non-UTF-8 NAME is `work_delta_unrepresentable`** — no `TreePath` can
/// carry it, so the tree is one no artifact can describe.
#[cfg(unix)]
#[test]
fn a_non_utf8_name_is_refused() {
    use std::os::unix::ffi::OsStringExt as _;
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[], &[], &[]);
    std::fs::write(
        work.join(std::ffi::OsString::from_vec(vec![0x66, 0x80])),
        b"bad\n",
    )
    .unwrap();

    let refusal = publish(&rig, &work, &base, ample()).expect_err("a non-UTF-8 name is refused");
    assert_eq!(refusal.label(), "work_delta_unrepresentable", "{refusal}");
    drop(rig.dir);
}

/// **A non-UTF-8 symlink TARGET is `work_delta_unrepresentable`** — verbatim
/// carriage is the rule, and a target that is not UTF-8 is one no
/// `SymlinkTarget` can carry.
#[cfg(unix)]
#[test]
fn a_non_utf8_symlink_target_is_refused() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[], &[], &[]);
    std::os::unix::fs::symlink(
        std::ffi::OsStr::from_bytes(&[0x2e, 0x2e, 0x80]),
        work.join("escape"),
    )
    .unwrap();

    let refusal =
        publish(&rig, &work, &base, ample()).expect_err("a non-UTF-8 target has no tree encoding");
    assert_eq!(refusal.label(), "work_delta_unrepresentable", "{refusal}");
    drop(rig.dir);
}

/// **A delta over `work_delta_entries` is refused BEFORE a byte is published.**
///
/// Two changes against a promise of one; the store count is the whole cell.
#[test]
fn a_delta_over_its_entry_bound_publishes_nothing() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[("a", b"1"), ("b", b"2")], &[], &[]);
    let before = object_count(&rig.cas_db);

    let refusal = publish(&rig, &work, &base, budgets(1 << 20, 1))
        .expect_err("two changes against a promise of one must be refused");
    assert_eq!(refusal.label(), "work_delta_entries_exceeded", "{refusal}");
    assert!(
        refusal.to_string().contains("NOTHING WAS PUBLISHED"),
        "the refusal must state the property: {refusal}"
    );
    assert_eq!(object_count(&rig.cas_db), before);
    drop(rig.dir);
}

/// A delta AT its entry bound is inside the promise — the fence is `>`, and
/// the boundary value itself publishes.
#[test]
fn a_delta_at_its_entry_bound_publishes() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[("a", b"1"), ("b", b"2")], &[], &[]);
    publish(&rig, &work, &base, budgets(1 << 20, 2))
        .expect("two changes against a promise of two must publish");
    drop(rig.dir);
}

/// A delta AT its byte bound is inside the promise — `>` again: the boundary
/// byte count itself publishes.
#[test]
fn a_delta_at_its_byte_bound_publishes() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(
        rig.dir.path(),
        &[("a", &[b'x'; 64]), ("b", &[b'y'; 64])],
        &[],
        &[],
    );
    publish(&rig, &work, &base, budgets(128, 128))
        .expect("128 written bytes against a 128-byte promise must publish");
    drop(rig.dir);
}

/// **A delta over `work_delta_bytes` is refused BEFORE a byte is published** —
/// the byte bound counts WRITTEN members' content (file bytes, symlink target
/// lengths), and deletes cost none of it.
#[test]
fn a_delta_over_its_byte_bound_publishes_nothing() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![file("gone.txt", b"gone\n")]),
        ArtifactPrivacy::Private,
    );
    // `gone.txt` absent in the result → a Delete, which carries no bytes; the
    // two writes carry 128, over a 64 promise.
    let work = write_work(
        rig.dir.path(),
        &[("a", &[b'x'; 64]), ("b", &[b'y'; 64])],
        &[],
        &[],
    );
    let before = object_count(&rig.cas_db);

    let refusal = publish(&rig, &work, &base, budgets(64, 128))
        .expect_err("128 written bytes against a 64-byte promise must be refused");
    assert_eq!(refusal.label(), "work_delta_bytes_exceeded", "{refusal}");
    assert_eq!(object_count(&rig.cas_db), before);
    drop(rig.dir);
}

/// **A member over `MAX_MEMBER_BYTES` is refused before it is hashed** — the
/// same per-member ceiling the materializer reads at, so a delta this side
/// publishes is never one the next worker declines. The file is sparse, so the
/// cell is the fstat, not a 64 MiB write.
#[cfg(unix)]
#[test]
fn a_member_over_the_per_member_ceiling_is_refused() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[], &[], &[]);
    let big = std::fs::File::create(work.join("huge")).unwrap();
    big.set_len(kata_types::tree_artifact::MAX_MEMBER_BYTES + 1)
        .unwrap();
    drop(big);
    let before = object_count(&rig.cas_db);

    let refusal = publish(&rig, &work, &base, budgets(1 << 30, 128))
        .expect_err("a member no materializer can write back is refused");
    assert_eq!(
        refusal.label(),
        "work_delta_member_over_ceiling",
        "{refusal}"
    );
    assert_eq!(object_count(&rig.cas_db), before);
    drop(rig.dir);
}

/// **A member AT the ceiling is admitted** — the refusal's own words are
/// "OVER the ceiling" (`size_bytes > MAX_MEMBER_BYTES`), so exactly
/// `MAX_MEMBER_BYTES` must publish. The cell is sparse: the fstat is the whole
/// scenario. The delta is read back out of the store, not trusted from the
/// return.
#[cfg(unix)]
#[test]
fn a_member_at_the_per_member_ceiling_is_admitted() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[], &[], &[]);
    let big = std::fs::File::create(work.join("huge")).unwrap();
    big.set_len(kata_types::tree_artifact::MAX_MEMBER_BYTES)
        .unwrap();
    drop(big);

    let reference = publish(&rig, &work, &base, budgets(1 << 30, 128))
        .expect("a member of exactly the ceiling is under no refusal");
    let delta = read_delta(&rig, &reference);
    let change = delta
        .changes()
        .iter()
        .find(|change| change.path.as_str() == "huge")
        .expect("the ceiling member is a change in the stored delta");
    let TreeChangeKind::Write {
        node: TreeNode::File {
            object, size_bytes, ..
        },
    } = &change.change
    else {
        panic!(
            "the ceiling member is a file write, got {}",
            kind(&change.change)
        );
    };
    assert_eq!(
        *size_bytes,
        kata_types::tree_artifact::MAX_MEMBER_BYTES,
        "the stored delta carries the member's real size"
    );
    assert!(
        holds(&rig.cas_db, &hex_of(object.0)),
        "the member's object is in the store"
    );
    drop(rig.dir);
}

/// **A member still growing while it is scanned is refused `MemberChanged`,
/// and the refusal names the count the kernel actually returned.** `read:` is
/// the scan loop's own tally of bytes read — strictly more than the fstat's
/// declared length, because the file is strictly larger by the time `read(2)`
/// reaches its end. A tally folded with the wrong operator reports `0` and the
/// refusal would claim "nothing was read" from a publish sitting mid-file.
///
/// The growth is a helper thread appending one byte in a tight loop for the
/// whole publish: with appends landing continuously across a 64 MiB sparse
/// scan, the EOF count cannot equal the open-time fstat, so `finish()` must
/// refuse and the refusal's `read` must be the real count — `> scanned`, never
/// 0, and never equal to `scanned`.
#[test]
fn a_member_growing_mid_scan_is_refused_naming_its_true_read_count() {
    use std::io::Write as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[], &[], &[]);
    let grown = work.join("grown.bin");
    // Under the ceiling by 8 MiB: appends landing before the scan's fstat must
    // never trip `MemberOverCeiling`, whose check is that same fstat — the
    // ceiling is asserted by its own cell one test up.
    let declared = kata_types::tree_artifact::MAX_MEMBER_BYTES - (8 << 20);
    std::fs::File::create(&grown)
        .unwrap()
        .set_len(declared)
        .unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let appender = {
        let stop = Arc::clone(&stop);
        let grown = grown.clone();
        std::thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&grown)
                .unwrap();
            while !stop.load(Ordering::Relaxed) {
                // One byte per write: strictly-monotonic growth, so a single
                // append landing inside the scan guarantees the EOF count is
                // above whatever the open-time fstat declared. Capped so a
                // stalled caller can never grow the member past the ceiling —
                // the cap is seconds of appends, the scan starts in
                // milliseconds.
                if file.metadata().unwrap().len() < declared + (4 << 20) {
                    file.write_all(&[0]).unwrap();
                } else {
                    std::thread::yield_now();
                }
            }
        })
    };
    // Prove the appender is hot before the subject opens the file — the window
    // it must land in is the entire read loop, so the only failure mode would
    // be a helper that never ran.
    while grown.metadata().unwrap().len() == declared {
        std::thread::yield_now();
    }

    let refusal = publish(&rig, &work, &base, budgets(1 << 30, 128))
        .expect_err("a member still writing during the scan must be refused");
    stop.store(true, Ordering::Relaxed);
    appender.join().unwrap();

    let WorkDeltaRefusal::MemberChanged { scanned, read, .. } = &refusal else {
        panic!("a growing member is MemberChanged, got {refusal}");
    };
    assert_eq!(refusal.label(), "work_delta_member_changed", "{refusal}");
    assert!(
        *scanned >= declared,
        "the refusal's `scanned` is the open-time fstat, >= {declared}: {scanned}"
    );
    assert!(
        *read > *scanned,
        "the refusal's `read` is the bytes the kernel returned across the loop — \
         above {scanned} while the file was still growing, got {read}"
    );
    drop(rig.dir);
}

/// **An absent `/work` is a refusal, not an empty delta** — a capsule that maps
/// `/work` and a container that leaves no directory there disagree about what
/// ran, and the answer to a disagreement is never an invention.
#[test]
fn an_absent_work_is_refused() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let refusal = publish(&rig, &rig.dir.path().join("work"), &base, ample())
        .expect_err("an absent /work is not an unchanged one");
    assert_eq!(refusal.label(), "work_delta_unreadable", "{refusal}");
    drop(rig.dir);
}

/// **A base the resolver never carried is refused** — the same refused set the
/// materializer's lookup states, asked one step earlier.
#[test]
fn a_base_the_resolver_does_not_carry_is_refused() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    let work = write_work(rig.dir.path(), &[], &[], &[]);
    let other = ArtifactRef::new(
        object_id_for_canonical_bytes(b"not the base"),
        13,
        ArtifactPrivacy::Private,
    );
    let refusal = {
        let sink = CasBlobSink(&rig.cas);
        publish_work_delta(&work, other.id(), &base, ample(), &sink, None, None)
    }
    .expect_err("a base the resolver never saw is refused, not resolved");
    assert_eq!(refusal.label(), "work_delta_base_unresolved", "{refusal}");
    drop(rig.dir);
}

// ---------------------------------------------------------------------------
// The ignore gate's gitfile exemption — the git view's one `.git` exception
// ---------------------------------------------------------------------------

/// **A TOP-LEVEL `/work/.git` is excluded, never refused — the git view's
/// gitfile is whatever the container left at that one name.** A NESTED `.git`
/// or `.jj` component keeps its `work_delta_reserved_path` refusal: a delta
/// carrying it could never check out of a jj workspace.
#[test]
fn only_the_toplevel_git_name_is_excluded() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    for (path, bytes, dir) in [
        (".git", &b"gitdir: /git\n"[..], false),
        (".git", &b""[..], true),
    ] {
        let work = write_work(rig.dir.path(), &[("a.txt", b"a\n")], &[], &[]);
        if dir {
            // The name as a DIRECTORY: same exclusion — a real repository
            // checkout's `.git` is the one shape the top level exempts.
            std::fs::create_dir_all(work.join(path)).unwrap();
            std::fs::write(work.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        } else {
            std::fs::write(work.join(path), bytes).unwrap();
        }
        let reference =
            publish(&rig, &work, &base, ample()).expect("the top-level .git is excluded");
        let delta = read_delta(&rig, &reference);
        let paths: Vec<&str> = delta
            .changes()
            .iter()
            .map(|change| change.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec!["a.txt"],
            "a top-level .git ({:?}) lands nothing",
            if dir { "dir" } else { "file" }
        );
        std::fs::remove_dir_all(&work).unwrap();
    }
    // A nested `.git` — the name at ANY depth but the root's own — and a
    // nested `.jj` keep their refusal: the gitfile exemption names the
    // top-level entry exactly.
    for nested in ["src/.git/config", "deep/.jj/repo/op_store"] {
        let work = write_work(rig.dir.path(), &[("a.txt", b"a\n")], &[], &[]);
        std::fs::create_dir_all(work.join(nested).parent().unwrap()).unwrap();
        std::fs::write(work.join(nested), b"reserved\n").unwrap();
        let before = object_count(&rig.cas_db);
        let refusal =
            publish(&rig, &work, &base, ample()).expect_err("a nested VCS component is refused");
        assert!(
            refusal.to_string().contains("work_delta_reserved_path"),
            "{nested}: {refusal}"
        );
        assert_eq!(
            object_count(&rig.cas_db),
            before,
            "{nested}: nothing published"
        );
        std::fs::remove_dir_all(&work).unwrap();
    }
    drop(rig.dir);
}

// ---------------------------------------------------------------------------
// The crash cell — `operational.after_work_delta_published_before_completion`
// ---------------------------------------------------------------------------

const DELTA_CHILD_MARKER: &str = "KATA_WORK_DELTA_CRASH_CHILD";
const DELTA_CHILD_DIR: &str = "KATA_WORK_DELTA_CRASH_DIR";

/// The one base manifest the crash cell uses, spelled once so the parent's
/// fixture and the child's resolver describe the SAME artifact.
fn crash_base_manifest() -> TreeManifest {
    manifest(vec![
        file("edited.txt", b"before\n"),
        file("kept.txt", b"kept\n"),
    ])
}

/// The post-run `/work` the armed child writes, spelled once so the parent can
/// re-derive the delta the child would have named WITHOUT reading anything the
/// child reported — the child dies before it can report one.
fn crash_post_run() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("edited.txt", b"after\n"),
        ("kept.txt", b"kept\n"),
        ("new.txt", b"new\n"),
    ]
}

/// The armed child: resolve the base the way `publish_work_delta` expects —
/// through the resolver, off the manifest's canonical bytes, with the store
/// holding only the base object — write the post-run tree, and die INSIDE the
/// window between the delta's durability and the completion frame.
fn delta_crash_child(dir: &Path) {
    let cas = CasStore::open(dir.join("cas.db"), dir.join("cas")).unwrap();
    let base_manifest = crash_base_manifest();
    let base_bytes = base_manifest.manifest_bytes().unwrap();
    let base = OneTree {
        reference: ArtifactRef::new(
            object_id_for_canonical_bytes(&base_bytes),
            base_bytes.len() as u64,
            ArtifactPrivacy::Private,
        ),
        manifest: base_manifest,
    };
    let work = write_work(dir, &crash_post_run(), &[], &[]);
    let sink = CasBlobSink(&cas);
    let published = publish_work_delta(
        &work,
        base.reference.id(),
        &base,
        ample(),
        &sink,
        None,
        None,
    )
    .expect("the publish reaches its crash point");
    panic!(
        "the armed fault point was never reached; the child published {} — the cell proves \
         nothing",
        published.object_id()
    );
}

/// **`after_work_delta_published_before_completion` — the delta and its changed
/// members are durable in the store, and no `CompletedCapsule` frame can name
/// them.**
///
/// # Would red if
///
/// The boundary fired before the delta's own publish (the store would be short
/// the delta object), or sat somewhere a frame could already carry (the frame
/// is built from this function's `Ok`, so nothing downstream of the abort can
/// produce one), or a re-publish did not converge on the identical object —
/// dedup is what makes the re-drive cost nothing, and the cell's second half
/// reads the store to prove it.
///
/// The recovery obligation is the result-publish window's own, one step later:
/// the main's worker-death leg settles the attempt PROVEN AMBIGUOUS and nothing
/// re-runs it, and the delta is NEVER adopted — the only thing that adopts one
/// is the frame this abort prevented. What this window additionally leaves is DURABLE ORPHAN
/// BYTES: a delta and its members that no `cas_roots` row names (no worker can
/// write one), so the residue is safe rather than referenced.
#[test]
fn after_work_delta_published_before_completion_leaves_an_orphan_delta() {
    if std::env::var(DELTA_CHILD_MARKER).is_ok() {
        delta_crash_child(Path::new(&std::env::var(DELTA_CHILD_DIR).unwrap()));
        return;
    }
    let rig = rig();
    // The base the way materialization leaves it: its manifest object already
    // in the store before any container ran.
    let base = publish_base(&rig, &crash_base_manifest(), ArtifactPrivacy::Private);
    let before = object_count(&rig.cas_db);

    let output = Command::new(std::env::current_exe().unwrap())
        .arg("after_work_delta_published_before_completion_leaves_an_orphan_delta")
        .arg("--exact")
        .arg("--nocapture")
        .env(DELTA_CHILD_MARKER, "1")
        .env(DELTA_CHILD_DIR, rig.dir.path())
        .env(
            "KATA_FAULT_INJECT",
            "operational.after_work_delta_published_before_completion",
        )
        .output()
        .expect("spawn the armed child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the armed child must abort, not exit cleanly:\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains(
            "crash point reached: operational.after_work_delta_published_before_completion"
        ),
        "the child must die IN the window, not incidentally:\nstderr:\n{stderr}"
    );

    // The residue, read off a raw handle and checked against a delta THIS test
    // derives from the base and the post-run tree it spelled — not against
    // anything the child returned, because the child died before it could.
    let post_run = manifest(vec![
        file("edited.txt", b"after\n"),
        file("kept.txt", b"kept\n"),
        file("new.txt", b"new\n"),
    ]);
    let expected = TreeDelta::between(base.reference.clone(), &base.manifest, &post_run).unwrap();
    let expected_bytes = expected.delta_bytes().unwrap();
    let delta_object = object_id_for_canonical_bytes(&expected_bytes);

    // Two changed members plus the delta object — `kept.txt` carries nothing,
    // an unchanged member being the input declaration's bytes rather than the
    // delta's.
    assert_eq!(
        object_count(&rig.cas_db),
        before + 3,
        "the window's residue is exactly the delta and the members it writes: durable bytes \
         no `artifacts` row or `cas_roots` row can reference, the only writer of either being \
         the accepting transaction a dead worker never reached"
    );
    for object in [
        object_id_for_canonical_bytes(b"after\n"),
        object_id_for_canonical_bytes(b"new\n"),
        delta_object,
    ] {
        assert!(
            holds(&rig.cas_db, &hex_of(object.0)),
            "the store must hold {object:?}"
        );
    }

    // The NEAR edge: the post-run `/work` survives on the worker's own disk —
    // the same evidence rule the result-publish window states.
    assert_eq!(
        std::fs::read(rig.dir.path().join("work/new.txt")).unwrap(),
        b"new\n",
        "the post-run /work outlives the crash where an operator reads it"
    );

    // RECOVERY, driven rather than described: an unarmed re-publish over the
    // same post-run tree re-derives the identical delta bytes, and the store's
    // dedup makes them the SAME object — the orphan and the retry are
    // byte-for-byte one artifact, so redelivery of the work converges rather
    // than accumulating.
    let republished = publish(&rig, &rig.dir.path().join("work"), &base, ample())
        .expect("the unarmed re-drive publishes");
    assert_eq!(
        republished.object_id(),
        delta_object,
        "the re-drive mints the identical delta object"
    );
    assert_eq!(
        object_count(&rig.cas_db),
        before + 3,
        "dedup makes the re-drive cost zero new objects"
    );
    assert_eq!(
        read_delta(&rig, &republished)
            .apply(&base.manifest)
            .unwrap(),
        post_run,
        "the re-driven delta still applies to the tree on disk"
    );
    drop(rig.dir);
}

/// **A `.jj` component anywhere in `/work` is `work_delta_reserved_path`** — a
/// checkout's own bookkeeping: jj's checkout refuses it by name, so a delta
/// carrying it would publish a tree no workspace can materialize and wedge the
/// apply sweep. The capture refuses before any byte is published — the same
/// token the adoption judge and the jj apply boundary carry. (`.git` is the
/// one exemption, and only at `/work`'s top level — the git view's gitfile;
/// `only_the_toplevel_git_name_is_excluded` carries that half.)
#[cfg(unix)]
#[test]
fn a_vcs_internal_component_is_refused_and_nothing_is_published() {
    let rig = rig();
    let base = publish_base(&rig, &manifest(vec![]), ArtifactPrivacy::Public);
    for nested in [".jj/repo/op_store", "deep/.jj/repo/op_store", ".jj"] {
        let work = write_work(rig.dir.path(), &[("a.txt", b"a\n")], &[], &[]);
        if nested == ".jj" {
            // The directory itself walks as a parent of its members; refuse a
            // lone `.jj/` entry too — write a marker under it.
            std::fs::create_dir_all(work.join(nested)).unwrap();
            std::fs::write(work.join(".jj/repo"), "marker\n").unwrap();
        } else {
            std::fs::create_dir_all(work.join(nested).parent().unwrap()).unwrap();
            std::fs::write(work.join(nested), b"reserved\n").unwrap();
        }
        let before = object_count(&rig.cas_db);
        let refusal =
            publish(&rig, &work, &base, ample()).expect_err("a VCS-internal component is refused");
        assert!(
            refusal.to_string().contains("work_delta_reserved_path"),
            "{nested}: {refusal}"
        );
        assert_eq!(
            object_count(&rig.cas_db),
            before,
            "{nested}: nothing published"
        );
        std::fs::remove_dir_all(&work).unwrap();
    }
    drop(rig.dir);
}

// ---------------------------------------------------------------------------
// The excluded set: a post-run
// path is out of the delta iff it is untracked AND ignored under git
// semantics by the post-run tree's own `.gitignore` files.
// ---------------------------------------------------------------------------

/// **The note's flagship cell.** A base with a `.gitignore` (`target/`,
/// `*.log`, `!keep.log`) and a tracked `target/keep.txt`; the run drops a
/// several-thousand-file `target/big/` (over the capsule's entry bound if any
/// of it were counted), a socket and a `.git` inside `target/`, a
/// `.gitignore` of `target/`'s own trying to re-include `other.txt`, and
/// `a.log`/`keep.log`; it modifies `target/keep.txt` and deletes the tracked,
/// pattern-matching `gone.log`. The delta read out of the store holds exactly
/// the three tracked-truth changes — and `target/` is descended ONLY because
/// the base tracked beneath it, so everything untracked inside stays out.
///
/// **Would red if:** excluded paths were hashed, counted, or refused — the
/// four-entry budget and the exact-change assertion both fail; if the socket
/// or `.git` under `target/` were reached, the walk refuses; if `target/`'s
/// own `.gitignore` were consulted, `other.txt` escapes the exclusion.
#[cfg(unix)]
#[test]
fn ignored_untracked_outputs_are_not_in_the_delta() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![
            file(".gitignore", b"target/\n*.log\n!keep.log\n"),
            file("gone.log", b"tracked, and matching an ignore pattern\n"),
            file("src/main.rs", b"fn main() {}\n"),
            file("target/keep.txt", b"before\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[
            (".gitignore", b"target/\n*.log\n!keep.log\n"),
            ("target/keep.txt", b"after\n"),
            ("src/main.rs", b"fn main() {}\n"),
            ("a.log", b"build noise\n"),
            ("keep.log", b"kept by the negation\n"),
            // A `.gitignore` inside the ignored directory — git cannot
            // re-include under an excluded parent, so `other.txt` stays out.
            ("target/.gitignore", b"!other.txt\n"),
            ("target/other.txt", b"untracked under the excluded dir\n"),
            // The view's own forbidden name, where the walk must not see it.
            ("target/.git", b"gitdir: /elsewhere\n"),
        ],
        &[],
        &[],
    );
    let big = work.join("target/big");
    std::fs::create_dir_all(&big).unwrap();
    for index in 0..3_000 {
        std::fs::write(big.join(format!("f{index:05}.o")), b"o").unwrap();
    }
    let _socket = kata_transport::unix_socket::bind_std(&work.join("target/agent.sock")).unwrap();
    let before = object_count(&rig.cas_db);

    // Four changes would already be over: three are the truth, so 3_000+
    // counted `big/` members can only be a refusal here.
    let reference = publish(&rig, &work, &base, budgets(1 << 20, 4))
        .expect("an ignored build tree publishes — nothing inside it was counted");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![
            ("gone.log", "delete"),
            ("keep.log", "write(file)"),
            ("target/keep.txt", "write(file)"),
        ],
        "exactly the delete, the negated write and the tracked modification — \
         every ignored untracked path is absent"
    );
    // The RESULT the delta encodes is the visible tree: the ignored members
    // exist on disk and must not exist in it.
    assert_eq!(
        delta.apply(&base.manifest).unwrap(),
        manifest(vec![
            file(".gitignore", b"target/\n*.log\n!keep.log\n"),
            file("keep.log", b"kept by the negation\n"),
            file("src/main.rs", b"fn main() {}\n"),
            file("target/keep.txt", b"after\n"),
        ]),
        "base + delta is the post-run tree MINUS the excluded set"
    );
    // Two member writes + the delta object — not one of `big`'s 3_000 bytes.
    assert_eq!(object_count(&rig.cas_db), before + 3);
    drop(rig.dir);
}

/// **A nested `.gitignore` participates with git's precedence** — a negation
/// in `docs/.gitignore` un-ignores what the root's `*.log` took, while
/// `docs/drop.log` stays out. The nested file itself is a delta member: it is
/// new, untracked, and matched by nothing.
#[test]
fn a_nested_gitignores_negation_overrides_the_root() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![
            file(".gitignore", b"*.log\n"),
            file("src/main.rs", b"fn main() {}\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[
            (".gitignore", b"*.log\n"),
            ("src/main.rs", b"fn main() {}\n"),
            ("docs/.gitignore", b"!trace.log\n"),
            ("docs/trace.log", b"un-ignored by the deeper file\n"),
            ("docs/drop.log", b"still ignored\n"),
            ("top.log", b"ignored at root\n"),
        ],
        &[],
        &[],
    );

    let reference = publish(&rig, &work, &base, ample()).expect("the publish is clean");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![
            ("docs/.gitignore", "write(file)"),
            ("docs/trace.log", "write(file)"),
        ],
        "the deeper file's negation wins over the root's pattern"
    );
    drop(rig.dir);
}

/// **A pruned directory exposes nothing inside it — a socket is content for
/// the refusal list only when it is seen, and an excluded path is never
/// seen.** One socket sits under `cache/` — ignored, untracked, and holding a
/// tracked member's DELETE, so the directory is descended for that member but
/// the socket is still excluded; a second sits at the root matching `*.sock`
/// — excluded on its own name. Neither produces `work_delta_special_file`.
///
/// **Would red if:** the exclusion ran after the kind dispatch (the root
/// socket would refuse), or a descended-but-excluded directory's untracked
/// members were compared (the `cache/` socket would refuse).
#[cfg(unix)]
#[test]
fn an_ignored_socket_is_excluded_and_its_dirs_delete_still_counts() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![
            file(".gitignore", b"cache/\n*.sock\n"),
            file("cache/old.txt", b"tracked under the ignored dir\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[(".gitignore", b"cache/\n*.sock\n")],
        &[],
        &[],
    );
    // `cache/` keeps one untracked inhabitant: a socket. The tracked member is
    // GONE — its delete must reach the delta through the excluded dir.
    std::fs::create_dir_all(work.join("cache")).unwrap();
    let _in_ignored_dir =
        kata_transport::unix_socket::bind_std(&work.join("cache/x.sock")).unwrap();
    let _at_root = kata_transport::unix_socket::bind_std(&work.join("y.sock")).unwrap();
    let before = object_count(&rig.cas_db);

    let reference = publish(&rig, &work, &base, ample())
        .expect("excluded sockets refuse nothing — they are never inspected as entries");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![("cache/old.txt", "delete")],
        "the tracked delete lands; both sockets are absent"
    );
    // One object — the delta itself; a socket has no bytes to write anyway.
    assert_eq!(object_count(&rig.cas_db), before + 1);
    drop(rig.dir);
}

/// **A `.git` the walk can see is still refused — exclusion is the only door
/// out of `work_delta_reserved_path`.** `src/.git` is under no ignore pattern
/// and refuses as it always has; `target/.git` under an ignored untracked
/// `target/` is never reached.
///
/// This is the keep-green half of the rule: the refusal is unchanged for
/// everything the excluded set does not cover.
#[cfg(unix)]
#[test]
fn a_nested_git_is_still_refused_where_it_is_seen() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![file(".gitignore", b"target/\n")]),
        ArtifactPrivacy::Private,
    );

    // Seen: `src/` is unignored, so `src/.git` is walked and refused.
    let work = write_work(
        rig.dir.path(),
        &[(".gitignore", b"target/\n"), ("src/x.txt", b"x\n")],
        &[],
        &[],
    );
    std::fs::create_dir_all(work.join("src/.git")).unwrap();
    std::fs::write(work.join("src/.git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    std::fs::create_dir_all(work.join("target/.git")).unwrap();
    std::fs::write(work.join("target/.git/HEAD"), b"ref: refs/heads/other\n").unwrap();
    let refusal =
        publish(&rig, &work, &base, ample()).expect_err("a seen `.git` is refused as ever");
    assert!(
        refusal.to_string().contains("work_delta_reserved_path"),
        "{refusal}"
    );
    assert!(
        refusal.to_string().contains("src/.git"),
        "the refusal names the seen component: {refusal}"
    );
    std::fs::remove_dir_all(&work).unwrap();

    // Unseen: the same `.git` under an ignored untracked directory is never
    // reached — the publish is clean and the delta empty.
    let work = write_work(rig.dir.path(), &[(".gitignore", b"target/\n")], &[], &[]);
    std::fs::create_dir_all(work.join("target/.git")).unwrap();
    std::fs::write(work.join("target/.git/HEAD"), b"ref: refs/heads/other\n").unwrap();
    let reference = publish(&rig, &work, &base, ample())
        .expect("a `.git` inside a pruned directory is never seen");
    let delta = read_delta(&rig, &reference);
    assert!(
        delta.changes().is_empty(),
        "nothing under the ignored directory entered the delta"
    );
    drop(rig.dir);
}

/// **The post-run tree's `.gitignore` is the consulted one** — in both
/// directions. A `.gitignore` the stage ADDS excludes from that same walk; a
/// `.gitignore` the stage DELETED stops excluding.
#[test]
fn the_post_run_gitignore_is_the_one_consulted() {
    let rig = rig();

    // Added: the run writes `*.tmp` beside `x.tmp` — `x.tmp` never lands.
    let base = publish_base(
        &rig,
        &manifest(vec![file("src/main.rs", b"fn main() {}\n")]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[
            ("src/main.rs", b"fn main() {}\n"),
            (".gitignore", b"*.tmp\n"),
            ("x.tmp", b"scratch\n"),
        ],
        &[],
        &[],
    );
    let reference = publish(&rig, &work, &base, ample()).expect("the publish is clean");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![(".gitignore", "write(file)")],
        "the rule the stage just wrote already governs: x.tmp is out"
    );
    std::fs::remove_dir_all(&work).unwrap();

    // Removed: the base ignored `*.tmp`; the run deleted the `.gitignore`, so
    // `x.tmp` counts and the `.gitignore` itself is a delete.
    let base = publish_base(
        &rig,
        &manifest(vec![
            file(".gitignore", b"*.tmp\n"),
            file("src/main.rs", b"fn main() {}\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[("src/main.rs", b"fn main() {}\n"), ("x.tmp", b"scratch\n")],
        &[],
        &[],
    );
    let reference = publish(&rig, &work, &base, ample()).expect("the publish is clean");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![(".gitignore", "delete"), ("x.tmp", "write(file)")],
        "the base's rules died with the base's file — post-run state governs"
    );
    drop(rig.dir);
}

/// **The residual the post-run judge admits, pinned exactly.** A `.gitignore`
/// the stage writes is consulted like any other, so an untracked `.gitignore`
/// whose own pattern matches it (`*`) leaves the delta together with every
/// untracked path it ignores — in a new directory (`d/`) and in a tracked one
/// that holds no tracked `.gitignore` (`src/`). What still counts: a tracked
/// path beneath it (`src/main.rs`), and a written `.gitignore` nothing ignores
/// (`e/.gitignore`, while the `e/y.rs` it ignores leaves).
#[test]
fn a_self_ignoring_gitignore_drops_its_new_siblings_from_the_delta() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![
            file(".gitignore", b"target/\n"),
            file("src/main.rs", b"fn main() {}\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[
            (".gitignore", b"target/\n"),
            ("src/main.rs", b"fn main() { changed() }\n"),
            ("src/.gitignore", b"*\n"),
            ("src/new.rs", b"new\n"),
            ("d/.gitignore", b"*\n"),
            ("d/new.rs", b"new\n"),
            ("e/.gitignore", b"*.rs\n"),
            ("e/y.rs", b"new\n"),
        ],
        &[],
        &[],
    );
    let reference = publish(&rig, &work, &base, ample()).expect("the publish is clean");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![
            ("e/.gitignore", "write(file)"),
            ("src/main.rs", "write(file)")
        ],
        "a self-ignoring .gitignore takes its new siblings out; a tracked path and a \
         .gitignore nothing ignores stay in"
    );
    drop(rig.dir);
}

/// **The residual's other arm: ignored by ANOTHER pattern.** A written
/// `.gitignore` need not ignore itself to leave the delta — any applicable
/// pattern that ignores it does, here a tracked base `.*` — and the untracked
/// paths its own patterns ignore leave with it: `src/.gitignore` of `new.rs`
/// takes itself and `src/new.rs` out, so the delta is empty.
#[test]
fn an_ignored_written_gitignore_drops_what_it_ignores_from_the_delta() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![
            file(".gitignore", b".*\n"),
            file("src/main.rs", b"fn main() {}\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[
            (".gitignore", b".*\n"),
            ("src/main.rs", b"fn main() {}\n"),
            ("src/.gitignore", b"new.rs\n"),
            ("src/new.rs", b"new\n"),
        ],
        &[],
        &[],
    );
    let reference = publish(&rig, &work, &base, ample()).expect("the publish is clean");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        Vec::<(&str, &str)>::new(),
        "a written .gitignore a tracked pattern ignores leaves, and so does what it ignores"
    );
    drop(rig.dir);
}

/// **Anchoring is git's** — `/logs/` bites at the root and nowhere else, so
/// `src/logs/` is content while `logs/` is excluded.
#[test]
fn an_anchored_pattern_bites_only_at_root() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![
            file(".gitignore", b"/logs/\n"),
            file("src/main.rs", b"fn main() {}\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[
            (".gitignore", b"/logs/\n"),
            ("src/main.rs", b"fn main() {}\n"),
            ("logs/a.txt", b"at the anchored spot - out\n"),
            ("src/logs/a.txt", b"not at the anchor - in\n"),
        ],
        &[],
        &[],
    );
    let reference = publish(&rig, &work, &base, ample()).expect("the publish is clean");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![("src/logs/a.txt", "write(file)")],
        "the anchored pattern excludes `logs/` only, never `src/logs/`"
    );
    drop(rig.dir);
}

/// **A dir-only pattern does not match a symlink** — `target/` cannot ignore
/// the LINK `target`, because the stat that feeds the match is
/// `AT_SYMLINK_NOFOLLOW` and a link is not a directory. `git status` reports
/// such a link the same way.
///
/// **Would red if:** the match ran with `is_dir` guessed from the name or the
/// target — the link would be wrongly excluded.
#[cfg(unix)]
#[test]
fn a_dir_only_pattern_does_not_match_a_symlink() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![
            file(".gitignore", b"target/\n"),
            file("real/keep.txt", b"real\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[(".gitignore", b"target/\n"), ("real/keep.txt", b"real\n")],
        &[],
        &[("target", "real")],
    );
    let reference = publish(&rig, &work, &base, ample()).expect("the publish is clean");
    let delta = read_delta(&rig, &reference);
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        vec![("target", "write(symlink)")],
        "the link is a member, not an ignored directory"
    );
    drop(rig.dir);
}

/// **The snapshot descends.** A stamped tree's `len` counts nested members,
/// not only the root's — a snapshot that skipped directories would leave
/// nested unchanged members re-reading their bytes on every delta, and the
/// stamp count is the honest way to see it.
#[test]
fn the_snapshot_records_members_beneath_subdirectories() {
    let rig = rig();
    let work = write_work(
        rig.dir.path(),
        &[
            ("a.txt", b"a\n"),
            ("dir/b.txt", b"b\n"),
            ("dir/deep/c.txt", b"c\n"),
        ],
        &[],
        &[],
    );
    let snapshot = MaterializationSnapshot::take(&work).unwrap();
    assert_eq!(
        snapshot.len(),
        3,
        "the stamp covers nested members — a directory arm that never \
         descended would count only the root's file"
    );
    drop(rig.dir);
}

/// **An ignored directory with nothing tracked beneath it is PRUNED, never
/// descended.** `vault/` matches the ignore rule and the base names nothing
/// under it: the walk skips it whole — its entries are never statted for
/// refusal and its directory is never opened. A `vault` the test itself
/// cannot open proves the difference: descending would answer an
/// `unreadable` refusal, pruning answers a clean delta.
#[test]
fn an_ignored_untracked_directory_is_pruned_without_being_opened() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![file("kept.txt", b"kept\n")]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[("kept.txt", b"kept\n"), (".gitignore", b"vault/\n")],
        &[],
        &[],
    );
    std::fs::create_dir_all(work.join("vault")).unwrap();
    std::fs::set_permissions(work.join("vault"), std::fs::Permissions::from_mode(0o000)).unwrap();
    // THE CONTROL: the cell's premise is that `vault/` cannot be opened at
    // all — a runner that opens it anyway (root, `CAP_DAC_READ_SEARCH`)
    // would make "never opened" unprovable and the assertion below vacuous.
    // Such a runner must fail HERE, named, not pass a cell that proves
    // nothing.
    assert!(
        std::fs::read_dir(work.join("vault")).is_err(),
        "this cell needs an unprivileged runner: it proves `vault/` is never \
         opened by making it unopenable — a runner that CAN open it (root, \
         CAP_DAC_READ_SEARCH) can no longer tell pruning from a tolerated \
         descent, and would pass vacuously"
    );

    let reference = publish(&rig, &work, &base, ample()).unwrap_or_else(|refusal| {
        // Restore the mode so the tempdir cleans up, then report.
        std::fs::set_permissions(work.join("vault"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        panic!("the pruned directory is never opened: {refusal}")
    });
    std::fs::set_permissions(work.join("vault"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let delta = read_delta(&rig, &reference);
    let paths: Vec<&str> = delta
        .changes()
        .iter()
        .map(|change| change.path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec![".gitignore"],
        "the ignored vault never entered the delta: {paths:?}"
    );
    drop(rig.dir);
}

/// **A `.gitignore` over the member ceiling is refused, not truncated.**
/// `load_gitignore` reads at most `MAX_MEMBER_BYTES + 1` so "too large to
/// apply" is distinguishable from "exactly the bound" — and the refusal must
/// come from THAT bound, not the member ceiling: the oversized file lives in
/// a descended subdirectory and is itself ignored by the parent's `*.gitignore`
/// rule, so it is never a member the ceiling could refuse. A shorter take or a
/// wrong comparison would accept the truncated pattern list and publish.
#[test]
fn a_gitignore_over_the_member_ceiling_is_refused() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![file("kept.txt", b"kept\n")]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(
        rig.dir.path(),
        &[("kept.txt", b"kept\n"), (".gitignore", b"*.gitignore\n")],
        &[],
        &[],
    );
    std::fs::create_dir_all(work.join("sub")).unwrap();
    std::fs::write(
        work.join("sub/.gitignore"),
        vec![
            b'#';
            usize::try_from(kata_types::tree_artifact::MAX_MEMBER_BYTES)
                .expect("the member bound fits usize")
                + 1
        ],
    )
    .unwrap();

    let refusal = publish(&rig, &work, &base, ample())
        .expect_err("a .gitignore past the member ceiling is refused");
    assert_eq!(
        refusal.label(),
        "work_delta_member_over_ceiling",
        "{refusal}"
    );
    drop(rig.dir);
}

/// **A `.gitignore` AT the ceiling is still applied** — the refused set is
/// `>`, and a bound that fires on `>=` would refuse the largest legal file.
/// The content is one comment line: the bound is read before any pattern is
/// parsed, so the cell needs only the file's size on the boundary.
#[test]
fn a_gitignore_at_the_member_ceiling_is_applied() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![file("kept.txt", b"kept\n")]),
        ArtifactPrivacy::Private,
    );
    let work = write_work(rig.dir.path(), &[("kept.txt", b"kept\n")], &[], &[]);
    std::fs::write(
        work.join(".gitignore"),
        vec![
            b'#';
            usize::try_from(kata_types::tree_artifact::MAX_MEMBER_BYTES)
                .expect("the member bound fits usize")
        ],
    )
    .unwrap();

    let reference = publish(&rig, &work, &base, ample())
        .expect("a .gitignore at exactly the ceiling is under no refusal");
    let delta = read_delta(&rig, &reference);
    let paths: Vec<&str> = delta
        .changes()
        .iter()
        .map(|change| change.path.as_str())
        .collect();
    assert!(
        paths.contains(&".gitignore"),
        "the at-ceiling ignore file is itself a delta member: {paths:?}"
    );
    drop(rig.dir);
}

/// **A confined `/work` view is never a deletion.** The cell's shape is the
/// live cell's, shrunk to the filesystem: the base tree carries `src/a` AND
/// `docs/b`, the confined container materializes only `src/` (the disk the
/// publisher walks literally lacks `docs/`), the stage rewrites `src/a`, and
/// the published delta — read back out of the CAS — must name `src/a` alone:
/// a `Delete` of `docs/b` would fold the unmaterialized side into the new
/// head and the work would be destroyed by the mechanism meant to confine it.
/// And the delta's `base` still names the FULL head's artifact id — the cell
/// the report's second half answers.
///
/// **Would red if:** the view merge were dropped (the delta would carry
/// `Delete docs/b`), the merge folded uncovered members' fresh bytes (a scan
/// entry at an uncovered path must STAY a scan entry — the `produces_files`
/// fence refuses it downstream, unchanged-member treatment would hide it), or
/// the delta's `base` were re-pointed at the view.
#[test]
fn a_confined_view_reports_the_stage_edit_and_never_a_deletion() {
    let rig = rig();
    let base = publish_base(
        &rig,
        &manifest(vec![
            file("src/a.txt", b"alpha\n"),
            file("docs/b.md", b"beta\n"),
        ]),
        ArtifactPrivacy::Private,
    );
    // The confined materialization: `docs/` is never written to disk.
    let work = write_work(
        rig.dir.path(),
        &[("src/a.txt", b"alpha edited\n")],
        &[],
        &[],
    );
    let view = CapsuleWorkView {
        include: vec![smol_str::SmolStr::new("src")],
    };

    let reference =
        publish_viewed(&rig, &work, &base, ample(), &view).expect("the confined delta publishes");
    let delta = read_delta(&rig, &reference);

    // The delta's base is the FULL head — the view is a predicate over it,
    // never a different base artifact.
    assert_eq!(
        delta.base().id(),
        base.reference.id(),
        "the delta names the full head as its base"
    );
    let changes: Vec<(&str, &str)> = delta
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        changes,
        [("src/a.txt", "write(file)")],
        "exactly the stage's own edit — no delete of the unmaterialized side"
    );

    // Applying the delta to the FULL base reproduces the full head: `docs/b`
    // survives byte-identical and `src/a` carries the edit.
    let result = delta.apply(&base.manifest).expect("the delta applies");
    let paths: Vec<&str> = result
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(paths, ["docs/b.md", "src/a.txt"]);
    let edited = result
        .entries()
        .iter()
        .find(|entry| entry.path.as_str() == "src/a.txt")
        .expect("the edit is a member");
    assert_eq!(
        edited.node,
        file("src/a.txt", b"alpha edited\n").node,
        "the recorded node is the stage's bytes"
    );

    // The control: a member the stage WROTE at an uncovered path is still a
    // scan entry — the merge folds only members the stage could not have seen.
    let work2 = write_work(
        rig.dir.path().join("work2").as_path(),
        &[
            ("src/a.txt", b"alpha\n"),
            ("docs/b.md", b"stage wrote here\n"),
        ],
        &[],
        &[],
    );
    let reference2 = publish_viewed(&rig, &work2, &base, ample(), &view)
        .expect("an out-of-view write still publishes");
    let delta2 = read_delta(&rig, &reference2);
    let kinds: Vec<(&str, &str)> = delta2
        .changes()
        .iter()
        .map(|change| (change.path.as_str(), kind(&change.change)))
        .collect();
    assert_eq!(
        kinds,
        [("docs/b.md", "write(file)")],
        "a write at an uncovered path is the scan's own entry — visible to the \
         downstream produces fence, not absorbed as unchanged"
    );
    drop(rig.dir);
}
