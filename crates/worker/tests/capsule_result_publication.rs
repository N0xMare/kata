//! Publishing a container's `/out` as a TREE ARTIFACT,
//! with every verdict read off the FILESYSTEM and off a second raw rusqlite handle.
//!
//! # Invariant
//!
//! The subject is asked nothing. A published member's bytes are read back from the CAS's
//! own blob file (or its inline column) through a connection this file opens itself, and
//! every "nothing was published" assertion counts `cas_objects` on that handle — because
//! *"the bound is enforced BEFORE any byte is published"* and *"the bound is enforced and
//! then the bytes are left behind"* return the same `Err` and differ only in the store.
//!
//! # CRASH CELL HOME
//!
//! This file is the home `operational_crash_matrix.rs`'s `ELSEWHERE` table credits with
//! `operational.after_container_exited_before_result_published`, so the boundary name and
//! the `KATA_FAULT_INJECT` arming below are load-bearing rather than decorative.

use std::path::Path;
use std::process::Command;

use kata_core::store::cas::CasStore;
use kata_types::execution_contract::{ArtifactPrivacy, CapsuleBudgets};
use kata_types::tree_artifact::{TreeEntryMode, TreeManifest, TreeNode};
use kata_worker::result_publication::{
    CasBlobSink, RESULT_PRIVACY, ResultPublicationRefusal, privacy_for, publish_result_tree,
};

const CHILD_MARKER: &str = "KATA_RESULT_PUBLICATION_CRASH_CHILD";
const CHILD_DIR: &str = "KATA_RESULT_PUBLICATION_CRASH_DIR";

/// The bytes the crash cell looks for in the store, and the member every happy-path cell
/// publishes.
const MEMBER: &[u8] = b"result-member\n";

/// Bounds a three-member tree is outside in ONE dimension each, so the two refusals are
/// reachable separately. See the sibling core test for the same argument on the adopting
/// side.
fn budgets(result_bytes: u64, result_entries: u32) -> CapsuleBudgets {
    CapsuleBudgets {
        wall_time_ms: 30_000,
        output_bytes: 1 << 20,
        memory_bytes: 512 * 1024 * 1024,
        process_count: 64,
        result_bytes,
        result_entries,
        work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
        work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
    }
}

/// A generous bound, for the cells whose subject is not the bound.
fn ample() -> CapsuleBudgets {
    budgets(1 << 20, 128)
}

/// One `out/` directory with `members` in it, relative paths and all.
fn out_with(root: &Path, members: &[(&str, &[u8])]) -> std::path::PathBuf {
    let out = root.join("out");
    std::fs::create_dir_all(&out).unwrap();
    for (path, bytes) in members {
        let target = out.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&target, bytes).unwrap();
    }
    out
}

/// The SECOND handle onto `cas.db`. Read-only: an observer that can write is an observer
/// that can repair what it was meant to catch.
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

/// **A real `/out` becomes a tree artifact whose members the STORE holds — read off a raw
/// handle, not off the publisher.**
///
/// **Would red if:** the manifest were published before its members (the members would be
/// absent), a member's recorded length disagreed with its bytes, the executable bit were
/// dropped or invented, or the reference's privacy were not the one the adopting side
/// refuses everything else for.
#[test]
fn a_real_out_directory_publishes_as_a_tree_the_store_holds() {
    let dir = tempfile::tempdir().unwrap();
    let cas_db = dir.path().join("cas.db");
    let cas = CasStore::open(&cas_db, dir.path().join("cas")).unwrap();
    let out = out_with(
        dir.path(),
        &[("hi", MEMBER), ("nested/deeper/also", b"two\n")],
    );
    // An EXECUTABLE member, so the mode is a measured fact rather than a constant.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(out.join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(out.join("run.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    let (reference, manifest) = {
        let sink = CasBlobSink(&cas);
        publish_result_tree(&out, ample(), &sink).expect("a well-formed /out publishes")
    };

    assert_eq!(
        reference.privacy(),
        RESULT_PRIVACY,
        "a NON-EMPTY result carries the conservative classification, and the adopting side \
         refuses the other for every object but the canonical empty tree"
    );
    assert_eq!(reference.privacy(), ArtifactPrivacy::Private);
    assert_eq!(privacy_for(&manifest), ArtifactPrivacy::Private);

    // The manifest names the members by SORTED path, which `TreeManifest::new` owns.
    let paths: Vec<&str> = manifest
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    #[cfg(unix)]
    assert_eq!(paths, ["hi", "nested/deeper/also", "run.sh"]);
    #[cfg(not(unix))]
    assert_eq!(paths, ["hi", "nested/deeper/also"]);

    #[cfg(unix)]
    {
        let modes: Vec<(&str, TreeEntryMode)> = manifest
            .entries()
            .iter()
            .map(|entry| match &entry.node {
                TreeNode::File { mode, .. } => (entry.path.as_str(), *mode),
                TreeNode::Symlink { .. } => panic!("this publisher still refuses links"),
            })
            .collect();
        assert_eq!(
            modes,
            [
                ("hi", TreeEntryMode::Regular),
                ("nested/deeper/also", TreeEntryMode::Regular),
                ("run.sh", TreeEntryMode::Executable),
            ],
            "the ONE permission bit a tree artifact carries is whether the guest may exec the \
             file, and it is read off the host rather than assumed"
        );
    }

    // THE STORE's own answer, through the second handle: the manifest AND every member.
    let manifest_hex = hex_of(reference.object_id().0);
    assert!(
        holds(&cas_db, &manifest_hex),
        "the manifest object must be in the store"
    );
    for entry in manifest.entries() {
        let object = entry
            .node
            .object()
            .expect("every entry this publisher emits is a file");
        assert!(
            holds(&cas_db, &hex_of(object.0)),
            "member {} must be in the store BEFORE the manifest that names it",
            entry.path.as_str()
        );
    }

    // And the bytes really are the file's. Read through the store's own verified read,
    // compared against the file this test wrote — two independent sources for one value.
    let hi = manifest
        .entries()
        .iter()
        .find(|entry| entry.path.as_str() == "hi")
        .expect("the `hi` member");
    let TreeNode::File {
        object: hi_object,
        size_bytes: hi_size,
        ..
    } = &hi.node
    else {
        panic!("`hi` is a file entry")
    };
    assert_eq!(*hi_size, MEMBER.len() as u64);
    assert_eq!(
        cas.get_verified(hi_object, *hi_size, 1 << 20).unwrap(),
        MEMBER,
        "the published member's bytes must be the bytes the container wrote"
    );
    drop(dir);
}

fn hex_of(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// **An EMPTY `/out` publishes the canonical empty tree rather than refusing.**
///
/// A stage that legitimately produces no files has a result, and it is that one — the same
/// object `kata_workflow::capsule_assembly::empty_tree_artifact` names, which is why the
/// address is derived here from `TreeManifest::new(vec![])` rather than pinned as a
/// literal.
#[test]
fn an_empty_out_publishes_the_canonical_empty_tree() {
    let dir = tempfile::tempdir().unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();
    let out = out_with(dir.path(), &[]);

    let (reference, manifest) = {
        let sink = CasBlobSink(&cas);
        publish_result_tree(&out, ample(), &sink).expect("an empty /out is a result")
    };
    assert!(manifest.entries().is_empty());
    let canonical = TreeManifest::new(Vec::new())
        .unwrap()
        .manifest_bytes()
        .unwrap();
    assert_eq!(
        reference.object_id(),
        kata_types::cache::object_id_for_canonical_bytes(&canonical),
        "an empty result is the CANONICAL empty tree, which every capsule already maps at /out"
    );
    // AND IT IS PUBLIC, which is the one exception to `RESULT_PRIVACY`. `Private` here
    // would mint a SECOND artifact id over bytes every capsule already declares as
    // `Public`, and the main's `idx_artifacts_object` would refuse whichever arrived
    // second — so the first empty result on a node would break every later capsule
    // assembly, or the reverse.
    assert_eq!(
        reference.privacy(),
        ArtifactPrivacy::Public,
        "the empty tree is the same object on every node and protects nothing by being \
         restricted; the adopting side admits `Public` for THIS object id and no other"
    );
    assert_eq!(privacy_for(&manifest), ArtifactPrivacy::Public);
    drop(dir);
}

/// **A result over `result_bytes` is refused and NOTHING was published.**
///
/// The store count is the whole cell: a publisher that streamed members and checked the
/// running total would return the same `Err` and leave the members it already wrote behind
/// — bytes no row references and nothing ever reclaims (kata has no CAS collection), for a
/// stage the node then refused.
#[test]
fn a_result_over_its_byte_bound_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cas_db = dir.path().join("cas.db");
    let cas = CasStore::open(&cas_db, dir.path().join("cas")).unwrap();
    let out = out_with(dir.path(), &[("a", &[b'x'; 64]), ("b", &[b'y'; 64])]);
    let before = object_count(&cas_db);

    let refusal = {
        let sink = CasBlobSink(&cas);
        publish_result_tree(&out, budgets(32, 128), &sink)
            .expect_err("128 member bytes against a 32-byte promise must be refused")
    };
    assert_eq!(refusal.label(), "result_bytes_exceeded", "{refusal}");
    assert!(
        refusal.to_string().contains("NOTHING WAS PUBLISHED"),
        "the refusal must state the property, because an operator's next question is whether \
         the bytes are in the store: {refusal}"
    );
    assert_eq!(
        object_count(&cas_db),
        before,
        "not one object was published. Counted on a raw handle, because the return value cannot \
         tell a bound checked before the publish from one checked during it"
    );
    drop(dir);
}

/// **A result whose MANIFEST would encode past the tree ceiling is refused and NOTHING was
/// published** — though it is inside both of the capsule's result budgets.
///
/// 18 000 EMPTY files under one 14-level chain of 250-byte directory names: every
/// relative path about 3 760 bytes, zero member bytes, 18 000 entries against a
/// 20 000-entry promise (the entry bound must not refuse first — it is not the door
/// under test). Its manifest is over `TreeManifest::MAXIMUM_ENCODED_BYTES`, the
/// ceiling the main's adoption and collection roots and every worker materializer
/// read manifests at — so publishing it would publish a result no reader can load.
///
/// **Would red if:** the ceiling were checked only on the real manifest after the members
/// (the empty member would be in the store: the count moves), or not at all (the publish
/// succeeds).
#[test]
fn a_result_whose_manifest_is_over_the_tree_ceiling_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cas_db = dir.path().join("cas.db");
    let cas = CasStore::open(&cas_db, dir.path().join("cas")).unwrap();
    let out = dir.path().join("out");
    let mut deep = out.clone();
    for level in 0..14 {
        deep.push(format!("{level:02}{}", "d".repeat(248)));
    }
    std::fs::create_dir_all(&deep).unwrap();
    for index in 0..18_000u32 {
        std::fs::write(deep.join(format!("{index:05}{}", "f".repeat(240))), b"").unwrap();
    }
    let before = object_count(&cas_db);

    let published = {
        let sink = CasBlobSink(&cas);
        publish_result_tree(&out, budgets(1 << 20, 20_000), &sink)
    };
    // Not `expect_err`: its `Ok` arm would print a ~72 MB manifest.
    let Err(refusal) = published else {
        panic!("a manifest no reader can load must be refused, and it was published");
    };
    assert_eq!(refusal.label(), "result_manifest_over_ceiling", "{refusal}");
    assert!(
        refusal
            .to_string()
            .contains(kata_types::tree_artifact::TREE_MANIFEST_OVER_CEILING),
        "the encoder's own name rides the refusal: {refusal}"
    );
    assert_eq!(
        object_count(&cas_db),
        before,
        "not one object was published — not even the one empty member every entry shares"
    );
    drop(dir);
}

/// **A result over `result_entries` is refused and NOTHING was published.**
///
/// Three one-byte members: three total bytes, far inside any byte bound, so only the
/// ENTRY bound can refuse it. Paired with its sibling, this is what makes "two bounds,
/// folded separately, neither implying the other" a measured claim.
#[test]
fn a_result_over_its_entry_bound_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cas_db = dir.path().join("cas.db");
    let cas = CasStore::open(&cas_db, dir.path().join("cas")).unwrap();
    let out = out_with(dir.path(), &[("a", b"1"), ("b", b"2"), ("c", b"3")]);
    let before = object_count(&cas_db);

    let refusal = {
        let sink = CasBlobSink(&cas);
        publish_result_tree(&out, budgets(1 << 20, 2), &sink)
            .expect_err("three entries against a promise of two must be refused")
    };
    assert_eq!(refusal.label(), "result_entries_exceeded", "{refusal}");
    assert_eq!(object_count(&cas_db), before);
    drop(dir);
}

/// **A SYMLINK in `/out` is refused by name, and nothing is published.**
///
/// A tree manifest CAN carry a symlink — but THAT is the crate producer's
/// disposition for a link it EMITS, not for a link it meets on disk. This walk
/// refuses one: a stage's stray symlink stays a named failure instead
/// of silently becoming artifact content, and a link pointing OUT of `/out`
/// never gets to pull arbitrary host bytes into one — which is why the link
/// below points at `/etc/passwd`.
#[cfg(unix)]
#[test]
fn a_symlink_in_out_is_refused_and_nothing_is_published() {
    let dir = tempfile::tempdir().unwrap();
    let cas_db = dir.path().join("cas.db");
    let cas = CasStore::open(&cas_db, dir.path().join("cas")).unwrap();
    let out = out_with(dir.path(), &[("hi", MEMBER)]);
    std::os::unix::fs::symlink("/etc/passwd", out.join("escape")).unwrap();
    let before = object_count(&cas_db);

    let refusal = {
        let sink = CasBlobSink(&cas);
        publish_result_tree(&out, ample(), &sink).expect_err("a symlink has no tree encoding")
    };
    assert_eq!(refusal.label(), "unrepresentable_entry", "{refusal}");
    assert!(refusal.to_string().contains("symlink"), "{refusal}");
    assert_eq!(
        object_count(&cas_db),
        before,
        "the scan runs to completion before the publish, so a malformed entry anywhere in the \
         tree costs no bytes in the store"
    );
    drop(dir);
}

/// **An `/out` that is not there at all is a refusal naming the path, not an empty
/// result.**
#[test]
fn an_absent_out_is_refused_rather_than_read_as_empty() {
    let dir = tempfile::tempdir().unwrap();
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap();
    let refusal = {
        let sink = CasBlobSink(&cas);
        publish_result_tree(&dir.path().join("out"), ample(), &sink)
            .expect_err("an unwalkable /out is a result that cannot be reported")
    };
    assert_eq!(refusal.label(), "out_unreadable", "{refusal}");
    drop(dir);
}

// ---------------------------------------------------------------------------
// The crash cell
// ---------------------------------------------------------------------------

/// The armed child: build a well-formed `/out` and die INSIDE the publish window.
fn crash_child(dir: &Path) {
    let cas = CasStore::open(dir.join("cas.db"), dir.join("cas")).unwrap();
    let out = out_with(dir, &[("hi", MEMBER)]);
    let sink = CasBlobSink(&cas);
    let published = publish_result_tree(&out, ample(), &sink)
        .expect("the publish reaches its crash point")
        .0;
    panic!(
        "the armed fault point was never reached; the child published {} — the cell proves \
         nothing",
        published.object_id()
    );
}

/// **`after_container_exited_before_result_published` — the container is gone, `/out` is on
/// the worker's disk, and the STORE holds nothing.**
///
/// # Would red if
///
/// The boundary fired after the first member was published (the store would hold it), or
/// the scan-then-publish order were inverted so a bound refusal could publish. The
/// recovery obligation is not repair: the main's worker-death leg settles the attempt
/// PROVEN AMBIGUOUS and nothing re-runs it, and `/out` is NEVER adopted — the only thing
/// that adopts one is a `CompletedCapsule` frame this abort prevented from being sent,
/// which is why the assertion is about the store and not about a retry.
///
/// The bytes on the WORKER's disk are asserted to survive, because they are the evidence
/// an operator reads and because a window that deleted them would be a different window.
#[test]
fn after_container_exited_before_result_published_leaves_the_store_untouched() {
    if std::env::var(CHILD_MARKER).is_ok() {
        crash_child(Path::new(&std::env::var(CHILD_DIR).unwrap()));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("after_container_exited_before_result_published_leaves_the_store_untouched")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir.path())
        .env(
            "KATA_FAULT_INJECT",
            "operational.after_container_exited_before_result_published",
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
            "crash point reached: operational.after_container_exited_before_result_published"
        ),
        "the child must die IN the window, not incidentally:\nstderr:\n{stderr}"
    );

    // The FAR edge: the store holds nothing at all — not the member, not a manifest.
    let cas_db = dir.path().join("cas.db");
    assert_eq!(
        object_count(&cas_db),
        0,
        "the window's whole property: the container exited, `/out` is on disk, and no byte of the \
         result reached the content store. A store holding the member would mean the boundary \
         sits after the first publish"
    );

    // The NEAR edge: the bytes are still on the worker's disk, where an operator finds
    // them under the attempt root.
    assert_eq!(
        std::fs::read(dir.path().join("out/hi")).unwrap(),
        MEMBER,
        "the container's output must survive the crash on the worker's own disk — it is the \
         evidence, and a window that deleted it would be a different window"
    );
}

/// The refusal type's labels are the tokens a log field and a test read, and every arm has
/// one.
///
/// A vacuity guard rather than a property: the cells above assert five of the eight, and
/// a label that was `""` or duplicated would make one of them pass for the wrong reason.
#[test]
fn every_refusal_label_is_a_distinct_non_empty_token() {
    let refusals = [
        ResultPublicationRefusal::Unreadable {
            path: std::path::PathBuf::from("/out"),
            error: "e".to_owned(),
        },
        ResultPublicationRefusal::UnrepresentableEntry {
            path: std::path::PathBuf::from("/out/x"),
            kind: "symlink",
        },
        ResultPublicationRefusal::UnacceptablePath(kata_types::error::KataError::Validation(
            "p".to_owned(),
        )),
        ResultPublicationRefusal::TooManyEntries {
            entries: 3,
            budget: 2,
        },
        ResultPublicationRefusal::TooManyBytes {
            bytes: 3,
            budget: 2,
        },
        ResultPublicationRefusal::ManifestOverCeiling(kata_types::error::KataError::Validation(
            "m".to_owned(),
        )),
        ResultPublicationRefusal::PublicationFailed(kata_types::error::KataError::Validation(
            "s".to_owned(),
        )),
        ResultPublicationRefusal::MemberChanged {
            path: std::path::PathBuf::from("/out/x"),
            scanned: 1,
            read: 2,
        },
    ];
    let labels: std::collections::BTreeSet<&str> = refusals
        .iter()
        .map(ResultPublicationRefusal::label)
        .collect();
    assert_eq!(
        labels.len(),
        refusals.len(),
        "two arms share a label, so a cell asserting one of them cannot tell which fired"
    );
    for refusal in &refusals {
        assert!(!refusal.label().is_empty());
        assert!(
            refusal.to_string().contains(refusal.label()),
            "the Display must carry the label an operator greps for: {refusal}"
        );
    }
}
