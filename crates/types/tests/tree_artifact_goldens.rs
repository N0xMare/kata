//! Pinned identity vectors for `kata_types::tree_artifact`.
//!
//! These literals are the external witness for a tree artifact's IDENTITY. Unlike
//! `nix_environment_goldens.rs`, the pinned value here is not a field-wise digest:
//! a tree has no second digest on purpose (see the module docs), so its identity is
//! the CAS address of `TreeManifest::manifest_bytes` and nothing else. That makes
//! the manifest's SERIALIZED SHAPE load-bearing in a way a field-wise digest never
//! is — a field order, a field rename, a mode spelling, a number formatting change
//! all rotate every tree artifact id — and the in-module tests cannot see any of
//! it, because they only compare kata's answer to kata's answer.
//!
//! A diff here means the tree artifact family rotated: either intended (bump
//! [`TREE_MANIFEST_SCHEMA_VERSION`] and re-pin every vector) or a defect. Every
//! cached materialization and every `artifacts` row keyed on one of these ids would
//! be stranded by a silent rotation — which is exactly the disposition schema 2
//! wants: a v1 manifest is refused on read, and the operational schema stamp
//! refuses the v1 data directory at boot.
//!
//! # The preimage these vectors are taken under
//!
//! `cas_address_for_canonical_bytes` — `blake3(b"kata.cas.object\0" ‖
//! function_code ‖ len_le ‖ bytes)`, the ONE spelling of the CAS address
//! (`kata_types::cache::ObjectIdHasher::for_canonical_len` is the streaming half of
//! the same scheme, and `cas_address_for_canonical_bytes` delegates to it). It is
//! cited rather than restated here so a rotation of the CAS scheme itself lands on
//! these vectors instead of on a local re-derivation that would rotate with it.

use kata_types::cache::cas_address_for_canonical_bytes;
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
use kata_types::primitives::{FixedBytes, ObjectId};
use kata_types::tree_artifact::{
    SymlinkTarget, TREE_MANIFEST_SCHEMA_VERSION, TreeEntry, TreeEntryMode, TreeManifest, TreeNode,
    TreePath,
};

/// Two fixed member object ids. Their VALUES are arbitrary; that they are fixed is
/// the whole point of a golden.
fn member(byte: u8) -> ObjectId {
    FixedBytes([byte; 32])
}

fn entry(path: &str, mode: TreeEntryMode, object: ObjectId, size_bytes: u64) -> TreeEntry {
    TreeEntry {
        path: TreePath::new(path).expect("a valid tree path"),
        node: TreeNode::File {
            mode,
            object,
            size_bytes,
        },
    }
}

fn link(path: &str, target: &str) -> TreeEntry {
    TreeEntry {
        path: TreePath::new(path).expect("a valid tree path"),
        node: TreeNode::Symlink {
            target: SymlinkTarget::new(target).expect("a valid symlink target"),
        },
    }
}

/// A two-entry tree with one regular file and one executable, SUPPLIED OUT OF
/// ORDER so the vector also witnesses that `new` sorts rather than trusting the
/// caller.
fn two_entry_manifest() -> TreeManifest {
    TreeManifest::new(vec![
        entry("src/run.sh", TreeEntryMode::Executable, member(0xB2), 4_096),
        entry("README.md", TreeEntryMode::Regular, member(0xA1), 2_048),
    ])
    .expect("the pinned manifest is valid")
}

/// The schema-2 vector: one regular file, one executable file and one symlink —
/// one entry of every kind the manifest can carry, so a rotation of any arm's
/// spelling lands here.
fn file_exe_link_manifest() -> TreeManifest {
    TreeManifest::new(vec![
        entry("README.md", TreeEntryMode::Regular, member(0xA1), 2_048),
        entry("src/run.sh", TreeEntryMode::Executable, member(0xB2), 4_096),
        link("docs/manual", "../README.md"),
    ])
    .expect("the pinned manifest is valid")
}

#[test]
fn schema_version_is_the_one_these_vectors_were_pinned_under() {
    assert_eq!(TREE_MANIFEST_SCHEMA_VERSION, 2);
}

/// The exact canonical bytes, pinned as a STRING.
///
/// The address below is a 32-byte digest, which tells a reader that something
/// changed and nothing about what. This vector is the one a diff can be read: the
/// field order, the `snake_case` node `kind` and mode tags, the hex member
/// encoding, and the sorted entry order are all visible in it.
#[test]
fn the_canonical_manifest_bytes_of_a_two_entry_tree_are_pinned() {
    let bytes = two_entry_manifest()
        .manifest_bytes()
        .expect("the pinned manifest serializes");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "{\"schema_version\":2,\"entries\":[\
           {\"path\":\"README.md\",\"node\":{\"kind\":\"file\",\"mode\":\"regular\",\
            \"object\":\"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\",\
            \"size_bytes\":2048}},\
           {\"path\":\"src/run.sh\",\"node\":{\"kind\":\"file\",\"mode\":\"executable\",\
            \"object\":\"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\",\
            \"size_bytes\":4096}}]}"
    );
}

/// The CAS object id of those bytes — the tree's identity, under the documented
/// preimage.
#[test]
fn the_cas_object_id_of_a_two_entry_tree_manifest_is_pinned() {
    let bytes = two_entry_manifest().manifest_bytes().unwrap();
    assert_eq!(
        cas_address_for_canonical_bytes(&bytes).hash().to_string(),
        "9b1a5f7d6227b168d5b6a51fe0de4df3eefc781039e5a613597315d5f6f89c27"
    );
}

/// The capsule-facing reference a declared tree artifact carries.
///
/// Pinned separately from the address because `ArtifactRef` folds the object id
/// together with the SIZE and the PRIVACY under its own domain tag and its own
/// execution-contract schema version, so either family's tag can rotate
/// independently and this vector sees it.
///
/// `size_bytes` is the MANIFEST's length — pinned below — not the bytes its
/// members hold. A reader who expects the member total will find the difference
/// here rather than in a materializer's bound.
#[test]
fn the_artifact_id_of_a_two_entry_tree_is_pinned() {
    let bytes = two_entry_manifest().manifest_bytes().unwrap();
    assert_eq!(bytes.len(), 346, "the pinned manifest's byte length");
    let object = cas_address_for_canonical_bytes(&bytes).hash();
    let reference = ArtifactRef::new(object, bytes.len() as u64, ArtifactPrivacy::Private);
    assert_eq!(
        reference.id().0.to_string(),
        "fa920f47e6fae760109b58406a9957d11901edb37cb1734e40a8c87fe9b42933"
    );
    assert_eq!(reference.object_id(), object);
    assert_eq!(reference.size_bytes(), bytes.len() as u64);
}

/// THE SCHEMA-2 VECTOR: file + executable + symlink.
///
/// The exact canonical bytes, pinned as a STRING — the one place a reader can see
/// the `node` object, the `kind` tag, the `symlink` arm's `target` field and the
/// verbatim `../README.md` spelling.
#[test]
fn the_canonical_manifest_bytes_of_a_file_exe_link_tree_are_pinned() {
    let bytes = file_exe_link_manifest()
        .manifest_bytes()
        .expect("the pinned manifest serializes");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "{\"schema_version\":2,\"entries\":[\
           {\"path\":\"README.md\",\"node\":{\"kind\":\"file\",\"mode\":\"regular\",\
            \"object\":\"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\",\
            \"size_bytes\":2048}},\
           {\"path\":\"docs/manual\",\"node\":{\"kind\":\"symlink\",\
            \"target\":\"../README.md\"}},\
           {\"path\":\"src/run.sh\",\"node\":{\"kind\":\"file\",\"mode\":\"executable\",\
            \"object\":\"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\",\
            \"size_bytes\":4096}}]}"
    );
}

/// The CAS object id of the schema-2 vector's bytes.
#[test]
fn the_cas_object_id_of_a_file_exe_link_manifest_is_pinned() {
    let bytes = file_exe_link_manifest().manifest_bytes().unwrap();
    assert_eq!(
        cas_address_for_canonical_bytes(&bytes).hash().to_string(),
        "ecd3be6566aa986bd8a54fb55e2aa64cac74a62a4a31567121e4c78187ee1515"
    );
}

/// The capsule-facing reference of the schema-2 vector — pinned separately for
/// the reason the two-entry one is.
#[test]
fn the_artifact_id_of_a_file_exe_link_tree_is_pinned() {
    let bytes = file_exe_link_manifest().manifest_bytes().unwrap();
    assert_eq!(bytes.len(), 419, "the pinned manifest's byte length");
    let object = cas_address_for_canonical_bytes(&bytes).hash();
    let reference = ArtifactRef::new(object, bytes.len() as u64, ArtifactPrivacy::Private);
    assert_eq!(
        reference.id().0.to_string(),
        "bd9c94dd140bb942288f13c96ce8e04897d9867a7e5ac02df9bd7a52ff5f7713"
    );
    assert_eq!(reference.object_id(), object);
    assert_eq!(reference.size_bytes(), bytes.len() as u64);
}

/// A MODE FLIP IS A BYTE CHANGE. One entry's mode moved from executable to
/// regular, everything else identical — a distinct pinned address, which is the
/// external witness that the execute bit is part of a tree's identity and that two
/// trees differing only in it cannot share one cached materialization.
#[test]
fn flipping_one_entrys_mode_is_pinned_to_a_different_address() {
    let flipped = TreeManifest::new(vec![
        entry("src/run.sh", TreeEntryMode::Regular, member(0xB2), 4_096),
        entry("README.md", TreeEntryMode::Regular, member(0xA1), 2_048),
    ])
    .unwrap();
    let bytes = flipped.manifest_bytes().unwrap();
    assert_eq!(
        cas_address_for_canonical_bytes(&bytes).hash().to_string(),
        "227c57852b0500676e4b6a27282e9cf3e2708142fdd2de553c03186c920b14e3"
    );
    assert_ne!(
        bytes,
        two_entry_manifest().manifest_bytes().unwrap(),
        "the execute bit is in the bytes, so it is in the identity"
    );
}

/// A TRUNCATED MEMBER IS A BYTE CHANGE. One byte off `README.md`'s `size_bytes`,
/// everything else identical — a distinct pinned address. `size_bytes` is what a
/// materializer bounds its read by, so a shorter member claiming the same length
/// must not be able to wear the same tree identity.
#[test]
fn a_truncated_member_size_is_pinned_to_a_different_address() {
    let truncated = TreeManifest::new(vec![
        entry("src/run.sh", TreeEntryMode::Executable, member(0xB2), 4_096),
        entry("README.md", TreeEntryMode::Regular, member(0xA1), 2_047),
    ])
    .unwrap();
    let bytes = truncated.manifest_bytes().unwrap();
    assert_eq!(
        cas_address_for_canonical_bytes(&bytes).hash().to_string(),
        "6495bffff9e7ca570cc33bc879794f2bcf3a0b2b3ebfa42785cc75dd1feaaf89"
    );
}
