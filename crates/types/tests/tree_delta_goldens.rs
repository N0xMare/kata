//! Pinned identity vectors for `kata_types::tree_delta`.
//!
//! The same role `tree_artifact_goldens.rs` plays for manifests: a `TreeDelta`'s
//! identity is the CAS address of `TreeDelta::delta_bytes`, so its serialized
//! shape is load-bearing — a field order, a rename, an `op` tag spelling all
//! rotate every delta id. A diff here means the delta family rotated: bump
//! [`TREE_DELTA_SCHEMA_VERSION`] and re-pin, or find the defect.
//!
//! The preimage is `cas_address_for_canonical_bytes`, the ONE spelling of the
//! CAS address — see `tree_artifact_goldens.rs`'s header for its citation.

use kata_types::cache::cas_address_for_canonical_bytes;
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
use kata_types::primitives::{FixedBytes, ObjectId};
use kata_types::tree_artifact::{
    SymlinkTarget, TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath,
};
use kata_types::tree_delta::{TREE_DELTA_SCHEMA_VERSION, TreeChange, TreeChangeKind, TreeDelta};

fn member(byte: u8) -> ObjectId {
    FixedBytes([byte; 32])
}

fn file(path: &str, object: ObjectId, size_bytes: u64) -> TreeEntry {
    TreeEntry {
        path: TreePath::new(path).expect("a valid tree path"),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object,
            size_bytes,
        },
    }
}

fn base_manifest() -> TreeManifest {
    TreeManifest::new(vec![
        file("README.md", member(0xA1), 2_048),
        file("gone.txt", member(0xC3), 9),
    ])
    .expect("the pinned base is valid")
}

fn base_reference() -> ArtifactRef {
    let bytes = base_manifest().manifest_bytes().unwrap();
    ArtifactRef::new(
        cas_address_for_canonical_bytes(&bytes).hash(),
        bytes.len() as u64,
        ArtifactPrivacy::Private,
    )
}

/// One delta carrying a write of every node kind plus a delete, SUPPLIED OUT OF
/// ORDER so the vector also witnesses that `new` sorts.
fn pinned_delta() -> TreeDelta {
    TreeDelta::new(
        base_reference(),
        vec![
            TreeChange {
                path: TreePath::new("README.md").unwrap(),
                change: TreeChangeKind::Write {
                    node: TreeNode::File {
                        mode: TreeEntryMode::Executable,
                        object: member(0xA1),
                        size_bytes: 2_048,
                    },
                },
            },
            TreeChange {
                path: TreePath::new("docs/manual").unwrap(),
                change: TreeChangeKind::Write {
                    node: TreeNode::Symlink {
                        target: SymlinkTarget::new("../README.md").unwrap(),
                    },
                },
            },
            TreeChange {
                path: TreePath::new("gone.txt").unwrap(),
                change: TreeChangeKind::Delete,
            },
        ],
    )
    .expect("the pinned delta is valid")
}

#[test]
fn schema_version_is_the_one_this_vector_was_pinned_under() {
    assert_eq!(TREE_DELTA_SCHEMA_VERSION, 1);
}

/// The exact canonical bytes, pinned as a STRING — the readable half of the
/// rotation witness: the `op` tags, the `node`/`change` field names and the
/// `base` reference's own encoding are all visible in it.
#[test]
fn the_canonical_bytes_of_a_pinned_delta_are_pinned() {
    let bytes = pinned_delta()
        .delta_bytes()
        .expect("the pinned delta serializes");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "{\"schema_version\":1,\"base\":{\"schema_version\":14,\
           \"id\":\"9c4b40095522eaf694fa40c62d315ba67407ac1a52097437fe7507a01c614eb9\",\
           \"object_id\":\"124c67e4cee004675fd413dbe079d15d4b0d3d0d02e7479e621253609df90ff5\",\
           \"size_bytes\":338,\"privacy\":\"private\"},\"changes\":[\
           {\"path\":\"README.md\",\"change\":{\"op\":\"write\",\"node\":{\"kind\":\"file\",\
            \"mode\":\"executable\",\
            \"object\":\"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\",\
            \"size_bytes\":2048}}},\
           {\"path\":\"docs/manual\",\"change\":{\"op\":\"write\",\"node\":{\"kind\":\"symlink\",\
            \"target\":\"../README.md\"}}},\
           {\"path\":\"gone.txt\",\"change\":{\"op\":\"delete\"}}]}"
    );
}

/// The CAS object id of those bytes — the delta's identity.
#[test]
fn the_cas_object_id_of_a_pinned_delta_is_pinned() {
    let bytes = pinned_delta().delta_bytes().unwrap();
    assert_eq!(
        cas_address_for_canonical_bytes(&bytes).hash().to_string(),
        "1be924e881393c76f26d3858484be61179e4e88a04e3cf83e4aa4d9cc4902ff0"
    );
}
