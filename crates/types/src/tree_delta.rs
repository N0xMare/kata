//! The versioned TREE DELTA — the typed difference between two tree artifacts,
//! named against the artifact it applies to.
//!
//! The `/work` loop publishes what a capsule CHANGED, not the tree again:
//! a worker materializes one input tree, the stage runs, and the worker reports
//! a [`TreeDelta`] — a sorted `path → {write(node) | delete}` list — bounded by
//! the change's size rather than the repo's. The main verifies the delta against
//! the very [`ArtifactRef`] the capsule's input carried ([`TreeDelta::apply`]
//! refuses any other base) and adopts the tree it produces.
//!
//! Like its sibling [`crate::tree_artifact`], nothing here performs I/O or opens
//! a CAS: these are pure types plus their refusals, so a delta can be built,
//! checked, published and refused with no store present. A delta's identity is
//! the CAS address of its canonical bytes, exactly as a manifest's is.
//!
//! # Canonicality — one delta per (base, result)
//!
//! [`TreeDelta::new`] sorts changes by path BYTES and refuses a duplicate path,
//! so the encoded order is a property of the content and not of the order a
//! differ happened to walk in. [`TreeDelta::between`] emits the MINIMAL delta —
//! only the paths that differ — and [`TreeDelta::apply`] refuses a delta that
//! carries a redundant change ([`TREE_DELTA_NOOP_WRITE`]) or a subtraction with
//! nothing to subtract ([`TREE_DELTA_DELETE_ABSENT`]), so two spellings of "the
//! same change to the same base" cannot produce two artifacts. Deleting a
//! directory is written as deletes of its files: directories are implied by
//! entry paths in a manifest, so a delta has no directory to name.

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{KataError, KataResult};
use crate::execution_contract::ArtifactRef;
use crate::tree_artifact::{TreeEntry, TreeManifest, TreeNode, TreePath};

/// Shape version of the tree delta.
///
/// Serialized into every delta and refused when foreign — the same discipline
/// as `kata_types::tree_artifact::TREE_MANIFEST_SCHEMA_VERSION`, for the same
/// reason: the delta's BYTES are its identity once addressed, so a bump rotates
/// every delta id by construction.
///
/// * v1 — the initial `base` + sorted `changes` shape.
pub const TREE_DELTA_SCHEMA_VERSION: u32 = 1;

/// The refusal token for a delta applied to a base its `base` reference does
/// not name: the object id of `base.manifest_bytes()` (or its length) is not
/// the reference's. A delta is only ever meaningful against ONE base, and
/// "close enough" is how a merge lands on the wrong tree.
pub const TREE_DELTA_BASE_MISMATCH: &str = "tree_delta_base_mismatch";

/// The refusal token for a `Delete` of a path the base does not carry. A
/// deletion with no subject is either a bug in the differ or a delta aimed at
/// another base; either way there is no canonical meaning to applying it.
pub const TREE_DELTA_DELETE_ABSENT: &str = "tree_delta_delete_absent";

/// The refusal token for a `Write` whose node equals the base's entry at that
/// path. A delta that re-states the base is a SECOND spelling of "no change at
/// this path" — and one delta per (base, result) is what keeps the artifact
/// id canonical.
pub const TREE_DELTA_NOOP_WRITE: &str = "tree_delta_noop_write";

/// The refusal token for a delta whose canonical encoding is over
/// [`TreeDelta::MAXIMUM_ENCODED_BYTES`].
pub const TREE_DELTA_OVER_CEILING: &str = "tree_delta_over_ceiling";

/// The refusal token for a [`TreeDelta::merge`] branch that names a different
/// base than the join's: branches over different bases have no shared truth to
/// merge against.
pub const TREE_DELTA_MERGE_FOREIGN_BASE: &str = "tree_delta_merge_foreign_base";

fn validation(message: String) -> KataError {
    KataError::Validation(message)
}

/// Refuse any `schema_version` other than [`TREE_DELTA_SCHEMA_VERSION`].
fn current_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != TREE_DELTA_SCHEMA_VERSION {
        return Err(serde::de::Error::custom(format!(
            "tree delta schema_version {version} is not supported; this build accepts only \
             {TREE_DELTA_SCHEMA_VERSION}"
        )));
    }
    Ok(version)
}

/// What one changed path becomes: written to a node, or deleted.
///
/// The serde tag is `op` and the arms spell `write` / `delete`, so a change
/// reads `{"path": "…", "change": {"op": "write", "node": {…}}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TreeChangeKind {
    /// The path names `node` in the result — added, or replacing whatever the
    /// base had there.
    Write {
        /// The node the path names after the delta applies.
        node: TreeNode,
    },
    /// The path is absent in the result. Whole-directory deletions are
    /// expressed as one `Delete` per FILE the directory held: a manifest has no
    /// directory entries (directories are implied by paths), so a delta has no
    /// directory to name.
    Delete,
}

/// One changed path in a [`TreeDelta`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeChange {
    /// The path the change applies to, relative to the root the tree is mapped
    /// at — the same [`TreePath`] a manifest entry carries.
    pub path: TreePath,
    /// Whether the path is written or deleted.
    pub change: TreeChangeKind,
}

/// A versioned, canonically ordered list of changes against ONE base artifact.
///
/// Built only through [`TreeDelta::new`], including on the deserialize path, so
/// a delta that reached this process as bytes is held to exactly the same
/// refusals as one built in memory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TreeDelta {
    schema_version: u32,
    base: ArtifactRef,
    changes: Vec<TreeChange>,
}

impl TreeDelta {
    /// The ceiling on a delta's own encoded bytes, for every reader AND every
    /// producer of one: [`TreeManifest::MAXIMUM_ENCODED_BYTES`]'s value, for its
    /// rationale — one change encodes like one manifest entry, and every reader
    /// of a delta (the main's adoption is the first) bounds its read at the same
    /// ceiling so no producer can emit a delta no reader loads.
    pub const MAXIMUM_ENCODED_BYTES: u64 = TreeManifest::MAXIMUM_ENCODED_BYTES;

    /// Build a delta, sorting the changes by path BYTES and refusing a
    /// duplicate path.
    ///
    /// ONE CANONICAL ORDER, for [`TreeManifest::new`]'s reason stated there:
    /// the delta's bytes are its identity once addressed, so two callers that
    /// collected the same changes in different orders must publish the SAME
    /// artifact.
    ///
    /// # Failure
    ///
    /// * an entry whose path [`TreePath::new`] refuses (that type's own refused
    ///   set; the deserialize path goes through it too);
    /// * a DUPLICATE path: which of two changes for one path applies would be an
    ///   invented answer, and a delta whose meaning depends on list order would
    ///   not be one artifact.
    ///
    /// An EMPTY change list is accepted — it is the answer `between` gives for
    /// two identical trees, and refusing it would force a caller to invent a
    /// no-op to carry.
    pub fn new(base: ArtifactRef, mut changes: Vec<TreeChange>) -> KataResult<Self> {
        changes.sort_by(|left, right| {
            left.path
                .as_str()
                .as_bytes()
                .cmp(right.path.as_str().as_bytes())
        });
        let mut previous: Option<&str> = None;
        for change in &changes {
            let path = change.path.as_str();
            if previous == Some(path) {
                return Err(validation(format!(
                    "tree delta refused: path {path:?} appears more than once, and which change \
                     applies would be an invented answer"
                )));
            }
            previous = Some(path);
        }
        Ok(Self {
            schema_version: TREE_DELTA_SCHEMA_VERSION,
            base,
            changes,
        })
    }

    /// The MINIMAL canonical delta between `base` and `result`, named against
    /// `base_ref` — which must BE `base`'s reference, or the delta it emits is
    /// one [`Self::apply`] could never accept.
    ///
    /// Every path in `result` whose node differs from the base's (or that the
    /// base does not carry) becomes a [`TreeChangeKind::Write`]; every path in
    /// `base` that `result` does not carry becomes a [`TreeChangeKind::Delete`].
    /// Nothing else is emitted: a mode flip is a write, a file becoming a
    /// symlink is a write, and a removed directory's files are one delete each.
    ///
    /// # Failure
    ///
    /// [`TREE_DELTA_BASE_MISMATCH`] when `base_ref` does not name `base`'s
    /// canonical bytes — the same check [`Self::apply`] runs, moved forward so
    /// the artifact is unconstructible rather than merely refused later.
    pub fn between(
        base_ref: ArtifactRef,
        base: &TreeManifest,
        result: &TreeManifest,
    ) -> KataResult<Self> {
        refuse_base_mismatch(&base_ref, base)?;
        let base_nodes: std::collections::HashMap<&str, &TreeNode> = base
            .entries()
            .iter()
            .map(|entry| (entry.path.as_str(), &entry.node))
            .collect();
        let mut changes = Vec::new();
        for entry in result.entries() {
            if base_nodes.get(entry.path.as_str()) != Some(&&entry.node) {
                changes.push(TreeChange {
                    path: entry.path.clone(),
                    change: TreeChangeKind::Write {
                        node: entry.node.clone(),
                    },
                });
            }
        }
        let result_paths: std::collections::HashSet<&str> = result
            .entries()
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        for entry in base.entries() {
            if !result_paths.contains(entry.path.as_str()) {
                changes.push(TreeChange {
                    path: entry.path.clone(),
                    change: TreeChangeKind::Delete,
                });
            }
        }
        Self::new(base_ref, changes)
    }

    /// Apply this delta to `base`, producing the manifest it encodes.
    ///
    /// # Failure — the refused set, stated exactly
    ///
    /// * [`TREE_DELTA_BASE_MISMATCH`] — `base`'s canonical bytes do not address
    ///   to this delta's `base` reference (object id AND length are compared,
    ///   with the same function the CAS uses to address bytes);
    /// * [`TREE_DELTA_DELETE_ABSENT`] — a `Delete` of a path the base does not
    ///   carry;
    /// * [`TREE_DELTA_NOOP_WRITE`] — a `Write` whose node equals the base's own
    ///   entry at that path;
    /// * [`TreeManifest::new`]'s own refusals over the result — e.g. a prefix
    ///   conflict from writing `a` where the base still carries `a/b`.
    ///
    /// Nothing else. A `Write` to a path beneath nothing the base holds is an
    /// ordinary addition; a `Delete` that empties a directory needs no
    /// directory delete, because a manifest has no directory to name.
    pub fn apply(&self, base: &TreeManifest) -> KataResult<TreeManifest> {
        refuse_base_mismatch(&self.base, base)?;
        let mut nodes: std::collections::BTreeMap<TreePath, TreeNode> = base
            .entries()
            .iter()
            .map(|entry| (entry.path.clone(), entry.node.clone()))
            .collect();
        for change in &self.changes {
            match &change.change {
                TreeChangeKind::Delete => {
                    if nodes.remove(&change.path).is_none() {
                        return Err(validation(format!(
                            "tree delta refused: {TREE_DELTA_DELETE_ABSENT}: {:?} is deleted but \
                             the base carries no such path. A deletion with no subject is a delta \
                             aimed at another base or a differ that invented one",
                            change.path.as_str()
                        )));
                    }
                }
                TreeChangeKind::Write { node } => {
                    if nodes.get(&change.path) == Some(node) {
                        return Err(validation(format!(
                            "tree delta refused: {TREE_DELTA_NOOP_WRITE}: {:?} is written with the \
                             node the base already carries. One delta per (base, result) is what \
                             keeps the artifact id canonical, and this change re-states the base",
                            change.path.as_str()
                        )));
                    }
                    nodes.insert(change.path.clone(), node.clone());
                }
            }
        }
        TreeManifest::new(
            nodes
                .into_iter()
                .map(|(path, node)| TreeEntry { path, node })
                .collect(),
        )
    }

    /// Merge several branches' deltas — each against the SAME `base` — into one
    /// delta: the join for parallel `/work` branches.
    ///
    /// Order-independent and never clobbering: two branches writing the same
    /// node to the same path merge to one change, while two DIFFERENT changes
    /// to one path (write/write, write/delete) are a conflict — there is no
    /// ordering that picks a winner without inventing content. A union that
    /// merges cleanly per-path is then validated against `base` so structural
    /// impossibilities a per-path view cannot see — branch A writing file `a`
    /// where branch B writes `a/b`, say — surface as conflicts too, named on
    /// both paths.
    ///
    /// # Failure and the conflict report
    ///
    /// * A branch whose [`Self::base`] is not `base_ref` is refused
    ///   [`TREE_DELTA_MERGE_FOREIGN_BASE`], naming the branch — a typed refusal,
    ///   not a merge conflict.
    /// * Otherwise the answer is `Ok(Err(conflict))` listing EVERY contested
    ///   path with its touching branches (sorted), plus any structural
    ///   conflict found in the union.
    ///
    /// Zero branches merge to the empty delta against `base_ref`; one branch
    /// merges to itself.
    pub fn merge(
        base_ref: &ArtifactRef,
        base: &TreeManifest,
        branches: &[(BranchLabel, &TreeDelta)],
    ) -> KataResult<Result<TreeDelta, TreeDeltaMergeConflict>> {
        for (label, delta) in branches {
            if delta.base() != base_ref {
                return Err(validation(format!(
                    "tree delta refused: {TREE_DELTA_MERGE_FOREIGN_BASE}: branch {label:?}'s delta \
                     names base {} ({} bytes), not the join's {} ({} bytes). Merging deltas off \
                     different bases would land whichever wrote last",
                    delta.base().object_id(),
                    delta.base().size_bytes(),
                    base_ref.object_id(),
                    base_ref.size_bytes(),
                )));
            }
        }
        if branches.is_empty() {
            return Ok(Ok(Self::new(base_ref.clone(), Vec::new())?));
        }
        if let [(_, delta)] = branches {
            // Validate it against the same base the union path would, then hand
            // the delta back unchanged — one branch is its own merge.
            delta.apply(base)?;
            return Ok(Ok((*delta).clone()));
        }

        // Union per path: identical changes collapse, disagreeing ones collect
        // every branch that touched the path.
        let mut by_path: std::collections::BTreeMap<
            &TreePath,
            Vec<(BranchLabel, &TreeChangeKind)>,
        > = std::collections::BTreeMap::new();
        for (label, delta) in branches {
            for change in delta.changes() {
                by_path
                    .entry(&change.path)
                    .or_default()
                    .push((label.clone(), &change.change));
            }
        }
        let mut union: Vec<TreeChange> = Vec::new();
        let mut contested: Vec<(TreePath, Vec<BranchLabel>)> = Vec::new();
        for (path, touches) in &by_path {
            let mut branches_at: Vec<BranchLabel> =
                touches.iter().map(|(label, _)| label.clone()).collect();
            branches_at.sort();
            branches_at.dedup();
            let first = touches[0].1;
            if touches.iter().all(|(_, kind)| *kind == first) {
                union.push(TreeChange {
                    path: (*path).clone(),
                    change: (*first).clone(),
                });
            } else {
                contested.push(((*path).clone(), branches_at));
            }
        }
        if !contested.is_empty() {
            return Ok(Err(TreeDeltaMergeConflict {
                paths: contested,
                structural: None,
            }));
        }

        // Structural: no two surviving paths may stand in a file-of-dir
        // relation — a write or a retained base entry at `p` forbids a write at
        // `p/…`. Compute the result path set the same way `apply` does, so the
        // conflict names what would refuse rather than refusing blindly.
        let deleted: std::collections::HashSet<&str> = union
            .iter()
            .filter(|c| c.change == TreeChangeKind::Delete)
            .map(|c| c.path.as_str())
            .collect();
        let written: std::collections::HashMap<&str, Vec<BranchLabel>> = union
            .iter()
            .filter_map(|c| match &c.change {
                TreeChangeKind::Write { .. } => Some((
                    c.path.as_str(),
                    by_path
                        .get(&c.path)
                        .map(|t| {
                            let mut l: Vec<BranchLabel> =
                                t.iter().map(|(l, _)| l.clone()).collect();
                            l.sort();
                            l.dedup();
                            l
                        })
                        .unwrap_or_default(),
                )),
                TreeChangeKind::Delete => None,
            })
            .collect();
        let mut result_paths: std::collections::BTreeSet<&str> = base
            .entries()
            .iter()
            .map(|entry| entry.path.as_str())
            .filter(|path| !deleted.contains(*path))
            .collect();
        result_paths.extend(union.iter().filter_map(|c| match &c.change {
            TreeChangeKind::Write { .. } => Some(c.path.as_str()),
            TreeChangeKind::Delete => None,
        }));
        // For each result path, each '/'-separated ancestor prefix that is ALSO
        // a result path is a structural conflict on the pair.
        let mut structural: Option<String> = None;
        let mut structural_paths: Vec<(TreePath, Vec<BranchLabel>)> = Vec::new();
        for path in &result_paths {
            for (offset, _) in path.char_indices().filter(|(_, byte)| *byte == '/') {
                let prefix = &path[..offset];
                if result_paths.contains(prefix) {
                    structural = Some(format!(
                        "path {prefix:?} is a FILE (or symlink) and path {path:?} lives under it — \
                         the merged tree cannot hold both"
                    ));
                    for involved in [prefix, *path] {
                        let labels = written.get(involved).cloned().unwrap_or_default();
                        let tp = TreePath::new(involved)?;
                        if !structural_paths.iter().any(|(p, _)| p == &tp) {
                            structural_paths.push((tp, labels));
                        }
                    }
                }
            }
        }
        if structural.is_some() {
            structural_paths.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
            return Ok(Err(TreeDeltaMergeConflict {
                paths: structural_paths,
                structural,
            }));
        }

        let merged = Self::new(base_ref.clone(), union)?;
        // The spec's final validator: apply against the real base so any
        // residual refusal (a malformed member delta, say) is the delta's own
        // typed refusal, not silently a merge answer.
        merged.apply(base)?;
        Ok(Ok(merged))
    }

    /// The base artifact this delta applies to.
    #[must_use]
    pub fn base(&self) -> &ArtifactRef {
        &self.base
    }

    /// The changes, sorted by path bytes, at most one per path.
    #[must_use]
    pub fn changes(&self) -> &[TreeChange] {
        &self.changes
    }

    /// Canonical bytes for CAS publication — and, addressed, the delta's
    /// identity. [`TreeManifest::manifest_bytes`]'s argument applies unchanged:
    /// `serde_json` emits fields in declaration order and `changes` is in its
    /// canonical order by construction, so there is no re-canonicalization step
    /// to drift from `new`.
    ///
    /// # Failure
    ///
    /// [`TREE_DELTA_OVER_CEILING`] (a `KataError::Validation`) when the encoding
    /// is longer than [`Self::MAXIMUM_ENCODED_BYTES`], and a
    /// `KataError::Serialization` if `serde_json` fails, which it cannot for
    /// this type.
    pub fn delta_bytes(&self) -> KataResult<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|error| {
            KataError::Serialization(format!("tree delta does not serialize: {error}"))
        })?;
        if bytes.len() as u64 > Self::MAXIMUM_ENCODED_BYTES {
            return Err(validation(format!(
                "tree delta refused: {TREE_DELTA_OVER_CEILING}: its {} changes encode to {} bytes \
                 and TreeDelta::MAXIMUM_ENCODED_BYTES is {}. Every reader of a tree delta bounds \
                 its read there, so these bytes would name a delta no reader can load",
                self.changes.len(),
                bytes.len(),
                Self::MAXIMUM_ENCODED_BYTES
            )));
        }
        Ok(bytes)
    }
}

/// The ONE comparison of a manifest against the reference that claims to name
/// it, shared by [`TreeDelta::between`] and [`TreeDelta::apply`]. The object id
/// is computed with `object_id_for_canonical_bytes` — the same function the CAS
/// uses to address bytes — and the LENGTH is compared too, because
/// `ArtifactRef` folds a size and a reference that gets the wrong length is a
/// different reference.
fn refuse_base_mismatch(reference: &ArtifactRef, base: &TreeManifest) -> KataResult<()> {
    let bytes = base.manifest_bytes()?;
    let object = crate::cache::object_id_for_canonical_bytes(&bytes);
    if object != reference.object_id() || bytes.len() as u64 != reference.size_bytes() {
        return Err(validation(format!(
            "tree delta refused: {TREE_DELTA_BASE_MISMATCH}: the delta names base object {} ({} \
             bytes) but the manifest handed over addresses to {object} ({} bytes). A delta is only \
             meaningful against the ONE base it names — applying it to another is a merge onto the \
             wrong tree",
            reference.object_id(),
            reference.size_bytes(),
            bytes.len()
        )));
    }
    Ok(())
}

/// A branch's name in a merge conflict report — the stage id that produced its
/// delta, or whatever label the join's caller speaks in.
pub type BranchLabel = smol_str::SmolStr;

/// What [`TreeDelta::merge`] reports when branches cannot be joined — every
/// contested path with the branches that touched it, plus the structural
/// conflict description when the union's paths cannot coexist in one tree
/// (a file and a path beneath it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeDeltaMergeConflict {
    /// Every contested path and the branches whose changes touched it, sorted
    /// by path. A structural pair appears here too — an entry with no labels
    /// names a path the BASE still carries (no branch changed it).
    pub paths: Vec<(TreePath, Vec<BranchLabel>)>,
    /// The structural refusal of the merged union, if the per-path merge was
    /// clean but the result tree is impossible.
    pub structural: Option<String>,
}

/// Raw mirror of [`TreeDelta`]: deserialization re-runs [`TreeDelta::new`] over
/// the body, so a forged delta — an unsorted change list, a duplicate path — is
/// refused rather than trusted. The same discipline as
/// [`crate::tree_artifact::TreeManifest`]'s raw mirror.
#[derive(Deserialize)]
struct TreeDeltaRaw {
    /// Read only to refuse a foreign version: `current_schema_version` rejects
    /// anything but this build's, so the value itself is never needed.
    #[serde(rename = "schema_version", deserialize_with = "current_schema_version")]
    _schema_version: u32,
    base: ArtifactRef,
    changes: Vec<TreeChange>,
}

impl<'de> Deserialize<'de> for TreeDelta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = TreeDeltaRaw::deserialize(deserializer)?;
        Self::new(raw.base, raw.changes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_contract::ArtifactPrivacy;
    use crate::primitives::FixedBytes;
    use crate::tree_artifact::TreeEntryMode;

    fn object(byte: u8) -> crate::primitives::ObjectId {
        FixedBytes([byte; 32])
    }

    fn file(path: &str, member: u8, size_bytes: u64) -> TreeEntry {
        TreeEntry {
            path: TreePath::new(path).expect("an accepted path"),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: object(member),
                size_bytes,
            },
        }
    }

    fn exe(path: &str, member: u8, size_bytes: u64) -> TreeEntry {
        TreeEntry {
            path: TreePath::new(path).expect("an accepted path"),
            node: TreeNode::File {
                mode: TreeEntryMode::Executable,
                object: object(member),
                size_bytes,
            },
        }
    }

    fn link(path: &str, target: &str) -> TreeEntry {
        TreeEntry {
            path: TreePath::new(path).expect("an accepted path"),
            node: TreeNode::Symlink {
                target: crate::tree_artifact::SymlinkTarget::new(target)
                    .expect("an accepted target"),
            },
        }
    }

    /// The reference a manifest's canonical bytes address to — the same way a
    /// publisher's `ArtifactRef` is minted over them.
    fn reference(manifest: &TreeManifest) -> ArtifactRef {
        let bytes = manifest.manifest_bytes().unwrap();
        ArtifactRef::new(
            crate::cache::object_id_for_canonical_bytes(&bytes),
            bytes.len() as u64,
            ArtifactPrivacy::Private,
        )
    }

    fn manifest(entries: Vec<TreeEntry>) -> TreeManifest {
        TreeManifest::new(entries).expect("a valid manifest")
    }

    fn write(path: &str, entry: &TreeEntry) -> TreeChange {
        TreeChange {
            path: TreePath::new(path).unwrap(),
            change: TreeChangeKind::Write {
                node: entry.node.clone(),
            },
        }
    }

    fn delete(path: &str) -> TreeChange {
        TreeChange {
            path: TreePath::new(path).unwrap(),
            change: TreeChangeKind::Delete,
        }
    }

    #[test]
    fn new_sorts_changes_by_path_bytes() {
        let base = manifest(vec![file("a", 1, 1)]);
        let delta = TreeDelta::new(
            reference(&base),
            vec![
                write("b", &file("b", 2, 2)),
                delete("a"),
                write("a!x", &file("a!x", 3, 3)),
            ],
        )
        .unwrap();
        assert_eq!(
            delta
                .changes()
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "a!x", "b"],
            "byte order: `!` (0x21) sorts before `/` would, and `a` before both"
        );
    }

    #[test]
    fn new_is_order_independent() {
        let base = manifest(vec![file("a", 1, 1)]);
        let base_ref = reference(&base);
        let first = TreeDelta::new(
            base_ref.clone(),
            vec![write("x", &file("x", 2, 2)), delete("a")],
        )
        .unwrap();
        let second =
            TreeDelta::new(base_ref, vec![delete("a"), write("x", &file("x", 2, 2))]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.delta_bytes().unwrap(), second.delta_bytes().unwrap());
    }

    #[test]
    fn new_refuses_a_duplicate_path() {
        let base = manifest(vec![file("a", 1, 1)]);
        let error = TreeDelta::new(reference(&base), vec![delete("a"), delete("a")])
            .expect_err("a duplicate path must be refused");
        assert!(error.to_string().contains("more than once"), "{error}");
    }

    /// `between` then `apply` is the identity on the result — the round-trip
    /// every wave-3 publisher and main-side adopter rely on — over hand-built
    /// pairs covering add, modify, delete, mode-flip, file→symlink and
    /// directory→file.
    #[test]
    fn between_then_apply_round_trips_to_the_result() {
        let cases: Vec<(TreeManifest, TreeManifest)> = vec![
            // Add only.
            (
                manifest(vec![file("a", 1, 1)]),
                manifest(vec![file("a", 1, 1), file("b", 2, 2)]),
            ),
            // Modify (object and size both move) plus a delete.
            (
                manifest(vec![file("a", 1, 1), file("gone", 3, 3)]),
                manifest(vec![file("a", 9, 9)]),
            ),
            // A mode flip is a write of the same object.
            (
                manifest(vec![file("run.sh", 4, 44)]),
                manifest(vec![exe("run.sh", 4, 44)]),
            ),
            // File → symlink and symlink → file.
            (
                manifest(vec![file("link", 5, 5), link("other", "/x")]),
                manifest(vec![link("link", "../../outside"), file("other", 6, 6)]),
            ),
            // A directory's files deleted and the path written as a FILE —
            // directory deletion is expressed as deletes of its files.
            (
                manifest(vec![file("dir/a", 7, 1), file("dir/b", 7, 2)]),
                manifest(vec![file("dir", 8, 8)]),
            ),
            // The reverse: a file becomes a directory of files.
            (
                manifest(vec![file("dir", 8, 8)]),
                manifest(vec![file("dir/a", 7, 1), file("dir/b", 7, 2)]),
            ),
            // Everything deleted.
            (manifest(vec![file("a", 1, 1)]), manifest(Vec::new())),
            // Everything added onto an empty base.
            (manifest(Vec::new()), manifest(vec![link("l", "/abs")])),
        ];
        for (index, (base, result)) in cases.iter().enumerate() {
            let delta = TreeDelta::between(reference(base), base, result)
                .unwrap_or_else(|error| panic!("case {index}: between refused: {error}"));
            let applied = delta
                .apply(base)
                .unwrap_or_else(|error| panic!("case {index}: apply refused: {error}"));
            assert_eq!(&applied, result, "case {index}: round-trip");
            // Minimal BY CONSTRUCTION: applying the delta to its OWN result must
            // refuse — every change it carries is either a noop write or a
            // delete of an absent path against the result it produced.
            assert!(
                delta.apply(&applied).is_err(),
                "case {index}: a delta re-applied to its own result must refuse \
                 (delete-absent or noop-write), not re-apply"
            );
        }
    }

    #[test]
    fn between_identical_manifests_is_empty() {
        let manifest = manifest(vec![file("a", 1, 1), link("l", "../x")]);
        let delta = TreeDelta::between(reference(&manifest), &manifest, &manifest).unwrap();
        assert!(delta.changes().is_empty());
        // And the empty delta applies as the identity.
        assert_eq!(delta.apply(&manifest).unwrap(), manifest);
    }

    #[test]
    fn apply_refuses_a_base_the_delta_does_not_name() {
        let base = manifest(vec![file("a", 1, 1)]);
        let other = manifest(vec![file("a", 2, 2)]);
        let delta =
            TreeDelta::between(reference(&base), &base, &manifest(vec![file("b", 3, 3)])).unwrap();
        let error = delta
            .apply(&other)
            .expect_err("a delta applied to a base it does not name must be refused");
        assert!(
            error.to_string().contains(TREE_DELTA_BASE_MISMATCH),
            "{error}"
        );
        // A forged base reference is refused the same way at `between`.
        let forged = reference(&other);
        let error = TreeDelta::between(forged, &base, &manifest(vec![file("b", 3, 3)]))
            .expect_err("a base ref that does not name the manifest must be refused");
        assert!(
            error.to_string().contains(TREE_DELTA_BASE_MISMATCH),
            "{error}"
        );
    }

    #[test]
    fn apply_refuses_a_delete_of_an_absent_path() {
        let base = manifest(vec![file("a", 1, 1)]);
        let delta = TreeDelta::new(reference(&base), vec![delete("absent")]).unwrap();
        let error = delta
            .apply(&base)
            .expect_err("deleting a path the base does not carry must be refused");
        assert!(
            error.to_string().contains(TREE_DELTA_DELETE_ABSENT),
            "{error}"
        );
    }

    #[test]
    fn apply_refuses_a_write_that_restates_the_base() {
        let base = manifest(vec![file("a", 1, 1), link("l", "/x")]);
        for change in [write("a", &file("a", 1, 1)), write("l", &link("l", "/x"))] {
            let delta = TreeDelta::new(reference(&base), vec![change]).unwrap();
            let error = delta
                .apply(&base)
                .expect_err("a write equal to the base's entry must be refused");
            assert!(error.to_string().contains(TREE_DELTA_NOOP_WRITE), "{error}");
        }
    }

    /// Writing `a` where the base still carries `a/b` produces a manifest
    /// `TreeManifest::new` itself refuses — the leaf rule surfaces through
    /// `apply`, not through a second check.
    #[test]
    fn apply_propagates_the_manifests_own_refusals() {
        let base = manifest(vec![file("a/b", 1, 1)]);
        let delta = TreeDelta::new(reference(&base), vec![write("a", &file("a", 2, 2))]).unwrap();
        let error = delta
            .apply(&base)
            .expect_err("a file written over a live directory must be refused");
        assert!(error.to_string().contains("lives under it"), "{error}");
        // Deleting `a/b` in the same delta makes it apply.
        let delta = TreeDelta::new(
            reference(&base),
            vec![delete("a/b"), write("a", &file("a", 2, 2))],
        )
        .unwrap();
        assert_eq!(delta.apply(&base).unwrap(), manifest(vec![file("a", 2, 2)]));
    }

    #[test]
    fn a_delta_deserializes_through_its_constructor() {
        let base = manifest(vec![file("a", 1, 1)]);
        let delta = TreeDelta::new(
            reference(&base),
            vec![write("b", &file("b", 2, 2)), delete("a")],
        )
        .unwrap();
        let bytes = delta.delta_bytes().unwrap();
        assert_eq!(serde_json::from_slice::<TreeDelta>(&bytes).unwrap(), delta);

        // An unsorted change list comes back SORTED; a duplicate is refused.
        let unsorted = serde_json::json!({
            "schema_version": TREE_DELTA_SCHEMA_VERSION,
            "base": serde_json::to_value(delta.base()).unwrap(),
            "changes": [
                {"path": "b", "change": {"op": "write", "node": file("b", 2, 2).node}},
                {"path": "a", "change": {"op": "delete"}},
            ],
        });
        assert_eq!(
            serde_json::from_value::<TreeDelta>(unsorted).unwrap(),
            delta
        );
        let duplicated = serde_json::json!({
            "schema_version": TREE_DELTA_SCHEMA_VERSION,
            "base": serde_json::to_value(delta.base()).unwrap(),
            "changes": [
                {"path": "a", "change": {"op": "delete"}},
                {"path": "a", "change": {"op": "delete"}},
            ],
        });
        assert!(serde_json::from_value::<TreeDelta>(duplicated).is_err());
    }

    #[test]
    fn a_foreign_schema_version_is_refused() {
        let base = manifest(Vec::new());
        let delta = TreeDelta::new(reference(&base), Vec::new()).unwrap();
        let mut value = serde_json::to_value(&delta).unwrap();
        value["schema_version"] = serde_json::json!(TREE_DELTA_SCHEMA_VERSION + 1);
        let error = serde_json::from_value::<TreeDelta>(value)
            .expect_err("a foreign schema version must be refused");
        assert!(error.to_string().contains("is not supported"), "{error}");
    }

    /// The encoder refuses a delta no reader can load, by name — the same door
    /// `TreeManifest::manifest_bytes` keeps.
    #[test]
    fn delta_bytes_refuses_an_encoding_over_the_ceiling_by_name() {
        let long = |index: usize| TreeChange {
            path: TreePath::new(format!("{index:05}{}", "p".repeat(3_800))).unwrap(),
            change: TreeChangeKind::Delete,
        };
        let base = manifest(Vec::new());
        // ~3.8 KB of path per change × 20 000 ≈ 77 MB — over the 64 MiB
        // encoding ceiling the manifest and delta share.
        let over = TreeDelta::new(reference(&base), (0..20_000).map(long).collect()).unwrap();
        let measured = serde_json::to_vec(&over).unwrap().len() as u64;
        assert!(
            measured > TreeDelta::MAXIMUM_ENCODED_BYTES,
            "the premise: {measured} bytes"
        );
        let Err(refusal) = over.delta_bytes() else {
            panic!("an encoding over the ceiling is refused, and it was encoded");
        };
        let refusal = refusal.to_string();
        assert!(refusal.contains(TREE_DELTA_OVER_CEILING), "{refusal}");
        assert!(refusal.contains(&measured.to_string()), "{refusal}");

        let under = TreeDelta::new(reference(&base), (0..4_000).map(long).collect()).unwrap();
        let bytes = under.delta_bytes().expect("inside the ceiling encodes");
        assert!(bytes.len() as u64 <= TreeDelta::MAXIMUM_ENCODED_BYTES);
        assert_eq!(bytes, serde_json::to_vec(&under).unwrap());
    }

    /// The ceiling is `>` — a delta whose encoding lands EXACTLY on
    /// `MAXIMUM_ENCODED_BYTES` is inside every reader's bound and must encode.
    /// Every change encodes `"path":"<fixed>+<pad>"`, so the total length is
    /// affine in the pad width; one measurement solves for it.
    #[test]
    fn delta_bytes_encodes_an_encoding_at_the_ceiling() {
        let base = manifest(Vec::new());
        const N: usize = 17_500;
        let delta = |pad: usize, extra: usize| -> TreeDelta {
            TreeDelta::new(
                reference(&base),
                (0..N)
                    .map(|index| TreeChange {
                        path: TreePath::new(format!(
                            "{index:05}{}",
                            "p".repeat(pad + if index == 0 { extra } else { 0 })
                        ))
                        .unwrap(),
                        change: TreeChangeKind::Delete,
                    })
                    .collect(),
            )
            .unwrap()
        };
        let measured = |pad: usize| serde_json::to_vec(&delta(pad, 0)).unwrap().len() as u64;
        let base_len = measured(0);
        assert!(
            base_len < TreeDelta::MAXIMUM_ENCODED_BYTES,
            "premise: {base_len}"
        );
        let deficit = usize::try_from(TreeDelta::MAXIMUM_ENCODED_BYTES - base_len)
            .expect("the deficit fits usize on a 64-bit host");
        // deficit bytes split as pad-per-change + a one-byte remainder on the
        // first `extra` paths (TreePath's 4096-byte cap forbids piling the
        // remainder onto one path).
        let (pad, extra) = (deficit / N, deficit % N);
        assert!(
            pad < 4_096,
            "premise: the pad width must fit inside a TreePath, got {pad}"
        );
        let delta_at = TreeDelta::new(
            reference(&base),
            (0..N)
                .map(|index| TreeChange {
                    path: TreePath::new(format!(
                        "{index:05}{}",
                        "p".repeat(pad + usize::from(index < extra))
                    ))
                    .unwrap(),
                    change: TreeChangeKind::Delete,
                })
                .collect(),
        )
        .unwrap();
        let at = delta_at;
        let bytes = at
            .delta_bytes()
            .expect("an encoding AT the ceiling is still loadable");
        assert_eq!(bytes.len() as u64, TreeDelta::MAXIMUM_ENCODED_BYTES);
    }

    /// A `Write` to a path the base never held is an ordinary add — inside the
    /// accepted set, stated so the refused set above cannot quietly widen.
    #[test]
    fn apply_accepts_a_write_of_a_new_path() {
        let base = manifest(vec![file("a", 1, 1)]);
        let delta = TreeDelta::new(
            reference(&base),
            vec![write("b", &link("b", "/etc/passwd"))],
        )
        .unwrap();
        assert_eq!(
            delta.apply(&base).unwrap(),
            manifest(vec![file("a", 1, 1), link("b", "/etc/passwd")])
        );
    }

    fn branch(
        label: &str,
        base_ref: &ArtifactRef,
        changes: Vec<TreeChange>,
    ) -> (BranchLabel, TreeDelta) {
        (
            BranchLabel::from(label),
            TreeDelta::new(base_ref.clone(), changes).unwrap(),
        )
    }

    /// Disjoint branches merge into the union delta, order-independently.
    #[test]
    fn disjoint_branches_merge() {
        let base = manifest(vec![file("keep.txt", 1, 4), file("rm.txt", 2, 4)]);
        let base_ref = reference(&base);
        let (la, da) = branch(
            "a",
            &base_ref,
            vec![write("a.txt", &file("a.txt", 10, 2)), delete("rm.txt")],
        );
        let (lb, db) = branch("b", &base_ref, vec![write("b.txt", &file("b.txt", 11, 2))]);
        let merged = TreeDelta::merge(&base_ref, &base, &[(la, &da), (lb, &db)])
            .unwrap()
            .unwrap();
        let result = merged.apply(&base).unwrap();
        assert_eq!(
            result
                .entries()
                .iter()
                .map(|e| e.path.as_str().to_string())
                .collect::<Vec<_>>(),
            vec!["a.txt", "b.txt", "keep.txt"],
            "the merged tree is the union: added paths present, deleted absent"
        );
    }

    /// Identical changes from two branches collapse to one — the merge is not
    /// a conflict just because two branches touched a path.
    #[test]
    fn identical_changes_merge_to_one() {
        let base = manifest(vec![file("keep.txt", 1, 4)]);
        let base_ref = reference(&base);
        let node = file("shared.txt", 9, 2);
        let (la, da) = branch("a", &base_ref, vec![write("shared.txt", &node)]);
        let (lb, db) = branch("b", &base_ref, vec![write("shared.txt", &node)]);
        let merged = TreeDelta::merge(&base_ref, &base, &[(la, &da), (lb, &db)])
            .unwrap()
            .unwrap();
        assert_eq!(merged.changes().len(), 1);
        assert_eq!(merged.changes()[0].path.as_str(), "shared.txt");
    }

    /// Two different writes to one path are a conflict naming both branches.
    #[test]
    fn write_write_conflict_names_every_branch() {
        let base = manifest(vec![file("keep.txt", 1, 4)]);
        let base_ref = reference(&base);
        let (la, da) = branch("a", &base_ref, vec![write("x.txt", &file("x.txt", 10, 2))]);
        let (lb, db) = branch("b", &base_ref, vec![write("x.txt", &file("x.txt", 11, 2))]);
        let conflict = TreeDelta::merge(&base_ref, &base, &[(lb, &db), (la, &da)])
            .unwrap()
            .unwrap_err();
        assert_eq!(conflict.structural, None);
        assert_eq!(conflict.paths.len(), 1);
        assert_eq!(conflict.paths[0].0.as_str(), "x.txt");
        assert_eq!(
            conflict.paths[0].1,
            vec![BranchLabel::from("a"), BranchLabel::from("b")],
            "both branches named, sorted — the input order does not leak"
        );
    }

    /// A write against a delete of the same path conflicts.
    #[test]
    fn write_delete_conflict() {
        let base = manifest(vec![file("victim.txt", 1, 4)]);
        let base_ref = reference(&base);
        let (la, da) = branch("a", &base_ref, vec![delete("victim.txt")]);
        let (lb, db) = branch(
            "b",
            &base_ref,
            vec![write("victim.txt", &file("victim.txt", 7, 2))],
        );
        let conflict = TreeDelta::merge(&base_ref, &base, &[(la, &da), (lb, &db)])
            .unwrap()
            .unwrap_err();
        assert_eq!(conflict.paths.len(), 1);
        assert_eq!(conflict.paths[0].0.as_str(), "victim.txt");
        assert_eq!(conflict.paths[0].1.len(), 2);
    }

    /// Branch A writes file `a`; branch B writes `a/b` — the union cannot be a
    /// manifest. A STRUCTURAL conflict, found by checking the result path set,
    /// naming both involved paths and their writing branches.
    #[test]
    fn file_vs_dir_is_a_structural_conflict() {
        let base = manifest(vec![file("keep.txt", 1, 4)]);
        let base_ref = reference(&base);
        let (la, da) = branch("a", &base_ref, vec![write("a", &file("a", 10, 2))]);
        let (lb, db) = branch("b", &base_ref, vec![write("a/b", &file("a/b", 11, 2))]);
        let conflict = TreeDelta::merge(&base_ref, &base, &[(la, &da), (lb, &db)])
            .unwrap()
            .unwrap_err();
        assert!(conflict.structural.is_some(), "a structural note is owed");
        assert_eq!(conflict.paths.len(), 2);
        assert_eq!(conflict.paths[0].0.as_str(), "a");
        assert_eq!(conflict.paths[0].1, vec![BranchLabel::from("a")]);
        assert_eq!(conflict.paths[1].0.as_str(), "a/b");
        assert_eq!(conflict.paths[1].1, vec![BranchLabel::from("b")]);
    }

    /// A write at a path the BASE still carries a subtree under conflicts too —
    /// the retained base path appears with no branch label.
    #[test]
    fn a_write_over_a_retained_base_dir_is_structural() {
        let base = manifest(vec![file("d/inner.txt", 1, 4)]);
        let base_ref = reference(&base);
        let (la, da) = branch("a", &base_ref, vec![write("d", &file("d", 10, 2))]);
        let (lb, db) = branch(
            "b",
            &base_ref,
            vec![write("other.txt", &file("other.txt", 3, 2))],
        );
        let conflict = TreeDelta::merge(&base_ref, &base, &[(la, &da), (lb, &db)])
            .unwrap()
            .unwrap_err();
        assert!(conflict.structural.is_some());
        assert!(
            conflict
                .paths
                .iter()
                .any(|(p, l)| { p.as_str() == "d/inner.txt" && l.is_empty() }),
            "the retained base path is named with an empty label list"
        );
    }

    /// But a DELETE of the subtree's files plus a write at the dir's path is
    /// fine — deletion means the subtree no longer conflicts.
    #[test]
    fn delete_contents_then_write_the_dir_is_fine() {
        let base = manifest(vec![file("d/inner.txt", 1, 4)]);
        let base_ref = reference(&base);
        let (la, da) = branch(
            "a",
            &base_ref,
            vec![delete("d/inner.txt"), write("d", &file("d", 10, 2))],
        );
        let (lb, db) = branch("b", &base_ref, vec![write("o.txt", &file("o.txt", 3, 2))]);
        let merged = TreeDelta::merge(&base_ref, &base, &[(la, &da), (lb, &db)])
            .unwrap()
            .unwrap();
        let result = merged.apply(&base).unwrap();
        assert_eq!(
            result
                .entries()
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            vec!["d", "o.txt"]
        );
    }

    /// A branch delta naming a different base is the typed refusal, naming the
    /// branch — never silently merged.
    #[test]
    fn a_foreign_base_is_refused_naming_the_branch() {
        let base = manifest(vec![file("keep.txt", 1, 4)]);
        let base_ref = reference(&base);
        let other = manifest(vec![file("other.txt", 5, 4)]);
        let foreign_ref = reference(&other);
        let (la, da) = branch("a", &base_ref, vec![write("a.txt", &file("a.txt", 10, 2))]);
        let (lf, df) = branch(
            "foreign",
            &foreign_ref,
            vec![write("f.txt", &file("f.txt", 11, 2))],
        );
        let err = TreeDelta::merge(&base_ref, &base, &[(la, &da), (lf, &df)]).unwrap_err();
        assert!(
            err.to_string().contains(TREE_DELTA_MERGE_FOREIGN_BASE),
            "the refusal names its token: {err}"
        );
        assert!(
            err.to_string().contains("foreign"),
            "it names the branch: {err}"
        );
    }

    /// The merge is invariant under branch order — permutations of three
    /// branches produce the SAME delta bytes.
    #[test]
    fn merge_is_permutation_invariant() {
        let base = manifest(vec![file("keep.txt", 1, 4), file("rm.txt", 2, 4)]);
        let base_ref = reference(&base);
        let (la, da) = branch(
            "a",
            &base_ref,
            vec![write("a.txt", &file("a.txt", 10, 2)), delete("rm.txt")],
        );
        let (lb, db) = branch("b", &base_ref, vec![write("b.txt", &file("b.txt", 11, 2))]);
        let (lc, dc) = branch(
            "c",
            &base_ref,
            vec![write("shared.txt", &file("shared.txt", 9, 2))],
        );
        let (ld, dd) = branch(
            "d",
            &base_ref,
            vec![write("shared.txt", &file("shared.txt", 9, 2))],
        );
        let all: Vec<(BranchLabel, &TreeDelta)> = vec![(la, &da), (lb, &db), (lc, &dc), (ld, &dd)];
        let reference_bytes = TreeDelta::merge(&base_ref, &base, &all)
            .unwrap()
            .unwrap()
            .delta_bytes()
            .unwrap();
        // Every permutation of the four branches.
        fn permute<T: Clone>(items: &[T], out: &mut Vec<Vec<T>>) {
            if items.is_empty() {
                out.push(vec![]);
                return;
            }
            for i in 0..items.len() {
                let mut rest = items.to_vec();
                let head = rest.remove(i);
                let mut tails = Vec::new();
                permute(&rest, &mut tails);
                for mut tail in tails {
                    tail.insert(0, head.clone());
                    out.push(tail);
                }
            }
        }
        let mut perms = Vec::new();
        permute(&all, &mut perms);
        assert_eq!(perms.len(), 24);
        for perm in perms {
            let bytes = TreeDelta::merge(&base_ref, &base, &perm)
                .unwrap()
                .unwrap()
                .delta_bytes()
                .unwrap();
            assert_eq!(bytes, reference_bytes, "branch order must not matter");
        }
    }

    /// Zero branches → empty delta (applies to base unchanged); one branch →
    /// itself.
    #[test]
    fn degenerate_merges() {
        let base = manifest(vec![file("keep.txt", 1, 4)]);
        let base_ref = reference(&base);
        let merged = TreeDelta::merge(&base_ref, &base, &[]).unwrap().unwrap();
        assert!(merged.changes().is_empty());
        assert_eq!(
            merged.apply(&base).unwrap().entries().len(),
            base.entries().len()
        );
        let (la, da) = branch("a", &base_ref, vec![write("a.txt", &file("a.txt", 10, 2))]);
        let merged = TreeDelta::merge(&base_ref, &base, &[(la, &da)])
            .unwrap()
            .unwrap();
        assert_eq!(merged, da);
    }

    /// Golden: the merged delta's canonical bytes — pinned so a field-order or
    /// tag change rotates loudly.
    #[test]
    fn merged_delta_bytes_golden() {
        let base = manifest(vec![file("keep.txt", 1, 4)]);
        let base_ref = reference(&base);
        let (la, da) = branch("a", &base_ref, vec![write("a.txt", &file("a.txt", 10, 2))]);
        let (lb, db) = branch("b", &base_ref, vec![write("b.txt", &file("b.txt", 11, 2))]);
        let merged = TreeDelta::merge(&base_ref, &base, &[(la, &da), (lb, &db)])
            .unwrap()
            .unwrap();
        let bytes = merged.delta_bytes().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        // Pin the whole shape: version, base ref fields, sorted changes with
        // both branches' writes — byte-exact, so a canonicalization drift fails
        // here rather than rotating artifact ids silently.
        let expected = format!(
            concat!(
                "{{\"schema_version\":1,\"base\":{{\"schema_version\":14,\"id\":\"{}\",",
                "\"object_id\":\"{}\",\"size_bytes\":{},\"privacy\":\"private\"}},",
                "\"changes\":[{{\"path\":\"a.txt\",\"change\":{{\"op\":\"write\",",
                "\"node\":{{\"kind\":\"file\",\"mode\":\"regular\",\"object\":\"{}\",",
                "\"size_bytes\":2}}}}}},{{\"path\":\"b.txt\",\"change\":{{\"op\":\"write\",",
                "\"node\":{{\"kind\":\"file\",\"mode\":\"regular\",\"object\":\"{}\",",
                "\"size_bytes\":2}}}}}}]}}"
            ),
            hex::encode(base_ref.id().0),
            hex::encode(base_ref.object_id().as_bytes()),
            base_ref.size_bytes(),
            hex::encode(object(10).as_bytes()),
            hex::encode(object(11).as_bytes()),
        );
        assert_eq!(text, expected);
    }
}
