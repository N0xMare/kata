//! The WORKER publishes `/out` as a TREE ARTIFACT.
//!
//! # What this module is
//!
//! [`publish_result_tree`] turns the host directory a container's `/out` was bound
//! to into a content-addressed [`ArtifactRef`] the main can adopt. It is the RESULT
//! half of the capsule plane: [`crate::materialize`] turns artifacts into
//! directories on the way in, and this turns one directory back into an artifact on
//! the way out.
//!
//! # SCAN, BOUND, THEN PUBLISH — in that order, and the order is the property
//!
//! The whole directory is walked and measured BEFORE a single byte is published —
//! against the capsule's two result bounds and against the manifest ceiling every
//! reader applies (`TreeManifest::MAXIMUM_ENCODED_BYTES`, see
//! [`ResultPublicationRefusal::ManifestOverCeiling`]).
//! That is not an optimization; it is what the capsule's two result bounds mean. A
//! publisher that streamed members and checked the running total as it went would
//! leave the members it had already published in the CAS when the bound tripped —
//! bytes no `artifacts` row references — kept for good, since nothing reclaims a CAS
//! object — produced by a stage the node then refused. The bound says "this result
//! is not adopted", and the honest reading of that is "and its bytes were never
//! put in the store either".
//!
//! Within the publish, members come first and the MANIFEST last, for the reason
//! `ArtifactDeclaration::for_durable_tree` states from the other side: a manifest
//! is a promise about objects, and a promise published before the objects exist is
//! one a reader can catch in a state where it is false.
//!
//! # `/work` IS NOT PUBLISHED HERE
//!
//! The capsule result plane publishes two artifacts — `/out`, and the `/work`
//! DIFF a capsule's mutation becomes. This module publishes only `/out`;
//! [`crate::work_delta`] owns the other, computing and publishing the
//! `TreeDelta` against the mapping's declared base tree.
//!
//! # The crash window, named
//!
//! `operational.after_container_exited_before_result_published` fires at the top of
//! the publish, once the scan has passed: the container has exited, the bytes exist
//! on the worker's disk under the attempt root, and NOTHING in the content store or
//! the operational plane references them. Its recovery is not repair — the worker
//! process ends, its connection closes, and the main's worker-death leg settles the
//! attempt failed PROVEN AMBIGUOUS — and `/out` is NEVER adopted, because the only
//! thing that adopts one is a `CompletedCapsule` frame that was never sent. Nothing
//! re-runs the stage: the failure retry never re-runs a PROVEN AMBIGUOUS attempt.

use std::path::{Path, PathBuf};

use kata_core::store::cas::DurableObject;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef, CapsuleBudgets};
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};

/// The PRIVACY a NON-EMPTY published result tree carries.
///
/// `Private`. A result tree's bytes are what one stage produced on one node; `Public`
/// is the classification for content that is IDENTICAL on every node and therefore
/// protects nothing by being restricted. Choosing the conservative arm costs nothing
/// (privacy gates no reader today) and means the day it does gate one, no
/// already-published result is sitting on the permissive side of it.
///
/// It is folded into [`ArtifactRef`]'s id, so this constant is part of the address the
/// main re-derives.
pub const RESULT_PRIVACY: ArtifactPrivacy = ArtifactPrivacy::Private;

/// The privacy ONE published tree carries: [`ArtifactPrivacy::Public`] for the canonical
/// EMPTY TREE, [`RESULT_PRIVACY`] for everything else.
///
/// # Why the empty tree is the exception, and why it is not a special case in the caller
///
/// A stage that writes nothing to `/out` has a result, and it is the empty tree — the
/// SAME object `kata_workflow::capsule_assembly::empty_tree_artifact` names, which every
/// capsule on this plane already maps at `/out` as a `Public` artifact. Publishing it as
/// `Private` would mint a SECOND artifact id over those bytes, and the main's
/// `idx_artifacts_object` would refuse whichever of the two arrived second — so the
/// first empty result on a node would break every later capsule assembly, or the
/// reverse. There is also no privacy to protect: the bytes are an empty list, identical
/// on every node.
///
/// Keyed on the manifest being EMPTY rather than on a pinned object id, because that is
/// the fact this side actually has; `OperationalDb::adopt_capsule_result` keys its
/// matching admission on the OBJECT ID, which is the fact THAT side has, and the two meet
/// at the canonical bytes. A pinned hex on either side would be a second answer to what
/// the empty tree is.
#[must_use]
pub fn privacy_for(manifest: &TreeManifest) -> ArtifactPrivacy {
    if manifest.entries().is_empty() {
        ArtifactPrivacy::Public
    } else {
        RESULT_PRIVACY
    }
}

/// WHERE published bytes go, stated as an obligation rather than as a handle.
///
/// # Why a trait
///
/// [`crate::materialize::BlobSource`]'s argument applies unchanged in the other
/// direction: the shared-disk assumption belongs at the interface, so removing it
/// later is a new impl rather than a rewrite of this module. What this trait adds is
/// a DURABILITY obligation the source side has no analogue of — an implementor must
/// return a receipt only for bytes that are fsync-durable, because the manifest
/// published after them is a promise about exactly that.
pub trait BlobSink: Send + Sync {
    /// Publish `bytes` and return the durability receipt for them.
    ///
    /// # Errors
    ///
    /// Whatever the underlying store refuses.
    fn publish(&self, bytes: &[u8]) -> KataResult<DurableObject>;
}

/// The production [`BlobSink`]: the shared CAS, publishing through
/// [`CasStore::put_durable`](kata_core::store::cas::CasStore::put_durable).
pub struct CasBlobSink<'a>(pub &'a kata_core::store::cas::CasStore);

impl BlobSink for CasBlobSink<'_> {
    fn publish(&self, bytes: &[u8]) -> KataResult<DurableObject> {
        self.0.put_durable(bytes)
    }
}

/// Why a stage's `/out` did not become an artifact.
///
/// A typed enum for [`crate::oci_driver::OciDriveRefusal`]'s reason: a bound refusal
/// and a malformed-entry refusal are read by different operators, and *"the refused
/// set is exactly this list"* is a claim only an enumerable type supports.
#[derive(Debug)]
pub enum ResultPublicationRefusal {
    /// `/out` could not be walked — it is absent, unreadable, or not a directory.
    Unreadable { path: PathBuf, error: String },
    /// An entry is not a regular file: a symlink, a directory entry kata cannot
    /// represent, a socket, a fifo or a device node.
    ///
    /// [`TreeManifest`] has a `Symlink` arm, but THIS producer refuses the
    /// link it meets: the `/out` walk emits no link entries, and a stage's
    /// accidental symlink stays a named failure rather than silently becoming
    /// artifact content no consumer asked for. Sockets, fifos and device nodes
    /// are unrepresentable in the manifest itself — see [`TreeNode`].
    UnrepresentableEntry { path: PathBuf, kind: &'static str },
    /// An entry's path is one [`TreePath`] refuses.
    UnacceptablePath(KataError),
    /// The tree carries more entries than the capsule's `result_entries` budget.
    ///
    /// Refused BEFORE any byte is published; see the module docs.
    TooManyEntries { entries: u64, budget: u32 },
    /// The tree's total member bytes exceed the capsule's `result_bytes` budget.
    ///
    /// Refused BEFORE any byte is published.
    TooManyBytes { bytes: u64, budget: u64 },
    /// The tree's MANIFEST would encode past
    /// [`TreeManifest::MAXIMUM_ENCODED_BYTES`] — the encoder's own
    /// `kata_types::tree_artifact::TREE_MANIFEST_OVER_CEILING`, carried here.
    ///
    /// Neither budget above implies it: a few thousand empty files with long paths are
    /// inside both. Refused BEFORE any byte is published, for the entry bound's reason,
    /// and refused here at all because every reader of a tree manifest — the main's
    /// adoption, a worker materializing it — bounds its read at that
    /// ceiling: a manifest over it is a result nobody can load.
    ManifestOverCeiling(KataError),
    /// A member's bytes could not be read at publish time, or the store refused
    /// them.
    PublicationFailed(KataError),
    /// A member CHANGED between the scan and the publish: its length at read time is
    /// not the length the bound was computed over.
    ///
    /// A refusal and not a re-measure, because the thing that can still be writing
    /// into `/out` after the container exited is a process the teardown failed to
    /// reap — so a second measurement would be a second guess, and adopting the
    /// larger read would adopt bytes the bound never covered.
    MemberChanged {
        path: PathBuf,
        scanned: u64,
        read: u64,
    },
}

impl ResultPublicationRefusal {
    /// The stable token for a log field and a test assertion.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Unreadable { .. } => "out_unreadable",
            Self::UnrepresentableEntry { .. } => "unrepresentable_entry",
            Self::UnacceptablePath(_) => "unacceptable_path",
            Self::TooManyEntries { .. } => "result_entries_exceeded",
            Self::TooManyBytes { .. } => "result_bytes_exceeded",
            Self::ManifestOverCeiling(_) => "result_manifest_over_ceiling",
            Self::PublicationFailed(_) => "publication_failed",
            Self::MemberChanged { .. } => "member_changed",
        }
    }
}

impl std::fmt::Display for ResultPublicationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "result tree refused ({}): ", self.label())?;
        match self {
            Self::Unreadable { path, error } => write!(
                f,
                "{} could not be walked ({error}). The container's `/out` bind is how a stage's \
                 result leaves it, so an unwalkable one is a result that cannot be reported rather \
                 than an empty one",
                path.display()
            ),
            Self::UnrepresentableEntry { path, kind } => write!(
                f,
                "{} is a {kind}, which this result walk does not emit: a tree artifact CAN carry \
                 a symlink, but /out publication still refuses one it finds on disk \
                 rather than record a link no consumer adopted deliberately",
                path.display()
            ),
            Self::UnacceptablePath(error) => write!(f, "{error}"),
            Self::TooManyEntries { entries, budget } => write!(
                f,
                "the result tree holds {entries} entries and the capsule's result_entries budget \
                 is {budget}. NOTHING WAS PUBLISHED: the bound is checked over the whole scan \
                 before the first member is written, so a refused result leaves no bytes in the \
                 content store"
            ),
            Self::TooManyBytes { bytes, budget } => write!(
                f,
                "the result tree's members total {bytes} bytes and the capsule's result_bytes \
                 budget is {budget}. NOTHING WAS PUBLISHED — see the entry-count refusal's note"
            ),
            Self::ManifestOverCeiling(error) => write!(
                f,
                "{error}. NOTHING WAS PUBLISHED — the manifest is measured over the scan, \
                 before the first member is written"
            ),
            Self::PublicationFailed(error) => {
                write!(f, "a member's bytes could not be published: {error}")
            }
            Self::MemberChanged {
                path,
                scanned,
                read,
            } => write!(
                f,
                "{} was {scanned} bytes when the tree was measured and {read} when it was read. \
                 Something is still writing into `/out` after the container exited, so the bound \
                 the capsule promised was computed over bytes that are no longer there — refusing \
                 rather than re-measuring, because a second measurement is a second guess",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ResultPublicationRefusal {}

impl From<ResultPublicationRefusal> for KataError {
    fn from(refusal: ResultPublicationRefusal) -> Self {
        KataError::Validation(refusal.to_string())
    }
}

/// One scanned member, before anything is published.
struct ScannedMember {
    host: PathBuf,
    path: TreePath,
    mode: TreeEntryMode,
    size_bytes: u64,
}

/// PUBLISH the `/out` directory at `out` as a tree artifact, bounded by `budgets`.
///
/// Returns the reference the worker puts on a `CompletedCapsule` frame, paired with
/// the manifest it published, so a caller that wants to log the entry count does not
/// re-read the bytes.
///
/// An EMPTY `/out` publishes the canonical empty tree — the same object
/// `kata_workflow::capsule_assembly::empty_tree_artifact` names — rather than refusing,
/// and carries [`ArtifactPrivacy::Public`] for the reason [`privacy_for`] states. A
/// stage that legitimately produces no files has a result, and it is that one.
///
/// # Errors
///
/// Exactly [`ResultPublicationRefusal`]'s arms.
pub fn publish_result_tree(
    out: &Path,
    budgets: CapsuleBudgets,
    sink: &dyn BlobSink,
) -> Result<(ArtifactRef, TreeManifest), ResultPublicationRefusal> {
    let members = scan(out)?;

    // THE BOUNDS, over the whole scan, before a byte is published. See the module
    // docs for why streaming-and-checking would have been the wrong shape.
    let entries = members.len() as u64;
    if entries > u64::from(budgets.result_entries) {
        return Err(ResultPublicationRefusal::TooManyEntries {
            entries,
            budget: budgets.result_entries,
        });
    }
    let total = members
        .iter()
        .try_fold(0u64, |total, member| total.checked_add(member.size_bytes))
        .ok_or(ResultPublicationRefusal::TooManyBytes {
            bytes: u64::MAX,
            budget: budgets.result_bytes,
        })?;
    if total > budgets.result_bytes {
        return Err(ResultPublicationRefusal::TooManyBytes {
            bytes: total,
            budget: budgets.result_bytes,
        });
    }
    refuse_manifest_over_ceiling(&members)?;

    // The container has exited and the bytes are on this worker's disk with nothing
    // in any store or row referencing them. See the module docs for the recovery
    // obligation this window carries.
    kata_core::fault_inject::operational_crash_point(
        "after_container_exited_before_result_published",
    );

    let mut published = Vec::with_capacity(members.len());
    for member in &members {
        let bytes = std::fs::read(&member.host).map_err(|error| {
            ResultPublicationRefusal::PublicationFailed(KataError::Storage(format!(
                "result member {}: {error}",
                member.host.display()
            )))
        })?;
        // The length the bound was computed over, re-checked against the length
        // actually read. See `MemberChanged`.
        if bytes.len() as u64 != member.size_bytes {
            return Err(ResultPublicationRefusal::MemberChanged {
                path: member.host.clone(),
                scanned: member.size_bytes,
                read: bytes.len() as u64,
            });
        }
        let receipt = sink
            .publish(&bytes)
            .map_err(ResultPublicationRefusal::PublicationFailed)?;
        published.push(TreeEntry {
            path: member.path.clone(),
            node: TreeNode::File {
                mode: member.mode,
                object: receipt.object_id(),
                size_bytes: receipt.size(),
            },
        });
    }

    let manifest =
        TreeManifest::new(published).map_err(ResultPublicationRefusal::PublicationFailed)?;
    let bytes = manifest
        .manifest_bytes()
        .map_err(ResultPublicationRefusal::PublicationFailed)?;
    let receipt = sink
        .publish(&bytes)
        .map_err(ResultPublicationRefusal::PublicationFailed)?;
    let privacy = privacy_for(&manifest);
    Ok((
        ArtifactRef::new(receipt.object_id(), receipt.size(), privacy),
        manifest,
    ))
}

/// Refuse, BEFORE anything is published, a scan whose manifest would encode past
/// [`TreeManifest::MAXIMUM_ENCODED_BYTES`].
///
/// The real manifest names each member's object id, which is not known until the member is
/// read and published. The encoded LENGTH does not depend on it: an [`ObjectId`] encodes as
/// fixed-width hex, and every other field (path, mode, length) is already scanned. So the
/// manifest over the scan with a placeholder id encodes to exactly as many bytes as the one
/// published after it, and asking the ONE encoder about it is the ceiling check — not a
/// second estimate of it.
///
/// [`ObjectId`]: kata_types::primitives::ObjectId
fn refuse_manifest_over_ceiling(members: &[ScannedMember]) -> Result<(), ResultPublicationRefusal> {
    let measured = TreeManifest::new(
        members
            .iter()
            .map(|member| TreeEntry {
                path: member.path.clone(),
                node: TreeNode::File {
                    mode: member.mode,
                    object: kata_types::primitives::ObjectId::zero(),
                    size_bytes: member.size_bytes,
                },
            })
            .collect(),
    )
    .map_err(ResultPublicationRefusal::PublicationFailed)?;
    match measured.manifest_bytes() {
        Ok(_) => Ok(()),
        Err(error @ KataError::Validation(_)) => {
            Err(ResultPublicationRefusal::ManifestOverCeiling(error))
        }
        Err(other) => Err(ResultPublicationRefusal::PublicationFailed(other)),
    }
}

/// Walk `out` depth-first, collecting every regular file as a scanned member.
///
/// Symlinks are NOT followed: `symlink_metadata` is what decides the kind, so a
/// symlink is the `UnrepresentableEntry` refusal rather than a silently copied
/// target — which is also what keeps a link pointing out of `/out` from pulling
/// arbitrary host bytes into an artifact.
fn scan(out: &Path) -> Result<Vec<ScannedMember>, ResultPublicationRefusal> {
    let mut members = Vec::new();
    let mut pending = vec![(out.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            ResultPublicationRefusal::Unreadable {
                path: directory.clone(),
                error: error.to_string(),
            }
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| ResultPublicationRefusal::Unreadable {
                path: directory.clone(),
                error: error.to_string(),
            })?;
            let host = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(ResultPublicationRefusal::UnrepresentableEntry {
                    path: host,
                    kind: "non-UTF-8 name",
                });
            };
            let relative = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            let metadata = std::fs::symlink_metadata(&host).map_err(|error| {
                ResultPublicationRefusal::Unreadable {
                    path: host.clone(),
                    error: error.to_string(),
                }
            })?;
            let kind = metadata.file_type();
            if kind.is_dir() {
                pending.push((host, relative));
                continue;
            }
            if kind.is_symlink() {
                return Err(ResultPublicationRefusal::UnrepresentableEntry {
                    path: host,
                    kind: "symlink",
                });
            }
            if !kind.is_file() {
                return Err(ResultPublicationRefusal::UnrepresentableEntry {
                    path: host,
                    kind: "socket, fifo or device node",
                });
            }
            let path = TreePath::new(relative.as_str())
                .map_err(ResultPublicationRefusal::UnacceptablePath)?;
            members.push(ScannedMember {
                host,
                path,
                mode: executable_mode(&metadata),
                size_bytes: metadata.len(),
            });
        }
    }
    Ok(members)
}

/// Whether the guest could `execve` the file — the ONE permission bit a tree
/// artifact carries.
///
/// The owner execute bit, and not "any execute bit": the container's process runs as
/// the single mapped uid that owns every materialized file, so the group and other
/// bits decide nothing about whether THIS stage's successor can run it, and folding
/// them in would make a manifest differ for a fact no materialization reproduces.
///
/// `pub(crate)` because [`crate::work_delta`] owes the SAME answer — the file→mode
/// mapping is a semantic of the artifact type, not of either walker.
#[cfg(unix)]
pub(crate) fn executable_mode(metadata: &std::fs::Metadata) -> TreeEntryMode {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o100 == 0 {
        TreeEntryMode::Regular
    } else {
        TreeEntryMode::Executable
    }
}

#[cfg(not(unix))]
pub(crate) fn executable_mode(_metadata: &std::fs::Metadata) -> TreeEntryMode {
    TreeEntryMode::Regular
}
