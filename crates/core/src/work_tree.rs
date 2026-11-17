//! The `/work` PRODUCER: walk an execution's scratch workspace
//! into a tree artifact, MAIN-side, ONCE at admission, and declare it retained by
//! the execution.
//!
//! # What this module is
//!
//! A capsule maps the execution's workspace at `/work` by CONTENT, never by host
//! path — and the content it maps is the execution's
//! recorded `execution_work_tree_heads` row at the stage's `parallel()`
//! coordinate, never a per-attempt re-walk. [`walk_work_tree`] reads a
//! directory into a [`TreeManifest`] plus the member bytes it read, and
//! [`publish_scratch_tree_head`] — the test-fixture seed — publishes the
//! members, then the manifest, into the CAS, declares a
//! `kind='tree'` artifact with [`CasRootOwner::Execution`], and records it as
//! the root head. Production admission under `oci` seeds the canonical EMPTY
//! tree instead ([`declare_empty_tree` + `record_work_tree_head`] via the
//! executor): nothing legitimately populates a scratch dir before admission,
//! so the walk's only remaining seat is tests authoring `/work` content.
//! Every later `/work` input is an apply's recorded advance.
//!
//! # The walk's discipline: descriptors, never re-resolved paths
//!
//! The materializer's rule, applied in the other direction: every directory is opened
//! `O_DIRECTORY | O_NOFOLLOW` RELATIVE TO ITS PARENT'S DESCRIPTOR, every file is opened
//! `O_NOFOLLOW | O_NONBLOCK` relative to its directory's descriptor and its type is read
//! off the OPENED descriptor. So a component swapped for a symlink between the listing and
//! the open fails the open (`ELOOP`/`ENOTDIR`) instead of being followed out of the
//! workspace, and a regular file swapped for a fifo is refused off `fstat` rather than
//! blocking the walk.
//!
//! # Refused set, each by name
//!
//! * [`WORK_TREE_UNMATERIALIZED`] — the root is absent or not a directory (the caller
//!   refuses the same name when no workspace path was resolved at all). The canonical
//!   EMPTY tree is never substituted: a stage that reads no sources and reports success
//!   is the defect.
//! * [`WORK_TREE_SYMLINK`] — any symlink, anywhere. The schema-2 manifest CAN
//!   carry one (`TreeNode::Symlink`), but THIS walker refuses: the `/work`
//!   producer emits no link entries, and a workspace link that escapes
//!   the root is safer refused at the snapshot — where the real target is still
//!   visible — than recorded.
//! * [`WORK_TREE_SPECIAL_FILE`] — a fifo, socket, block or character device.
//! * [`WORK_TREE_BOUND_EXCEEDED`] — more than [`WORK_TREE_MAX_ENTRIES`] walked entries
//!   (files AND directories, because the walk's cost is per entry and a million empty
//!   directories would otherwise be unbounded), more than [`WORK_TREE_MAX_BYTES`] of
//!   member bytes, or a manifest whose canonical encoding is over
//!   `TreeManifest::MAXIMUM_ENCODED_BYTES` (the encoder's own
//!   `kata_types::tree_artifact::TREE_MANIFEST_OVER_CEILING`, carried inside this name) —
//!   the ceiling every reader, the worker's `/work` resolver among them, bounds its read
//!   at. The first two do not imply the third, and since the 64 MiB manifest ceiling the
//!   third is reachable through THIS producer only in shape, not in fact: a walked tree
//!   tops out under [`WORK_TREE_MAX_ENTRIES`] (10 000), whose worst-case encoding stays
//!   inside the ceiling. It remains stated because the committed-base producer's input
//!   bound (default 100 000 entries) CAN overrun it, and `manifest_bytes` is the one
//!   encoder both producers share. Refused during the walk, before anything is
//!   published or any attempt is claimed.
//! * [`WORK_TREE_UNACCEPTABLE_PATH`] — a non-UTF-8 name, or a path [`TreePath`] refuses.
//! * [`WORK_TREE_CHANGED_DURING_WALK`] — an entry changed type between the listing and
//!   the descriptor open (`ENOTDIR` on a directory swap, or a type mismatch off `fstat`).
//! * [`WORK_TREE_UNREADABLE`] — an I/O failure reading a directory or a member.
//! * [`WORK_TREE_MEMBER_UNVERIFIED`] — at declaration, a member the content store does not
//!   hold or holds at a different length (the presence-and-length check, the same
//!   function `adopt_and_accept_capsule_completion` runs).
//!
//! Empty directories are not entries: a manifest implies them from entry paths. And
//! though a schema-2 tree CAN carry symlinks, THIS walker emits files only (see
//! [`WORK_TREE_SYMLINK`]), so the walked tree and a `find -type f` of the workspace
//! are the same set.
//!
//! # The second producer: the COMMITTED base tree
//!
//! [`publish_base_tree_head`] is the same publish-declare shape over a different
//! source: the VCS provider's `committed_base_tree` conversion walks the base
//! COMMIT's `MergedTree` — committed content, never the workspace's mutable
//! file state — and streams each member through a `put_member` callback this
//! function backs with the CAS. The manifest then publishes
//! and declares exactly as a walked tree does, and the execution's
//! `execution_work_tree_heads` row is recorded LAST, after the
//! `after_base_tree_published_before_head_recorded` boundary — the one window
//! where the artifact is durable and no head names it yet. Re-admission
//! converges through CAS dedup plus `record_work_tree_head`'s
//! converge-or-refuse, so this function is safe to re-drive end to end.

#[cfg(any(test, feature = "test-support"))]
use std::ffi::CStr;
#[cfg(any(test, feature = "test-support"))]
use std::io::Read as _;
#[cfg(any(test, feature = "test-support"))]
use std::os::unix::fs::MetadataExt as _;
#[cfg(any(test, feature = "test-support"))]
use std::path::Path;

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
#[cfg(any(test, feature = "test-support"))]
use kata_types::execution_contract::{CAPSULE_RESULT_BYTES, CAPSULE_RESULT_ENTRIES};
use kata_types::primitives::ObjectId;
#[cfg(any(test, feature = "test-support"))]
use kata_types::tree_artifact::TreeEntry;
use kata_types::tree_artifact::{CommittedBaseTree, TreeManifest};
#[cfg(any(test, feature = "test-support"))]
use kata_types::tree_artifact::{TreeEntryMode, TreeNode, TreePath};
use ulid::Ulid;

use crate::OperationalDb;
use crate::operational::{ArtifactDeclaration, CasRootOwner, ExecutionWorkTreeHead};
use crate::store::cas::{CasStore, DurableObject};

/// The workspace was not materialized.
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_UNMATERIALIZED: &str = "work_tree_unmaterialized";
/// A symlink was found in the workspace.
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_SYMLINK: &str = "work_tree_symlink";
/// A fifo, socket or device node was found in the workspace.
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_SPECIAL_FILE: &str = "work_tree_special_file";
/// The workspace exceeds [`WORK_TREE_MAX_ENTRIES`] or [`WORK_TREE_MAX_BYTES`].
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_BOUND_EXCEEDED: &str = "work_tree_bound_exceeded";
/// A name a tree path cannot carry.
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_UNACCEPTABLE_PATH: &str = "work_tree_unacceptable_path";
/// An entry changed type between the listing and the open.
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_CHANGED_DURING_WALK: &str = "work_tree_changed_during_walk";
/// An I/O failure during the walk.
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_UNREADABLE: &str = "work_tree_unreadable";
/// A declared member absent from, or mis-measured in, `cas_objects`.
pub const WORK_TREE_MEMBER_UNVERIFIED: &str = "work_tree_member_unverified";

/// The most member bytes a walked workspace may carry: the capsule's `result_bytes`
/// class ([`CAPSULE_RESULT_BYTES`], 64 MiB). The same class because the same two costs
/// bind it — the main holds the walked bytes in memory between the walk and the publish,
/// and the worker copies every member into the attempt root — and a second number would
/// be a second answer to "how large a tree does this node move per attempt".
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_MAX_BYTES: u64 = CAPSULE_RESULT_BYTES;

/// The most entries (files and directories) a walk may visit: the capsule's
/// `result_entries` class ([`CAPSULE_RESULT_ENTRIES`], 10 000), for the same reason.
#[cfg(any(test, feature = "test-support"))]
pub const WORK_TREE_MAX_ENTRIES: u32 = CAPSULE_RESULT_ENTRIES;

fn refused(name: &str, detail: impl std::fmt::Display) -> KataError {
    KataError::Validation(format!("work tree refused: {name}: {detail}"))
}

/// A walked workspace: its manifest, the manifest's canonical bytes, and the bytes of each
/// member, in manifest order.
#[derive(Debug)]
#[cfg(any(test, feature = "test-support"))]
pub struct WalkedTree {
    manifest: TreeManifest,
    /// `manifest.manifest_bytes()`, encoded ONCE by the walk (which is where an encoding
    /// over the ceiling is refused) and then both addressed and published from here.
    manifest_bytes: Vec<u8>,
    /// The bytes of each FILE entry in `manifest.entries()`, in manifest order —
    /// a symlink entry carries its content (the target) inside the manifest and
    /// has no member bytes here.
    members: Vec<Vec<u8>>,
}

#[cfg(any(test, feature = "test-support"))]
impl WalkedTree {
    /// The manifest the walk produced.
    #[must_use]
    pub fn manifest(&self) -> &TreeManifest {
        &self.manifest
    }

    /// The reference [`publish_scratch_tree_head`] declares: derived from the
    /// manifest's own canonical bytes, so the caller's published id is the
    /// manifest's own, not a re-derivation's.
    #[must_use]
    pub fn reference(&self) -> ArtifactRef {
        ArtifactRef::new(
            kata_types::cache::object_id_for_canonical_bytes(&self.manifest_bytes),
            self.manifest_bytes.len() as u64,
            privacy_for(&self.manifest),
        )
    }
}

/// `Public` for the canonical EMPTY tree, `Private` for anything else — the result plane's
/// rule (`kata_worker::result_publication::privacy_for`), for its reason: the empty tree is
/// one object every capsule already maps as `Public`, and a second privacy over it is
/// refused by `idx_artifacts_object`.
fn privacy_for(manifest: &TreeManifest) -> ArtifactPrivacy {
    if manifest.entries().is_empty() {
        ArtifactPrivacy::Public
    } else {
        ArtifactPrivacy::Private
    }
}

/// WALK the directory at `root` into a [`WalkedTree`], or refuse by name.
///
/// # Errors
///
/// The module docs' refused set, minus [`WORK_TREE_MEMBER_UNVERIFIED`].
#[cfg(any(test, feature = "test-support"))]
pub fn walk_work_tree(root: &Path) -> KataResult<WalkedTree> {
    let root_dir = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(std::fs::File::from)
    .map_err(|error| {
        refused(
            WORK_TREE_UNMATERIALIZED,
            format!(
                "the execution workspace {} is not an openable directory ({error}); a capsule \
                 maps what was walked, and there is nothing to walk",
                root.display()
            ),
        )
    })?;

    let mut entries: Vec<(TreeEntry, Vec<u8>)> = Vec::new();
    let mut visited: u32 = 0;
    let mut total_bytes: u64 = 0;
    let mut pending: Vec<(std::fs::File, String)> = vec![(root_dir, String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let listing = rustix::fs::Dir::read_from(&directory)
            .map_err(|error| refused(WORK_TREE_UNREADABLE, format!("{prefix:?}: {error}")))?;
        for entry in listing {
            let entry = entry
                .map_err(|error| refused(WORK_TREE_UNREADABLE, format!("{prefix:?}: {error}")))?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            visited = visited.saturating_add(1);
            if visited > WORK_TREE_MAX_ENTRIES {
                return Err(refused(
                    WORK_TREE_BOUND_EXCEEDED,
                    format!(
                        "the workspace holds more than WORK_TREE_MAX_ENTRIES \
                         ({WORK_TREE_MAX_ENTRIES}) files and directories. Nothing was published"
                    ),
                ));
            }
            let relative = relative_path(&prefix, name)?;
            let kind = classify(&directory, name, &relative)?;
            match kind {
                Kind::Directory => {
                    let child = open_beneath(&directory, name, true, &relative)?;
                    require_kind(&child, Kind::Directory, &relative)?;
                    pending.push((child, relative));
                }
                Kind::File => {
                    let mut file = open_beneath(&directory, name, false, &relative)?;
                    let metadata = require_kind(&file, Kind::File, &relative)?;
                    let remaining = WORK_TREE_MAX_BYTES - total_bytes;
                    // Refused off the DESCRIPTOR's length before a byte is read, and the
                    // buffer is pre-sized to it, so `read_to_end` never grows past the
                    // bound; the `take` below still bounds a file that grows mid-read.
                    if metadata.len() > remaining {
                        return Err(refused(
                            WORK_TREE_BOUND_EXCEEDED,
                            format!(
                                "the workspace's files total more than WORK_TREE_MAX_BYTES \
                                 ({WORK_TREE_MAX_BYTES}) bytes (reached at {relative}). Nothing \
                                 was published"
                            ),
                        ));
                    }
                    let mut bytes = Vec::with_capacity(
                        usize::try_from(metadata.len())
                            .unwrap_or(0)
                            .saturating_add(1),
                    );
                    (&mut file)
                        .take(remaining.saturating_add(1))
                        .read_to_end(&mut bytes)
                        .map_err(|error| {
                            refused(WORK_TREE_UNREADABLE, format!("{relative}: {error}"))
                        })?;
                    let length = bytes.len() as u64;
                    if length > remaining {
                        return Err(refused(
                            WORK_TREE_BOUND_EXCEEDED,
                            format!(
                                "the workspace's files total more than WORK_TREE_MAX_BYTES \
                                 ({WORK_TREE_MAX_BYTES}) bytes (reached at {relative}). Nothing \
                                 was published"
                            ),
                        ));
                    }
                    total_bytes += length;
                    let path = TreePath::new(relative.as_str()).map_err(|error| {
                        refused(WORK_TREE_UNACCEPTABLE_PATH, format!("{relative}: {error}"))
                    })?;
                    let mode = if metadata.mode() & 0o100 == 0 {
                        TreeEntryMode::Regular
                    } else {
                        TreeEntryMode::Executable
                    };
                    entries.push((
                        TreeEntry {
                            path,
                            node: TreeNode::File {
                                mode,
                                object: kata_types::cache::object_id_for_canonical_bytes(&bytes),
                                size_bytes: length,
                            },
                        },
                        bytes,
                    ));
                }
            }
        }
    }

    // THE MANIFEST ORDERS ITS ENTRIES (`TreeManifest::new` sorts them), so the member
    // bytes are re-aligned to the manifest's order by path rather than by an order this
    // function would have to agree with.
    let mut by_path: std::collections::BTreeMap<String, Vec<u8>> =
        std::collections::BTreeMap::new();
    let mut tree_entries = Vec::with_capacity(entries.len());
    for (entry, bytes) in entries {
        by_path.insert(entry.path.as_str().to_owned(), bytes);
        tree_entries.push(entry);
    }
    let manifest = TreeManifest::new(tree_entries)?;
    // THE MANIFEST'S OWN SIZE, the third bound: the encoder refuses an encoding over the
    // ceiling every reader applies, and the refusal is this walk's bound by name — so a
    // workspace the worker's resolver would refuse is refused HERE, before a byte is
    // published or an attempt claimed, rather than authorized on the main and refused on
    // the worker it was dispatched to.
    let manifest_bytes = manifest.manifest_bytes().map_err(|error| match error {
        KataError::Validation(_) => refused(
            WORK_TREE_BOUND_EXCEEDED,
            format!("{error}. Nothing was published"),
        ),
        other => other,
    })?;
    // Every entry this walk produces is a FILE (a symlink is refused above), so
    // each manifest entry consumes exactly one walked member.
    let members = manifest
        .entries()
        .iter()
        .map(|entry| {
            by_path.remove(entry.path.as_str()).ok_or_else(|| {
                KataError::Validation(format!(
                    "work tree: the manifest names {} and the walk read no such member",
                    entry.path.as_str()
                ))
            })
        })
        .collect::<KataResult<Vec<_>>>()?;
    Ok(WalkedTree {
        manifest,
        manifest_bytes,
        members,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "test-support"))]
enum Kind {
    Directory,
    File,
}

#[cfg(any(test, feature = "test-support"))]
fn relative_path(prefix: &str, name: &CStr) -> KataResult<String> {
    let name = name.to_str().map_err(|_| {
        refused(
            WORK_TREE_UNACCEPTABLE_PATH,
            format!("{prefix:?} holds a non-UTF-8 name, which a tree path cannot carry"),
        )
    })?;
    Ok(if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    })
}

/// Classify an entry WITHOUT following it, so a symlink or a special file is refused
/// before anything opens it (opening a device node can have effects).
#[cfg(any(test, feature = "test-support"))]
fn classify(directory: &std::fs::File, name: &CStr, relative: &str) -> KataResult<Kind> {
    let stat = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| refused(WORK_TREE_UNREADABLE, format!("{relative}: {error}")))?;
    kind_of(rustix::fs::FileType::from_raw_mode(stat.st_mode), relative)
}

#[cfg(any(test, feature = "test-support"))]
fn kind_of(file_type: rustix::fs::FileType, relative: &str) -> KataResult<Kind> {
    match file_type {
        rustix::fs::FileType::Directory => Ok(Kind::Directory),
        rustix::fs::FileType::RegularFile => Ok(Kind::File),
        rustix::fs::FileType::Symlink => Err(refused(
            WORK_TREE_SYMLINK,
            format!(
                "{relative} is a symlink, which this walker refuses to record — a manifest can \
                 carry one, but no kata consumer adopts a walked link yet, and the \
                 refusal is where the real target is still visible"
            ),
        )),
        other => Err(refused(
            WORK_TREE_SPECIAL_FILE,
            format!("{relative} is a {other:?}, which a tree artifact cannot carry"),
        )),
    }
}

/// Open `name` beneath `directory` without following a final symlink.
#[cfg(any(test, feature = "test-support"))]
fn open_beneath(
    directory: &std::fs::File,
    name: &CStr,
    as_directory: bool,
    relative: &str,
) -> KataResult<std::fs::File> {
    let mut flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NOCTTY
        | rustix::fs::OFlags::NONBLOCK;
    if as_directory {
        flags |= rustix::fs::OFlags::DIRECTORY;
    }
    rustix::fs::openat(directory, name, flags, rustix::fs::Mode::empty())
        .map(std::fs::File::from)
        .map_err(|error| {
            if error == rustix::io::Errno::LOOP {
                refused(
                    WORK_TREE_SYMLINK,
                    format!("{relative} became a symlink while it was walked ({error})"),
                )
            } else if error == rustix::io::Errno::NOTDIR {
                refused(
                    WORK_TREE_CHANGED_DURING_WALK,
                    format!("{relative} stopped being a directory while it was walked ({error})"),
                )
            } else {
                refused(WORK_TREE_UNREADABLE, format!("{relative}: {error}"))
            }
        })
}

/// The type read off the OPENED descriptor must be the type the listing classified.
#[cfg(any(test, feature = "test-support"))]
fn require_kind(
    file: &std::fs::File,
    expected: Kind,
    relative: &str,
) -> KataResult<std::fs::Metadata> {
    let metadata = file
        .metadata()
        .map_err(|error| refused(WORK_TREE_UNREADABLE, format!("{relative}: {error}")))?;
    let found = kind_of(
        rustix::fs::FileType::from_raw_mode(metadata.mode()),
        relative,
    )?;
    if found != expected {
        return Err(refused(
            WORK_TREE_CHANGED_DURING_WALK,
            format!("{relative} changed type while it was walked"),
        ));
    }
    Ok(metadata)
}

/// The refusal token for re-presenting one occurrence over a DIFFERENT bound tree.
pub const WORK_TREE_DIVERGENT_REDECLARATION: &str = "work_tree_divergent_redeclaration";

/// Refuse binding `artifact` as `/work` for an occurrence whose stored row already binds a
/// DIFFERENT tree — the head artifact its first submit mapped. Nothing is written.
///
/// # Errors
///
/// [`WORK_TREE_DIVERGENT_REDECLARATION`], and a plane read failure.
pub fn refuse_divergent_work_tree(
    db: &OperationalDb,
    occurrence_id: [u8; 32],
    artifact: [u8; 32],
) -> KataResult<()> {
    let Some(stored) = db
        .occurrence(occurrence_id)?
        .and_then(|row| row.work_tree_artifact_id)
    else {
        return Ok(());
    };
    if stored == artifact {
        return Ok(());
    }
    Err(refused(
        WORK_TREE_DIVERGENT_REDECLARATION,
        format!(
            "occurrence {} already binds /work tree {} and this attempt maps {}. The \
             /work head moved between two submissions of ONE occurrence; running the second over \
             different inputs would be a different body of work under the same occurrence",
            hex::encode(occurrence_id),
            hex::encode(stored),
            hex::encode(artifact)
        ),
    ))
}

/// The publish-and-declare body [`publish_scratch_tree_head`] owns: every
/// member published, verified against the manifest's own
/// recorded address and length, then the manifest and its `kind='tree'`
/// declaration.
#[cfg(any(test, feature = "test-support"))]
fn publish_walked_tree(
    db: &OperationalDb,
    cas: &CasStore,
    execution: Ulid,
    walked: &WalkedTree,
) -> KataResult<ArtifactRef> {
    // `members` is one byte-string per FILE entry, in manifest order; a symlink
    // entry has no member bytes — its content is the target inside the manifest.
    let mut members = walked.members.iter();
    for entry in walked.manifest.entries() {
        let TreeNode::File {
            object, size_bytes, ..
        } = &entry.node
        else {
            continue;
        };
        let bytes = members.next().ok_or_else(|| {
            KataError::Validation(format!(
                "work tree: the manifest names {} and the walk read no such member",
                entry.path.as_str()
            ))
        })?;
        let receipt = cas.put_durable(bytes)?;
        if receipt.object_id() != *object || receipt.size() != *size_bytes {
            return Err(refused(
                WORK_TREE_MEMBER_UNVERIFIED,
                format!(
                    "{} was walked as {} bytes at {} and the store recorded {} bytes at {}",
                    entry.path.as_str(),
                    size_bytes,
                    object,
                    receipt.size(),
                    receipt.object_id()
                ),
            ));
        }
    }
    debug_assert!(
        members.next().is_none(),
        "the walk records one member per FILE entry: an unconsumed member means the \
         manifest and the member list disagreed"
    );
    let manifest_durable = cas.put_durable(&walked.manifest_bytes)?;
    let reference = declare_work_tree(db, cas, execution, &walked.manifest, &manifest_durable)?;
    Ok(reference)
}

/// Publish a host directory as an execution's durable `/work` head — walk it,
/// publish the walked tree, and record it as the root (`branch = ''`)
/// `execution_work_tree_heads` row.
///
/// TEST-FIXTURE tooling: there is no production caller
/// (`kata_api::executor`'s non-isolated admission seeds the canonical empty
/// tree through `declare_empty_tree` — nothing legitimately pre-populates a
/// scratch dir before admission), so the callers are test rigs
/// authoring `/work` content (a seed with real files).
///
/// `base_commit` and `candidate_commit_id` are recorded EMPTY: there is no jj
/// workspace behind a non-isolated execution, and the row documents exactly
/// that — the head's content is the published tree and every applies'
/// CAS-advanced tree, never a commit the provider checked out. The same
/// emptiness is what routes this execution's applies onto the CAS-only leg:
/// a `''` candidate is the recorded fact "no checkout to rewrite".
///
/// # The window this leaves
///
/// `operational.after_scratch_seed_published_before_head_recorded` — members,
/// manifest, `artifacts` and `cas_roots` durable, the head row not yet
/// written. Recovery re-runs the seed: `record_work_tree_head`'s
/// converge-or-refuse accepts an identical re-seed (CAS dedup makes the
/// republish content-idempotent) and refuses a divergent one by name
/// ([`WORK_TREE_HEAD_DIVERGENT`](crate::operational::WORK_TREE_HEAD_DIVERGENT)).
///
/// # Errors
///
/// [`walk_work_tree`]'s refusals, [`declare_work_tree`]'s,
/// `record_work_tree_head`'s, and the store's.
#[cfg(any(test, feature = "test-support"))]
pub fn publish_scratch_tree_head(
    db: &OperationalDb,
    cas: &CasStore,
    execution: Ulid,
    scratch_root: &std::path::Path,
) -> KataResult<crate::operational::ExecutionWorkTreeHead> {
    let walked = walk_work_tree(scratch_root)?;
    let reference = publish_walked_tree(db, cas, execution, &walked)?;
    crate::fault_inject::operational_crash_point(
        "after_scratch_seed_published_before_head_recorded",
    );
    db.record_work_tree_head(execution, "", reference.id().0.0, "")
}

/// DECLARE a published work-tree manifest retained by `execution`, after the
/// presence-and-length check over every member.
///
/// # Errors
///
/// [`WORK_TREE_MEMBER_UNVERIFIED`], and `declare_artifact`'s own refusals.
pub fn declare_work_tree(
    db: &OperationalDb,
    cas: &CasStore,
    execution: Ulid,
    manifest: &TreeManifest,
    durable: &DurableObject,
) -> KataResult<ArtifactRef> {
    crate::operational::refuse_absent_or_mismeasured_member(cas, manifest)
        .map_err(|error| refused(WORK_TREE_MEMBER_UNVERIFIED, error))?;
    let privacy = privacy_for(manifest);
    let declaration = ArtifactDeclaration::for_durable_tree(
        manifest,
        privacy,
        CasRootOwner::Execution(execution),
        durable,
    )?;
    db.declare_artifact(&declaration)?;
    Ok(ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        privacy,
    ))
}

/// DECLARE the canonical EMPTY tree retained by `execution`: what a capsule maps at `/out`
/// and `/tmp`, and which `declare_capsule` requires a live row for like any other mapping.
///
/// # Errors
///
/// A store or declaration refusal.
pub fn declare_empty_tree(
    db: &OperationalDb,
    cas: &CasStore,
    execution: Ulid,
) -> KataResult<ArtifactRef> {
    let empty = TreeManifest::new(Vec::new())?;
    let durable = cas.put_durable(&empty.manifest_bytes()?)?;
    let reference = declare_work_tree(db, cas, execution, &empty, &durable)?;
    Ok(reference)
}

/// PUBLISH a COMMITTED base tree as the execution's
/// durable `/work` head, and RECORD it.
///
/// `convert` is the VCS provider's committed-base conversion
/// (`kata_effects_contract::ExecutionWorkspaceProvider::committed_base_tree`,
/// wired at `kata_api`'s admission): it walks the base commit's `MergedTree` and invokes
/// the supplied `put_member` once per file member. This function backs the
/// callback with the CAS, so member bytes stream into the
/// store as the conversion produces them and the whole tree is never held at
/// once — the streaming property the callback shape exists for. The manifest
/// publishes after the members and is declared execution-retained by
/// [`declare_work_tree`], exactly as a walked tree's.
///
/// # The window this leaves
///
/// `operational.after_base_tree_published_before_head_recorded` — members and
/// manifest durable, `artifacts` + `cas_roots` rows committed, and the
/// `execution_work_tree_heads` row NOT yet written. Recovery is RE-ADMISSION:
/// the admission path reads no head row, drives this function again, CAS
/// deduplicates the same content, and
/// `record_work_tree_head` inserts the row the first drive never reached. A
/// head row that already exists is returned unchanged; a divergent one is
/// refused (`WORK_TREE_HEAD_DIVERGENT`). The window is narrower than the
/// equivalent walked-tree one by construction: no occurrence exists yet, so
/// no claim can outrun it.
///
/// # Errors
///
/// The conversion's refused set (the `work_tree_base_*` family),
/// [`declare_work_tree`]'s, `record_work_tree_head`'s, and the store's.
pub fn publish_base_tree_head(
    db: &OperationalDb,
    cas: &CasStore,
    execution: Ulid,
    convert: impl FnOnce(&mut dyn FnMut(&[u8]) -> KataResult<ObjectId>) -> KataResult<CommittedBaseTree>,
) -> KataResult<ExecutionWorkTreeHead> {
    let committed = convert(&mut |bytes: &[u8]| Ok(cas.put_durable(bytes)?.object_id()))?;
    let manifest_durable = cas.put_durable(&committed.manifest_bytes)?;
    let reference = declare_work_tree(db, cas, execution, &committed.manifest, &manifest_durable)?;
    crate::fault_inject::operational_crash_point("after_base_tree_published_before_head_recorded");
    let head = db.record_work_tree_head(
        execution,
        &committed.base_commit,
        reference.id().0.0,
        &committed.candidate_commit_id,
    )?;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::{
        Kind, WORK_TREE_CHANGED_DURING_WALK, WORK_TREE_SYMLINK, classify, open_beneath,
        require_kind,
    };

    fn dir_with_link() -> (tempfile::TempDir, std::fs::File) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.path().join("target"), dir.path().join("link")).unwrap();
        let handle = std::fs::File::open(dir.path()).unwrap();
        (dir, handle)
    }

    /// The LISTING half alone: `classify` reads the entry without following it, so a
    /// symlink is refused by name before anything opens it.
    #[test]
    fn classify_refuses_a_symlink_without_following_it() {
        let (_dir, handle) = dir_with_link();
        let refusal = classify(&handle, &CString::new("link").unwrap(), "link")
            .expect_err("a symlink is not a tree entry")
            .to_string();
        assert!(refusal.contains(WORK_TREE_SYMLINK), "{refusal}");
        assert_eq!(
            classify(&handle, &CString::new("target").unwrap(), "target").unwrap(),
            Kind::File
        );
    }

    /// The OPEN half alone: a name that is a symlink by the time it is opened (the race
    /// the listing cannot close) fails `O_NOFOLLOW` and is refused by name — the open is
    /// never followed out of the workspace.
    #[test]
    fn open_beneath_refuses_a_symlink_it_was_asked_to_open() {
        let (_dir, handle) = dir_with_link();
        let refusal = open_beneath(&handle, &CString::new("link").unwrap(), false, "link")
            .expect_err("O_NOFOLLOW refuses the link")
            .to_string();
        assert!(refusal.contains(WORK_TREE_SYMLINK), "{refusal}");
        open_beneath(&handle, &CString::new("target").unwrap(), false, "target")
            .expect("a regular file opens");
    }

    /// `work_tree_changed_during_walk`, the OPEN site: an entry the listing classified a
    /// DIRECTORY that is a regular file by the time it is opened (the swap the listing
    /// cannot close) fails `O_DIRECTORY` with `ENOTDIR`, and is refused as changed — not
    /// as unreadable, and not as a symlink.
    #[test]
    fn open_beneath_refuses_a_directory_that_became_a_file_as_changed() {
        let (_dir, handle) = dir_with_link();
        let refusal = open_beneath(&handle, &CString::new("target").unwrap(), true, "target")
            .expect_err("O_DIRECTORY refuses a regular file")
            .to_string();
        assert!(refusal.contains(WORK_TREE_CHANGED_DURING_WALK), "{refusal}");
    }

    /// `work_tree_changed_during_walk`, the DESCRIPTOR site: the type read off the opened
    /// descriptor must be the type the listing classified — a file opened where the
    /// listing saw a directory, and a directory where it saw a file, are both refused as
    /// changed. The matching kinds are admitted, so the cell cannot pass by refusing all.
    #[test]
    fn require_kind_refuses_a_descriptor_whose_type_changed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), b"x").unwrap();
        let file = std::fs::File::open(dir.path().join("file")).unwrap();
        let directory = std::fs::File::open(dir.path()).unwrap();
        for (opened, expected) in [(&file, Kind::Directory), (&directory, Kind::File)] {
            let refusal = require_kind(opened, expected, "swapped")
                .expect_err("a changed type is refused")
                .to_string();
            assert!(refusal.contains(WORK_TREE_CHANGED_DURING_WALK), "{refusal}");
        }
        require_kind(&file, Kind::File, "file").expect("a file stays a file");
        require_kind(&directory, Kind::Directory, "dir").expect("a directory stays one");
    }
}
