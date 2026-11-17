//! The WORKER reports what a stage changed under `/work` as
//! a TREE DELTA artifact.
//!
//! # What this module is
//!
//! [`publish_work_delta`] takes the host directory a capsule's `/work` mapping
//! was materialized into — the directory the container's `/work` bind wrote —
//! and publishes the DIFFERENCE against the very tree artifact the mapping
//! named, as a [`TreeDelta`]. It is the workspace half of the capsule plane's
//! mutation record: [`crate::result_publication`] publishes `/out` wholesale,
//! this publishes `/work` as a diff — bounded by the change's size, not the
//! repo's.
//!
//! The artifact reference it returns rides `WorkerMessage::CompletedCapsule`'s
//! `work_delta` field; a capsule that maps no `/work` never reaches here and
//! reports `None` instead — an absent mapping and an unchanged tree are
//! different answers and the wire carries them differently.
//!
//! # The walk is LEXICAL — no path resolved twice, no link ever followed
//!
//! Every operation is relative to a descriptor proven a directory ONCE
//! ([`crate::materialize::Dir`], the same proven-fd type the materializer writes
//! through): `getdents` for names, `statat` with `AT_SYMLINK_NOFOLLOW` for
//! kinds, `readlinkat` for a link's target bytes — VERBATIM, never resolved —
//! and `openat` with `O_NOFOLLOW` for member bytes. A symlink is content: an
//! unchanged link produces no change, a created or retargeted one a
//! `Write{Symlink}`, a file↔link flip a `Write`, and a missing entry a
//! `Delete` — [`TreeDelta::between`] owns all four dispositions; this module's
//! job is to hand it a faithful post-run manifest.
//!
//! # Excluded set, stated exactly
//!
//! A post-run path is EXCLUDED
//! from the delta iff it is absent from the base manifest — untracked — AND
//! ignored under git semantics by the `.gitignore` files present in the
//! post-run tree itself (the root's and every descended directory's; negation,
//! dir-only patterns, anchoring, and a deeper file's precedence are the
//! `gix-ignore` matcher's, which is how `git status` / `git add -A` treat
//! them). A tracked path is NEVER excluded: a modification or a deletion
//! counts, ignored or not.
//!
//! **The residual this admits, stated exactly.** The post-run `.gitignore`
//! files include the ones the stage itself wrote, and a written `.gitignore`'s
//! patterns apply whether or not the file itself is excluded. An untracked
//! `.gitignore` is excluded whenever it is itself ignored — by its own
//! patterns (`*`) or by any other applicable `.gitignore`, tracked (a base
//! `.*`) or written — and every untracked path its patterns ignore is excluded
//! with it. So a stage can take out of its own delta any NEW path for which it
//! can write such a file in a directory on that path holding no tracked
//! `.gitignore` (a new directory always qualifies). What still counts: a
//! tracked path beneath it, a change to a tracked one, and a written
//! `.gitignore` nothing ignores — though the untracked paths ITS patterns
//! ignore leave the delta all the same, so under `workspace = "ro"` it is that
//! `.gitignore` itself the judge refuses. Under `workspace = "ro"` an excluded
//! path is discarded, not refused: nothing of it lands, and the stage gets no
//! failure signal
//! (`a_self_ignoring_gitignore_drops_its_new_siblings_from_the_delta`,
//! `an_ignored_written_gitignore_drops_what_it_ignores_from_the_delta`).
//! Judging new paths against the base tree's `.gitignore` files alone would
//! close it; that is a semantics change this census does not make.
//!
//! An ignored directory holding no tracked member beneath it is PRUNED —
//! never opened — so nothing inside is inspected: a socket or a nested `.git`
//! under `target/` produces no refusal, no entry and no bound charge. An
//! ignored directory that DOES hold tracked members is descended for them
//! alone — git cannot re-include under an excluded parent, so every untracked
//! descendant stays excluded and its own `.gitignore` is never consulted.
//!
//! Only `.gitignore` files are consulted — not `.git/info/exclude`, not
//! `core.excludesFile`, not any global or host exclude list: kata inherits
//! the repo's committed answer, never a machine's. A `.gitignore` that is not
//! a regular file contributes no patterns — a link's target is content, never
//! resolved. Matching runs on raw name bytes, so a non-UTF-8 name under an
//! ignore pattern is excluded rather than refused.
//!
//! The top-level `/work/.git` entry is excluded by construction, whatever its
//! type — it is the git view's gitfile, kata's own
//! plumbing rather than stage content. Every OTHER `.git`/`.jj` component —
//! a nested `src/.git` included — stays refused exactly as
//! `reserved_vcs_component` already spelled it.
//!
//! # Refused set, stated exactly
//!
//! [`WorkDeltaRefusal`]'s arms are the whole list, and they apply to entries
//! the walk actually SEES — an excluded path can produce none of them, because
//! it is never inspected beyond the stat its exclusion needed: an unwalkable
//! directory, an entry no `TreePath`/`SymlinkTarget`/`TreeNode` can carry
//! (non-UTF-8 name or target, an over-long or NUL-bearing one, a member over
//! [`MAX_MEMBER_BYTES`]), a fifo/socket/device — which no manifest can
//! represent, so it is refused rather than dropped — a base the resolver cannot
//! produce, the capsule's `work_delta_entries`/`work_delta_bytes` bounds, the
//! delta's own encoding ceiling, a member that moved between the scan and the
//! publish, and the store refusing bytes.
//!
//! # SCAN, BOUND, THEN PUBLISH — the same order as `/out`, for the same reason
//!
//! The whole walk and both budget checks run BEFORE one byte is published, and
//! the delta's own bytes go in LAST — after every member it names — for the
//! reason `ArtifactDeclaration::for_durable_tree` states from the adopting
//! side: a delta is a promise about objects, and a promise published before
//! the objects exist is one a reader can catch in a state where it is false.
//!
//! # The crash window, named
//!
//! `operational.after_work_delta_published_before_completion` fires once the
//! delta's bytes are durable — members and delta in the store, no
//! `CompletedCapsule` frame anywhere — and its recovery is the result-publish
//! window's own, stated in [`crate::result_publication`]'s module docs: the
//! residue is an orphan (the worker cannot write a root row), and the only
//! thing that could adopt the delta is the frame the abort prevented.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use kata_types::cache::{ObjectIdHasher, object_id_for_canonical_bytes};
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{ArtifactId, ArtifactRef, CapsuleBudgets};
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::{
    MAX_MEMBER_BYTES, SymlinkTarget, TreeEntry, TreeManifest, TreeNode, TreePath,
};
use kata_types::tree_delta::{TreeChangeKind, TreeDelta};

use crate::materialize::{Dir, TreeResolver};
use crate::result_publication::{BlobSink, RESULT_PRIVACY, executable_mode};

/// The privacy a published `/work` delta carries: [`RESULT_PRIVACY`], and the
/// empty-delta exception does NOT apply — a delta's bytes embed its base
/// reference, so an "empty" delta is still per-base stage-produced content, not
/// a canonical object every node shares.
const DELTA_PRIVACY: kata_types::execution_contract::ArtifactPrivacy = RESULT_PRIVACY;

/// The guest path the `/work` mapping sits at — [`MATERIALIZED_ROOTS`]' spelling,
/// which `mapping_root` is the only door that accepts.
///
/// [`MATERIALIZED_ROOTS`]: crate::materialize
pub(crate) const WORK_GUEST_ROOT: &str = "/work";

/// What `materialize` observed about one `/work` member the moment it wrote it
/// — `(st_ino, st_size, st_ctime, kind, owner-exec)` — the tuple whose equality
/// lets the post-run scan REUSE the base's node instead of re-reading bytes.
///
/// `st_ctime` is the load-bearing field and the reason is syscall law: an
/// unprivileged process can rewind `mtime`/`atime` (`utimensat` reaches both)
/// but ctime is the kernel's own metadata-change stamp — `printf > f` moves it,
/// `chmod` moves it, a rewrite in place moves it. A tuple including ctime
/// therefore answers "this member is the same bytes" for anything the guest
/// could do to it, and the scan's read of an unchanged member is skipped
/// entirely.
///
/// Inode reuse between materialize and scan is not a hazard: the snapshot lives
/// and dies inside one attempt's root, which the attempt lock holds for the
/// duration — a new inode CAN appear (the guest rewrites a file by
/// rename-over), but then `st_ino` differs and the tuple misses, which is
/// exactly the fallback that re-reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializationSnapshot {
    tuples: std::collections::BTreeMap<String, SnapshotTuple>,
}

/// One member's materialize-time kernel stamp.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotTuple {
    /// `st_ino`.
    inode: u64,
    /// `st_size`.
    size: u64,
    /// `st_ctime` — seconds.
    ctime_secs: u64,
    /// `st_ctime_nsec` — the nanoseconds arm of the same stamp.
    ctime_nanos: u64,
    /// `FileType` reduced to the two kinds a manifest can carry: file or link.
    kind: u8,
    /// Any owner-exec bit — the manifest's `Executable`/`Regular` distinction.
    executable: bool,
}

/// The `SnapshotTuple` a `statat` answer carries.
fn snapshot_tuple(stat: &rustix::fs::Stat) -> SnapshotTuple {
    SnapshotTuple {
        inode: stat.st_ino,
        size: stat.st_size.cast_unsigned(),
        ctime_secs: stat.st_ctime.cast_unsigned(),
        ctime_nanos: stat.st_ctime_nsec,
        kind: match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
            rustix::fs::FileType::Symlink => 1,
            _ => 0,
        },
        executable: stat.st_mode & 0o111 != 0,
    }
}

impl MaterializationSnapshot {
    /// Record every member's tuple under `root` — a stat-only walk, no byte is
    /// read. Called by `materialize` the moment the `/work` tree is complete,
    /// so the snapshot states the tree the STAGE was handed rather than the
    /// bytes the resolver promised.
    ///
    /// # Errors
    ///
    /// A directory that cannot be walked is the materializer's own refusal —
    /// the tree it just wrote must be readable back.
    pub fn take(root: &Path) -> KataResult<Self> {
        let dir = Dir::open(root).map_err(|error| {
            KataError::Storage(format!(
                "materialization snapshot refused of {} could not open the root: {error}",
                root.display()
            ))
        })?;
        let mut tuples = std::collections::BTreeMap::new();
        let mut pending = vec![(dir, String::new())];
        while let Some((directory, prefix)) = pending.pop() {
            let names = directory.entries().map_err(|error| {
                KataError::Storage(format!(
                    "materialization snapshot could not list {}: {error}",
                    directory.display().display()
                ))
            })?;
            for name in names {
                let Ok(name_str) = name.to_str() else {
                    continue;
                };
                let relative = if prefix.is_empty() {
                    name_str.to_owned()
                } else {
                    format!("{prefix}/{name_str}")
                };
                let stat = directory.stat_child(&name).map_err(|error| {
                    KataError::Storage(format!(
                        "materialization snapshot could not stat {}: {error}",
                        directory.display().join(name_str).display()
                    ))
                })?;
                match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
                    rustix::fs::FileType::Directory => {
                        let child = directory.open_child_dir(&name).map_err(|error| {
                            KataError::Storage(format!(
                                "materialization snapshot could not descend {}: {error}",
                                directory.display().join(name_str).display()
                            ))
                        })?;
                        pending.push((child, relative));
                    }
                    rustix::fs::FileType::RegularFile | rustix::fs::FileType::Symlink => {
                        tuples.insert(relative, snapshot_tuple(&stat));
                    }
                    _ => {}
                }
            }
        }
        Ok(Self { tuples })
    }

    /// How many members were stamped — a test's check against the materialized
    /// entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tuples.len()
    }

    /// `len() == 0` — the materialized tree carried no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tuples.is_empty()
    }

    /// Whether `stat` is the tuple `take` recorded at `path` — every field, so
    /// a guest that rewrote content and rewound mtime still misses on ctime.
    fn matches(&self, path: &str, stat: &rustix::fs::Stat) -> bool {
        self.tuples
            .get(path)
            .is_some_and(|recorded| *recorded == snapshot_tuple(stat))
    }
}

/// Why a stage's `/work` did not become a delta artifact.
///
/// A typed enum for [`crate::result_publication::ResultPublicationRefusal`]'s
/// reason: the refused set is exactly this list, and each arm's label is what a
/// log field and a test assertion key on.
#[derive(Debug)]
pub enum WorkDeltaRefusal {
    /// `/work` or an entry beneath it could not be opened, read or statted.
    Unreadable { path: PathBuf, error: String },
    /// An entry no tree type can carry: a non-UTF-8 name, a symlink target that
    /// is not UTF-8 or that [`SymlinkTarget`] refuses, a path [`TreePath`]
    /// refuses.
    Unrepresentable { path: PathBuf, reason: String },
    /// A fifo, socket, device node or other non-file non-link entry — kinds no
    /// [`TreeNode`] arm can name, so they are refused rather than dropped.
    SpecialFile { path: PathBuf, kind: &'static str },
    /// A member over [`MAX_MEMBER_BYTES`] — the same per-member ceiling the
    /// materializer reads at, so a delta this side publishes is never one the
    /// next worker declines.
    MemberOverCeiling { path: PathBuf, size_bytes: u64 },
    /// The base artifact's reference or manifest could not be resolved.
    BaseUnresolved(KataError),
    /// [`TreeDelta::between`]'s own base check fired — unreachable through a
    /// resolver that answers `tree_reference` and `tree_manifest` consistently,
    /// typed anyway so a resolver that doesn't is refused rather than believed.
    BaseMismatch(KataError),
    /// The walked entry list is not a manifest — unreachable from a real
    /// filesystem (one name holds one inode), typed anyway.
    ResultInvalid(KataError),
    /// The delta carries more changes than the capsule's `work_delta_entries`
    /// budget. Refused BEFORE any byte is published.
    TooManyChanges { changes: u64, budget: u32 },
    /// The delta's written members total more than the capsule's
    /// `work_delta_bytes` budget. Refused BEFORE any byte is published.
    TooManyBytes { bytes: u64, budget: u64 },
    /// The delta's canonical encoding is over
    /// [`TreeDelta::MAXIMUM_ENCODED_BYTES`] — the ceiling every reader bounds at.
    /// Refused BEFORE any byte is published.
    DeltaOverCeiling(KataError),
    /// A member's byte length moved between its stat and the end of its read —
    /// a still-writing file is the thing a confirmed teardown said was
    /// impossible, so this is a refusal, not a re-measure.
    MemberChanged {
        path: PathBuf,
        scanned: u64,
        read: u64,
    },
    /// A member re-read for publication does not address to the node the delta
    /// carries — same-length different-bytes drift, [`Self::MemberChanged`]'s
    /// sibling.
    MemberRewritten {
        path: PathBuf,
        scanned: ObjectId,
        read: ObjectId,
    },
    /// A member's or the delta's bytes could not be read at publish time, or
    /// the store refused them.
    PublicationFailed(KataError),
}

impl WorkDeltaRefusal {
    /// The stable token for a log field and a test assertion.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Unreadable { .. } => "work_delta_unreadable",
            Self::Unrepresentable { .. } => "work_delta_unrepresentable",
            Self::SpecialFile { .. } => "work_delta_special_file",
            Self::MemberOverCeiling { .. } => "work_delta_member_over_ceiling",
            Self::BaseUnresolved(_) => "work_delta_base_unresolved",
            Self::BaseMismatch(_) => "work_delta_base_mismatch",
            Self::ResultInvalid(_) => "work_delta_result_invalid",
            Self::TooManyChanges { .. } => "work_delta_entries_exceeded",
            Self::TooManyBytes { .. } => "work_delta_bytes_exceeded",
            Self::DeltaOverCeiling(_) => "work_delta_over_ceiling",
            Self::MemberChanged { .. } => "work_delta_member_changed",
            Self::MemberRewritten { .. } => "work_delta_member_rewritten",
            Self::PublicationFailed(_) => "work_delta_publication_failed",
        }
    }
}

impl std::fmt::Display for WorkDeltaRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "work delta refused ({}): ", self.label())?;
        match self {
            Self::Unreadable { path, error } => write!(
                f,
                "{} could not be walked ({error}). The container's `/work` bind is how a stage's \
                 mutation leaves it, so an unwalkable one is a mutation that cannot be reported \
                 rather than an empty one",
                path.display()
            ),
            Self::Unrepresentable { path, reason } => write!(
                f,
                "{} is unrepresentable in a tree artifact: {reason}",
                path.display()
            ),
            Self::SpecialFile { path, kind } => write!(
                f,
                "{} is a {kind}, which no tree node can name — a delta that dropped it would \
                 record a `/work` that never existed, so it is refused instead",
                path.display()
            ),
            Self::MemberOverCeiling { path, size_bytes } => write!(
                f,
                "{} is {size_bytes} bytes, over the {MAX_MEMBER_BYTES}-byte per-member ceiling \
                 every materializer reads at — a delta carrying it would name a member no next \
                 worker can write",
                path.display()
            ),
            Self::BaseUnresolved(error)
            | Self::BaseMismatch(error)
            | Self::ResultInvalid(error) => write!(f, "{error}"),
            Self::TooManyChanges { changes, budget } => write!(
                f,
                "the delta carries {changes} changes and the capsule's work_delta_entries budget \
                 is {budget}. NOTHING WAS PUBLISHED: the bound is checked over the whole delta \
                 before the first member is written, so a refused delta leaves no bytes in the \
                 content store"
            ),
            Self::TooManyBytes { bytes, budget } => write!(
                f,
                "the delta's written members total {bytes} bytes and the capsule's \
                 work_delta_bytes budget is {budget}. NOTHING WAS PUBLISHED — see the \
                 change-count refusal's note"
            ),
            Self::DeltaOverCeiling(error) => write!(
                f,
                "{error}. NOTHING WAS PUBLISHED — the delta is measured before the first member \
                 is written"
            ),
            Self::MemberChanged {
                path,
                scanned,
                read,
            } => write!(
                f,
                "{} was {scanned} bytes when the tree was walked and {read} when it was read. \
                 Something is still writing into `/work` after the container exited — refusing \
                 rather than re-measuring, because a second measurement is a second guess",
                path.display()
            ),
            Self::MemberRewritten {
                path,
                scanned,
                read,
            } => write!(
                f,
                "{} addressed to {scanned} when the tree was walked and to {read} at the publish \
                 read — same length, different bytes. Something is still writing into `/work` \
                 after the container exited",
                path.display()
            ),
            Self::PublicationFailed(error) => {
                write!(
                    f,
                    "a member's or the delta's bytes could not be published: {error}"
                )
            }
        }
    }
}

impl std::error::Error for WorkDeltaRefusal {}

impl From<WorkDeltaRefusal> for KataError {
    fn from(refusal: WorkDeltaRefusal) -> Self {
        KataError::Validation(refusal.to_string())
    }
}

/// Publish the delta from the `/work` mapping's base tree to the post-run
/// contents of `work`, bounded by the capsule's `work_delta_*` budgets, and
/// return the artifact reference the `CompletedCapsule` frame carries.
///
/// Members are published BEFORE the delta bytes — the promise after the
/// objects. Nothing that did not change is re-published: an unchanged member's
/// object is already retained by the input declaration's `cas_roots`, and
/// re-writing it would be a second copy of bytes the store already addresses.
///
/// # Errors
///
/// Exactly [`WorkDeltaRefusal`]'s arms.
pub fn publish_work_delta(
    work: &Path,
    base_artifact: ArtifactId,
    trees: &dyn TreeResolver,
    budgets: CapsuleBudgets,
    sink: &dyn BlobSink,
    snapshot: Option<&MaterializationSnapshot>,
    view: Option<&kata_types::execution_contract::CapsuleWorkView>,
) -> Result<ArtifactRef, WorkDeltaRefusal> {
    // The BASE first, through the same resolver the materializer read it
    // through — a mapping whose artifact this assignment carries no reference
    // for is refused by the same door, with the same vocabulary.
    let base_reference = trees
        .tree_reference(base_artifact)
        .map_err(WorkDeltaRefusal::BaseUnresolved)?;
    let base = trees
        .tree_manifest(base_artifact)
        .map_err(WorkDeltaRefusal::BaseUnresolved)?;

    let root = Dir::open(work).map_err(|error| WorkDeltaRefusal::Unreadable {
        path: work.to_path_buf(),
        error: error.to_string(),
    })?;
    // The base manifest's nodes by path, for the snapshot fast path: a member
    // whose kernel stamp is the materializer's own record of it carries the
    // SAME content, so the node the base already names IS the post-run node —
    // no re-read, no re-hash.
    let base_nodes: std::collections::HashMap<&str, &TreeNode> = base
        .entries()
        .iter()
        .map(|entry| (entry.path.as_str(), &entry.node))
        .collect();
    // The same paths in the manifest's own sorted order — the lookup
    // `tracked_beneath` answers "does the base track anything under this
    // directory" with, which is what keeps an ignored directory's tracked
    // members (and their deletions) reachable.
    let base_paths: Vec<&str> = base
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    let mut entries = Vec::new();
    scan(
        &root,
        String::new(),
        &mut entries,
        snapshot,
        &base_nodes,
        &base_paths,
    )?;
    // The confined `/work` view: the container held only the
    // members the view covers, so a base member outside it was never ABSENT
    // — it was never MATERIALIZED, which the delta must not read as the
    // stage deleting it. Fold every uncovered base member into the result
    // UNCHANGED, so `TreeDelta::between` emits no delete for it. A member the
    // stage actually wrote at an uncovered path stays a scan entry (the
    // clone skips it), and the adoption-side `produces_files` fence is what
    // refuses that write.
    if let Some(view) = view {
        let scanned: std::collections::HashSet<&TreePath> =
            entries.iter().map(|entry| &entry.path).collect();
        let mut merged: Vec<TreeEntry> = Vec::with_capacity(entries.len() + base.entries().len());
        for entry in base.entries() {
            if !view.covers(entry.path.as_str()) && !scanned.contains(&entry.path) {
                merged.push(entry.clone());
            }
        }
        entries.extend(merged);
    }
    let result = TreeManifest::new(entries).map_err(WorkDeltaRefusal::ResultInvalid)?;
    let delta = TreeDelta::between(base_reference, &base, &result)
        .map_err(WorkDeltaRefusal::BaseMismatch)?;

    // THE BOUNDS, over the whole delta, before a byte is published — the same
    // contract as the result publisher's module docs state for `/out`.
    let changes = delta.changes().len() as u64;
    if changes > u64::from(budgets.work_delta_entries) {
        return Err(WorkDeltaRefusal::TooManyChanges {
            changes,
            budget: budgets.work_delta_entries,
        });
    }
    let written = delta
        .changes()
        .iter()
        .try_fold(0u64, |total, change| match &change.change {
            TreeChangeKind::Write { node } => total.checked_add(node.size_bytes()),
            TreeChangeKind::Delete => Some(total),
        })
        .ok_or(WorkDeltaRefusal::TooManyBytes {
            bytes: u64::MAX,
            budget: budgets.work_delta_bytes,
        })?;
    if written > budgets.work_delta_bytes {
        return Err(WorkDeltaRefusal::TooManyBytes {
            bytes: written,
            budget: budgets.work_delta_bytes,
        });
    }
    let delta_bytes = delta.delta_bytes().map_err(|error| match error {
        error @ KataError::Validation(_) => WorkDeltaRefusal::DeltaOverCeiling(error),
        other => WorkDeltaRefusal::PublicationFailed(other),
    })?;

    // MEMBERS FIRST, the delta LAST — the promise after the objects, the same
    // rule the result publisher follows for the same adopting side.
    for change in delta.changes() {
        let TreeChangeKind::Write {
            node: TreeNode::File {
                object, size_bytes, ..
            },
        } = &change.change
        else {
            continue;
        };
        publish_member(&root, &change.path, *object, *size_bytes, sink)?;
    }
    let receipt = sink
        .publish(&delta_bytes)
        .map_err(WorkDeltaRefusal::PublicationFailed)?;
    // The delta and every member it names are fsync-durable in the store, and
    // the `CompletedCapsule` frame that could name them is not built yet — the
    // frame is constructed from this function's `Ok`, so nothing downstream of
    // an abort here can produce one. Recovery is the result-publish window's
    // own: the objects carry no root (the only writer of `cas_roots` is the
    // accepting transaction on the main), so they are orphan residue, and
    // the attempt's reclaim re-runs the stage rather than repairing this.
    kata_core::fault_inject::operational_crash_point(
        "after_work_delta_published_before_completion",
    );
    Ok(ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        DELTA_PRIVACY,
    ))
}

/// One directory the walk still owes a listing: the descriptor proven once,
/// the directory's `/work`-relative prefix, the pattern-list depth its
/// ancestors reached — its own `.gitignore` loads when the frame is popped
/// and a sibling's is truncated back away — and whether the directory is
/// itself EXCLUDED: an ignored directory descended only because the base
/// tracks members beneath it, opened for those members and nothing else.
struct PendingDir {
    dir: Dir,
    prefix: String,
    ancestor_patterns: usize,
    excluded: bool,
}

/// Walk `dir` recursively, appending one [`TreeEntry`] per regular file and per
/// symlink, at `prefix`-relative paths. Iterative because a path's depth is a
/// fact of the input, not of this function's stack.
///
/// Directories produce NO entry — a manifest implies them from paths — and a
/// link is never descended into: `open_child_dir`'s `O_NOFOLLOW` is what stands
/// between a planted link and a walk out of the root.
///
/// The excluded set the module doc states is applied per entry, BEFORE any
/// refusal or representability check the path could raise: `statat` answers
/// the kind (`is_dir` is what a dir-only pattern matches), the post-run
/// tree's own `.gitignore` stack answers the ignore question, and an excluded
/// path is never opened, read or named a member of.
fn scan(
    dir: &Dir,
    prefix: String,
    entries: &mut Vec<TreeEntry>,
    snapshot: Option<&MaterializationSnapshot>,
    base_nodes: &std::collections::HashMap<&str, &TreeNode>,
    base_paths: &[&str],
) -> Result<(), WorkDeltaRefusal> {
    // The REUSE decision, shared by the file and link arms: the materializer's
    // own kernel stamp still stands AND the base carries an entry at the path
    // (a snapshot can only describe members the base wrote — an entry absent
    // from the base is hashed like any other).
    let unchanged = |path: &str, stat: &rustix::fs::Stat| -> Option<TreeNode> {
        if snapshot.is_some_and(|s| s.matches(path, stat)) {
            base_nodes.get(path).map(|node| (*node).clone())
        } else {
            None
        }
    };
    // The post-run tree's own `.gitignore` files — the excluded set's whole
    // source. Lists stack root-first as directories open, so the matcher's
    // reversed scan order IS git's precedence: a deeper file's latest
    // matching line wins. `ancestor_patterns` truncates a sibling's or an
    // unstacked branch's lists back out when the frame pops.
    let mut search = gix_ignore::Search::default();
    let mut pending = vec![PendingDir {
        dir: dir.reopen().map_err(|error| unreadable(dir, error))?,
        prefix,
        ancestor_patterns: 0,
        excluded: false,
    }];
    while let Some(frame) = pending.pop() {
        let directory = frame.dir;
        search.patterns.truncate(frame.ancestor_patterns);
        if !frame.excluded {
            load_gitignore(&directory, &frame.prefix, &mut search)?;
        }
        for name in directory
            .entries()
            .map_err(|error| unreadable(&directory, error))?
        {
            // The git view's gitfile at `/work/.git` — the ONE `.git` the walk
            // never sees, whatever its type. Excluded by construction, before
            // stat or `TreePath`: it is kata's own plumbing, not stage content.
            if frame.prefix.is_empty() && name.to_bytes() == b".git" {
                continue;
            }
            let display = directory
                .display()
                .join(String::from_utf8_lossy(name.to_bytes()).as_ref());
            let stat = directory
                .stat_child(&name)
                .map_err(|error| unreadable_path(&display, &error))?;
            let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
            let is_dir = matches!(kind, rustix::fs::FileType::Directory);
            // The path the matcher answers, as raw BYTES — ignore patterns
            // match names, not text, so a non-UTF-8 name still answers `*`.
            // Only a NON-excluded path owes the `TreePath` below.
            let mut relative_bytes = frame.prefix.as_bytes().to_vec();
            if !relative_bytes.is_empty() {
                relative_bytes.push(b'/');
            }
            relative_bytes.extend_from_slice(name.to_bytes());
            let relative = std::str::from_utf8(&relative_bytes).ok();
            // Tracked means the base manifest names the path — for a
            // directory, that it holds a member beneath it, a manifest
            // implying directories from member paths and never listing one.
            // A tracked path is never excluded; an untracked one is excluded
            // when the pattern stack's last answer is not a negation, or when
            // its directory already is excluded — git re-includes nothing
            // beneath an excluded parent.
            let tracked = relative.is_some_and(|relative| {
                if is_dir {
                    tracked_beneath(base_paths, relative)
                } else {
                    base_nodes.contains_key(relative)
                }
            });
            let ignored = frame.excluded
                || search
                    .pattern_matching_relative_path(
                        bstr::BStr::new(&relative_bytes),
                        Some(is_dir),
                        gix_glob::pattern::Case::Sensitive,
                    )
                    .is_some_and(|matched| !matched.pattern.is_negative());
            if ignored {
                if !tracked {
                    // Pruned — never opened, no entry, no refusal, no bound.
                    continue;
                }
                if is_dir {
                    let child = directory
                        .open_child_dir(&name)
                        .map_err(|error| unreadable_path(&display, &error))?;
                    pending.push(PendingDir {
                        dir: child,
                        prefix: relative
                            .expect("a directory with a member tracked beneath it has a UTF-8 path")
                            .to_owned(),
                        ancestor_patterns: search.patterns.len(),
                        excluded: true,
                    });
                    continue;
                }
                // A tracked file or link matching an ignore pattern is never
                // excluded — it falls through to the same member handling an
                // unignored one gets.
            }
            let Some(relative) = relative.map(str::to_owned) else {
                return Err(WorkDeltaRefusal::Unrepresentable {
                    path: display,
                    reason: "the name is not UTF-8, and a tree path is".to_owned(),
                });
            };
            let path =
                TreePath::new(&relative).map_err(|error| WorkDeltaRefusal::Unrepresentable {
                    path: display.clone(),
                    reason: error.to_string(),
                })?;
            if let Some(component) = path.reserved_vcs_component() {
                return Err(WorkDeltaRefusal::Unrepresentable {
                    path: display,
                    reason: format!(
                        "{token}: `{component}` is a VCS-internal name — a delta \
                         path carrying it could never check out of a jj workspace, so it is \
                         refused at capture rather than published",
                        token = kata_types::tree_artifact::WORK_DELTA_RESERVED_PATH,
                    ),
                });
            }
            match kind {
                rustix::fs::FileType::Directory => {
                    let child = directory
                        .open_child_dir(&name)
                        .map_err(|error| unreadable_path(&display, &error))?;
                    pending.push(PendingDir {
                        dir: child,
                        prefix: relative,
                        ancestor_patterns: search.patterns.len(),
                        excluded: false,
                    });
                }
                rustix::fs::FileType::RegularFile => match unchanged(&relative, &stat) {
                    Some(node) => entries.push(TreeEntry { path, node }),
                    None => entries.push(scan_file(&directory, &name, path, display)?),
                },
                rustix::fs::FileType::Symlink => {
                    if let Some(node) = unchanged(&relative, &stat) {
                        entries.push(TreeEntry { path, node });
                        continue;
                    }
                    let target = directory
                        .read_link(&name)
                        .map_err(|error| unreadable_path(&display, &error))?;
                    let target =
                        target
                            .into_string()
                            .map_err(|_| WorkDeltaRefusal::Unrepresentable {
                                path: display.clone(),
                                reason: "the link's target is not UTF-8, and a SymlinkTarget is"
                                    .to_owned(),
                            })?;
                    let target = SymlinkTarget::new(target.as_str()).map_err(|error| {
                        WorkDeltaRefusal::Unrepresentable {
                            path: display.clone(),
                            reason: error.to_string(),
                        }
                    })?;
                    entries.push(TreeEntry {
                        path,
                        node: TreeNode::Symlink { target },
                    });
                }
                rustix::fs::FileType::Fifo => {
                    return Err(WorkDeltaRefusal::SpecialFile {
                        path: display,
                        kind: "fifo",
                    });
                }
                rustix::fs::FileType::Socket => {
                    return Err(WorkDeltaRefusal::SpecialFile {
                        path: display,
                        kind: "socket",
                    });
                }
                rustix::fs::FileType::CharacterDevice => {
                    return Err(WorkDeltaRefusal::SpecialFile {
                        path: display,
                        kind: "character device",
                    });
                }
                rustix::fs::FileType::BlockDevice => {
                    return Err(WorkDeltaRefusal::SpecialFile {
                        path: display,
                        kind: "block device",
                    });
                }
                rustix::fs::FileType::Unknown => {
                    return Err(WorkDeltaRefusal::SpecialFile {
                        path: display,
                        kind: "unknown kind",
                    });
                }
            }
        }
    }
    Ok(())
}

/// Whether the base manifest holds a member beneath the directory at
/// `relative` — the condition that makes an ignored directory descendable for
/// its tracked entries rather than pruned whole. `base_paths` is the
/// manifest's own canonical order, so the answer is a partition point plus a
/// prefix check.
fn tracked_beneath(base_paths: &[&str], relative: &str) -> bool {
    let prefix = format!("{relative}/");
    let index = base_paths.partition_point(|path| *path < prefix.as_str());
    base_paths
        .get(index)
        .is_some_and(|path| path.starts_with(prefix.as_str()))
}

/// Read `directory`'s `.gitignore` into `search` when one is present AND is a
/// regular file — the patterns the directory's own entries are then matched
/// against. `prefix` is the directory's `/work`-relative path, so the pattern
/// list's base is the directory itself: its rules govern beneath it, never
/// above.
///
/// A `.gitignore` that is not a regular file contributes no patterns — a
/// link's target is content, VERBATIM, never resolved, and a fifo is the
/// entry walk's own refusal.
fn load_gitignore(
    directory: &Dir,
    prefix: &str,
    search: &mut gix_ignore::Search,
) -> Result<(), WorkDeltaRefusal> {
    const GITIGNORE: &std::ffi::CStr = c".gitignore";
    let display = directory.display().join(".gitignore");
    let stat = match directory.stat_child(GITIGNORE) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(unreadable_path(&display, &error)),
    };
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Ok(());
    }
    let file = directory
        .open_child_file(GITIGNORE)
        .map_err(|error| unreadable_path(&display, &error))?;
    // The open descriptor's own fstat — `scan_file`'s discipline — so a
    // mid-walk swap cannot put a fifo's read beside the walk's stat.
    if !file
        .metadata()
        .map_err(|error| unreadable_path(&display, &error))?
        .is_file()
    {
        return Ok(());
    }
    // Bounded like any member's read — a `.gitignore` too large to carry as
    // one is also one this walk cannot honestly apply.
    let mut bytes = Vec::new();
    let mut limited = file.take(MAX_MEMBER_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable_path(&display, &error))?;
    if bytes.len() as u64 > MAX_MEMBER_BYTES {
        return Err(WorkDeltaRefusal::MemberOverCeiling {
            path: display,
            size_bytes: bytes.len() as u64,
        });
    }
    // `source` spelled relative to the `/work` root, so `add_patterns_buffer`
    // derives the list's base as this directory's own relative prefix.
    search.add_patterns_buffer(
        &bytes,
        PathBuf::from(prefix).join(".gitignore"),
        Some(Path::new("")),
        gix_ignore::search::Ignore::default(),
    );
    Ok(())
}

/// Hash one regular file's bytes into the [`TreeNode::File`] the walk records —
/// the object's content address computed over a STREAM, so the delta's node is
/// known before a single byte is published.
fn scan_file(
    dir: &Dir,
    name: &std::ffi::CStr,
    path: TreePath,
    display: PathBuf,
) -> Result<TreeEntry, WorkDeltaRefusal> {
    let mut file = dir
        .open_child_file(name)
        .map_err(|error| unreadable_path(&display, &error))?;
    // The OPEN descriptor's fstat, not the walk's statat: it answers for the
    // very bytes this function is about to hash, so a mid-walk swap cannot put
    // one kind's stat beside another kind's content.
    let metadata = file
        .metadata()
        .map_err(|error| unreadable_path(&display, &error))?;
    if !metadata.is_file() {
        return Err(WorkDeltaRefusal::SpecialFile {
            path: display,
            kind: "no longer a regular file",
        });
    }
    let size_bytes = metadata.len();
    if size_bytes > MAX_MEMBER_BYTES {
        return Err(WorkDeltaRefusal::MemberOverCeiling {
            path: display,
            size_bytes,
        });
    }
    let mut hasher = ObjectIdHasher::for_canonical_len(size_bytes);
    let mut fed = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| unreadable_path(&display, &error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        fed += read as u64;
    }
    let object = hasher
        .finish()
        .ok_or(WorkDeltaRefusal::MemberChanged {
            path: display.clone(),
            scanned: size_bytes,
            read: fed,
        })?
        .hash();
    Ok(TreeEntry {
        path,
        node: TreeNode::File {
            mode: executable_mode(&metadata),
            object,
            size_bytes,
        },
    })
}

/// Re-read one written member's bytes — checked against the node the delta
/// already carries — and publish them.
fn publish_member(
    root: &Dir,
    path: &TreePath,
    object: ObjectId,
    size_bytes: u64,
    sink: &dyn BlobSink,
) -> Result<(), WorkDeltaRefusal> {
    let mut components = path.as_str().split('/');
    let name = components
        .next_back()
        .expect("TreePath has a last component");
    let mut dir = root.reopen().map_err(|error| unreadable(root, error))?;
    for component in components {
        let component = std::ffi::CString::new(component)
            .expect("a TreePath component cannot contain a NUL byte");
        dir = dir
            .open_child_dir(&component)
            .map_err(|error| unreadable(&dir, error))?;
    }
    let name =
        std::ffi::CString::new(name).expect("a TreePath component cannot contain a NUL byte");
    let display = dir.display().join(name.to_string_lossy().as_ref());
    let file = dir
        .open_child_file(&name)
        .map_err(|error| unreadable_path(&display, &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| unreadable_path(&display, &error))?;
    if !metadata.is_file() {
        return Err(WorkDeltaRefusal::SpecialFile {
            path: display,
            kind: "no longer a regular file",
        });
    }
    if metadata.len() != size_bytes {
        return Err(WorkDeltaRefusal::MemberChanged {
            path: display,
            scanned: size_bytes,
            read: metadata.len(),
        });
    }
    // Bounded by the size the delta claims plus one: a grown member is caught
    // by the length check, not by reading however large it became.
    let mut bytes = Vec::with_capacity(usize::try_from(size_bytes).map_err(|_| {
        WorkDeltaRefusal::MemberOverCeiling {
            path: display.clone(),
            size_bytes,
        }
    })?);
    file.take(size_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| unreadable_path(&display, &error))?;
    if bytes.len() as u64 != size_bytes {
        return Err(WorkDeltaRefusal::MemberChanged {
            path: display,
            scanned: size_bytes,
            read: bytes.len() as u64,
        });
    }
    let read = object_id_for_canonical_bytes(&bytes);
    if read != object {
        return Err(WorkDeltaRefusal::MemberRewritten {
            path: display,
            scanned: object,
            read,
        });
    }
    sink.publish(&bytes)
        .map_err(WorkDeltaRefusal::PublicationFailed)?;
    Ok(())
}

fn unreadable(dir: &Dir, error: rustix::io::Errno) -> WorkDeltaRefusal {
    WorkDeltaRefusal::Unreadable {
        path: dir.display().to_path_buf(),
        error: error.to_string(),
    }
}

fn unreadable_path(path: &Path, error: &dyn std::fmt::Display) -> WorkDeltaRefusal {
    WorkDeltaRefusal::Unreadable {
        path: path.to_path_buf(),
        error: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// The tuple's kind and exec-bit fields must track the real mode — they
    /// are the reason a file↔symlink or exec-bit swap at an otherwise-
    /// identical `(ino, size, ctime)` still misses the fast path.
    #[test]
    fn snapshot_tuple_distinguishes_kind_and_owner_exec() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f.txt");
        let exec = tmp.path().join("x.sh");
        let link = tmp.path().join("l.txt");
        std::fs::write(&file, b"x").unwrap();
        std::fs::write(&exec, b"x").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("f.txt", &link).unwrap();

        let stat_of = |p: &Path| {
            rustix::fs::statat(rustix::fs::CWD, p, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).unwrap()
        };
        let file_tuple = snapshot_tuple(&stat_of(&file));
        let exec_tuple = snapshot_tuple(&stat_of(&exec));
        let link_tuple = snapshot_tuple(&stat_of(&link));

        assert_eq!(file_tuple.kind, 0, "a regular file is kind 0");
        assert!(!file_tuple.executable, "a 0644 file is not owner-exec");
        assert_eq!(link_tuple.kind, 1, "a symlink is kind 1");
        assert!(exec_tuple.executable, "a 0755 file is owner-exec");
        assert_ne!(
            file_tuple, link_tuple,
            "a symlink and a file must never share a tuple"
        );
    }
}
