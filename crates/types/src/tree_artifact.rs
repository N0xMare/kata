//! The versioned TREE artifact manifest — WHICH exact entries a portable
//! artifact is, and which CAS object holds each file's bytes.
//!
//! Portable capsules and artifacts need one shape that names a directory of files without naming a
//! main-host path, so a worker can materialize it from references alone. That shape is
//! [`TreeManifest`]: a sorted list of guest-relative paths, each naming a [`TreeNode`] — a file
//! (mode, the [`ObjectId`] of its bytes, and their length) or a symlink (its target, verbatim).
//! Nothing here performs I/O, opens a CAS, or materializes anything — these are pure types plus
//! their refusals, so a manifest can be built, checked, published and refused with no store
//! present.
//!
//! # A tree has ONE identity and it is its manifest's `ArtifactRef`
//!
//! There is deliberately NO tree digest in this module. A blob artifact's
//! identity is `ArtifactRef::new(object_id_of(bytes), size, privacy)`; a tree
//! artifact's identity is the very same call over the CANONICAL MANIFEST BYTES:
//! `ArtifactRef::new(object_id_of(manifest_bytes), manifest_bytes.len(),
//! privacy)`. The `size_bytes` half of a tree's `ArtifactRef` is therefore the
//! MANIFEST's length, not the sum of the members' — the reference addresses the
//! manifest, and the members are addressed by the manifest.
//!
//! A second, field-wise "tree digest" was considered and rejected. It would be a
//! second answer to a question the CAS address already answers exactly, and the
//! two answers can disagree: a manifest byte change that the field-wise digest
//! excluded (a schema version, a mode spelling) would leave two manifests sharing
//! one tree identity while materializing differently. `kata_types::nix_environment`
//! takes the opposite decision for the opposite reason — a closure digest must
//! survive a re-sign, so it cannot be the bytes — and the contrast is the point:
//! here nothing about the manifest is presentation, so nothing may be excluded.
//!
//! # A symlink is a LEAF — representable, inert, never followed
//!
//! [`TreeNode`] has a `Symlink` arm, so the archive-extraction escape question
//! is not answered by making a link unencodable. It is answered by making a
//! link INERT:
//!
//! * A symlink is a LEAF. [`TreeManifest::new`]'s prefix rule — no entry beneath
//!   another entry's path — applies to it exactly as to a file, so `link` and
//!   `link/x` cannot share a manifest and no tree can put content "through" a
//!   link's path.
//! * A materializer creates a symlink AS a link (`symlinkat` beneath a proven
//!   parent descriptor) and never opens or writes a path THROUGH one — the leaf
//!   rule means no entry ever needs to.
//! * Every walker over a tree or a work tree uses `lstat` semantics and never
//!   follows a link, so a target like `/etc/passwd` or `../../out` resolves on
//!   NO host kata controls. Which is why [`SymlinkTarget`] does not refuse them:
//!   they are legitimate repository content (git records them verbatim), and a
//!   refusal here could only make a real repo's tree unrepresentable — it could
//!   not widen a safety the never-follow discipline already provides.
//!
//! Device nodes, fifos, sockets and submodules are still unrepresentable — no
//! [`TreeNode`] arm carries them — and directories are implied by the paths
//! rather than listed (an empty directory is not representable, and that is
//! stated where it matters: [`TreeManifest::new`]).

use serde::{Deserialize, Deserializer, Serialize};
use smol_str::SmolStr;

use crate::primitives::ObjectId;
use crate::{KataError, KataResult};

/// Shape version of the tree manifest.
///
/// It is serialized into every manifest and refused when foreign, so a manifest
/// written by a different shape is rejected rather than read under this build's
/// field meanings. Because the manifest BYTES are the tree's identity (see the
/// module docs), a bump rotates every tree artifact id by construction.
///
/// * v1 — the initial path / mode / object / size entry shape.
/// * v2 — entries carry a [`TreeNode`]: a file (the v1 fields, nested) or a
///   symlink. A v1 manifest is REFUSED on read rather than reinterpreted, so a
///   data directory written by a v1 build is refused at boot by the operational
///   schema stamp, which is where the recourse lives.
pub const TREE_MANIFEST_SCHEMA_VERSION: u32 = 2;

/// Refuse any `schema_version` other than [`TREE_MANIFEST_SCHEMA_VERSION`]. A
/// tolerated foreign version would be a silent compatibility layer: the body
/// would be read under this build's field meanings.
fn current_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != TREE_MANIFEST_SCHEMA_VERSION {
        return Err(serde::de::Error::custom(format!(
            "tree manifest schema_version {version} is not supported; this build accepts only \
             {TREE_MANIFEST_SCHEMA_VERSION}"
        )));
    }
    Ok(version)
}

fn validation(message: String) -> KataError {
    KataError::Validation(message)
}

/// A RELATIVE, normalized path to one file inside a tree artifact.
///
/// # Refused set
///
/// [`TreePath::new`] accepts a path if and only if ALL of the following hold: it
/// is non-empty; it is at most 4096 bytes; it does not begin with `/`; every
/// `/`-separated component is non-empty and is neither `.` nor `..`; and it
/// contains no NUL and no other ASCII control byte. Everything else is refused,
/// including: the empty string, an absolute path (`/work/a`), a trailing slash
/// (`a/`), a doubled separator (`a//b`), a current-directory component (`./a`,
/// `a/./b`), a traversal (`../a`, `a/../b`, `a/..`), an embedded NUL (`"a\0b"`),
/// a newline or tab, and a path of 4097 bytes or more.
///
/// It is RELATIVE by construction because a tree is materialized UNDER a guest
/// root the manifest does not name: a tree that carried its own absolute paths
/// could contradict the root it was mapped at, and
/// `kata_types::execution_contract::GuestPath` is the type that names an absolute
/// guest location. The traversal refusal is what makes "under the root" a
/// property of the path rather than of the materializer's care.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TreePath(SmolStr);

impl TreePath {
    /// Maximum accepted byte length; matches Linux `PATH_MAX`, so a path this
    /// type accepts cannot be one the guest kernel would reject outright.
    const MAXIMUM_BYTES: usize = 4096;

    /// Build a tree path, refusing exactly the set documented on the type.
    pub fn new(path: impl Into<SmolStr>) -> KataResult<Self> {
        let path = path.into();
        let refuse =
            |reason: &str| Err(validation(format!("tree path {path:?} refused: {reason}")));
        if path.is_empty() {
            return refuse("empty");
        }
        if path.len() > Self::MAXIMUM_BYTES {
            return refuse("longer than 4096 bytes");
        }
        if path.bytes().any(|byte| byte.is_ascii_control()) {
            return refuse("contains a NUL or other ASCII control byte");
        }
        if path.starts_with('/') {
            return refuse("absolute; a tree entry path is relative to the root it is mapped at");
        }
        if path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return refuse(
                "not normalized: an empty, `.` or `..` component (a trailing or doubled separator \
                 spells an empty one)",
            );
        }
        Ok(Self(path))
    }

    /// The path as it is stored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `Some(component)` when any `/`-separated component is a VCS-internal
    /// directory name — `.git` or `.jj`. A `/work` delta path carrying one is
    /// [`WORK_DELTA_RESERVED_PATH`]: jj's checkout refuses such a path
    /// (`CheckoutError::ReservedPathComponent`), so a tree that names it would
    /// publish into the store and then wedge every checkout of the workspace.
    /// The producer, the adoption judge and the jj apply boundary all refuse
    /// it by that name rather than let it through.
    #[must_use]
    pub fn reserved_vcs_component(&self) -> Option<&str> {
        self.0
            .split('/')
            .find(|component| RESERVED_VCS_COMPONENTS.contains(component))
    }
}

/// The VCS-internal directory names a tree path must never carry — see
/// [`TreePath::reserved_vcs_component`].
pub const RESERVED_VCS_COMPONENTS: [&str; 2] = [".git", ".jj"];

/// The refusal token for a `/work` delta path carrying a VCS-internal
/// component — `.git` or `.jj` at any depth. The worker's capture, the
/// adoption judge and the jj apply boundary each refuse such a path; all three
/// name it by this one token so an operator (and a test) can grep one word.
pub const WORK_DELTA_RESERVED_PATH: &str = "work_delta_reserved_path";

impl<'de> Deserialize<'de> for TreePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path = SmolStr::deserialize(deserializer)?;
        Self::new(path).map_err(serde::de::Error::custom)
    }
}

/// The two file modes a tree entry may carry.
///
/// Exactly two, because exactly two survive the boundary: whether the guest may
/// `execve` the file. Every other POSIX permission bit is a main-host fact that a
/// materializer would have to either honour (making the artifact non-portable) or
/// silently drop (making the manifest a claim it does not keep).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreeEntryMode {
    /// A regular, non-executable file (`0o644` when materialized).
    Regular,
    /// A regular, executable file (`0o755` when materialized).
    Executable,
}

impl TreeEntryMode {
    /// The stable tag this mode is named by in messages and in any field-wise
    /// hash that folds it. Never an integer discriminant: reordering the arms
    /// must not be able to alias one mode onto the other.
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::Executable => "executable",
        }
    }
}

/// The target a symlink entry points at, stored VERBATIM.
///
/// # Refused set — stated exactly
///
/// [`SymlinkTarget::new`] accepts a target if and only if ALL of the following
/// hold: it is non-empty (a zero-length link cannot be created); it is at most
/// 4096 bytes (the `PATH_MAX` a readlink answer is bounded by); and it contains
/// no NUL byte (the one byte a path-taking syscall cannot carry). Everything
/// else is refused.
///
/// And NOTHING else is refused — in particular an ABSOLUTE target
/// (`/etc/passwd`) and a `..`-bearing one (`../../out`) are ACCEPTED. Both are
/// legitimate repository content (git records them verbatim), and they are
/// inert inside a tree because the module docs' leaf rule is honoured
/// everywhere: no kata reader ever follows a link, so a target never resolves
/// on a host kata controls. A refusal here could not widen that safety — it
/// could only make a real repository's tree unrepresentable.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SymlinkTarget(SmolStr);

impl SymlinkTarget {
    /// Maximum accepted byte length; matches `PATH_MAX`, the bound a readlink
    /// answer itself is subject to.
    const MAXIMUM_BYTES: usize = 4096;

    /// Build a symlink target, refusing exactly the set documented on the type.
    pub fn new(target: impl Into<SmolStr>) -> KataResult<Self> {
        let target = target.into();
        let refuse = |reason: &str| {
            Err(validation(format!(
                "symlink target {target:?} refused: {reason}"
            )))
        };
        if target.is_empty() {
            return refuse("empty");
        }
        if target.len() > Self::MAXIMUM_BYTES {
            return refuse("longer than 4096 bytes");
        }
        if target.bytes().any(|byte| byte == 0) {
            return refuse("contains a NUL byte");
        }
        Ok(Self(target))
    }

    /// The target as it is stored — verbatim, never resolved.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SymlinkTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let target = SmolStr::deserialize(deserializer)?;
        Self::new(target).map_err(serde::de::Error::custom)
    }
}

/// What one entry's path names: a file whose bytes are a CAS object, or a
/// symlink whose whole content is its target.
///
/// The serde tag is `kind` and the arms spell `file` / `symlink`, so a member
/// reads `{"path": "…", "node": {"kind": "file", "mode": …, "object": …,
/// "size_bytes": …}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TreeNode {
    /// A regular file: the mode the guest sees, the CAS object holding its
    /// bytes, and their length.
    ///
    /// `size_bytes` is the member's own byte length, recorded so a materializer
    /// can bound a read and check what it got before it writes the file, rather
    /// than discovering the length by reading whatever the CAS hands back.
    File {
        /// Whether the guest may execute it.
        mode: TreeEntryMode,
        /// The CAS object holding its bytes.
        object: ObjectId,
        /// Its byte length.
        size_bytes: u64,
    },
    /// A symlink. The target is content, verbatim — which is why it lives in
    /// the manifest rather than in a CAS object, and why it is inert: no kata
    /// reader follows it (see the module docs).
    Symlink {
        /// The link's target, stored verbatim and never resolved.
        target: SymlinkTarget,
    },
}

impl TreeNode {
    /// The CAS object this entry's bytes live at: `Some` for a file, `None` for
    /// a symlink — whose content is inside the manifest itself, so it is an
    /// ENTRY for every count and carries no object for any reachability walk.
    #[must_use]
    pub fn object(&self) -> Option<ObjectId> {
        match self {
            Self::File { object, .. } => Some(*object),
            Self::Symlink { .. } => None,
        }
    }

    /// The byte length this entry charges to a tree's member budget: a file's
    /// `size_bytes`, or a symlink's target length — which is also the answer
    /// `lstat` gives for the link's `st_size`, so the budget and the filesystem
    /// agree on what the entry's content costs.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        match self {
            Self::File { size_bytes, .. } => *size_bytes,
            Self::Symlink { target } => target.as_str().len() as u64,
        }
    }
}

/// One entry in a tree artifact: a path, and the node that path names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// Where the node lives, relative to the root the tree is mapped at.
    pub path: TreePath,
    /// What the path names — a file or a symlink.
    pub node: TreeNode,
}

/// A versioned, canonically ordered list of the entries one tree artifact is.
///
/// Built only through [`TreeManifest::new`], including on the deserialize path, so
/// a manifest that reached this process as bytes is held to exactly the same
/// refusals as one built in memory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TreeManifest {
    schema_version: u32,
    entries: Vec<TreeEntry>,
}

/// The refusal token for a manifest whose canonical encoding is over
/// [`TreeManifest::MAXIMUM_ENCODED_BYTES`].
pub const TREE_MANIFEST_OVER_CEILING: &str = "tree_manifest_over_ceiling";

/// Ceiling on ONE tree member's bytes — a producer bound and a reader bound at once.
///
/// `kata_worker::materialize` reads a member's verified bytes into memory before writing
/// them out, so a manifest could otherwise name a member large enough to exhaust the
/// worker's memory before anything checked it. The `/work` INPUT producers make the same
/// refusal at admission (`kata_vcs`'s committed-base conversion) and per attempt
/// (`kata_core::work_tree` bounds its walk the same way in bytes total): a tree published
/// with a member over this bound would be one the node retains and every worker refuses,
/// which is the disagreement ONE constant exists to prevent. 64 MiB is the worker's
/// per-capture ceiling order of magnitude and is refused BY NAME rather than truncated.
/// Streaming a member through a bounded buffer — which would lift this to the manifest's
/// own declared size — is not done, and nothing here assumes it.
pub const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;

/// The `[node]`-configured `/work` INPUT ceiling, carried to the
/// base-tree producer.
///
/// These two bounds are the INPUT half of a deliberate split: they bound the
/// committed base tree published at admission — a repository's real size, so the
/// defaults are large (1 GiB, 100 000 entries) — while the capsule RESULT's own budgets
/// (`kata_types::execution_contract::CAPSULE_RESULT_BYTES`/`CAPSULE_RESULT_ENTRIES`,
/// and the same values the per-attempt workspace walk reuses) stay at their smaller
/// classes. The two never share a knob: a result delta is budgeted against the input
/// it lands on, and folding the numbers into one would make a bigger input ceiling
/// silently buy a bigger result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkTreeInputBounds {
    /// The most member bytes the published base tree may total.
    pub max_bytes: u64,
    /// The most entries (files and symlinks — directories are implied, not
    /// entries, so the producer counts what the manifest will carry) the
    /// published base tree may hold.
    pub max_entries: u64,
}

/// Default `work_tree_max_bytes`: 1 GiB.
pub const DEFAULT_WORK_TREE_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Default `work_tree_max_entries`: 100 000.
pub const DEFAULT_WORK_TREE_MAX_ENTRIES: u64 = 100_000;

impl Default for WorkTreeInputBounds {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_WORK_TREE_MAX_BYTES,
            max_entries: DEFAULT_WORK_TREE_MAX_ENTRIES,
        }
    }
}

/// A COMMITTED tree converted for `/work` publication.
///
/// What `kata_effects_contract::ExecutionWorkspaceProvider::committed_base_tree` returns and
/// `kata_core::work_tree::publish_base_tree_head` publishes: the base commit the
/// execution workspace was created over, the [`TreeManifest`] its tree converted to,
/// and the manifest's canonical bytes — computed ONCE by the conversion (which is where
/// an encoding over the ceiling is refused) and then addressed and published from here.
/// The member bytes are NOT carried: they were streamed to the publisher's `put_member`
/// callback during the walk and never all held at once.
#[derive(Clone, Debug)]
pub struct CommittedBaseTree {
    /// The base commit the execution workspace was created over, in the backend's own
    /// id spelling (jj's commit hex). Recorded on the head row as the head's provenance —
    /// the durable answer to "which commit did this execution's `/work` come from".
    pub base_commit: String,
    /// The workspace's candidate commit (`@`) as the workspace was created — the
    /// apply effect's fence re-checks this on the head row before it rewrites the
    /// candidate (`work_apply_candidate_diverged`).
    pub candidate_commit_id: String,
    /// The manifest the base tree converted to.
    pub manifest: TreeManifest,
    /// `manifest.manifest_bytes()`, encoded by the conversion.
    pub manifest_bytes: Vec<u8>,
}

/// An execution's disposable git HISTORY, converted for `/git-history`
/// publication.
///
/// What `kata_effects_contract::ExecutionWorkspaceProvider::committed_base_git_history`
/// returns and `kata_core::git_view::publish_execution_git_view` publishes:
/// the base commit and base branch the view is rooted at, the committer
/// identity the capsule's scratch repository inherits, and the [`TreeManifest`]
/// of the artifact the worker mounts read-only — `objects/pack/pack-*.{pack,idx}`
/// members carrying every object reachable from the base commit (each pack at
/// most [`MAX_MEMBER_BYTES`]), an `index` member built from the base tree, and
/// a `shallow` member when [`crate::config::GitViewConfig::history_depth`]
/// truncated the walk. The member bytes are NOT carried: they were streamed
/// to the publisher's `put_member` callback as each pack, index and marker
/// completed, and never all held at once.
#[derive(Clone, Debug)]
pub struct CommittedBaseGitView {
    /// The base commit the view is rooted at, in the backend's own hex
    /// spelling (the git object id the workspace's base names).
    pub base_commit: String,
    /// The view's branch ref, off the execution's frozen target — the
    /// capsule's second scratch ref. `None` writes none.
    pub branch: Option<crate::execution_contract::GitViewRef>,
    /// The committer identity the scratch repository's config inherits —
    /// resolved from the host's own git settings at admission.
    pub identity: crate::execution_contract::GitIdentity,
    /// The manifest the history artifact converted to.
    pub manifest: TreeManifest,
    /// `manifest.manifest_bytes()`, encoded by the conversion.
    pub manifest_bytes: Vec<u8>,
}

impl TreeManifest {
    /// The ceiling on a tree manifest's own encoded bytes, for every reader AND every
    /// producer of one.
    ///
    /// A tree manifest is one JSON entry (~200 bytes for a short-path file, up to ~4.3 KB
    /// for a 4096-byte one, and up to ~8.3 KB for a symlink under a 4096-byte path with a
    /// 4096-byte target) per entry, so 64 MiB covers over three hundred thousand
    /// short-path files and about eight thousand of the longest links — comfortably past
    /// the `[node] work_tree_max_entries` input ceiling (100 000 by default) for every
    /// real repository shape, while staying a bound every reader loads within. ONE
    /// constant because the worker's
    /// `materialize`, the worker's `plane_index` and the main's adoption read the very
    /// same manifests: two readers of one object must not disagree about whether it is
    /// readable, or a tree the node declared would be one the worker refuses to
    /// materialize.
    ///
    /// The PRODUCER side is [`Self::manifest_bytes`], the one encoder every publisher goes
    /// through: it refuses [`TREE_MANIFEST_OVER_CEILING`] rather than hand back bytes no
    /// reader will load. The entry and member-byte budgets do not imply this bound — ten
    /// thousand empty files with long paths are inside both and encode to over 40 MiB.
    pub const MAXIMUM_ENCODED_BYTES: u64 = 64 * 1024 * 1024;

    /// Build a manifest, sorting the entries by path BYTES and refusing a
    /// duplicate path or a file-versus-directory prefix conflict.
    ///
    /// # Invariant
    ///
    /// ONE CANONICAL ORDER, ESTABLISHED HERE AND NOWHERE ELSE. Entries are sorted
    /// by the raw bytes of their path, so the order is a property of the content
    /// rather than of the order a snapshotter happened to walk a directory in.
    /// Because the manifest BYTES are the tree's identity, two callers that
    /// collected the same files in different orders publish the SAME artifact —
    /// and [`Self::manifest_bytes`] therefore needs no re-canonicalization step
    /// that could drift from this one.
    ///
    /// # Failure
    ///
    /// This is the refused set, stated exactly:
    ///
    /// * an entry whose path [`TreePath::new`] refuses (that type's own refused
    ///   set; the deserialize path goes through it too);
    /// * a DUPLICATE path. Which of two entries for one path wins would be an
    ///   invented answer, and a materializer that wrote both would leave a tree
    ///   whose content depends on write order;
    /// * an ENTRY-VERSUS-DIRECTORY PREFIX CONFLICT: `a` and `a/b` in one
    ///   manifest. Every entry is a LEAF — a file or a symlink alike — so no
    ///   filesystem can hold both, and a materializer would have to fail halfway
    ///   through, having already written part of the tree. For a symlink the
    ///   refusal is the leaf rule that makes the link inert: nothing may live
    ///   beneath it, so no write can ever need to pass through it. The check is
    ///   total rather than adjacent-only: sorted byte order puts `a!x` BETWEEN
    ///   `a` and `a/b` (`0x21 < 0x2f`), so a neighbour comparison would miss the
    ///   very conflict it appears to test. Every entry is instead checked against
    ///   the set of all paths for each of its own ancestor prefixes.
    ///
    /// An EMPTY manifest is accepted: an empty output directory is a real,
    /// meaningful result and refusing it would force a caller to invent a
    /// placeholder file. An EMPTY DIRECTORY inside a tree is not representable at
    /// all — directories are implied by the entry paths — and a snapshotter that
    /// must preserve one has to say so at the snapshot rather than here.
    pub fn new(mut entries: Vec<TreeEntry>) -> KataResult<Self> {
        entries.sort_by(|left, right| {
            left.path
                .as_str()
                .as_bytes()
                .cmp(right.path.as_str().as_bytes())
        });
        let mut paths: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(entries.len());
        for entry in &entries {
            if !paths.insert(entry.path.as_str()) {
                return Err(validation(format!(
                    "tree manifest refused: path {:?} appears more than once, and which entry wins \
                     would be an invented answer",
                    entry.path.as_str()
                )));
            }
        }
        for entry in &entries {
            let path = entry.path.as_str();
            for (offset, _) in path.char_indices().filter(|(_, byte)| *byte == '/') {
                if paths.contains(&path[..offset]) {
                    return Err(validation(format!(
                        "tree manifest refused: path {:?} is a FILE and path {:?} lives under it. \
                         No filesystem can hold both, so a materializer would fail with part of \
                         the tree already written",
                        &path[..offset],
                        path
                    )));
                }
            }
        }
        Ok(Self {
            schema_version: TREE_MANIFEST_SCHEMA_VERSION,
            entries,
        })
    }

    /// The entries, sorted by path bytes, one entry per path.
    #[must_use]
    pub fn entries(&self) -> &[TreeEntry] {
        &self.entries
    }

    /// Canonical bytes for CAS publication — and, addressed, the tree's IDENTITY.
    ///
    /// `serde_json` of the struct: serde emits a struct's fields in DECLARATION
    /// order, and `entries` is already in its canonical order BY CONSTRUCTION
    /// ([`Self::new`] sorts it). So there is no re-canonicalization step here to
    /// drift from the one in `new` — the value cannot be in a non-canonical state
    /// to begin with.
    ///
    /// Unlike `kata_types::nix_environment::NixEnvironmentManifest::manifest_bytes`,
    /// these bytes ARE an identity: the tree artifact's `ArtifactRef` is
    /// `ArtifactRef::new(object_id_of(these bytes), these bytes' length, privacy)`.
    /// A change to what this emits — a field order, a rename, a number spelling —
    /// rotates every tree artifact id, which is why
    /// `crates/types/tests/tree_artifact_goldens.rs` pins the address of a fixed
    /// two-entry manifest.
    ///
    /// # Failure
    ///
    /// [`TREE_MANIFEST_OVER_CEILING`] (a `KataError::Validation`) when the encoding is
    /// longer than [`Self::MAXIMUM_ENCODED_BYTES`] — every reader bounds its read there, so
    /// bytes over it would be a tree published, declared and dispatched that no reader can
    /// load. And a `KataError::Serialization` if `serde_json` fails, which it cannot for
    /// this type.
    pub fn manifest_bytes(&self) -> KataResult<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|error| {
            KataError::Serialization(format!("tree manifest does not serialize: {error}"))
        })?;
        if bytes.len() as u64 > Self::MAXIMUM_ENCODED_BYTES {
            return Err(validation(format!(
                "tree manifest refused: {TREE_MANIFEST_OVER_CEILING}: its {} entries encode to {} \
                 bytes and TreeManifest::MAXIMUM_ENCODED_BYTES is {}. Every reader of a tree \
                 manifest bounds its read there, so these bytes would name a tree no reader can \
                 load",
                self.entries.len(),
                bytes.len(),
                Self::MAXIMUM_ENCODED_BYTES
            )));
        }
        Ok(bytes)
    }
}

/// Raw mirror of [`TreeManifest`]: deserialization re-runs [`TreeManifest::new`]
/// over the body, so a forged manifest — an unsorted entry list, a duplicate
/// path, a file with entries under it — is refused rather than trusted. The same
/// discipline as `kata_types::execution_contract::ArtifactRef`'s raw mirror; here
/// the constructor validates instead of recomputing an id, so there is no id to
/// compare.
#[derive(Deserialize)]
struct TreeManifestRaw {
    /// Read only to refuse a foreign version: `current_schema_version` rejects
    /// anything but this build's, so the value itself is never needed.
    #[serde(rename = "schema_version", deserialize_with = "current_schema_version")]
    _schema_version: u32,
    entries: Vec<TreeEntry>,
}

impl<'de> Deserialize<'de> for TreeManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = TreeManifestRaw::deserialize(deserializer)?;
        Self::new(raw.entries).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::FixedBytes;

    fn object(byte: u8) -> ObjectId {
        FixedBytes([byte; 32])
    }

    fn entry(path: &str) -> TreeEntry {
        TreeEntry {
            path: TreePath::new(path).expect("an accepted path"),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: object(1),
                size_bytes: 7,
            },
        }
    }

    fn link(path: &str, target: &str) -> TreeEntry {
        TreeEntry {
            path: TreePath::new(path).expect("an accepted path"),
            node: TreeNode::Symlink {
                target: SymlinkTarget::new(target).expect("an accepted target"),
            },
        }
    }

    #[test]
    fn a_tree_path_accepts_a_relative_normalized_path() {
        for accepted in ["a", "a/b", "src/main.rs", "a-b_c.d/e", "ünïcode/f"] {
            TreePath::new(accepted).unwrap_or_else(|error| panic!("{accepted} refused: {error}"));
        }
        let at_limit = "a".repeat(TreePath::MAXIMUM_BYTES);
        TreePath::new(at_limit).expect("a 4096-byte tree path is accepted");
    }

    #[test]
    fn a_tree_path_refuses_exactly_what_it_claims() {
        for refused in [
            "", "/a", "/", "a/", "a//b", "./a", "a/./b", "../a", "a/../b", "a/..", "..", ".",
            "a\0b", "a\nb", "a\tb",
        ] {
            assert!(
                TreePath::new(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
        let over_limit = "a".repeat(TreePath::MAXIMUM_BYTES + 1);
        assert!(
            TreePath::new(over_limit).is_err(),
            "a 4097-byte tree path must be refused"
        );
    }

    /// `reserved_vcs_component` answers the FIRST `.git`/`.jj` component at any
    /// depth and `None` for every path without one — a reserved name is refused
    /// only as a whole component, so `.gitx` or `x.git` stay clean. Every
    /// `work_delta_reserved_path` refusal stands on this query.
    #[test]
    fn a_tree_path_names_only_a_whole_reserved_vcs_component() {
        for (spelling, component) in [
            (".git", ".git"),
            (".jj", ".jj"),
            ("a/.git/config", ".git"),
            ("deep/.jj/repo/op_store", ".jj"),
            ("a/.git/b/.jj/c", ".git"),
        ] {
            let path = TreePath::new(spelling).expect("an accepted path");
            assert_eq!(
                path.reserved_vcs_component(),
                Some(component),
                "{spelling:?}"
            );
        }
        for clean in ["a", "a/b", ".gitx", "x.git/config", "a/.gitx/y", "a/.jjj"] {
            let path = TreePath::new(clean).expect("an accepted path");
            assert_eq!(path.reserved_vcs_component(), None, "{clean:?}");
        }
    }

    #[test]
    fn a_symlink_target_accepts_what_a_real_repo_holds() {
        // Absolute and `..`-bearing targets are legitimate repository content and
        // are inert under the module docs' never-follow discipline — so they are
        // INSIDE the accepted set, and this table is the proof the refused set is
        // exactly the three stated on the type.
        for accepted in [
            "a",
            "relative/dir/file",
            "../sibling",
            "../../outside",
            "/etc/passwd",
            "/abs/../mixed/./path",
            "a\tb\nc", // control bytes are legal in a target and inert here
            "ünïcode/f",
        ] {
            SymlinkTarget::new(accepted)
                .unwrap_or_else(|error| panic!("{accepted:?} refused: {error}"));
        }
        let at_limit = "t".repeat(SymlinkTarget::MAXIMUM_BYTES);
        SymlinkTarget::new(at_limit).expect("a 4096-byte target is accepted");
    }

    /// The same discipline as `a_tree_path_refuses_exactly_what_it_claims`: the
    /// accepted table above minus these cases is the WHOLE refused set.
    #[test]
    fn a_symlink_target_refuses_exactly_what_it_claims() {
        for refused in ["", "a\0b"] {
            assert!(
                SymlinkTarget::new(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
        let over_limit = "t".repeat(SymlinkTarget::MAXIMUM_BYTES + 1);
        assert!(
            SymlinkTarget::new(over_limit).is_err(),
            "a 4097-byte target must be refused"
        );
    }

    #[test]
    fn a_symlink_target_deserializes_through_its_constructor() {
        assert_eq!(
            serde_json::from_str::<SymlinkTarget>("\"/etc/passwd\"")
                .unwrap()
                .as_str(),
            "/etc/passwd"
        );
        assert!(serde_json::from_str::<SymlinkTarget>("\"\"").is_err());
        assert!(serde_json::from_str::<SymlinkTarget>("\"a\\u0000b\"").is_err());
    }

    /// A symlink is a LEAF: the same prefix rule that refuses `a` + `a/b` refuses
    /// `link` + `link/x`, so no manifest can put content beneath a link — which is
    /// what makes "a materializer never writes through one" a property of the
    /// TYPE rather than of the writer's care.
    #[test]
    fn new_refuses_an_entry_beneath_a_symlink() {
        let error = TreeManifest::new(vec![link("link", "/etc/passwd"), entry("link/x")])
            .expect_err("a symlink with an entry under it must be refused");
        let message = error.to_string();
        assert!(message.contains("\"link\""), "{message}");
        assert!(message.contains("\"link/x\""), "{message}");
    }

    #[test]
    fn a_tree_path_deserializes_through_its_constructor() {
        assert_eq!(
            serde_json::from_str::<TreePath>("\"a/b\"")
                .unwrap()
                .as_str(),
            "a/b"
        );
        assert!(serde_json::from_str::<TreePath>("\"../escape\"").is_err());
        assert!(serde_json::from_str::<TreePath>("\"/absolute\"").is_err());
        assert!(serde_json::from_str::<TreePath>("\"\"").is_err());
    }

    #[test]
    fn new_sorts_by_path_bytes() {
        let manifest = TreeManifest::new(vec![entry("b"), entry("a/z"), entry("a!x")]).unwrap();
        assert_eq!(
            manifest
                .entries()
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a!x", "a/z", "b"],
            "byte order, not component order: `!` (0x21) sorts before `/` (0x2f)"
        );
    }

    #[test]
    fn new_refuses_a_duplicate_path() {
        let error = TreeManifest::new(vec![entry("a/b"), entry("a/b")])
            .expect_err("a duplicate path must be refused");
        assert!(error.to_string().contains("more than once"), "{error}");
    }

    /// The conflict `a` / `a/b` with `a!x` BETWEEN them in sorted byte order — the
    /// case an adjacent-pair check passes and a real filesystem cannot hold.
    #[test]
    fn new_refuses_a_file_that_another_entry_lives_under_even_when_not_adjacent() {
        let error = TreeManifest::new(vec![entry("a"), entry("a!x"), entry("a/b")])
            .expect_err("a file with an entry under it must be refused");
        let message = error.to_string();
        assert!(message.contains("\"a\""), "{message}");
        assert!(message.contains("\"a/b\""), "{message}");
    }

    #[test]
    fn new_accepts_an_empty_manifest_and_a_deep_path() {
        assert!(TreeManifest::new(Vec::new()).unwrap().entries().is_empty());
        TreeManifest::new(vec![entry("a/b/c/d/e")]).unwrap();
    }

    /// A prefix that is not a PATH BOUNDARY is not a conflict: `ab` and `a/b` can
    /// both exist, and refusing them would be a guarantee wider than its mechanism.
    #[test]
    fn new_accepts_a_prefix_that_is_not_a_path_boundary() {
        TreeManifest::new(vec![entry("ab"), entry("a/b")]).unwrap();
    }

    #[test]
    fn a_manifest_deserializes_through_its_constructor() {
        let manifest = TreeManifest::new(vec![entry("b"), entry("a")]).unwrap();
        let bytes = manifest.manifest_bytes().unwrap();
        assert_eq!(
            serde_json::from_slice::<TreeManifest>(&bytes).unwrap(),
            manifest
        );

        // An unsorted body comes back SORTED rather than as written: the
        // constructor, not the wire order, decides the canonical order.
        let file = |path: &str| {
            serde_json::json!({
                "path": path,
                "node": {"kind": "file", "mode": "regular", "object": object(1).to_string(), "size_bytes": 7},
            })
        };
        let unsorted = serde_json::json!({
            "schema_version": TREE_MANIFEST_SCHEMA_VERSION,
            "entries": [file("b"), file("a")],
        });
        let decoded: TreeManifest = serde_json::from_value(unsorted).unwrap();
        assert_eq!(decoded, manifest);

        // And a body whose entries conflict is refused on the wire, not accepted.
        let conflicting = serde_json::json!({
            "schema_version": TREE_MANIFEST_SCHEMA_VERSION,
            "entries": [file("a"), file("a/b")],
        });
        assert!(serde_json::from_value::<TreeManifest>(conflicting).is_err());

        // A symlink entry round-trips through the same door, and a target the
        // constructor refuses is refused on the wire too.
        let with_link = serde_json::json!({
            "schema_version": TREE_MANIFEST_SCHEMA_VERSION,
            "entries": [{
                "path": "link",
                "node": {"kind": "symlink", "target": "../../outside"},
            }],
        });
        assert_eq!(
            serde_json::from_value::<TreeManifest>(with_link).unwrap(),
            TreeManifest::new(vec![link("link", "../../outside")]).unwrap()
        );
        let bad_link = serde_json::json!({
            "schema_version": TREE_MANIFEST_SCHEMA_VERSION,
            "entries": [{"path": "link", "node": {"kind": "symlink", "target": ""}}],
        });
        assert!(serde_json::from_value::<TreeManifest>(bad_link).is_err());
    }

    #[test]
    fn a_foreign_schema_version_is_refused() {
        let mut value = serde_json::to_value(TreeManifest::new(vec![entry("a")]).unwrap()).unwrap();
        value["schema_version"] = serde_json::json!(TREE_MANIFEST_SCHEMA_VERSION + 1);
        let error = serde_json::from_value::<TreeManifest>(value)
            .expect_err("a foreign schema version must be refused");
        assert!(error.to_string().contains("is not supported"), "{error}");
    }

    /// The ENCODER refuses a manifest no reader can load, by name, and hands back the
    /// bytes of one just inside the ceiling. The over-ceiling manifest is built the way a
    /// real one gets there — thousands of entries with long paths — and its length is
    /// measured with `serde_json` directly, not through the function under test.
    #[test]
    fn manifest_bytes_refuses_an_encoding_over_the_ceiling_by_name() {
        let long = |index: usize| TreeEntry {
            path: TreePath::new(format!("{index:05}{}", "p".repeat(3_800))).unwrap(),
            ..entry("x")
        };
        let over = TreeManifest::new((0..18_000).map(long).collect()).unwrap();
        let measured = serde_json::to_vec(&over).unwrap().len() as u64;
        assert!(
            measured > TreeManifest::MAXIMUM_ENCODED_BYTES,
            "the premise: {measured} bytes"
        );
        // Not `expect_err`: its `Ok` arm would print the whole encoding.
        let Err(refusal) = over.manifest_bytes() else {
            panic!("an encoding over the ceiling is refused, and it was encoded");
        };
        let refusal = refusal.to_string();
        assert!(refusal.contains(TREE_MANIFEST_OVER_CEILING), "{refusal}");
        assert!(refusal.contains(&measured.to_string()), "{refusal}");

        let under = TreeManifest::new((0..4_000).map(long).collect()).unwrap();
        let bytes = under.manifest_bytes().expect("inside the ceiling encodes");
        assert!(bytes.len() as u64 <= TreeManifest::MAXIMUM_ENCODED_BYTES);
        assert_eq!(bytes, serde_json::to_vec(&under).unwrap());
    }

    /// The input ceiling and the manifest ceiling agree: the largest base tree the
    /// `[node]` config admits by ENTRIES (100 000 at `DEFAULT_WORK_TREE_MAX_ENTRIES`)
    /// still encodes under `MAXIMUM_ENCODED_BYTES`, with margin. If the ceiling ever
    /// tightened past the default entry bound, admission would publish trees no reader
    /// — the worker's materializer among them — can load.
    #[test]
    fn a_hundred_thousand_entry_manifest_stays_under_the_encoding_ceiling() {
        let entries = (0..DEFAULT_WORK_TREE_MAX_ENTRIES)
            .map(|index| {
                // Realistic repository-shaped paths, not the degenerate shortest one:
                // two directory levels and a name long enough that the encoding is
                // honest about per-entry cost.
                let path = format!("src/tree/{:02}/{index:06}.rs", index % 97);
                TreeEntry {
                    path: TreePath::new(path).expect("a real path shape"),
                    node: TreeNode::File {
                        mode: TreeEntryMode::Regular,
                        object: object(2),
                        size_bytes: 64,
                    },
                }
            })
            .collect();
        let manifest = TreeManifest::new(entries).expect("100k distinct paths build");
        let bytes = manifest
            .manifest_bytes()
            .expect("the default input entry bound encodes inside the reader ceiling");
        assert!(
            (bytes.len() as u64) < TreeManifest::MAXIMUM_ENCODED_BYTES / 3,
            "100 000 realistic entries encode to {} bytes — well under the {}-byte \
             ceiling, so the input entry bound, not the encoding ceiling, is what bites \
             a real repository",
            bytes.len(),
            TreeManifest::MAXIMUM_ENCODED_BYTES,
        );
    }

    #[test]
    fn the_mode_tags_are_stable() {
        assert_eq!(TreeEntryMode::Regular.as_tag(), "regular");
        assert_eq!(TreeEntryMode::Executable.as_tag(), "executable");
    }

    /// `TreeNode`'s accessors are the honest read of the variant — a file's
    /// object and size, a symlink's absence of object and its target length.
    #[test]
    fn a_node_reports_its_object_and_size_from_the_variant() {
        let oid = object(b'k');
        let file = TreeNode::File {
            mode: TreeEntryMode::Executable,
            object: oid,
            size_bytes: 17,
        };
        assert_eq!(file.object(), Some(oid));
        assert_eq!(file.size_bytes(), 17);

        let link = TreeNode::Symlink {
            target: SymlinkTarget::new("a/b/target").unwrap(),
        };
        assert_eq!(link.object(), None);
        assert_eq!(link.size_bytes(), 10, "a symlink's size is its target's");
    }
}
