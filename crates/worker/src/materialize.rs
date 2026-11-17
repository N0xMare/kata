//! The LOCAL MATERIALIZER: turn a capsule's authorized
//! references into real directories on this worker, or refuse BY NAME.
//!
//! # What this module is
//!
//! [`materialize`] is handed a [`Capsule`] (the authorization), a
//! [`NixEnvironmentManifest`] (the environment closure), a [`TreeResolver`] (how
//! an [`ArtifactId`] becomes a [`TreeManifest`]), a [`BlobSource`] (how an
//! [`ObjectId`] becomes verified bytes), a [`StorePathProbe`] (whether a closure
//! path is present on this host), and ONE attempt-scoped directory. It creates
//! exactly three children of that directory — `work`, `out`, `tmp` — and writes
//! each mapped tree's files beneath the one its guest path names.
//!
//! It issues nothing, records nothing, and consults no database of its own. The
//! caller owns the layout ABOVE the root it passes (production spells it
//! `<worker_state>/attempts/<attempt_tag>/root`), so nothing here mints an
//! attempt coordinate or decides where an attempt lives.
//!
//! # The authorized set, stated exactly
//!
//! A materialization touches exactly two sets of bytes:
//!
//! 1. the capsule's [`GuestMapping`]s, materialized here as files; and
//! 2. the environment closure, which is **NOT MATERIALIZED**. A closure entry is
//!    bound by the OCI spec at its own `/nix/store/<path>` ([`crate::oci_bundle`]),
//!    so copying or linking it here would produce a second, divergent copy of a
//!    store object whose whole point is that its path IS its identity. What this
//!    module does with a closure is VERIFY that every entry is present locally
//!    ([`StorePathProbe`]) and refuse otherwise — a spec that binds an absent
//!    source fails at container start with the runtime's vocabulary, not kata's.
//!
//! There is no third set and no policy check that could disagree with the
//! capsule: **the capsule IS the authorization**. A reference "outside the
//! authorized set" is therefore not a policy refusal here — it is a mapping whose
//! artifact the assignment carries no reference for, which is refused as
//! [`unresolved`](TreeResolver) (see [`DeclaredTreeResolver`]), and a tree entry
//! whose object the CAS does not hold, which is refused as missing bytes. Both
//! are stated that way deliberately: a "policy check" wording would claim a
//! second authority that does not exist.
//!
//! # Two refusals this module DOES NOT own, and must not be read as owning
//!
//! * A mapping whose guest path is outside
//!   `kata_types::execution_contract`'s guest roots, and a capsule that maps one
//!   guest path twice, are refused at CAPSULE DECODE — `GuestPath::new` and
//!   `Capsule::new`, which `Capsule`'s `Deserialize` re-runs over the bytes. By
//!   the time a `Capsule` value exists, neither is representable, so the
//!   materializer cannot be the thing that refuses them and does not claim to.
//!   `crates/worker/tests/materialize_live.rs` asserts against the capsule BYTES.
//! * A tree entry path that escapes its root (`../x`, `/abs`, `a/../b`) is
//!   refused by `TreePath::new`, i.e. it is UNREPRESENTABLE in a `TreeManifest`
//!   rather than caught while writing. The same test asserts that at the type.
//!
//! # EVERY file member is COPIED, and a symlink entry is CREATED as a link.
//! Nothing is hardlinked, and that is a decision
//!
//! A [`TreeNode::File`] is copied in; a [`TreeNode::Symlink`] is created with
//! `symlinkat` beneath the entry's proven parent descriptor, its target stored
//! verbatim and never resolved — a link is a LEAF (no entry can live beneath
//! one, the manifest's prefix rule), so no write ever needs to pass through it.
//!
//! There is no hardlink from the CAS blob, not even behind a condition, for
//! three reasons that compound:
//!
//! 1. **It is unreachable on the only route.** `kata_workflow::capsule_assembly`
//!    emits `/work`, `/out` and `/tmp` READ-WRITE, and
//!    [`crate::oci_bundle::spec_for`] REFUSES a read-only mapping at any of the
//!    three, so no capsule this build can assemble carries the read-only mapping a
//!    link would have been taken for. Code that cannot run is code whose
//!    correctness nothing checks.
//! 2. **It was umask-dependent.** A link shares the inode, so its mode is the CAS
//!    blob's, and a blob file is created at `0o666 & ~umask` — `0o664` under this
//!    box's `umask 002`, `0o644` under `022`. Linking therefore either presented a
//!    mode the manifest does not claim or was silently skipped depending on the
//!    worker's environment, which is exactly the kind of guarantee that is wider
//!    than its mechanism.
//! 3. **The hazard it carried is severe and one-directional.** A link into the CAS
//!    shares the INODE and the guest runs as this same uid, so a write through a
//!    linked `/work` file rewrites the CAS BLOB ITSELF — every content address in
//!    the node then names bytes it does not hold, permanently, with no error
//!    anywhere. `writing_into_work_leaves_the_cas_blob_bytes_unchanged` keeps
//!    proving the copy with `stat %i` (distinct inodes) and `sha256sum` (the blob
//!    is unmoved after a guest write), so the property survives its mechanism's
//!    deletion.
//!
//! If linking ever comes back for a genuinely read-only mapping, the
//! READ-WRITE PROHIBITION comes back with it — never linking into the CAS from a
//! directory the guest may write is the invariant, not an optimization detail.
//!
//! # Every write is `openat`-relative with `O_NOFOLLOW`
//!
//! No path is ever string-joined and resolved a second time: a directory is
//! proven once as an [`OwnedFd`] and every subsequent operation is relative to
//! that descriptor, with `O_NOFOLLOW` (and `O_EXCL` for files) so a symlink
//! planted under the root cannot redirect a write out of it — and a manifest's
//! own symlink entry is created with `symlinkat` under the proven parent, which
//! never opens or writes through a link at all. The paths in this module's
//! error messages are for the READER; nothing resolves them.

use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use kata_types::execution_contract::{ArtifactId, ArtifactRef, Capsule, GuestMapping, GuestPath};
use kata_types::nix_environment::{NixEnvironmentManifest, StorePath};
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::{SymlinkTarget, TreeEntry, TreeEntryMode, TreeManifest, TreeNode};
use kata_types::{KataError, KataResult};

/// Ceiling on ONE tree member's bytes — defined in `kata_types::tree_artifact`, ONE
/// constant for every reader and every producer: this module's materialize refuses a
/// member over it on the READ side, and the `/work` input producers refuse the same
/// member on the WRITE side, so a published tree is never one this worker declines.
pub use kata_types::tree_artifact::MAX_MEMBER_BYTES;

/// Mode a materialized directory carries. Every directory this module creates,
/// with no per-tree variation: a `TreeManifest` cannot carry a directory at all
/// (directories are implied by entry paths), so there is no declared mode to
/// honour and inventing one per tree would be a fact no manifest states.
const DIRECTORY_MODE: u32 = 0o755;

/// The three guest roots a capsule mapping may be materialized at, and the
/// directory name each takes under the attempt root.
///
/// **`/tmp` IS NOT IN THIS LIST.** The guest's `/tmp` is a TMPFS
/// ([`crate::oci_bundle::BundleMounts`] gives it a size and carries no host path at
/// all), so there is nothing on this side for a `/tmp` mapping's bytes to be. A
/// materialized `<root>/tmp` nothing binds is a directory whose only effect is to
/// look bound, and worse, it puts a stage's scratch on the host's disk where a later
/// attempt could read it.
///
/// So this module does not CREATE a `/tmp` directory, and the consequence is a
/// refusal rather than a silent drop: a `/tmp` mapping is accepted only when it names
/// an EMPTY tree — which is the only thing `kata_workflow::capsule_assembly` emits
/// for it — and a `/tmp` mapping carrying real entries is refused BY NAME here, in
/// the one place that can see the manifest. See [`refuse_non_empty_tmpfs_mapping`].
///
/// A consumer that `rmdir`s the directory after the fact would be the wrong shape:
/// two producers of one rule (this module creates, the driver
/// removes), its refusal fires on an `ErrorKind` instead of on the capsule, and it
/// leaves this list disagreeing with the route that reads it — which is the
/// ambiguous-name defect with the disagreement written down.
///
/// `/nix/store` is deliberately ABSENT even though it is a legal `GuestPath`
/// root: the closure is bound at its own store paths and never materialized (see
/// the module docs), so a mapping naming it is refused rather than written
/// somewhere the runtime will not look.
const MATERIALIZED_ROOTS: &[(&str, &str)] = &[("/work", "work"), ("/out", "out")];

/// The one guest root this module accepts a mapping for and creates NO directory
/// under: the container serves it from a tmpfs.
///
/// A constant beside [`MATERIALIZED_ROOTS`] rather than a literal in the loop, so the
/// two halves of "which guest roots are representable here" are read together.
const TMPFS_GUEST_ROOT: &str = "/tmp";

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("materialize refused: {reason}"))
}

fn io_refused(reason: &str, error: &impl std::fmt::Display) -> KataError {
    KataError::Storage(format!("materialize refused: {reason}: {error}"))
}

/// Where one artifact's BYTES come from.
///
/// A trait rather than a `CasStore` parameter, and the reason is the honest
/// statement of what [`LocalCasBlobSource`] assumes: that the worker and the
/// publisher share a disk. That assumption is TRUE today (every enrollment door
/// refuses a worker outside the main's filesystem namespace), and a remote
/// worker would have to remove it. Keeping the interface at a
/// trait is what makes removing it a new impl rather than a rewrite of this
/// module: nothing below reaches for a path, a database, or a lock.
pub trait BlobSource: Send + Sync {
    /// The object's bytes, VERIFIED against its content address, refusing before
    /// any allocation when `expected_size` exceeds `maximum`.
    fn read_verified(
        &self,
        object: ObjectId,
        expected_size: u64,
        maximum: u64,
    ) -> KataResult<Vec<u8>>;
}

/// How an [`ArtifactId`] becomes the [`TreeManifest`] it names.
pub trait TreeResolver: Send + Sync {
    /// The manifest for `artifact`, or a refusal naming the artifact.
    ///
    /// An artifact this resolver carries no reference for is REFUSED: the
    /// resolver's reference set is the assignment's own, and inventing a lookup
    /// for an id it was not handed is the one thing that would let a mapping name
    /// bytes nobody authorized.
    fn tree_manifest(&self, artifact: ArtifactId) -> KataResult<TreeManifest>;

    /// The REFERENCE this resolver carries for `artifact` — [`Self::tree_manifest`]'s
    /// same lookup, answered one step earlier. The `/work` delta publisher wants
    /// the reference itself: it is the `base` a [`kata_types::tree_delta::TreeDelta`]
    /// names, and re-deriving it from the resolved manifest's bytes would be a
    /// second answer to a question the reference set already answers.
    fn tree_reference(&self, artifact: ArtifactId) -> KataResult<ArtifactRef>;
}

/// Whether a Nix store path is present on THIS host.
pub trait StorePathProbe: Send + Sync {
    /// `true` when the store object exists locally. A probe that cannot tell
    /// returns an error; it never guesses, because "assume present" is the answer
    /// that turns a missing closure into a container that starts and behaves
    /// differently.
    fn present(&self, path: &StorePath) -> KataResult<bool>;
}

/// [`StorePathProbe`] over the real `/nix/store`.
///
/// It `stat`s the store path with `AT_SYMLINK_NOFOLLOW` and answers on
/// EXISTENCE ONLY — not on contents, not on a NAR hash. That is the whole claim:
/// the closure's integrity is `kata_types::nix_environment::IntegrityPolicy`'s
/// business at DECLARE time, and re-litigating it here would be a second,
/// weaker answer to a question already answered.
#[derive(Debug, Clone, Copy)]
pub struct LocalStorePathProbe;

impl StorePathProbe for LocalStorePathProbe {
    fn present(&self, path: &StorePath) -> KataResult<bool> {
        match rustix::fs::statat(
            rustix::fs::CWD,
            path.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => Ok(false),
            Err(error) => Err(io_refused(
                &format!("stat of closure path {}", path.as_str()),
                &error,
            )),
        }
    }
}

/// [`TreeResolver`] over the artifact references the assignment CARRIES.
///
/// A tree artifact's id is `blake3(object, size, privacy)`, which is a one-way
/// function: the id alone cannot produce the object to read. So the reference set
/// is an INPUT, and this resolver is a lookup in it plus the two refusals that
/// lookup owes — an id it was not handed, and a manifest whose bytes do not parse.
pub struct DeclaredTreeResolver<'a> {
    references: Vec<ArtifactRef>,
    source: &'a dyn BlobSource,
}

impl<'a> DeclaredTreeResolver<'a> {
    /// Build a resolver over exactly `references`.
    #[must_use]
    pub fn new(references: Vec<ArtifactRef>, source: &'a dyn BlobSource) -> Self {
        Self { references, source }
    }
}

impl TreeResolver for DeclaredTreeResolver<'_> {
    fn tree_reference(&self, artifact: ArtifactId) -> KataResult<ArtifactRef> {
        self.references
            .iter()
            .find(|candidate| candidate.id() == artifact)
            .cloned()
            .ok_or_else(|| {
                refused(&format!(
                    "artifact {} is named by a capsule mapping but this assignment carries no \
                     reference for it, so there is nothing to resolve it to",
                    artifact.0
                ))
            })
    }

    fn tree_manifest(&self, artifact: ArtifactId) -> KataResult<TreeManifest> {
        let reference = self.tree_reference(artifact)?;
        let bytes = self
            .source
            .read_verified(
                reference.object_id(),
                reference.size_bytes(),
                TreeManifest::MAXIMUM_ENCODED_BYTES,
            )
            .map_err(|error| {
                refused(&format!(
                    "tree artifact {}'s manifest object {} could not be read: {error}",
                    artifact.0,
                    reference.object_id()
                ))
            })?;
        serde_json::from_slice::<TreeManifest>(&bytes).map_err(|error| {
            refused(&format!(
                "tree artifact {}'s manifest object {} does not parse as a tree manifest: {error}",
                artifact.0,
                reference.object_id()
            ))
        })
    }
}

/// The two directories a materialization produced.
///
/// **There is no `tmp` here.** The guest's `/tmp` is a tmpfs with no host path
/// behind it, so there is no path here to hand a caller — see
/// [`MATERIALIZED_ROOTS`] for why, and for the `rmdir`-afterwards alternative
/// that was rejected.
///
/// These are PATHS, and the caller that binds them (the OCI spec's `/work`,
/// `/out` and `/tmp` sources) resolves them again. That is deliberate and is the
/// limit of what this module claims: every write it performed went through a
/// descriptor it proved, and what it hands back is where it proved them. Between
/// this return and the runtime's bind, the attempt directory's own ownership is
/// what keeps the answer true — a claim this module cannot make and does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedRoots {
    /// `<root>/work` — the guest's `/work`.
    pub work: PathBuf,
    /// `<root>/out` — the guest's `/out`.
    pub out: PathBuf,
    /// The kernel stamps of every `/work` member the moment it was written —
    /// the fast-path evidence `work_delta`'s post-run scan reuses base nodes
    /// from. `None` when the capsule maps no `/work`.
    pub work_snapshot: Option<crate::work_delta::MaterializationSnapshot>,
    /// The git view's two host roots, `<root>/git-history` and
    /// `<root>/git`, when the capsule declares one (an `Agent` capsule mapping
    /// `/work` — `Capsule::new` has already refused every other shape). `None`
    /// on every capsule without one, which is every `Command` capsule.
    pub git_view: Option<crate::git_view::GitViewLayout>,
}

/// Materialize one capsule's mappings beneath `root`.
///
/// # What it creates
///
/// Exactly `<root>/work` and `<root>/out`, each mode `0o755`, each fresh: an
/// ALREADY-PRESENT child is refused rather than reused, so a retried attempt can
/// never inherit a previous attempt's files. There is NO `<root>/tmp` — see
/// [`MATERIALIZED_ROOTS`].
///
/// `root` ITSELF MAY PRE-EXIST and is created with its ancestors when it does not
/// (`create_dir_all`), because the attempt directory is the CALLER's: a caller that
/// has already written a bundle or a log beside `root/` must not be told its own
/// directory is in the way. The freshness claim is therefore about the three
/// children and only them — which is the whole of what this module writes. BOTH are
/// created even when the capsule maps only one of them — an unmapped root is an empty
/// directory, which is what "`/out` starts empty" means on disk.
///
/// # Failure — the refused set, stated exactly
///
/// * a closure entry whose store path the probe reports absent (or cannot read);
/// * a mapping whose guest path is not `/work`, `/out` or `/tmp` — including
///   `/nix/store`, which is bound at its own paths and never materialized, and
///   including a path BENEATH one of the three, which the materializer does not
///   place (a sub-path mapping is a second tree inside a tree, and which one wins
///   where they overlap would be an invented answer);
/// * a `/tmp` mapping whose tree is NOT EMPTY. `/tmp` is the one accepted guest root
///   this module writes nothing for, because the container serves it from a tmpfs; a
///   mapping carrying real entries there declares bytes the route has nowhere to put,
///   and refusing is the alternative to running the stage with an input it declared
///   and never received. See [`refuse_non_empty_tmpfs_mapping`];
/// * a mapping naming an artifact the resolver carries no reference for;
/// * a manifest that does not parse, or is larger than [`TreeManifest::MAXIMUM_ENCODED_BYTES`];
/// * a member larger than [`MAX_MEMBER_BYTES`];
/// * a member whose bytes the source does not hold, or holds at a different
///   content address (the CAS's own verified read refuses both);
/// * any `openat`/`mkdirat`/`symlinkat` failure, including an already-present
///   `work` or `out` (`mkdirat`'s `EEXIST` is NOT tolerated for either) and a
///   symlink anywhere inside a member's path (`O_DIRECTORY|O_NOFOLLOW` answers
///   `ELOOP`).
///
/// Nothing else is refused here. In particular the guest-root and duplicate-path
/// refusals belong to capsule decode, and path escape is unrepresentable in a
/// `TreeManifest` — see the module docs.
pub fn materialize(
    capsule: &Capsule,
    environment: &NixEnvironmentManifest,
    trees: &dyn TreeResolver,
    source: &dyn BlobSource,
    probe: &dyn StorePathProbe,
    root: &Path,
    execution: ulid::Ulid,
) -> KataResult<MaterializedRoots> {
    verify_closure_present(environment, probe)?;

    std::fs::create_dir_all(root)
        .map_err(|error| io_refused(&format!("create attempt root {}", root.display()), &error))?;
    let root_dir = Dir::open(root)
        .map_err(|error| io_refused(&format!("open directory {}", root.display()), &error))?;

    let mut work_snapshot = None;
    let mut created = Vec::with_capacity(MATERIALIZED_ROOTS.len());
    for (guest, name) in MATERIALIZED_ROOTS {
        created.push((*guest, root_dir.create_child(name, DIRECTORY_MODE)?));
    }

    for mapping in capsule.inputs() {
        // `/tmp` FIRST, because it is the one accepted guest root with no directory
        // in `created` — reaching `mapping_root` with it would report it as an
        // unplaceable path, which is a true sentence about the wrong mistake.
        if mapping.guest_path.as_str() == TMPFS_GUEST_ROOT {
            refuse_non_empty_tmpfs_mapping(mapping, trees)?;
            continue;
        }
        let dir = mapping_root(&created, &mapping.guest_path)?;
        let view = (mapping.guest_path.as_str() == crate::work_delta::WORK_GUEST_ROOT)
            .then(|| capsule.work_view())
            .flatten();
        materialize_tree(dir, mapping.artifact, trees, source, view)?;
        if let Some(view) = view {
            materialize_include_dirs(dir, view)?;
        }
        if mapping.guest_path.as_str() == crate::work_delta::WORK_GUEST_ROOT {
            // The materializer's own record of what it wrote, taken the moment
            // the tree is complete — BEFORE the stage runs. `st_ctime` is the
            // field an unprivileged guest cannot rewind (`utimensat` reaches
            // mtime/atime only), so a matching tuple in the post-run scan means
            // the member's bytes are the base's own and need no re-read.
            work_snapshot = Some(crate::work_delta::MaterializationSnapshot::take(
                dir.display(),
            )?);
        }
    }

    // THE GIT VIEW — after every mapping lands (the `/work` the gitfile is
    // written into is complete, and its snapshot already taken, so `work/.git`
    // is never part of the base the delta diffs). `Capsule::new` has already
    // refused the view on anything but an `Agent` capsule mapping `/work`.
    let git_view = match capsule.git_view() {
        Some(view) => Some(crate::git_view::materialize_git_view(
            view, trees, source, root, execution,
        )?),
        None => None,
    };

    Ok(MaterializedRoots {
        work: root.join("work"),
        out: root.join("out"),
        work_snapshot,
        git_view,
    })
}

/// A `/tmp` mapping is accepted only as the EMPTY tree.
///
/// The manifest is RESOLVED rather than assumed empty, and that is the whole of the
/// check: `kata_workflow::capsule_assembly` maps `/tmp` to the canonical empty tree,
/// so a capsule carrying entries there did not come from that assembler, and a route
/// that served it from a tmpfs anyway would run the stage with an input it declared
/// and never received.
///
/// Nothing is written on either path — the accepted case creates no directory, which
/// is the point.
///
/// # Errors
///
/// [`KataError::Validation`] naming the entry count and the first entry's path, so an
/// operator reads WHICH bytes had nowhere to go; plus whatever the resolver refuses
/// for a manifest it cannot produce.
fn refuse_non_empty_tmpfs_mapping(
    mapping: &GuestMapping,
    trees: &dyn TreeResolver,
) -> KataResult<()> {
    let manifest = trees.tree_manifest(mapping.artifact)?;
    let entries = manifest.entries();
    if entries.is_empty() {
        return Ok(());
    }
    Err(refused(&format!(
        "the mapping at guest path {root} names a tree with {count} entr{plural} (the first is {first}), and {root} is served from a TMPFS inside the container — there is no host directory behind it for those bytes to be. This module therefore writes nothing for {root} and refuses a mapping that carries content, rather than dropping it silently and running the stage with an input it declared and never received. An EMPTY tree at {root} is what `kata_workflow::capsule_assembly` emits and is accepted",
        root = TMPFS_GUEST_ROOT,
        count = entries.len(),
        plural = if entries.len() == 1 { "y" } else { "ies" },
        first = entries[0].path.as_str(),
    )))
}

/// Every closure entry must be present locally before anything is written — refused
/// `environment_closure_incomplete`.
///
/// THE ONE closure-presence door. `plane_index::resolve_environment` deliberately does not
/// repeat it: that door pairs an id with bytes, this one decides whether the host can bind
/// them, and two refused sets for one question is how they come to disagree.
///
/// Checked BEFORE the roots are created so a host missing a store object fails
/// with nothing on disk to clean up, and checked over the CLOSURE rather than the
/// roots: the runtime binds one mount per closure entry, so an absent transitive
/// dependency is as fatal as an absent root and is invisible in the root list.
/// [`verify_closure_present`] for a caller that must decide BEFORE the container whether
/// this host can bind the closure — `capsule_route::CapsuleRoute::execute`, which reports
/// a refusal here as an observation that nothing ran.
///
/// The same function, not a second one: `materialize` still calls it on its own path, so
/// the closure's presence has ONE answer and this door only changes WHEN it is asked.
///
/// # Errors
///
/// `environment_closure_incomplete`, naming the absent store path.
pub fn verify_closure_present_for_route(
    environment: &NixEnvironmentManifest,
    probe: &dyn StorePathProbe,
) -> KataResult<()> {
    verify_closure_present(environment, probe)
}

fn verify_closure_present(
    environment: &NixEnvironmentManifest,
    probe: &dyn StorePathProbe,
) -> KataResult<()> {
    for entry in environment.closure() {
        if !probe.present(&entry.store_path)? {
            return Err(refused(&format!(
                "environment_closure_incomplete: environment {}'s closure entry {} is not present \
                 on this worker; the closure is BOUND at its store paths, never materialized, so \
                 an absent entry has nothing for this module to substitute",
                environment.label(),
                entry.store_path.as_str()
            )));
        }
    }
    Ok(())
}

/// Which created root a mapping's guest path names.
fn mapping_root<'a>(
    created: &'a [(&'static str, Dir)],
    guest_path: &GuestPath,
) -> KataResult<&'a Dir> {
    created
        .iter()
        .find(|(guest, _)| *guest == guest_path.as_str())
        .map(|(_, dir)| dir)
        .ok_or_else(|| {
            refused(&format!(
                "mapping at guest path {} is not materializable: this module places a tree at \
                 exactly /work or /out. /tmp is accepted but placed NOWHERE — the container \
                 serves it from a tmpfs — so it is handled before this lookup; /nix/store is \
                 bound at its own store paths by the runtime; and a path beneath a root would be \
                 a tree inside a tree",
                guest_path.as_str()
            ))
        })
}

/// Write one mapped tree's entries beneath `dir`: every file member is copied
/// in, every symlink is created as a link.
///
/// `pub(crate)` for `crate::git_view`: the history artifact is one more tree
/// the attempt root materializes (read-only under `git-history/`), and it
/// materializes through the same verified-member machinery rather than a
/// second writer.
pub(crate) fn materialize_tree(
    dir: &Dir,
    artifact: ArtifactId,
    trees: &dyn TreeResolver,
    source: &dyn BlobSource,
    view: Option<&kata_types::execution_contract::CapsuleWorkView>,
) -> KataResult<()> {
    let manifest = trees.tree_manifest(artifact)?;
    for entry in manifest.entries() {
        // The confined `/work` view: a member the declared
        // closure does not cover is never written — the capsule materializes
        // the SUBSET the stage is allowed to see.
        if let Some(view) = view
            && !view.covers(entry.path.as_str())
        {
            continue;
        }
        let (parents, name) = split_entry_path(entry)?;
        let mut current = dir.reopen().map_err(|error| {
            io_refused(
                &format!("reopen directory {}", dir.display().display()),
                &error,
            )
        })?;
        for component in parents {
            // `ensure_child` opens each ancestor `O_DIRECTORY|O_NOFOLLOW`, so the
            // parent chain a link hangs off was created by THIS materializer or
            // refuses — never a planted link, and never a declared one: the
            // manifest's prefix rule means no entry lives beneath a symlink.
            current = current.ensure_child(component, DIRECTORY_MODE)?;
        }
        match &entry.node {
            TreeNode::File {
                mode,
                object,
                size_bytes,
            } => write_member(&current, entry, name, *mode, *object, *size_bytes, source)?,
            TreeNode::Symlink { target } => current.create_symlink(name, target)?,
        }
    }
    Ok(())
}

/// The write closure: a declared view entry's ENCLOSING
/// directory is materialized even when the base carries nothing under it.
///
/// The directory a declared output will be written into must exist, because a
/// redirect (`> kata-out/check.log`) fails `ENOENT` on the missing dir long
/// before the write grant is even read. The flat `include` list cannot tell which
/// patterns came from `produces_files`, so the rule is applied uniformly: for
/// a glob entry the literal prefix is the directory its matches live under,
/// for a literal entry the parent (the declared node itself may be the file),
/// and an entry whose target is the tree root creates nothing. A read-pattern entry can mint an
/// EMPTY directory the base lacked (the divergent cost of the flat union); a
/// directory alone carries no manifest member, so it is visible to the stage
/// and to nothing else.
fn materialize_include_dirs(
    dir: &Dir,
    view: &kata_types::execution_contract::CapsuleWorkView,
) -> KataResult<()> {
    for pattern in &view.include {
        let Some(components) =
            kata_types::execution_contract::work_view_pattern_components(pattern.as_str())
        else {
            continue;
        };
        let literal: Vec<&str> = components
            .iter()
            .take_while(|component| {
                !component.contains(kata_types::execution_contract::WORK_VIEW_GLOB_METACHARS)
            })
            .copied()
            .collect();
        if literal.is_empty() {
            continue;
        }
        let has_glob = components.iter().any(|component| {
            component.contains(kata_types::execution_contract::WORK_VIEW_GLOB_METACHARS)
        });
        let target: &[&str] = if has_glob {
            &literal
        } else {
            // A literal entry's containing directory; a top-level literal's
            // parent is the root itself, which already exists.
            &literal[..literal.len() - 1]
        };
        let mut current = dir.reopen().map_err(|error| {
            io_refused(
                &format!("reopen directory {}", dir.display().display()),
                &error,
            )
        })?;
        for component in target {
            current = current.ensure_child(component, DIRECTORY_MODE)?;
        }
    }
    Ok(())
}

/// A tree entry's parent components and its file name.
///
/// Total by construction: `TreePath` refuses an empty path and every empty,
/// `.` or `..` component, so the split cannot produce an empty name or a
/// component that could climb.
fn split_entry_path(entry: &TreeEntry) -> KataResult<(Vec<&str>, &str)> {
    let mut components: Vec<&str> = entry.path.as_str().split('/').collect();
    let name = components.pop().ok_or_else(|| {
        refused(&format!(
            "tree entry path {:?} has no final component",
            entry.path.as_str()
        ))
    })?;
    Ok((components, name))
}

/// Write one FILE member: verify its bytes, then COPY them.
///
/// `access` is deliberately NOT a parameter: every member is copied, so the
/// read-only/read-write distinction has no effect here and taking one would imply
/// a branch that does not exist. That distinction is the MOUNT's
/// ([`crate::oci_bundle::spec_for`] binds `rw`, and refuses `ro` on these three
/// roots), which is where a reader should look for it.
fn write_member(
    dir: &Dir,
    entry: &TreeEntry,
    name: &str,
    mode: TreeEntryMode,
    object: ObjectId,
    size_bytes: u64,
    source: &dyn BlobSource,
) -> KataResult<()> {
    if size_bytes > MAX_MEMBER_BYTES {
        return Err(refused(&format!(
            "tree entry {:?} declares {} bytes, over the {MAX_MEMBER_BYTES}-byte per-member \
             ceiling",
            entry.path.as_str(),
            size_bytes
        )));
    }
    // VERIFIED BEFORE ANYTHING IS WRITTEN: the bytes are read and checked against
    // their content address first, so a missing or corrupt object leaves no entry
    // under the root at all. What is written is the very buffer that was verified —
    // never a re-read — so there is no window between the check and the write for
    // the answer to change in.
    let bytes = source
        .read_verified(object, size_bytes, size_bytes)
        .map_err(|error| {
            refused(&format!(
                "tree entry {:?} object {}: {error}",
                entry.path.as_str(),
                object
            ))
        })?;

    dir.write_file(name, member_mode(mode), &bytes)
}

/// The mode a materialized member carries.
const fn member_mode(mode: TreeEntryMode) -> u32 {
    match mode {
        TreeEntryMode::Regular => 0o644,
        TreeEntryMode::Executable => 0o755,
    }
}

/// A directory PROVEN once as a descriptor. Nothing here re-resolves a path.
///
/// The WRITE verbs above serve [`materialize`]; the READ verbs below serve
/// [`crate::work_delta`]'s post-run walk of `/work`. The two share one type
/// because the property both need is the same one — every operation relative to
/// a descriptor proven a directory ONCE — and the verbs return
/// `rustix::io::Errno` rather than a `KataError` because the refusal vocabulary
/// ("materialize refused" vs "work delta refused") is the caller's, not the
/// descriptor's.
pub(crate) struct Dir {
    /// Rendered in refusals and resolved by NOTHING — the moment a path is
    /// walked a second time the proof this type exists for is gone.
    display: PathBuf,
    fd: OwnedFd,
}

impl Dir {
    pub(crate) fn open(path: &Path) -> rustix::io::Result<Self> {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Self {
            display: path.to_path_buf(),
            fd,
        })
    }

    /// The path a refusal may RENDER — never resolve through it.
    pub(crate) fn display(&self) -> &Path {
        &self.display
    }

    /// A second descriptor for the SAME directory, so a walk can hold one
    /// without consuming the caller's.
    pub(crate) fn reopen(&self) -> rustix::io::Result<Self> {
        let fd = rustix::fs::openat(
            &self.fd,
            ".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Self {
            display: self.display.clone(),
            fd,
        })
    }

    /// Every entry name in this directory, `.`/`..` excluded. A name's KIND is
    /// deliberately not returned: `d_type` may be `DT_UNKNOWN`, and the
    /// caller's [`Self::stat_child`] is the authoritative answer anyway.
    pub(crate) fn entries(&self) -> rustix::io::Result<Vec<std::ffi::CString>> {
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(&self.fd)? {
            let name = entry?.file_name().to_owned();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            names.push(name);
        }
        Ok(names)
    }

    /// `statat` a child by name, NEVER following a link — the answer describes
    /// the link itself, which is what a lexical walk must see.
    pub(crate) fn stat_child(&self, name: &std::ffi::CStr) -> rustix::io::Result<rustix::fs::Stat> {
        rustix::fs::statat(&self.fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
    }

    /// `readlinkat` a child by name — the target's bytes, VERBATIM and never
    /// resolved.
    pub(crate) fn read_link(&self, name: &std::ffi::CStr) -> rustix::io::Result<std::ffi::CString> {
        rustix::fs::readlinkat(&self.fd, name, Vec::new())
    }

    /// Open a child DIRECTORY under this descriptor, refusing a link
    /// (`O_DIRECTORY|O_NOFOLLOW` answers `ELOOP`).
    pub(crate) fn open_child_dir(&self, name: &std::ffi::CStr) -> rustix::io::Result<Self> {
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Ok(Self {
            display: self
                .display
                .join(String::from_utf8_lossy(name.to_bytes()).as_ref()),
            fd,
        })
    }

    /// Open a child for READING without following a link. `O_NONBLOCK` so a
    /// fifo swapped in mid-walk fails the caller's `fstat` instead of blocking
    /// this open until a writer appears; the flag changes nothing for the
    /// regular file the caller then verifies it got.
    pub(crate) fn open_child_file(
        &self,
        name: &std::ffi::CStr,
    ) -> rustix::io::Result<std::fs::File> {
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        Ok(std::fs::File::from(fd))
    }

    /// Create `name` under this directory and prove it in turn, REFUSING one that
    /// already exists.
    pub(crate) fn create_child(&self, name: &str, mode: u32) -> KataResult<Self> {
        let display = self.display.join(name);
        rustix::fs::mkdirat(&self.fd, name, rustix::fs::Mode::from_raw_mode(mode)).map_err(
            |error| io_refused(&format!("create directory {}", display.display()), &error),
        )?;
        self.open_created_child(name, display, mode)
    }

    /// [`Self::create_child`] where an existing directory is the ordinary case: a
    /// manifest holding `a/b` and `a/c` names `a` twice, and refusing the second
    /// would refuse a legal manifest. `EEXIST` is tolerated and the `openat`
    /// decides what is actually there — `O_DIRECTORY|O_NOFOLLOW` returns `ELOOP`
    /// for a symlink and `ENOTDIR` for a file, so a planted entry is refused
    /// rather than written through.
    pub(crate) fn ensure_child(&self, name: &str, mode: u32) -> KataResult<Self> {
        let display = self.display.join(name);
        match rustix::fs::mkdirat(&self.fd, name, rustix::fs::Mode::from_raw_mode(mode)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => {
                return Err(io_refused(
                    &format!("create directory {}", display.display()),
                    &error,
                ));
            }
        }
        self.open_created_child(name, display, mode)
    }

    /// Open a directory this module just created and stamp its mode.
    ///
    /// The `fchmod` is not redundant with `mkdirat`'s mode argument: the umask
    /// narrows the latter, and a materialized tree whose modes depend on the
    /// worker's umask would be a different tree on two hosts from one manifest.
    fn open_created_child(&self, name: &str, display: PathBuf, mode: u32) -> KataResult<Self> {
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| io_refused(&format!("open directory {}", display.display()), &error))?;
        rustix::fs::fchmod(&fd, rustix::fs::Mode::from_raw_mode(mode)).map_err(|error| {
            io_refused(
                &format!("set mode on directory {}", display.display()),
                &error,
            )
        })?;
        Ok(Self { display, fd })
    }

    /// Create `name` under this directory as a symlink to `target`, VERBATIM.
    ///
    /// `symlinkat` relative to this proven descriptor: the link path never
    /// resolves through anything, and the TARGET is never resolved at all — it
    /// is content, stored exactly as the manifest carries it. `EEXIST` is not
    /// tolerated: the manifest's uniqueness rule means a second node at one
    /// path is an already-present child, not an entry to replace.
    fn create_symlink(&self, name: &str, target: &SymlinkTarget) -> KataResult<()> {
        let display = self.display.join(name);
        rustix::fs::symlinkat(target.as_str(), &self.fd, name)
            .map_err(|error| io_refused(&format!("create symlink {}", display.display()), &error))
    }

    /// Replace whatever entry `name` is with a NEW file holding `bytes`:
    /// `unlinkat` (an absent entry is not an error; a directory is refused,
    /// `EISDIR`), then [`Self::write_file`]'s `O_EXCL|O_NOFOLLOW` create — the
    /// written file is never one the caller did not just create.
    pub(crate) fn replace_file(&self, name: &str, mode: u32, bytes: &[u8]) -> KataResult<()> {
        match rustix::fs::unlinkat(&self.fd, name, rustix::fs::AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(io_refused(
                    &format!("remove {}", self.display.join(name).display()),
                    &error,
                ));
            }
        }
        self.write_file(name, mode, bytes)
    }

    /// Write `bytes` to a NEW file `name` under this directory.
    pub(crate) fn write_file(&self, name: &str, mode: u32, bytes: &[u8]) -> KataResult<()> {
        let display = self.display.join(name);
        let fd = rustix::fs::openat(
            &self.fd,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(mode),
        )
        .map_err(|error| io_refused(&format!("create file {}", display.display()), &error))?;
        // Same umask argument as `open_created_child`, and one more: the mode is
        // a MANIFEST claim, so it must be what the manifest said and not what the
        // process environment allowed.
        rustix::fs::fchmod(&fd, rustix::fs::Mode::from_raw_mode(mode)).map_err(|error| {
            io_refused(&format!("set mode on file {}", display.display()), &error)
        })?;
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)
            .map_err(|error| io_refused(&format!("write file {}", display.display()), &error))?;
        Ok(())
    }
}

/// [`BlobSource`] over a READ-ONLY open of the CAS this node publishes into.
///
/// # The shared-disk assumption, stated honestly
///
/// This impl reads `cas.db` and the blob tree DIRECTLY, so it only works while the
/// worker and the publishing main see the same filesystem. That is true of every
/// worker kata can enroll today — the main has no network worker transport and
/// `load_worker_config` refuses a non-`unix://` home node —
/// and it is precisely the assumption a remote worker would remove. It lives in an
/// impl of [`BlobSource`] rather than in [`materialize`] so removing it is a new
/// impl and not a rewrite: nothing in the materializer knows a database exists.
///
/// # What "read-only" means here, exactly
///
/// The SQLite handle is opened `SQLITE_OPEN_READ_ONLY`; no pragma is set and no table
/// is created. Nothing deletes a CAS object (kata has no CAS collection), so a read
/// here needs no serialization against one.
pub struct LocalCasBlobSource {
    connection: std::sync::Mutex<rusqlite::Connection>,
    blob_dir: PathBuf,
    db_path: PathBuf,
}

impl std::fmt::Debug for LocalCasBlobSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCasBlobSource")
            .field("db_path", &self.db_path)
            .field("blob_dir", &self.blob_dir)
            .finish_non_exhaustive()
    }
}

impl LocalCasBlobSource {
    /// Open `cas.db` read-only with its blob tree at `blob_dir`.
    ///
    /// # Failure
    ///
    /// Refuses an absent `cas.db` and a `blob_dir` that is not a directory. Both
    /// are refused HERE rather than at the first read so a worker that cannot see
    /// the store says so once, with the paths, instead of once per member.
    pub fn open(db_path: &Path, blob_dir: &Path) -> KataResult<Self> {
        if !db_path.is_file() {
            return Err(refused(&format!(
                "cas database {} is absent or is not a regular file",
                db_path.display()
            )));
        }
        if !blob_dir.is_dir() {
            return Err(refused(&format!(
                "cas blob tree {} is absent or is not a directory",
                blob_dir.display()
            )));
        }
        let connection = rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            io_refused(
                &format!("open cas database {} read-only", db_path.display()),
                &error,
            )
        })?;
        Ok(Self {
            connection: std::sync::Mutex::new(connection),
            blob_dir: blob_dir.to_path_buf(),
            db_path: db_path.to_path_buf(),
        })
    }

    fn locked(&self) -> KataResult<std::sync::MutexGuard<'_, rusqlite::Connection>> {
        self.connection
            .lock()
            .map_err(|error| refused(&format!("cas read handle is poisoned: {error}")))
    }

    /// The LENGTH this store records for `object`, or `None` when it holds no row.
    ///
    /// # Why a reader for a length, on a source whose every read takes one
    ///
    /// [`BlobSource::read_verified`] requires the expected length UP FRONT — that bound
    /// is what keeps a sender-chosen size from becoming an unbounded allocation — and a
    /// capsule's ENVIRONMENT reference does not carry one: `nix_environments` has no size
    /// column, because an environment id folds the manifest's ARTIFACT id and the length
    /// is inside that. So the length comes from the store, and the store's answer is
    /// safe to use for exactly one reason: it cannot pass
    /// `plane_index::resolve_environment`'s identity check unless it is right, because
    /// the artifact id folds the size.
    ///
    /// # Errors
    ///
    /// An unreadable database. A missing row is `Ok(None)`: absence is an answer the
    /// caller refuses by name, not an I/O failure.
    pub fn recorded_size(
        &self,
        object: kata_types::primitives::ObjectId,
    ) -> KataResult<Option<u64>> {
        let connection = self.locked()?;
        let size: Option<i64> = rusqlite::OptionalExtension::optional(connection.query_row(
            "SELECT size FROM cas_objects WHERE object_id = ?1",
            rusqlite::params![object.as_bytes()],
            |row| row.get(0),
        ))
        .map_err(|error| {
            refused(&format!(
                "read the recorded length of object {object}: {error}"
            ))
        })?;
        size.map(|size| {
            u64::try_from(size).map_err(|_| {
                refused(&format!(
                    "object {object} records a negative length, which is not a length"
                ))
            })
        })
        .transpose()
    }
}

impl BlobSource for LocalCasBlobSource {
    fn read_verified(
        &self,
        object: ObjectId,
        expected_size: u64,
        maximum: u64,
    ) -> KataResult<Vec<u8>> {
        // THE store's own verified read, not a second spelling of it: the bound,
        // the inline/file storage split and the address re-check are one
        // implementation in `kata_core::store::cas`, and a copy here would be a
        // second answer to "are these the object's bytes".
        let connection = self.locked()?;
        kata_core::store::cas::CasStore::read_verified(
            &connection,
            &self.blob_dir,
            &object,
            expected_size,
            maximum,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kata_types::execution_contract::ArtifactPrivacy;
    use kata_types::tree_artifact::TreePath;

    /// `open_child_file`'s `O_NOFOLLOW` is a REFUSAL, not a walk detail: a
    /// symlink planted at a name the walk believes is a file must error
    /// (`ELOOP`) rather than open the target's bytes — the target's content is
    /// outside the tree the walk described.
    #[test]
    fn open_child_file_refuses_a_symlink_and_opens_a_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.txt"), b"content\n").unwrap();
        std::os::unix::fs::symlink("real.txt", dir.path().join("link.txt")).unwrap();

        let root = Dir::open(dir.path()).expect("the root opens");
        let name = std::ffi::CString::new("link.txt").unwrap();
        let error = root
            .open_child_file(&name)
            .expect_err("a symlink is refused at the descriptor, not followed");
        assert_eq!(
            error,
            rustix::io::Errno::LOOP,
            "O_NOFOLLOW answers ELOOP: {error:?}"
        );
        let name = std::ffi::CString::new("real.txt").unwrap();
        let mut file = root
            .open_child_file(&name)
            .expect("the plain file still opens");
        let mut bytes = String::new();
        std::io::Read::read_to_string(&mut file, &mut bytes).unwrap();
        assert_eq!(bytes, "content\n");
    }

    /// The confinement halves, in the fixture the module's other tests
    /// already reach for: a tree the manifest describes, materialized under a
    /// declared view. `view.covers` is the ONLY thing asked — the member bytes
    /// are verified through the same `BlobSource` either way.
    struct OneTree {
        manifest: TreeManifest,
        artifact: ArtifactId,
    }

    impl TreeResolver for OneTree {
        fn tree_manifest(&self, artifact: ArtifactId) -> KataResult<TreeManifest> {
            assert_eq!(artifact, self.artifact);
            Ok(self.manifest.clone())
        }
        fn tree_reference(&self, artifact: ArtifactId) -> KataResult<ArtifactRef> {
            assert_eq!(artifact, self.artifact);
            Ok(ArtifactRef::new(
                kata_types::cache::object_id_for_canonical_bytes(b"ref"),
                0,
                ArtifactPrivacy::Private,
            ))
        }
    }

    /// Every object the manifest names is its own bytes: the fixture's store
    /// answers `read_verified` from a name→content map.
    struct Members(std::collections::HashMap<ObjectId, Vec<u8>>);

    impl BlobSource for Members {
        fn read_verified(
            &self,
            object: ObjectId,
            expected_size: u64,
            _maximum: u64,
        ) -> KataResult<Vec<u8>> {
            let bytes = self.0.get(&object).expect("the fixture holds the member");
            assert_eq!(bytes.len() as u64, expected_size);
            Ok(bytes.clone())
        }
    }

    fn member(path: &str, content: &[u8], members: &mut Members) -> TreeEntry {
        let object = kata_types::cache::object_id_for_canonical_bytes(content);
        members.0.insert(object, content.to_vec());
        TreeEntry {
            path: TreePath::new(path).unwrap(),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object,
                size_bytes: content.len() as u64,
            },
        }
    }

    /// **A confined view materializes only the members it covers** — the
    /// `reads=` closure's `oci` spelling: the base `{src/a, docs/b}` under
    /// `include: ["src"]` lands `src/a` alone, and `docs/` exists only if a
    /// declared entry's enclosing-dir rule creates it — here no entry names
    /// `docs`, so nothing does.
    ///
    /// **Would red if:** the `covers` check were dropped (both members land),
    /// inverted (nothing lands), or the dir parity minted `docs/` anyway.
    #[test]
    fn a_confined_view_materializes_only_the_members_it_covers() {
        let dir = tempfile::tempdir().unwrap();
        let mut members = Members(std::collections::HashMap::new());
        let manifest = TreeManifest::new(vec![
            member("src/a.txt", b"alpha\n", &mut members),
            member("docs/b.md", b"beta\n", &mut members),
        ])
        .unwrap();
        let artifact = ArtifactId(kata_types::cache::object_id_for_canonical_bytes(
            &manifest.manifest_bytes().unwrap(),
        ));
        let trees = OneTree { manifest, artifact };
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let root = Dir::open(&work).unwrap();
        let view = kata_types::execution_contract::CapsuleWorkView {
            include: vec![smol_str::SmolStr::new("src")],
        };
        materialize_tree(&root, trees.artifact, &trees, &members, Some(&view))
            .expect("the confined view materializes");

        assert!(work.join("src/a.txt").is_file(), "the covered member lands");
        assert_eq!(std::fs::read(work.join("src/a.txt")).unwrap(), b"alpha\n");
        assert!(
            !work.join("docs").exists(),
            "an uncovered member's whole subtree stays unmaterialized"
        );

        // The same view over the same tree, plus a declared output under a
        // not-yet-existing directory: the enclosing dir is materialized — the
        // write-closure shim's `create_dir_all` parity.
        let work2 = dir.path().join("work2");
        std::fs::create_dir(&work2).unwrap();
        let root2 = Dir::open(&work2).unwrap();
        let view2 = kata_types::execution_contract::CapsuleWorkView {
            include: vec![
                smol_str::SmolStr::new("src"),
                smol_str::SmolStr::new("kata-out/check.log"),
            ],
        };
        materialize_tree(&root2, trees.artifact, &trees, &members, Some(&view2)).unwrap();
        materialize_include_dirs(&root2, &view2).unwrap();
        assert!(work2.join("kata-out").is_dir());
        assert!(!work2.join("kata-out/check.log").exists());
        // … and the dir is writable — the declared output lands where a
        // redirect expects it (the shim's `create_dir_all` parity).
        std::fs::write(work2.join("kata-out/check.log"), b"ran\n").unwrap();
        assert!(!work2.join("docs").exists());
    }

    /// **A symlink in the view is materialized AS the symlink, never as its
    /// target.** The link's target may name a path outside the view — the
    /// closure confines members, not link contents, and copying target bytes
    /// would be how an out-of-view read reached the container. Dangling
    /// inside the container is the correct answer — the same tree the
    /// manifest describes, verbatim.
    ///
    /// **Would red if:** the symlink arm resolved targets (the bytes of
    /// `docs/secret` would land where a link was declared), or `covers`
    /// refused a member on its target's behalf.
    #[test]
    fn a_symlink_inside_the_view_materializes_as_the_link_not_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let mut members = Members(std::collections::HashMap::new());
        let manifest = TreeManifest::new(vec![
            member("docs/secret.txt", b"hidden\n", &mut members),
            TreeEntry {
                path: TreePath::new("src/link").unwrap(),
                node: TreeNode::Symlink {
                    target: SymlinkTarget::new("../docs/secret.txt").unwrap(),
                },
            },
        ])
        .unwrap();
        let artifact = ArtifactId(kata_types::cache::object_id_for_canonical_bytes(
            &manifest.manifest_bytes().unwrap(),
        ));
        let trees = OneTree { manifest, artifact };
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let root = Dir::open(&work).unwrap();
        let view = kata_types::execution_contract::CapsuleWorkView {
            include: vec![smol_str::SmolStr::new("src")],
        };
        materialize_tree(&root, artifact, &trees, &members, Some(&view)).unwrap();

        let link = work.join("src/link");
        assert!(link.is_symlink(), "the member materializes AS a symlink");
        assert_eq!(
            std::fs::read_link(&link).unwrap().to_string_lossy(),
            "../docs/secret.txt",
            "the target bytes are verbatim — never resolved"
        );
        assert!(
            std::fs::read(&link).is_err(),
            "and it dangles: the target is outside the view"
        );
        assert!(!work.join("docs").exists());
    }
}
