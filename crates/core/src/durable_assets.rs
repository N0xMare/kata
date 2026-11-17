//! The cross-store **durable-asset map**: one executable record of every asset a
//! Kata installation keeps on disk, and what recovery is entitled to assume about
//! each.
//!
//! Every durable asset family has a class and a recovery rule; this module is
//! the executable form of that table, for the asset set measured in the tree.
//! It answers five questions of every asset — ownership, class (authoritative vs
//! rebuildable), capture rule, snapshot rank, and retention — and says
//! `Unregistered` out loud for the assets no capture mechanism reaches.
//!
//! It is a DECLARATION rather than a mechanism — it copies, restores, and deletes
//! nothing — but it is not inert: [`crate::store::backup`] reads it.
//!
//! * `discover_databases` globs top-level `*.db` and refuses a name whose row is
//!   [`AssetAuthority::Rebuildable`] (`artifact_carries_database`). The cheap
//!   capture tier models LOSS, which rebuildability answers; it does not model
//!   ALTERATION, and nothing rebuilds a database that is present and wrong.
//!   `stage_cache.db` is the one such row and its restore-side complement is
//!   `clear_rebuildable_databases`.
//! * `discover_captured_trees` enumerates the [`AssetLocation::DataDirTree`] rows
//!   whose [`CaptureRule`] is `Tree`; the accepted tree set comes from the map.
//! * The copy order is DERIVED from [`SnapshotRank`], and every capture produces a
//!   [`ConsistencyToken`] the backup verifies before it publishes a manifest.
//!
//! Non-`.db` files (`main-identity.json`, `local-worker.secret`) are reached by
//! neither pass, and the `BackupManifest` carries no class field, so the rule
//! "omitting signing keys changes its class and is surfaced in the manifest" is
//! not satisfied by the artifact an operator inspects offline.
//!
//! # What this module is NOT
//!
//! Declaring the map does not promote an ordinary data snapshot to recoverable.
//! `the_shipped_backup_artifact_is_assessed_as_an_incomplete_data_snapshot`
//! measures the ordinary `backup_data_dir` path. The separate v3 recovery path
//! now verifies closed treatments, worker generations and remote closure;
//! `VerifiedRecoveryArtifact::completeness` exposes its verified verdict.
//!
//! Raw `assess_backup_class` derives its class from the asset set. That does not
//! make the ordinary snapshot's class sensitive to every omission:
//! `manifest_completeness` reads only three structural channels, which cannot
//! name five authoritative groups. Its omission tests must assert the changed
//! `CompletenessVerdict::missing_authoritative` set rather than an unchanged
//! class. `structural_inventory_alone_cannot_earn_recoverable` pins this adapter
//! boundary, not a module-wide prohibition on verified v3 recovery.
//!
//! # Scope
//!
//! Paths and layout claims are Linux/x86-64 claims measured on ext4. The
//! ordering and class claims are filesystem-independent; the durability
//! mechanics the capture rules imply (fsync, atomic rename, WAL checkpoint) are
//! not, and are not asserted here.

use std::collections::{BTreeMap, BTreeSet};

use kata_types::error::{KataError, KataResult};

/// Where an asset lives, expressed WITHOUT an absolute host path.
///
/// Durable identities contain content or semantic IDs and never absolute host
/// paths. A registry keyed on absolute
/// paths would violate the rule it exists to enforce, so every entry is
/// relative to a named root and the root is resolved at capture time.
///
/// # There is more than one durable root
///
/// One root — the main's `<data_dir>` — plus escape hatches for paths the
/// operator names would not be enough: a standalone `kata-worker` daemon opens
/// its OWN `credential_path.parent()/idempotency.db`
/// (`kata_worker::daemon::open_worker_idempotency_store`) and REFUSES TO BOOT without
/// it. A recovery contract that resolves only the main's data directory does
/// not reach the worker-local double-spend latch at all, so
/// [`Self::SubordinateWorkerFile`] is a distinct root and not a `DataDirFile` with a
/// different prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssetLocation {
    /// A single regular file directly under `<data_dir>`.
    DataDirFile(&'static str),
    /// A directory tree under `<data_dir>`, captured (if at all) as a tree.
    DataDirTree(&'static str),
    /// A family of files under `<data_dir>` matched by a stable prefix — names
    /// that carry a generated part, such as a publish's ULID-named temporary.
    DataDirPrefix(&'static str),
    /// A path the operator names in configuration; the registry knows the
    /// config field, never the value.
    ConfigDeclared(&'static str),
    /// A file under a WORKER NODE's own root — the directory holding the
    /// worker's `credential_path`, which the operator chooses and the main's
    /// `<data_dir>` does not contain.
    ///
    /// The payload carries a `subordinate-worker:` qualifier because [`Self::name`] is
    /// this map's global key: [`assess_backup_class`] matches on it, and the
    /// worker's `idempotency.db` is a DIFFERENT asset from the main data
    /// directory's file of the same name. Unqualified, a verdict about the
    /// worker's latch would be read as one about the main's.
    SubordinateWorkerFile(&'static str),
    /// State owned by something outside Kata; Kata may record a reference and a
    /// required digest, never the asset.
    External(&'static str),
}

impl AssetLocation {
    /// The location's stable name — the leaf under its root, or the config
    /// field / external system that names it.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::DataDirFile(name)
            | Self::DataDirTree(name)
            | Self::DataDirPrefix(name)
            | Self::ConfigDeclared(name)
            | Self::SubordinateWorkerFile(name)
            | Self::External(name) => name,
        }
    }

    /// The durable ROOT this asset lives under.
    ///
    /// A capture that resolves one root does not reach the others. This is the
    /// field that makes "the map models one data dir; production has at least
    /// two" checkable instead of arguable.
    #[must_use]
    pub fn root(&self) -> AssetRoot {
        match self {
            Self::DataDirFile(_) | Self::DataDirTree(_) | Self::DataDirPrefix(_) => {
                AssetRoot::MainDataDir
            }
            Self::SubordinateWorkerFile(_) => AssetRoot::SubordinateWorker,
            Self::ConfigDeclared(_) => AssetRoot::OperatorDeclared,
            Self::External(_) => AssetRoot::External,
        }
    }

    /// Whether this location is a top-level entry under `<data_dir>` — the set
    /// [`classify_data_dir_entry`] is total over.
    #[must_use]
    pub fn is_data_dir_local(&self) -> bool {
        matches!(
            self,
            Self::DataDirFile(_) | Self::DataDirTree(_) | Self::DataDirPrefix(_)
        )
    }
}

/// A durable root — a directory a recovery mechanism must resolve SEPARATELY.
///
/// `backup_data_dir` resolves exactly one of these ([`Self::MainDataDir`]).
/// Every other root is unreached by every shipped capture mechanism, and that
/// is a fact about the mechanism's REACH, not about the assets' importance:
/// **NAMED `SubordinateWorker`, NOT `WorkerNode`.** There is one main and no
/// peer mesh, so `WorkerNode` is not an authority name anywhere in the tree.
/// This variant names a PLACE durable assets live, not an authority, and it
/// uses the architecture's term: workers are SUBORDINATE execution capacity,
/// never peers or durable workflow authorities.
///
/// [`AssetRoot::SubordinateWorker`] holds the latch a worker daemon refuses to boot
/// without.
///
/// `Serialize`/`Deserialize` are derived because
/// [`crate::store::backup::CapturedTree`] records which root a captured tree
/// hangs off. A tree record without it is a record a restore cannot act on: `cas`
/// is under `<data_dir>` and `vcs.jj_repo` is under a path the operator names, and
/// a reader that assumed the first would put the jj repo in the wrong place.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AssetRoot {
    /// The main's `<data_dir>`.
    MainDataDir,
    /// A worker node's own directory — the parent of its `credential_path`.
    SubordinateWorker,
    /// A path the operator declares in configuration.
    OperatorDeclared,
    /// State owned by a system outside Kata.
    External,
}

/// An asset's authority class — the central distinction of the asset table,
/// stated as a PROHIBITION: "An asset may not be called cache or derived if
/// losing it can lose the only copy of a committed result, unlanded candidate,
/// checked program, invocation, effect outcome, identity, or required offline
/// toolchain."
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssetAuthority {
    /// Losing it loses the only copy of something committed. Must be captured,
    /// or named as a mandatory external rebind.
    Authoritative,
    /// Reconstructible from an authoritative asset named in `from`. Losing it
    /// costs work, never correctness.
    Rebuildable {
        /// The authoritative asset(s) it can be rebuilt from.
        from: &'static str,
    },
    /// Process coordination or in-flight scratch. Never recovery authority; a
    /// restore that carries one is carrying a lie about a process that is not
    /// running.
    Transient,
}

impl AssetAuthority {
    /// Whether losing this asset can lose the only copy of a committed result.
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::Authoritative)
    }
}

/// How an asset can be captured — and, for the ones nothing can capture today,
/// WHY.
///
/// # Which `Tree` rows a shipped mechanism captures
///
/// * `cas` (`AssetLocation::DataDirTree("cas")`) IS captured:
///   `crate::store::backup::discover_captured_trees` enumerates `DataDirTree`
///   rows carrying this rule, and [`crate::store::backup::CapturedTree`] is the
///   manifest record.
/// * `vcs.jj_repo` (`AssetLocation::ConfigDeclared("vcs.jj_repo")`) is NOT, and
///   the reason is a ROOT rather than a shape: it hangs off
///   [`AssetRoot::OperatorDeclared`], which no capture mechanism in the tree
///   resolves. Per-entry activation is sound for `cas` (immutable,
///   content-addressed, so a partial tree is a strict SUBSET) and is NOT sound
///   for a jj repo, whose op-log and index carry cross-file invariants a
///   per-file restore can break.
///
/// # A `Tree` row must also say what its members' PATHS claim
///
/// [`TreeMemberAddressing`] is carried by the variant rather than derived from
/// the asset's name, because it is what lets a restore bind a member's CONTENT
/// to its PATH — a check the per-member digest alone does not make.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CaptureRule {
    /// A SQLite database: `VACUUM INTO` inside one read transaction, checked
    /// with `PRAGMA quick_check`, restored with its `-wal`/`-shm`/`-journal`
    /// sidecars cleared.
    Sqlite,
    /// A file whose internal structure Kata does not own: byte copy, digest
    /// equality and nothing else.
    OpaqueFile,
    /// A directory tree: captured MEMBER BY MEMBER, with per-member integrity
    /// and a digest over the member index.
    ///
    /// `crate::store::backup::discover_captured_trees` captures every
    /// `DataDirTree` row carrying this rule; see the type doc for which rows
    /// that reaches.
    Tree {
        /// What a member's PATH claims about its own BYTES.
        ///
        /// Stated on the ROW because it is a property of the asset. `cas` is a
        /// content-addressed store: a member's basename IS the address its
        /// bytes must hash to, so capture and restore can BIND the two and a
        /// forged artifact cannot serve bytes under an address they do not hash
        /// to. Nothing else in the map can be asked that question, and asking
        /// it through a name test in `backup.rs` would put a second
        /// classification of `cas` beside this one.
        members: TreeMemberAddressing,
    },
    /// Secret material that may only appear in a sealed backup, encrypted to an
    /// operator-selected recipient, or be rebound externally. Plaintext copying
    /// is never implicit.
    SealedOrRebound,
    /// Not captured; reacquired by verified digest or provenance before resume.
    Reacquire {
        /// How the asset is reacquired.
        by: &'static str,
    },
    /// Deliberately excluded from every artifact.
    Excluded {
        /// Why exclusion is correct rather than an omission.
        because: &'static str,
    },
}

/// What a [`CaptureRule::Tree`] member's PATH claims about its own BYTES.
///
/// # Why this is a field on the map row and not a check in `backup.rs`
///
/// A tree capture that verifies every member's bytes against the digest the
/// manifest records FOR THAT MEMBER, and never against the PATH the member is
/// written to, is complete for an opaque tree. For `cas` it is not, because the path is not a
/// name — it is a content ADDRESS, derived from the bytes by
/// [`crate::store::cas::blob_relative_path`]. A manifest is unauthenticated
/// JSON, so an artifact could carry object X's bytes at object Y's address with
/// Y's entry rewritten to X's digest and length and the index digest recomputed,
/// and every per-member check in the artifact would agree.
///
/// The knowledge that closes it — "this tree's members are content-addressed" —
/// belongs to the ROW, because it is a fact about the asset and not about the
/// backup mechanism. Spelling it as `if tree.name == "cas"` inside `backup.rs`
/// would be a SECOND classification of `cas` living beside
/// [`DURABLE_ASSETS`], and a successor adding a third content-addressed tree
/// would have to find both. As a field, the compiler asks a new `Tree` row the
/// question and a new row cannot forget to answer it.
///
/// The SCHEME itself stays in [`crate::store::cas`]. This enum names which one
/// applies; it does not restate a hash layout the store owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TreeMemberAddressing {
    /// Every member's tree-relative path is the CAS blob path its own bytes
    /// require — `<hex[0..2]>/<hex>`, `hex` being
    /// [`kata_types::cache::object_id_for_canonical_bytes`] over those bytes.
    /// [`crate::store::cas::blob_relative_path_of_handle`] is the single
    /// definition; capture refuses a source member that does not satisfy it and
    /// restore refuses an artifact member that does not. The handle form is
    /// what the `openat(2)` walk can use without re-resolving a path it has
    /// already proven; there is no path form.
    CasObject,
    /// A member's path is a NAME. Its bytes are bound to the manifest's
    /// per-member digest and to nothing else, because nothing else is derivable
    /// — a jj op-log file's path says nothing about its contents.
    ///
    /// This is the honest answer, not the permissive default: a tree that took
    /// it while its members really were addressable would be declining a check
    /// that was available, which is the defect this enum exists to make
    /// impossible to take silently.
    PathOpaque,
}

/// The retention rule an asset is under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RetentionRule {
    /// Kept for the installation's life; only compaction may shrink it, and
    /// only behind a proof that nothing authoritative is lost.
    Indefinite,
    /// Bounded by an operator-visible policy Kata enforces.
    Bounded {
        /// The policy that bounds it.
        policy: &'static str,
    },
    /// Reclaimable at any time without correctness loss.
    Reclaimable,
    /// Lives only as long as the process or attempt that created it.
    ProcessLifetime,
    /// No retention rule exists in the tree. Named, not invented — deriving a
    /// bound needs a measured steady-state growth rate, which nothing measures.
    Unbounded,
}

/// Whether the shipped capture mechanism reaches this asset.
///
/// This is the field that makes the map a MEASUREMENT rather than a wish, and the
/// totality test fails if a new asset is added without answering it. There is ONE
/// shipped capture mechanism, `backup_data_dir`, so the answer is binary;
/// `the_backup_reaches_exactly_the_rows_registered_to_it` (in
/// `crates/core/tests/durable_asset_map.rs`) holds every main-data-directory row
/// to it against a real artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Registration {
    /// Reached by `backup_data_dir`: its top-level `*.db` discovery, its tree pass
    /// (`crate::store::backup::discover_captured_trees`) for [`CaptureRule::Tree`]
    /// rows under [`AssetRoot::MainDataDir`], or its bundled copy of the node
    /// config.
    Backup,
    /// Reached by no shipped capture mechanism.
    Unregistered,
}

/// One durable asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableAsset {
    /// The asset family this asset belongs to.
    pub family: &'static str,
    /// Where it lives, relative to a named root.
    pub location: AssetLocation,
    /// The component that WRITES it — the owner of record.
    pub owner: &'static str,
    /// Its authority class.
    pub authority: AssetAuthority,
    /// How it can be captured, or why it cannot.
    pub capture: CaptureRule,
    /// Its retention rule.
    pub retention: RetentionRule,
    /// Whether a shipped mechanism reaches it today.
    pub registration: Registration,
    /// Its rank in the snapshot order (lower is copied earlier).
    pub snapshot_rank: SnapshotRank,
}

/// The snapshot-order rank of an asset.
///
/// [`crate::store::backup`] already enforces the two-level version of this
/// ("authoritative last") over the `*.db` set it discovers. Once the asset set
/// includes trees and identity material, two levels are not enough: the CAS
/// BYTES must be captured before the operational roots that reference them, or
/// a restore carries a root whose object is absent — the exact state
/// `verify_authoritative_roots_resolve` refuses at boot.
///
/// The rule is one sentence: **an asset is copied before anything that can
/// reference it.** Ranks make that a total order rather than a pairwise
/// argument.
///
/// A rank states WHERE an asset goes in a recovery set, not whether a shipped
/// mechanism can put it there. The ranked tree families are `cas`,
/// `recovery-evidence`, and `vcs.jj_repo`. The two data-directory trees are
/// captured; the jj repository is reacquired with verified closure. The rank
/// is the ordering a capture has to satisfy, and
/// [`Registration`] is the separate record of what actually reaches them.
/// Conflating the two would have made this map describe the product's wishes
/// instead of its state.
///
/// `cas` is copied at exactly the position this rank names — first, before
/// every database — by [`crate::store::backup::backup_data_dir`]. `vcs.jj_repo`
/// is copied by nothing: it lives under an operator-declared root that no
/// shipped mechanism resolves; see [`CaptureRule`]'s doc.
///
/// `ranked_tree_capture_families_are_exact` pins this set so adding a family
/// requires updating the capture and recovery treatment deliberately.
///
/// `Serialize`/`Deserialize` are derived because the backup manifest carries
/// the [`ConsistencyToken`] INSIDE it, and a token is a sequence of
/// `{asset, rank, instant}`. The rank is the field that makes the token
/// checkable offline: without it a manifest reader can see the capture sequence
/// and cannot see whether that sequence was legal.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum SnapshotRank {
    /// Never part of a recovery set, by rule — transient, deliberately excluded,
    /// or reacquired rather than copied.
    NotCaptured = 0,
    /// Content- or ref-addressed assets that authoritative rows point AT.
    /// Copied first so every later reference resolves against bytes that are
    /// already durable.
    ReferencedContent = 1,
    /// Rebuildable mirrors and caches. Copied before their authorities so their
    /// snapshot instant cannot LEAD the authority they mirror.
    Derived = 2,
    /// Authoritative planes that no other captured asset is a mirror of.
    Authoritative = 3,
    /// The nucleus authority, copied strictly last: every other captured plane
    /// is derived from it or older than it.
    NucleusLast = 4,
}

/// The measured durable-asset set.
///
/// Every entry was read out of the tree, not out of a design table. A family
/// with no writer has no row — a registry that invented one would be exactly the
/// aspirational declaration this map forbids. Two such families are absent on
/// purpose: provider certifications have no durable store (no table and no
/// persistence site holds one, so a certification survives only in the process
/// that computed it), and no shipped path writes a VM kernel, rootfs or guest
/// image, because the rootless OCI container is the one execution engine.
pub const DURABLE_ASSETS: &[DurableAsset] = &[
    // -- content bytes: copied first, referenced by everything ---------------
    DurableAsset {
        family: "CAS object bytes/trees",
        location: AssetLocation::DataDirTree("cas"),
        owner: "kata_core::store::cas::CasStore",
        authority: AssetAuthority::Authoritative,
        // CONTENT-ADDRESSED, and that is a capture/restore obligation rather
        // than a description: a member of this tree may only be written to the
        // path its own bytes derive. See [`TreeMemberAddressing`].
        capture: CaptureRule::Tree {
            members: TreeMemberAddressing::CasObject,
        },
        // `Unbounded`, stated. Nothing deletes a CAS object: kata has no CAS
        // collection, so the tree only grows for the life of the data directory.
        // No value here is a byte or object CAP — a size cap on an authority is
        // data loss on a timer — and the archival half is
        // [`Registration::Backup`] below.
        //
        // It must also stay EQUAL to `cas.db`'s. That row is the metadata plane
        // for these same objects; a reclaim licensed against one and not the
        // other is precisely how a `cas_objects` row outlives its bytes, which
        // is the dangling reference `verify_authoritative_roots_resolve` exists
        // to refuse. `the_cas_bytes_and_their_metadata_share_one_retention_rule`
        // pins the equality.
        retention: RetentionRule::Unbounded,
        // `backup_data_dir`'s tree-discovery pass, driven by THIS map
        // (`crate::store::backup::discover_captured_trees`), carries every
        // file-backed object under `<data_dir>/cas` with a per-object digest, and
        // `restore_data_dir` puts them back.
        registration: Registration::Backup,
        snapshot_rank: SnapshotRank::ReferencedContent,
    },
    DurableAsset {
        family: "immutable clone/import recovery evidence",
        location: AssetLocation::DataDirTree("recovery-evidence"),
        owner: "kata_core::store::backup::import_catalog",
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Tree {
            members: TreeMemberAddressing::PathOpaque,
        },
        retention: RetentionRule::Indefinite,
        registration: Registration::Backup,
        snapshot_rank: SnapshotRank::ReferencedContent,
    },
    // -- authoritative planes -------------------------------------------------
    DurableAsset {
        family: "CAS metadata/index",
        location: AssetLocation::DataDirFile("cas.db"),
        owner: "kata_core::store::cas::CasStore",
        // Conditional by design: rebuildable only if every object byte is
        // self-identifying and discoverable, and inline objects keep the DB
        // authoritative. Objects under
        // `cas::INLINE_THRESHOLD` live IN this file and exist nowhere else, so
        // the condition is not met and the class is Authoritative.
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Sqlite,
        retention: RetentionRule::Unbounded,
        registration: Registration::Backup,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    DurableAsset {
        family: "derived delivery with durable cursor identity",
        location: AssetLocation::DataDirFile("ledger_events.db"),
        owner: "kata_core::operational::delivery::DeliveryProjector::project",
        // Event facts are derived from operational history, but the published
        // sequence high-water is not: failed reservations may leave holes.
        // Losing this file in the SAME runtime identity could reclaim a client
        // cursor. A fresh-identity clone may reset delivery; ordinary restart may
        // not replace this strongest retained fact with an empty store.
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Sqlite,
        // NOT `Bounded`: that variant requires "an operator-visible policy Kata
        // ENFORCES", and nothing enforces one here: kata has no path that deletes
        // this file's rows, and the operator-visible knob that looks like the
        // policy, `runtime.ledger_ttl_secs`, documents itself as "kata deletes
        // no ledger rows" and only emits a retained-state warning at boot
        // (`BootRig::build_workflow_executor`).
        // A retention table that calls an unarmed mechanism a bound is exactly
        // the aspirational declaration the map exists to stop.
        retention: RetentionRule::Unbounded,
        registration: Registration::Backup,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    DurableAsset {
        family: "memory.db",
        location: AssetLocation::DataDirFile("memory.db"),
        owner: "kata_core::store::native_memory_store",
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Sqlite,
        // NOT `Unbounded`: that variant means "no retention rule exists in the
        // tree", and one does — the per-namespace fold, armed by default.
        //
        // The cadence is on the write path, not on an operator verb:
        // `SqliteNativeMemoryStore::apply_proposal_with_entitlement`
        // (`crates/core/src/store/native_memory_store/store.rs`) invokes
        // `SqliteNativeMemoryStore::maybe_auto_compact`
        // (`crates/core/src/store/native_memory_store/store.rs`) after every
        // committed write, and on every
        // `memory_compaction_write_interval`-th of them that runs
        // `SqliteNativeMemoryStore::compact_with`
        // (`crates/core/src/store/native_memory_store/store.rs`) — folding
        // each namespace's oldest overflow past
        // `memory_compaction_max_live_per_namespace` into that namespace's
        // `Summary` object and then DELETING the folded objects and their events.
        // Both knobs are operator-visible and read in PRODUCTION, not just
        // declared: boot passes them straight into `with_compaction`
        // (`bin/kata/src/boot.rs`), and they default to 512 and 256
        // (`default_memory_compaction_max_live_per_namespace`,
        // `crates/types/src/config.rs`). `0` on either knob disables that
        // dimension and boot logs the narrowing, which is the operator-visible
        // half `Bounded` asks for.
        //
        // # The bound is a per-namespace LIVE-OBJECT COUNT, not a byte cap
        //
        // Stated here because `Bounded` is the strongest retention variant this
        // map has and a reader is entitled to know what it does NOT buy.
        // Compaction touches `memory_objects` and `memory_events` only:
        // `memory_proposals` and `memory_conflicts` are insert-only — the
        // workspace contains no `DELETE FROM` against either — and nothing prunes
        // by age. So this file
        // is bounded in the sense the variant defines (an operator-visible policy
        // Kata enforces) and still carries no enforced BYTE bound.
        //
        // # AND THE COUNT BOUND DOES NOT BOUND THE STORE, because the number of
        // namespaces is itself unbounded
        //
        // This is the sharper half and it is stated because `Bounded` invites the
        // opposite reading. `compact_with` groups by `object.scope.canonical_key()`
        // and enforces the ceiling WITHIN each group, while `MemoryScope`
        // (`crates/types/src/memory.rs`) is `Global | Project { project } |
        // Workflow { project, workflow }` — arbitrary operator-supplied strings.
        // So the enforced invariant is "no NAMESPACE exceeds N live objects", and
        // total live objects are bounded by `N × (namespace count)` where the
        // second factor has no ceiling anywhere in the tree. A deployment that
        // mints a new project or workflow name per run grows this file forever
        // while every namespace in it stays inside its cap and compaction reports
        // itself working.
        //
        // The row is still `Bounded` and that is correct: the variant asks
        // whether a rule EXISTS and production enforces it, and one does. What a
        // successor must not do is read this row as evidence that `memory.db`
        // cannot grow without limit, which is why the denominator is written down
        // here rather than left to be re-derived.
        retention: RetentionRule::Bounded {
            policy: "runtime.memory_compaction_max_live_per_namespace / \
                     memory_compaction_write_interval",
        },
        registration: Registration::Backup,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    DurableAsset {
        family: "operational.db (effect idempotency plane)",
        location: AssetLocation::DataDirFile("idempotency.db"),
        owner: "kata_core::idempotency_store",
        // Losing it re-runs an effect that already happened. "Effect outcome"
        // is in the prohibition list, so this is not a cache.
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Sqlite,
        retention: RetentionRule::Unbounded,
        registration: Registration::Backup,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    DurableAsset {
        family: "stage cache",
        location: AssetLocation::DataDirFile("stage_cache.db"),
        owner: "kata_core::store::SqliteWorkflowStore",
        // `capsule_reuse_v1` is the whole of this file: a HINT naming which
        // accepted occurrence last produced a capsule reuse key. The
        // operational plane re-verifies every hit, a lost row is a miss, and
        // the next run of the stage re-records it — so it is rebuilt by
        // re-execution.
        authority: AssetAuthority::Rebuildable {
            from: "re-execution of the cached stage",
        },
        capture: CaptureRule::Sqlite,
        retention: RetentionRule::Reclaimable,
        // The cheap tier `AssetAuthority::Rebuildable` earns
        // ([`crate::store::backup::durability_tier`]) takes no digest and no
        // `PRAGMA quick_check`, so a restored copy is unverified at every point
        // — and that models LOSS, which rebuildability answers, not ALTERATION,
        // which it does not: nothing rebuilds a database that is PRESENT and
        // wrong. The durable tier is not the answer either: it would let a
        // bit-rotted hint table refuse the restore of the LEDGER, a cost no
        // hint is worth.
        //
        // So the disposition is the one this class already licenses — *"losing
        // it costs work, never correctness"*. `backup::artifact_carries_database`
        // refuses the name at discovery and `backup::clear_rebuildable_databases`
        // clears it from a restore target (its `Reclaimable` retention is
        // exactly that licence), so a restored node rebuilds it against the CAS
        // the artifact actually carried.
        registration: Registration::Unregistered,
        // `Derived` — *"rebuildable mirrors and caches; copied before their
        // authorities so their snapshot instant cannot LEAD the authority they
        // mirror."* The rank is a DESIGN position that no capture exercises
        // (this file is `Registration::Unregistered`), which is the split
        // [`SnapshotRank`]'s own doc makes, and it stays stated rather than
        // blanked so that a capture of a rebuildable plane
        // inherits the position instead of re-deriving it.
        snapshot_rank: SnapshotRank::Derived,
    },
    // -- the nucleus, copied last --------------------------------------------
    DurableAsset {
        family: "operational.db",
        location: AssetLocation::DataDirFile("operational.db"),
        owner: "kata_core::operational",
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Sqlite,
        retention: RetentionRule::Indefinite,
        registration: Registration::Backup,
        snapshot_rank: SnapshotRank::NucleusLast,
    },
    // -- identity material ----------------------------------------------------
    DurableAsset {
        family: "main identity and worker credentials",
        location: AssetLocation::DataDirFile("main-identity.json"),
        owner: "kata::data_dir_lock",
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::SealedOrRebound,
        retention: RetentionRule::Indefinite,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    DurableAsset {
        family: "main identity and worker credentials",
        location: AssetLocation::DataDirFile("local-worker.secret"),
        owner: "kata::local_capacity",
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::SealedOrRebound,
        retention: RetentionRule::Indefinite,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    // -- the SECOND durable root: a worker node's own directory ---------------
    //
    // Everything above this comment lives under the main's `<data_dir>`, its
    // repo, or the operator's config. These two do not, and no capture
    // mechanism in the tree resolves the root they are under.
    DurableAsset {
        family: "operational.db (effect idempotency plane)",
        location: AssetLocation::SubordinateWorkerFile("subordinate-worker:idempotency.db"),
        owner: "kata_worker::daemon",
        // The worker-local double-spend latch.
        // `kata_worker::daemon::open_worker_idempotency_store` propagates the open
        // failure rather than returning a membrane-less store — a worker that crashes
        // mid-effect and restarts must find its claim latch still standing — so
        // this is not merely authoritative, it is boot-blocking on the node that
        // holds it. It is a DIFFERENT asset from the main's `idempotency.db`: different
        // root, different claims. That is not this map's
        // reading — the worker-local latch is excluded BY DESIGN and permanently,
        // on the ground that "standalone workers also open their OWN store", so
        // collapsing the two membranes breaks double-spend protection. The map had
        // one row for what are necessarily two stores.
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Sqlite,
        retention: RetentionRule::Unbounded,
        // Carrying it onto another node makes that node believe it already spent
        // effects it never spent, which SUPPRESSES effects that must run;
        // leaving it behind re-opens the double-spend window it exists to close.
        // Either way it is bound to the node that wrote it.
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    DurableAsset {
        family: "main identity and worker credentials",
        location: AssetLocation::SubordinateWorkerFile("subordinate-worker:credential_path"),
        owner: "kata_worker::daemon",
        // The enrollment credential is identity material ON THE WORKER NODE.
        // `local-worker.secret` is the main's copy, which it checks every local
        // worker's proof against; a standalone `kata-worker` authenticates with
        // this file, from its own directory, and nothing in the main's data
        // directory stands in for it. (The supervised node's copy,
        // `node.cred`, is rendered from `local-worker.secret` at every boot.)
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::SealedOrRebound,
        retention: RetentionRule::Indefinite,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    // -- the supervised node's rendered files ---------------------------------
    //
    // `kata serve` writes both at every boot from its own config and
    // `local-worker.secret` (`kata::supervised_node`); the node's membrane
    // store is the data directory's own `idempotency.db` above.
    DurableAsset {
        family: "node configuration",
        location: AssetLocation::DataDirFile("node.toml"),
        owner: "kata::supervised_node",
        authority: AssetAuthority::Rebuildable { from: "--config" },
        capture: CaptureRule::Excluded {
            because: "rendered from the main's config at every boot",
        },
        retention: RetentionRule::ProcessLifetime,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "main identity and worker credentials",
        location: AssetLocation::DataDirFile("node.cred"),
        owner: "kata::supervised_node",
        authority: AssetAuthority::Rebuildable {
            from: "local-worker.secret",
        },
        capture: CaptureRule::Excluded {
            because: "a copy of `local-worker.secret`, rendered at every boot",
        },
        retention: RetentionRule::ProcessLifetime,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    // -- operator intent ------------------------------------------------------
    DurableAsset {
        family: "node configuration",
        location: AssetLocation::ConfigDeclared("--config"),
        owner: "operator",
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::OpaqueFile,
        retention: RetentionRule::Indefinite,
        // `backup_data_dir` copies it to `kata.toml` inside the artifact when
        // `config_included` is set.
        registration: Registration::Backup,
        snapshot_rank: SnapshotRank::Authoritative,
    },
    // -- source / candidate / landing -----------------------------------------
    DurableAsset {
        family: "jj repository, op-log, bookmarks/refs",
        location: AssetLocation::ConfigDeclared("vcs.jj_repo"),
        owner: "kata_vcs::JjBackend",
        authority: AssetAuthority::Authoritative,
        // PATH-OPAQUE. A jj repository's op-log entries, index segments, and
        // store files are named by sequence and by internal id, not by their
        // own content, so no path-to-content binding is derivable and claiming
        // one would be inventing a check.
        capture: CaptureRule::Tree {
            members: TreeMemberAddressing::PathOpaque,
        },
        retention: RetentionRule::Indefinite,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::ReferencedContent,
    },
    DurableAsset {
        family: "workflow packs, lockfile, source lineage",
        location: AssetLocation::ConfigDeclared("workflow roots"),
        owner: "kata_program::library",
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Reacquire {
            by: "content digest against verified provenance",
        },
        retention: RetentionRule::Indefinite,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    // -- transient ------------------------------------------------------------
    DurableAsset {
        family: "pidfiles/locks",
        location: AssetLocation::DataDirFile("main.lock"),
        owner: "kata::data_dir_lock",
        authority: AssetAuthority::Transient,
        capture: CaptureRule::Excluded {
            because: "process coordination; a restored lock describes a process \
                      that is not running",
        },
        retention: RetentionRule::ProcessLifetime,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "pidfiles/locks",
        location: AssetLocation::DataDirFile("installed-main.discovery.lock"),
        owner: "kata::data_dir_lock",
        authority: AssetAuthority::Transient,
        capture: CaptureRule::Excluded {
            because: "process coordination; a restored lock describes a process \
                      that is not running",
        },
        retention: RetentionRule::ProcessLifetime,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "pidfiles/locks",
        // The PATH is operator-declared (`workers.transports[].path`); the
        // convention is `<data_dir>/worker.sock`.
        location: AssetLocation::DataDirFile("worker.sock"),
        // The owner is whatever calls `bind(2)`, not the module that assembles
        // the config: `LocalSocketListener::listen` creates the inode (and
        // unlinks a stale one).
        owner: "kata_transport::local_socket::LocalSocketListener",
        authority: AssetAuthority::Transient,
        capture: CaptureRule::Excluded {
            because: "a Unix socket is not a file a copy can reproduce",
        },
        retention: RetentionRule::ProcessLifetime,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "pidfiles/locks",
        // The supervised node's socket, bound by the main.
        location: AssetLocation::DataDirFile("node.sock"),
        owner: "kata_transport::local_socket::LocalSocketListener",
        authority: AssetAuthority::Transient,
        capture: CaptureRule::Excluded {
            because: "a Unix socket is not a file a copy can reproduce",
        },
        retention: RetentionRule::ProcessLifetime,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "pidfiles/locks",
        // The supervised node's `kata-worker` writes it: the main starts the node
        // with `KATA_DATA_DIR` = the data directory, which names its pidfile's.
        location: AssetLocation::DataDirFile("kata-worker.pid"),
        owner: "kata::supervised_node",
        authority: AssetAuthority::Transient,
        capture: CaptureRule::Excluded {
            because: "process coordination; a restored pidfile describes a process \
                      that is not running",
        },
        retention: RetentionRule::ProcessLifetime,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "derived events/metrics/traces/read projections",
        location: AssetLocation::DataDirFile("installed-main.shutdown.json"),
        owner: "kata::shutdown_journal",
        authority: AssetAuthority::Rebuildable {
            from: "the next clean shutdown",
        },
        capture: CaptureRule::Excluded {
            because: "describes the last shutdown of a main that is not the one \
                      being restored",
        },
        retention: RetentionRule::ProcessLifetime,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    // -- publish-through-rename residue --------------------------------------
    //
    // Each is the tmp half of a write-then-rename publish that current code
    // performs —
    // `shutdown_journal`'s `TEMPORARY_FILE`, `data_dir_lock`'s
    // `.main-identity-<ulid>.tmp` and `supervised_node`'s
    // `.node-staged-<file>-<pid>` — so each is exactly what a node killed
    // mid-publish leaves behind, which is the state a recovery contract is most
    // likely to meet and least likely to have thought about.
    DurableAsset {
        family: "derived events/metrics/traces/read projections",
        location: AssetLocation::DataDirFile(".installed-main.shutdown.tmp"),
        owner: "kata::shutdown_journal",
        authority: AssetAuthority::Transient,
        capture: CaptureRule::Excluded {
            because: "crash residue of the shutdown journal's write-then-rename \
                      publish; it describes a shutdown that did not complete",
        },
        retention: RetentionRule::Reclaimable,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "main identity and worker credentials",
        // A PREFIX, not a file: the name carries a fresh ULID per attempt
        // (`.main-identity-<ulid>.tmp`), so no exact row could ever match one.
        location: AssetLocation::DataDirPrefix(".main-identity-"),
        owner: "kata::data_dir_lock",
        // The half-published identity of a directory that HAS no identity yet.
        // Transient, not authoritative: a `.tmp` that lost its rename never
        // became anyone's identity, and treating it as one would make an
        // interrupted first boot look like an impersonation attempt.
        authority: AssetAuthority::Transient,
        capture: CaptureRule::Excluded {
            because: "an identity file whose atomic publish did not complete; \
                      the next boot allocates a new one",
        },
        retention: RetentionRule::Reclaimable,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "node configuration",
        // A PREFIX: the staged half of `node.toml` or `node.cred`, named by the
        // file and the main's pid (`.node-staged-node.toml-<pid>`).
        location: AssetLocation::DataDirPrefix(".node-staged-"),
        owner: "kata::supervised_node",
        // Rendered from the config and `local-worker.secret`, like the files it
        // stages: a staged `node.cred` holds the enrollment secret, so it is never
        // captured.
        authority: AssetAuthority::Transient,
        capture: CaptureRule::Excluded {
            because: "a node file whose atomic publish did not complete; the next \
                      boot renders both files again",
        },
        retention: RetentionRule::Reclaimable,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    DurableAsset {
        family: "derived events/metrics/traces/read projections",
        location: AssetLocation::DataDirTree("recovery-generations"),
        owner: "kata_core::store::backup::restore_journal_path",
        // The one file under this root is `backup-restore-journal.json`, the
        // in-progress journal a restore publishes (`restore_journal_path`) and
        // clears when it completes (`clear_restore_journal`). It exists only
        // between an interrupted restore and its resume, and deleting it during
        // that window costs a re-copy, never correctness — the resume re-verifies
        // every target against the manifest digest regardless. A reclaim that runs
        // while a restore is in flight is still the wrong reclaim.
        authority: AssetAuthority::Rebuildable {
            from: "re-running the interrupted restore from its artifact",
        },
        capture: CaptureRule::Excluded {
            because: "the progress record of a restore into this directory, not of the one \
                      a capture would be restored into",
        },
        retention: RetentionRule::Reclaimable,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    // -- external -------------------------------------------------------------
    DurableAsset {
        family: "external proxy/vault/filter state",
        location: AssetLocation::External("operator secret/proxy backend"),
        owner: "operator",
        authority: AssetAuthority::Authoritative,
        capture: CaptureRule::Reacquire {
            by: "non-secret reference plus required identity/digest; explicit \
                 external rebind",
        },
        retention: RetentionRule::Indefinite,
        registration: Registration::Unregistered,
        snapshot_rank: SnapshotRank::NotCaptured,
    },
    // -- names no row classifies ---------------------------------------------
    //
    // A top-level name this binary does not write has no row, and
    // `classify_data_dir_entry` returns `None` for it. A stray `*.db` is still
    // BACKED UP — an unclassified database is carried at `DurabilityTier::Durable`
    // by `crate::store::backup::tier_of_database`, because ignorance argues for the
    // expensive tier — and is reported `unclassified` by [`assess_backup_class`],
    // which is the true statement about a file this binary knows nothing about.
    // Boot does not open beside one: `refuse_undeclared_databases` refuses the
    // directory.
];

/// Classify a top-level entry name under `<data_dir>`.
///
/// Returns the asset that owns the name, matching a
/// [`AssetLocation::DataDirPrefix`] family by prefix and ignoring SQLite's
/// `-wal` / `-shm` / `-journal` sidecars (which belong to their main file, not
/// to a row of their own).
#[must_use]
pub fn classify_data_dir_entry(entry: &str) -> Option<&'static DurableAsset> {
    let base = sqlite_sidecar_owner(entry);
    // Exact names win over a prefix family, so an exact row can never be
    // absorbed by a prefix that happens to match it.
    DURABLE_ASSETS
        .iter()
        .find(|asset| {
            matches!(
                asset.location,
                AssetLocation::DataDirFile(name) | AssetLocation::DataDirTree(name) if name == base
            )
        })
        .or_else(|| {
            DURABLE_ASSETS.iter().find(|asset| {
                matches!(asset.location, AssetLocation::DataDirPrefix(prefix)
                    if base.starts_with(prefix))
            })
        })
}

/// The file a SQLite `-wal` / `-shm` / `-journal` sidecar belongs to, or `entry` itself.
fn sqlite_sidecar_owner(entry: &str) -> &str {
    entry
        .strip_suffix("-wal")
        .or_else(|| entry.strip_suffix("-shm"))
        .or_else(|| entry.strip_suffix("-journal"))
        .unwrap_or(entry)
}

/// Refuse a data directory that holds a database no row of this map declares.
///
/// The refused set is every top-level entry under `data_dir` — a regular file, a
/// directory or a symlink, dangling or not — whose name, with a SQLite `-wal` /
/// `-shm` / `-journal` suffix stripped, has a `.db` extension in any letter case and which
/// [`classify_data_dir_entry`] does not classify. Every other unclassified name passes
/// (a configured worker socket may take any name under `<data_dir>`), so the refusal is
/// keyed on databases, not on every name the map does not row.
///
/// This binary's databases are exactly the declared set, so a database outside it is
/// one this binary did not write and cannot read, and it may hold the only copy of what
/// its writer recorded. Opening the declared stores beside it would serve a directory
/// whose authority is partly unreadable, and deleting it would destroy that record, so
/// the directory is refused with the new-empty-data-directory recourse. The probe reads
/// directory entries only: nothing is opened, followed or removed.
///
/// # Errors
///
/// [`KataError::Validation`] naming every undeclared database, sorted; an I/O error
/// listing the directory propagates rather than being read as an empty directory.
pub fn refuse_undeclared_databases(data_dir: &std::path::Path) -> KataResult<()> {
    let mut undeclared = Vec::new();
    for entry in std::fs::read_dir(data_dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let is_database = std::path::Path::new(sqlite_sidecar_owner(&name))
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("db"));
        if is_database && classify_data_dir_entry(&name).is_none() {
            undeclared.push(name);
        }
    }
    if undeclared.is_empty() {
        return Ok(());
    }
    undeclared.sort();
    Err(KataError::Validation(format!(
        "data directory {} holds database(s) this binary does not declare: {}. This binary \
         cannot read them and will not delete them, because they may hold the only copy of \
         what their writer recorded. Use a new empty data directory and preserve this \
         directory offline",
        data_dir.display(),
        undeclared.join(", ")
    )))
}

/// The class of a backup artifact.
///
/// [`assess_backup_class`] DERIVES [`BackupClass::Recoverable`], and
/// `the_complete_authoritative_set_earns_recoverable_and_one_omission_costs_it`
/// reaches it.
///
/// [`Self::SealedFull`] is unreachable from [`assess_backup_class`], and for a
/// STRUCTURAL reason rather than an unbuilt-yet one: it is a property of
/// how the artifact's identity material is ENCRYPTED, and this function sees
/// only which asset NAMES an artifact carries. No asset set can express it, so
/// no amount of work on this function reaches it; the producer it needs is a
/// sealing mechanism, and until one ships, `SealedFull` names the class an
/// artifact would earn and nothing claims it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackupClass {
    /// Explicitly incomplete for bootable recovery.
    DataSnapshot,
    /// Every required asset is included, content-verified reacquirable, or
    /// named as a mandatory external rebind.
    Recoverable,
    /// A recoverable backup that additionally includes required identity
    /// material, encrypted to an operator-selected recipient.
    SealedFull,
}

impl BackupClass {
    /// The operator-facing spelling, which is what both reports print.
    ///
    /// It lives on the enum rather than at the two call sites for the reason
    /// [`CompletenessVerdict`]'s `Display` does: `kata backup` and
    /// `kata restore` carried two hand-written class lines that disagreed in
    /// wording (*"not a complete recoverable-node backup"* vs *"complete-asset
    /// recovery is not implied"*), and two hand-written accounts of one derived
    /// fact is how the two reports drift.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::DataSnapshot => "database data snapshot (not a complete recoverable-node backup)",
            Self::Recoverable => {
                "recoverable-node backup (every authoritative asset is captured, or named for \
                 mandatory external rebind)"
            }
            Self::SealedFull => {
                "sealed full backup (recoverable, plus identity material encrypted to an \
                 operator-selected recipient)"
            }
        }
    }
}

/// A completeness verdict over a captured asset set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletenessVerdict {
    /// The class the captured set actually earns.
    pub class: BackupClass,
    /// Authoritative assets that a complete artifact must INCLUDE and this one
    /// does not, by location name. This is the field a manifest must carry: the
    /// incompleteness must be surfaced in the artifact an
    /// operator inspects offline, not in a Rust doc comment.
    pub missing_authoritative: Vec<&'static str>,
    /// Authoritative assets a complete artifact is never expected to include,
    /// because they are satisfied by *"content-verified reacquirable, or named
    /// as a mandatory external rebind"* instead.
    ///
    /// Separate from [`Self::missing_authoritative`] on purpose: an operator who
    /// cannot tell "this artifact is missing something it should have copied"
    /// from "this artifact requires you to rebind an external dependency" cannot
    /// act on either. Folding them into one list is how a completeness report
    /// becomes noise nobody reads.
    pub requires_external_rebind: Vec<&'static str>,
    /// Captured names the map does not know. A capture that carries an asset
    /// nothing classified is a map that has gone stale.
    pub unclassified: Vec<String>,
    /// Why a name in [`Self::missing_authoritative`] is missing, when the
    /// capture that produced the artifact knows.
    ///
    /// # A missing asset an operator cannot EXPLAIN is indistinguishable from a bug
    ///
    /// [`assess_backup_class`] can only ever say an asset is ABSENT — that is
    /// all an artifact's own evidence can support. A capture that DEGRADED knows
    /// more: it knows which bound it hit and by how much. That reason reached
    /// only a `tracing::warn!` on a code path (`kata backup`) that installs no
    /// subscriber, so it was formatted and dropped, and the operator was told
    /// `cas` is missing with no way to tell a capacity degradation from a defect.
    ///
    /// It rides HERE rather than in a second report section because the omission
    /// and its reason are one fact: the artifact makes no claim to the asset,
    /// and this says why. [`CompletenessVerdict::explaining`] is the only way to
    /// populate it, and it refuses a reason for an asset that is not missing.
    pub omission_reasons: BTreeMap<&'static str, String>,
}

impl CompletenessVerdict {
    /// Attach a capture's own account of why it omitted an asset.
    ///
    /// Reasons for names NOT in [`Self::missing_authoritative`] are DROPPED
    /// rather than recorded. A reason attached to an asset the artifact holds
    /// would be a report contradicting itself in two adjacent lines, and the
    /// input is a capture's word about its own run — the verdict's own
    /// derivation from the map is the authority on what is missing.
    #[must_use]
    pub fn explaining<I, N>(mut self, reasons: I) -> Self
    where
        I: IntoIterator<Item = (N, String)>,
        N: AsRef<str>,
    {
        for (name, reason) in reasons {
            if let Some(missing) = self
                .missing_authoritative
                .iter()
                .find(|missing| **missing == name.as_ref())
            {
                self.omission_reasons.insert(missing, reason);
            }
        }
        self
    }
}

/// The verdict as the OPERATOR-FACING block both `kata backup` and
/// `kata restore` print, one asset per line.
///
/// # Why the rendering lives here and not in the CLI
///
/// There are two reports, backup and restore, and each must name WHICH
/// authoritative assets are absent, not merely that some are: an operator told
/// their artifact is incomplete and not told WHICH cannot act, and cannot tell
/// `cas` (bytes their `cas.db` rows point at, on this host) from `vcs.jj_repo`
/// (a tree the operator's own config names) from
/// `subordinate-worker:credential_path` (a file under a worker node's own root).
///
/// Rendering here rather than at each call site means the two reports cannot
/// drift into two different accounts of the same map, and means the rendering
/// is reachable from a test that does not have to acquire a lifecycle lease.
///
/// Each line carries its [`AssetRoot`], because the name alone does not say
/// which of the FIVE durable roots a recovery has to resolve to obtain it — the
/// distinction [`AssetLocation`]'s own doc calls out as the easy one to get
/// wrong.
///
/// The `class = …` line is rendered here for the same reason: [`assess_backup_class`]
/// DERIVES the class, and a report printing a hand-typed class line would be
/// printing a claim nothing computed beside a block that was derived.
///
/// A [`Self::omission_reasons`] entry renders INDENTED UNDER the asset it
/// explains, never as a separate list: an operator scanning a fourteen-line
/// omission block has to be able to tell which line the reason belongs to.
impl std::fmt::Display for CompletenessVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "class = {}", self.class.describe())?;
        writeln!(
            f,
            "authoritative assets NOT captured = {}",
            self.missing_authoritative.len()
        )?;
        for name in &self.missing_authoritative {
            writeln!(f, "  {}", with_root(name))?;
            if let Some(reason) = self.omission_reasons.get(name) {
                writeln!(f, "    omitted by this capture: {reason}")?;
            }
        }
        writeln!(
            f,
            "authoritative assets satisfied by external rebind, never by copy = {}",
            self.requires_external_rebind.len()
        )?;
        for name in &self.requires_external_rebind {
            writeln!(f, "  {}", with_root(name))?;
        }
        writeln!(
            f,
            "captured names the durable-asset map does not classify = {}",
            self.unclassified.len()
        )?;
        for name in &self.unclassified {
            writeln!(f, "  {name}")?;
        }
        Ok(())
    }
}

/// `<name> [<root>]` for a name that resolves to a map row, and the bare name
/// for one that does not.
///
/// The fallback is unreachable for the two lists it renders — both are built
/// from `DURABLE_ASSETS` rows by [`assess_backup_class`] — and
/// `every_named_omission_carries_the_root_it_lives_under` pins that. It is a
/// fallback and not an `expect` because a report is not the place to panic: an
/// operator holding an artifact is entitled to the rest of the block even if
/// one name has gone stale under them.
fn with_root(name: &str) -> String {
    DURABLE_ASSETS
        .iter()
        .find(|asset| asset.location.name() == name)
        .map_or_else(
            || name.to_string(),
            |asset| format!("{name} [{:?}]", asset.location.root()),
        )
}

/// Assess what class a captured asset set earns.
///
/// `captured` is the set of asset location names an artifact actually contains.
///
/// # What earns [`BackupClass::Recoverable`], and why this DERIVES it
///
/// A recoverable backup requires every authoritative asset to be included,
/// content-verified reacquirable, or named as a mandatory external rebind. That
/// is a statement about the captured SET, and it is decidable from one:
/// `missing_authoritative` empty means every authoritative row is either covered
/// or a [`CaptureRule::Reacquire`] rebind obligation, which is the clause
/// verbatim. It is necessary; it is not quite sufficient, because a captured
/// name the map cannot classify means the map has gone stale under the artifact
/// and this function cannot vouch for a completeness it cannot see. So both
/// lists must be empty.
///
/// # Raw set classification and verified artifact recovery are distinct
///
/// This function derives the class from the supplied asset set. Its recovery
/// branch is reachable and is tested by
/// `the_complete_authoritative_set_earns_recoverable_and_one_omission_costs_it`.
/// A complete name set alone is not evidence that bytes, external generations,
/// remote object closure or target bindings were verified.
///
/// The ordinary snapshot adapter `manifest_completeness` reads three structural
/// channels: admitted database names, accepted tree roots and the bundled-config
/// flag. Five authoritative asset groups are inexpressible in those channels;
/// `structural_inventory_alone_cannot_earn_recoverable` pins that exact missing
/// set and distinguishes it from an inadmissible raw `BackupManifest` value.
/// Its bound applies to that adapter, not every readable artifact or product
/// path. The separate v3 recovery-treatment/verifier path can produce
/// `VerifiedRecoveryArtifact`, whose completeness verdict includes the verified
/// treatment evidence.
///
/// An ordinary snapshot omission changes `missing_authoritative` even when its
/// class remains `DataSnapshot` because other groups are still absent. Such an
/// omission test must assert the independently observable missing asset rather
/// than infer correctness from the unchanged class.
#[must_use]
pub fn assess_backup_class(captured: &BTreeSet<String>) -> CompletenessVerdict {
    // Resolve every captured NAME to the map row it belongs to before deciding
    // anything. A captured name is not always a location name: a file under a
    // `DataDirPrefix` row carries more than the prefix, and comparing the strings
    // directly would report such a file as unclassified AND its family as missing.
    // Exact match first (that is how a caller names a config-declared,
    // repo-relative, or tree asset), then the data-dir classifier, which also folds
    // `-wal`/`-shm`/`-journal` sidecars.
    let mut covered: BTreeSet<&'static str> = BTreeSet::new();
    let mut unclassified = Vec::new();
    for name in captured {
        let resolved = DURABLE_ASSETS
            .iter()
            .find(|asset| asset.location.name() == name.as_str())
            .or_else(|| classify_data_dir_entry(name));
        match resolved {
            Some(asset) => {
                covered.insert(asset.location.name());
            }
            None => unclassified.push(name.clone()),
        }
    }
    let absent_authoritative = DURABLE_ASSETS
        .iter()
        .filter(|asset| asset.authority.is_authoritative())
        .filter(|asset| !covered.contains(asset.location.name()));
    let (rebind, missing): (Vec<&DurableAsset>, Vec<&DurableAsset>) = absent_authoritative
        .partition(|asset| matches!(asset.capture, CaptureRule::Reacquire { .. }));
    CompletenessVerdict {
        // DERIVED from the two lists below rather than typed beside them. See
        // the doc above for what earns the class.
        class: if missing.is_empty() && unclassified.is_empty() {
            BackupClass::Recoverable
        } else {
            BackupClass::DataSnapshot
        },
        missing_authoritative: missing.iter().map(|asset| asset.location.name()).collect(),
        requires_external_rebind: rebind.iter().map(|asset| asset.location.name()).collect(),
        unclassified,
        // Populated only by `CompletenessVerdict::explaining`, from a capture
        // that knows why it degraded. The map cannot know; absence is all an
        // artifact's own evidence supports.
        omission_reasons: BTreeMap::new(),
    }
}

/// A capture's proof that its parts were taken in an order that cannot be
/// mis-restored.
///
/// # Why a token, and why THIS token
///
/// Without it, the only cross-asset ordering guarantee is COPY ORDER
/// ([`SnapshotRank`], cross-checked by `backup::AUTHORITATIVE_LAST`).
/// Copy order bounds the DIRECTION of skew — a derived mirror's snapshot
/// instant is earlier-than-or-equal-to its authority's — and says nothing about
/// its MAGNITUDE. That is the right guarantee to have, because "mirror lags
/// authority" is the direction recovery can repair and "mirror leads" is the one
/// it cannot; but a manifest that records only the order cannot tell an operator
/// how stale the restored derived plane is, and cannot detect a capture whose
/// parts were interleaved by a concurrent mechanism.
///
/// So the token records the per-asset snapshot INSTANT alongside the order, and
/// verifies both: the ranks must be non-decreasing in capture sequence, and
/// each asset's instant must not exceed the instant of anything ranked after it.
/// [`ConsistencyToken::max_skew_ms`] then reports the magnitude the copy order
/// cannot.
///
/// The instants are wall-clock milliseconds from the capturing host's clock and
/// are used only for DIFFERENCES between reads taken by one capture, on one
/// host, within one capture window. They are not compared across hosts and are
/// not an authority for anything but this token.
///
/// # Why it is serializable
///
/// The token is carried IN the artifact (see
/// [`crate::store::backup::backup_data_dir_with_consistency_token`]), because
/// the operator who runs the RESTORE — a different person, on a different day,
/// holding only the artifact — must be able to see the order its parts were
/// taken in.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsistencyToken {
    /// Per-asset snapshot instant, keyed by asset location name, in capture
    /// sequence.
    entries: Vec<ConsistencyEntry>,
}

/// One asset's entry in a [`ConsistencyToken`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsistencyEntry {
    /// The asset's location name.
    pub asset: String,
    /// The asset's snapshot rank at capture.
    pub rank: SnapshotRank,
    /// The wall-clock millisecond at which this asset's snapshot instant was
    /// taken.
    pub instant_ms: i64,
}

impl ConsistencyToken {
    /// Build a token from a capture's entries, in the sequence they were
    /// captured.
    #[must_use]
    pub fn new(entries: Vec<ConsistencyEntry>) -> Self {
        Self { entries }
    }

    /// The entries, in capture sequence.
    #[must_use]
    pub fn entries(&self) -> &[ConsistencyEntry] {
        &self.entries
    }

    /// The largest wall-clock gap, in milliseconds, between any two assets'
    /// snapshot instants in this capture.
    ///
    /// This is the number the copy-order rule cannot produce: it bounds how
    /// stale the earliest-captured plane is relative to the latest. A recovery
    /// contract that wants a skew BOUND states it against this value; this
    /// module deliberately states no bound, because no bound has been measured.
    #[must_use]
    pub fn max_skew_ms(&self) -> i64 {
        let Some(first) = self.entries.first() else {
            return 0;
        };
        let mut low = first.instant_ms;
        let mut high = first.instant_ms;
        for entry in &self.entries[1..] {
            low = low.min(entry.instant_ms);
            high = high.max(entry.instant_ms);
        }
        high - low
    }

    /// Verify the capture order this token records.
    ///
    /// Refuses two distinct defects:
    ///
    /// 1. **Out-of-rank capture** — an asset captured after one of a strictly
    ///    higher rank. The whole point of the rank is that a reference is
    ///    captured after the thing it references; reversing it produces an
    ///    artifact with a root whose object is absent.
    /// 2. **Instant inversion** — an asset whose snapshot instant is LATER than
    ///    that of an asset ranked after it. Copy order alone cannot catch this,
    ///    because a capture can copy in the right order and still read the
    ///    earlier file at a later instant if something re-reads it.
    ///
    /// # [`SnapshotRank::NotCaptured`] entries are EXCLUDED from the predicate
    ///
    /// The invariant this function enforces is about REFERENCES: content is
    /// captured before anything that can reference it. An asset ranked
    /// `NotCaptured` is by definition not part of a recovery set — *"never part
    /// of a recovery set, by rule — transient, deliberately excluded, or
    /// reacquired rather than copied"* — so it cannot be the
    /// REFERENT of anything a restore will place. Ordering it against a captured
    /// asset compares a position in the recovery set against a thing that has no
    /// position in it, and the comparison always fails in one direction because
    /// `NotCaptured` is rank `0`: it sorts before `ReferencedContent`, while the
    /// tree pass copies `cas` first unconditionally.
    ///
    /// A token that ordered a `NotCaptured` entry against `cas` would make a
    /// capture refuse itself, and the `NotCaptured` rows in this map are LIVE
    /// assets (`main.lock`, `worker.sock`, the `.main-identity-` family).
    ///
    /// **The gap between what this REFUSES and what its name CLAIMS.** NO shipped
    /// capture emits a `NotCaptured` entry at all: `crate::store::backup` only pushes an entry for an asset it
    /// actually copied, and every copyable row ranks `ReferencedContent` or
    /// above. So this exclusion is enforcement for a state only a hand-built
    /// token — or a future map edit that gives a `NotCaptured` row a capture
    /// rule — can reach. It is kept because the alternative is a predicate that
    /// is WRONG the first time such a row is captured, and because a filter that
    /// states the category is cheaper to read than a refusal that has to be
    /// explained.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] naming the two assets and which rule they broke.
    pub fn verify(&self) -> KataResult<()> {
        let mut previous: Option<&ConsistencyEntry> = None;
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.rank != SnapshotRank::NotCaptured)
        {
            if let Some(previous) = previous {
                if entry.rank < previous.rank {
                    return Err(KataError::Storage(format!(
                        "consistency token: asset {} (rank {:?}) was captured AFTER {} (rank \
                         {:?}); a referenced asset must be captured before anything that can \
                         reference it",
                        entry.asset, entry.rank, previous.asset, previous.rank
                    )));
                }
                if entry.rank > previous.rank && previous.instant_ms > entry.instant_ms {
                    return Err(KataError::Storage(format!(
                        "consistency token: asset {} snapshot instant {} LEADS the \
                         later-ranked {} instant {}; the derived plane would lead the \
                         authority it mirrors, which recovery cannot repair",
                        previous.asset, previous.instant_ms, entry.asset, entry.instant_ms
                    )));
                }
            }
            previous = Some(entry);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The map's own internal consistency, in the ONE direction that is a
    /// statement about the design rather than about today's mechanisms.
    ///
    /// A rank says where an asset goes in a recovery set. The only assets with
    /// no rank are the ones that are never in one BY RULE — deliberately
    /// excluded, or reacquired rather than copied. Nothing else may be
    /// rankless: an asset that belongs in a recovery set and has no position in
    /// it is a hole a restore would have to guess at.
    ///
    /// Note what this deliberately does NOT assert: that a ranked asset is
    /// capturable today. Three ranked assets carry [`CaptureRule::Tree`] and
    /// one of them, `vcs.jj_repo`, is still copied by nothing. Asserting the
    /// stronger property here would have forced the map to drop it from the
    /// snapshot order, which is exactly the omission it exists to expose.
    ///
    /// The captured data-directory trees are CAS and immutable recovery
    /// evidence. The complete tree family set is derived by
    /// [`ranked_tree_capture_families_are_exact`].
    #[test]
    fn only_excluded_and_reacquired_assets_are_rankless() {
        for asset in DURABLE_ASSETS {
            let by_rule_absent = matches!(
                asset.capture,
                CaptureRule::Excluded { .. } | CaptureRule::Reacquire { .. }
            );
            let rankless = asset.snapshot_rank == SnapshotRank::NotCaptured;
            assert_eq!(
                by_rule_absent,
                rankless,
                "{}: capture rule {:?} and snapshot rank {:?} disagree — only an asset excluded \
                 or reacquired by rule may lack a position in the recovery set",
                asset.location.name(),
                asset.capture,
                asset.snapshot_rank
            );
        }
    }

    /// The nucleus is copied last, and exactly one asset holds that rank.
    #[test]
    fn operational_db_is_the_sole_nucleus_last_asset() {
        let last: Vec<_> = DURABLE_ASSETS
            .iter()
            .filter(|asset| asset.snapshot_rank == SnapshotRank::NucleusLast)
            .map(|asset| asset.location.name())
            .collect();
        assert_eq!(last, vec!["operational.db"]);
        let captured = || {
            DURABLE_ASSETS
                .iter()
                .filter(|asset| asset.snapshot_rank != SnapshotRank::NotCaptured)
        };
        assert!(
            captured().all(|asset| asset.location.name() == "operational.db"
                || asset.snapshot_rank < SnapshotRank::NucleusLast),
            "the nucleus must rank after every other captured asset"
        );
        let cas = captured()
            .find(|asset| asset.location.name() == "cas")
            .expect("cas is captured");
        assert!(
            captured().all(|asset| cas.snapshot_rank <= asset.snapshot_rank),
            "content bytes must be captured before anything that can reference them"
        );
    }

    /// The CAS retention rule, made executable.
    ///
    /// An `Authoritative` asset never takes a size cap — *a size cap on an
    /// authority is data loss on a timer*. `cas` is [`RetentionRule::Unbounded`]
    /// because nothing deletes a CAS object — the argument is on the row — and
    /// the two halves a successor could break silently are asserted here rather
    /// than left in prose:
    ///
    /// 1. **The bytes and their metadata share ONE rule.** `cas` holds the
    ///    file-backed object bytes and `cas.db` holds every `cas_objects` row,
    ///    including the inline ones. A reclaim licensed against one and refused
    ///    against the other produces a row whose bytes are gone — the dangling
    ///    reference `verify_authoritative_roots_resolve` refuses at boot, and
    ///    the one thing a reclaim may never produce.
    /// 2. **Neither is a size cap.** `Bounded { policy }` is the only variant in
    ///    this enum that can express one, and neither row carries it. That is
    ///    the size-cap prohibition, restated as a check instead of as a sentence.
    #[test]
    fn the_cas_bytes_and_their_metadata_share_one_retention_rule() {
        let bytes = classify_data_dir_entry("cas").expect("the map must row the CAS byte tree");
        let metadata =
            classify_data_dir_entry("cas.db").expect("the map must row the CAS metadata plane");

        assert_eq!(
            bytes.retention, metadata.retention,
            "`cas` is retained {:?} and `cas.db` is retained {:?}. They are two halves of ONE \
             object store — the inline objects live in the file, the large ones in the tree — so \
             a rule that licenses reclaiming one and not the other is a rule for producing \
             dangling references",
            bytes.retention, metadata.retention
        );
        assert_eq!(
            bytes.retention,
            RetentionRule::Unbounded,
            "nothing deletes a CAS object — kata has no CAS collection — so the store's \
             retention is unbounded. A row claiming a retention rule needs a mechanism that \
             enforces it; changing this value needs that mechanism, not a re-wording"
        );
        // SCOPE: these two rows, and the message says so.
        //
        // The loop refuses over exactly the two rows the test names, so the
        // message claims no more: `memory.db` is `Authoritative` and carries
        // `RetentionRule::Bounded`, and a message about "an authoritative asset"
        // would wrongly read as saying the map violates the size-cap rule.
        //
        // It does not. The rule forbids a SIZE CAP on an authority; `Bounded`
        // is the only variant that CAN express one, which is not the same as
        // every `Bounded` row expressing one. `memory.db`'s bound is a
        // per-namespace LIVE-OBJECT COUNT, argued at length on its own row,
        // together with the fact that it bounds no byte total and does not even
        // bound the store (the namespace count has no ceiling).
        //
        // NARROWED rather than widened, deliberately. Widening the loop to every
        // `Authoritative` row would require `memory.db` to be carved out, and
        // whether a count bound on an authority satisfies the rule is not
        // decided, so an assertion message may not decide it. The
        // honest form is a check that refuses exactly what its message claims.
        for asset in [bytes, metadata] {
            assert!(
                asset.authority.is_authoritative(),
                "{} must stay authoritative for the retention rule to be the one that applies",
                asset.location.name()
            );
            assert!(
                !matches!(asset.retention, RetentionRule::Bounded { .. }),
                "{} carries {:?}. Neither half of the CAS object store may take a size cap: \
                 `Bounded {{ policy }}` is the only variant here that can express one, and \
                 a size cap on an authority is refused. This asserts over `cas` and \
                 `cas.db` ONLY — it is not a statement about every authoritative row, and \
                 `memory.db` is authoritative AND `Bounded` for reasons its own row argues",
                asset.location.name(),
                asset.retention
            );
        }
    }

    /// Pin the current tree families and distinguish main-directory capture
    /// from operator-declared remote reacquisition.
    #[test]
    fn ranked_tree_capture_families_are_exact() {
        let trees: Vec<&str> = DURABLE_ASSETS
            .iter()
            .filter(|asset| matches!(asset.capture, CaptureRule::Tree { .. }))
            .map(|asset| asset.location.name())
            .collect();
        assert_eq!(
            trees,
            vec!["cas", "recovery-evidence", "vcs.jj_repo"],
            "the `CaptureRule::Tree` set is named by three doc paragraphs in this file; if it \
             changed, those paragraphs are now wrong and must be re-derived, not re-worded"
        );

        // The SPLIT, which is what the rename records. `cas` hangs off the one
        // root a capture mechanism resolves and is reached; `vcs.jj_repo` hangs
        // off an operator-declared path and is reached by nothing. The second
        // stays deferred on that ground, so flipping its
        // registration without a resolver for `AssetRoot::OperatorDeclared`
        // would be the map claiming a capture the product cannot perform.
        let row = |name: &str| {
            DURABLE_ASSETS
                .iter()
                .find(|asset| asset.location.name() == name)
                .expect("a name taken from the map resolves in the map")
        };
        assert_eq!(row("cas").location.root(), AssetRoot::MainDataDir);
        assert_eq!(
            row("cas").registration,
            Registration::Backup,
            "`cas` is captured by `backup_data_dir`'s tree pass"
        );
        assert_eq!(
            row("vcs.jj_repo").location.root(),
            AssetRoot::OperatorDeclared
        );
        assert_eq!(
            row("vcs.jj_repo").registration,
            Registration::Unregistered,
            "`vcs.jj_repo` is under a root no shipped mechanism resolves; it stays deferred \
             on that named prerequisite, and a registration here would be a claim about a \
             capture that does not exist"
        );

        // The ADDRESSING split, which is what binds a `cas` member's content to
        // the path it is written to. `PathOpaque` is the weaker answer and a
        // successor could reach for it to make a compile error go away, so the
        // stronger one is pinned by name rather than left to the row.
        assert_eq!(
            row("cas").capture,
            CaptureRule::Tree {
                members: TreeMemberAddressing::CasObject
            },
            "`cas` is a content-addressed store: a member's basename IS the address its bytes \
             must hash to. Downgrading this row to `PathOpaque` would silently re-open the \
             forgery `crate::store::backup::verify_captured_tree_sources` refuses — an artifact \
             serving object X's bytes under object Y's address"
        );
        assert_eq!(
            row("vcs.jj_repo").capture,
            CaptureRule::Tree {
                members: TreeMemberAddressing::PathOpaque
            },
            "a jj op-log entry's path is a sequence number; claiming a content binding for it \
             would be inventing a check nothing can perform"
        );

        // Every one is RANKED and AUTHORITATIVE, which is what makes the
        // paragraphs' framing ("ranked", "of the map's authoritative assets")
        // true of the same two rows rather than of three different subsets.
        for name in &trees {
            let asset = DURABLE_ASSETS
                .iter()
                .find(|asset| asset.location.name() == *name)
                .expect("a name taken from the map resolves in the map");
            assert_ne!(
                asset.snapshot_rank,
                SnapshotRank::NotCaptured,
                "{name} carries CaptureRule::Tree and must hold a position in the recovery set"
            );
            assert!(
                asset.authority.is_authoritative(),
                "{name} carries CaptureRule::Tree and must be authoritative"
            );
        }
    }

    /// Every asset the operator report NAMES carries the root it lives under.
    ///
    /// [`with_root`]'s fallback exists so a report never panics, and a fallback
    /// that silently engages is how a report degrades without anyone noticing.
    /// The two lists it renders are built from map rows by
    /// [`assess_backup_class`], so the fallback must be unreachable for them —
    /// pinned here rather than argued from the construction.
    #[test]
    fn every_named_omission_carries_the_root_it_lives_under() {
        // The emptiest possible capture: every authoritative asset is absent, so
        // both rendered lists are at their widest.
        let verdict = assess_backup_class(&BTreeSet::new());
        assert!(!verdict.missing_authoritative.is_empty());
        assert!(!verdict.requires_external_rebind.is_empty());
        for name in verdict
            .missing_authoritative
            .iter()
            .chain(verdict.requires_external_rebind.iter())
        {
            let rendered = with_root(name);
            assert!(
                rendered.starts_with(name) && rendered.ends_with(']'),
                "`{name}` rendered as `{rendered}`, which carries no root; the operator cannot \
                 tell which of the five durable roots a recovery must resolve for it"
            );
        }

        // COUNTERFACTUAL: a name the map does not carry renders bare, so the
        // assertion above is about the JOIN succeeding and not about every
        // string ending in `]`.
        assert_eq!(with_root("no-such-asset"), "no-such-asset");
    }

    /// Rebuild sources that name a PROCESS rather than an asset in the map.
    ///
    /// Sized on purpose, as a quarantine list: the map cannot
    /// check "the next clean shutdown" the way it can check a named asset, so each one is
    /// ratified by hand with its reason and a NEW prose source fails until
    /// someone examines it. Every entry here was confirmed to reconstruct the
    /// asset from something OUTSIDE the data directory, which is what makes the
    /// asset genuinely disposable rather than merely inconvenient to lose.
    ///
    /// - `the next clean shutdown` — warm/liveness state re-derives from the
    ///   running process, not from a stored plane.
    /// - `re-running the interrupted restore from its artifact` — the restore
    ///   journal records progress through an artifact the operator still holds;
    ///   losing it costs the resume a re-copy, which re-verifies every target.
    /// - `re-execution of the cached stage` — `stage_cache.db`'s sole table,
    ///   `capsule_reuse_v1`, is a hint over the operational plane's accepted
    ///   occurrences that a re-execution re-records and that no reader trusts
    ///   without re-verifying it.
    const RATIFIED_RECONSTRUCTION_PROCESSES: &[&str] = &[
        "the next clean shutdown",
        "re-running the interrupted restore from its artifact",
        "re-execution of the cached stage",
    ];

    /// No asset may be called rebuildable while nothing can rebuild it — the
    /// rebuildability prohibition, enforced structurally by the `from` field being
    /// mandatory on the variant.
    ///
    /// It closes two holes: a `from` that resolves to nothing, and a `from` that
    /// chains onto another derived plane. Whether a source can rebuild a TABLE is
    /// not derivable from a FILE-granular map, so a row whose file holds an
    /// authority its named source cannot rebuild still passes; that is a review
    /// question for every new `Rebuildable` row.
    #[test]
    fn every_rebuildable_asset_names_what_rebuilds_it() {
        for asset in DURABLE_ASSETS {
            if let AssetAuthority::Rebuildable { from } = asset.authority {
                assert!(
                    !from.trim().is_empty(),
                    "{} is called rebuildable with an empty source",
                    asset.location.name()
                );
                // A `from` is one of exactly two things, and conflating them is
                // what let the defect through. Either it NAMES ANOTHER ASSET, in
                // which case the map can and must check the relationship; or it
                // describes a RECONSTRUCTION PROCESS, which the map cannot check
                // at all and which therefore has to be ratified by hand instead
                // of accepted because it is a non-empty string.
                if let Some(source) = DURABLE_ASSETS
                    .iter()
                    .find(|candidate| candidate.location.name() == from)
                {
                    assert!(
                        source.authority.is_authoritative(),
                        "{} is called rebuildable from `{from}`, but `{from}` is itself {:?}. \
                         Rebuilding from a plane that is not authoritative chains one derived \
                         claim onto another and bottoms out in nothing.",
                        asset.location.name(),
                        source.authority
                    );
                    assert!(
                        source.snapshot_rank > asset.snapshot_rank,
                        "{} is called rebuildable from `{from}`, but `{from}` ranks {:?} \
                         against this asset's {:?}. A source must outrank what it rebuilds, \
                         or the snapshot captures the derivative BEFORE the authority it \
                         derives from and the restore cannot reproduce it.",
                        asset.location.name(),
                        source.snapshot_rank,
                        asset.snapshot_rank
                    );
                } else {
                    assert!(
                        RATIFIED_RECONSTRUCTION_PROCESSES.contains(&from),
                        "{} is called rebuildable from `{from}`, which is neither an asset in \
                         this map nor a ratified reconstruction process. A prose source the \
                         map cannot resolve is a claim nothing checks. Add it to \
                         RATIFIED_RECONSTRUCTION_PROCESSES with the reason, or name a real \
                         asset.",
                        asset.location.name()
                    );
                }
            }
        }
    }

    /// The store holding operational authority and execution evidence is never
    /// classified as a reclaimable mirror.
    #[test]
    fn execution_authority_and_retained_evidence_are_not_reclaimable_mirrors() {
        const RETAINED_STORES: &[&str] = &["operational.db"];

        for name in RETAINED_STORES {
            let asset = DURABLE_ASSETS
                .iter()
                .find(|asset| asset.location.name() == *name)
                .unwrap_or_else(|| panic!("{name} must have a row in the map"));
            assert!(
                asset.authority.is_authoritative(),
                "retained authority/evidence `{name}` must not be reclaimed as {:?}",
                asset.authority
            );
        }
    }

    /// A sidecar is classified as its main file, not as an unknown entry.
    #[test]
    fn sqlite_sidecars_classify_as_their_main_file() {
        for suffix in ["-wal", "-shm", "-journal"] {
            let entry = format!("operational.db{suffix}");
            let asset =
                classify_data_dir_entry(&entry).unwrap_or_else(|| panic!("{entry} must classify"));
            assert_eq!(asset.location.name(), "operational.db");
        }
    }

    /// COUNTEREXAMPLE 1: a capture that omits an asset class does not earn a
    /// higher backup class, and the omission is enumerated rather than implied.
    #[test]
    fn a_capture_missing_authoritative_assets_is_a_data_snapshot_that_names_them() {
        // Exactly what `backup_data_dir` produces on a current data dir: the
        // top-level `*.db` set and nothing else.
        let captured: BTreeSet<String> = [
            "operational.db",
            "ledger_events.db",
            "memory.db",
            "idempotency.db",
            "stage_cache.db",
            "cas.db",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let verdict = assess_backup_class(&captured);

        // NO CLASS ASSERTION HERE, deliberately. `assess_backup_class` DERIVES
        // the class: `DataSnapshot` unless `missing` and `unclassified` are both
        // empty. The loop below asserts four names ARE in `missing_authoritative`,
        // so `DataSnapshot` is already entailed, and a class assertion here could
        // not separate a correct implementation from a broken one.
        //
        // The class assertion IS load-bearing exactly where the two lists are
        // EMPTY, because only there can the derivation return `Recoverable`. That
        // is a different input and it has its own test —
        // `the_complete_authoritative_set_earns_recoverable_and_one_omission_costs_it`
        // immediately below — so making this
        // one discriminate would have duplicated that test rather than added
        // coverage here.
        for expected in [
            "cas",
            "main-identity.json",
            "local-worker.secret",
            "vcs.jj_repo",
        ] {
            assert!(
                verdict.missing_authoritative.contains(&expected),
                "a `*.db`-only capture omits {expected}; the verdict must say so, and said {:?}",
                verdict.missing_authoritative
            );
        }
        assert!(verdict.unclassified.is_empty());

        // The rebind list is a DIFFERENT list, and the two must not overlap: an
        // operator reading "missing" must be reading things the artifact should
        // have copied, never things it was never supposed to.
        for expected in ["workflow roots", "operator secret/proxy backend"] {
            assert!(
                verdict.requires_external_rebind.contains(&expected),
                "{expected} is satisfied by rebind, not inclusion, and must be listed as such; \
                 rebind list was {:?}",
                verdict.requires_external_rebind
            );
            assert!(
                !verdict.missing_authoritative.contains(&expected),
                "{expected} must not also be reported as missing"
            );
        }
    }

    /// The set that EARNS [`BackupClass::Recoverable`], and the single omission
    /// that costs it.
    ///
    /// # Why both directions are asserted
    ///
    /// A class function that returned `DataSnapshot` for every input would pass
    /// every `assert_ne!(verdict.class, BackupClass::Recoverable, …)` written
    /// against an incomplete set. Only an input that EARNS `Recoverable` can
    /// tell a derived class from a constant one.
    ///
    /// # What the class is a statement ABOUT
    ///
    /// The set, not the product. This function's whole contract is *"assess what
    /// class a captured asset set earns"*; returning the class the set earns is
    /// the job. That the SHIPPED CAPTURE cannot produce such a set is a
    /// different claim, is still true, and is pinned separately by
    /// `the_shipped_backup_artifact_is_assessed_as_an_incomplete_data_snapshot`
    /// against a real `backup_data_dir` run — which is also the assertion that
    /// stopped being vacuous when this one became possible.
    #[test]
    fn the_complete_authoritative_set_earns_recoverable_and_one_omission_costs_it() {
        // DERIVED from the map: every authoritative row an artifact is expected
        // to INCLUDE. `Reacquire` rows are excluded because they are satisfied
        // by external rebind and never by copy — including them would be
        // asking the artifact to carry something it is never supposed to.
        let complete: BTreeSet<String> = DURABLE_ASSETS
            .iter()
            .filter(|asset| asset.authority.is_authoritative())
            .filter(|asset| !matches!(asset.capture, CaptureRule::Reacquire { .. }))
            .map(|asset| asset.location.name().to_string())
            .collect();
        assert!(
            complete.len() > 1,
            "the map must carry more than one includable authoritative asset, or the omission arm \
             below is not a counterfactual"
        );

        let verdict = assess_backup_class(&complete);
        assert!(
            verdict.missing_authoritative.is_empty(),
            "an artifact carrying every includable authoritative asset omits none, and this said \
             {:?}",
            verdict.missing_authoritative
        );
        assert!(verdict.unclassified.is_empty());
        assert_eq!(
            verdict.class,
            BackupClass::Recoverable,
            "the class is defined as *every required asset included, content-verified \
             reacquirable, or named as a mandatory external rebind*; this set satisfies that \
             clause by construction, so a function that still called it a data snapshot would be \
             a function whose class is a constant with a name"
        );

        // THE COUNTERFACTUAL, and it is per-asset rather than one sample: drop
        // any single includable authoritative asset and the class drops with it.
        // A class that survived one omission would be reporting a property of
        // the map's SIZE rather than of the artifact's contents.
        for dropped in &complete {
            let mut partial = complete.clone();
            partial.remove(dropped);
            let verdict = assess_backup_class(&partial);
            assert_eq!(
                verdict.class,
                BackupClass::DataSnapshot,
                "omitting `{dropped}` must cost the class; it did not"
            );
            assert!(
                verdict.missing_authoritative.contains(&dropped.as_str()),
                "and the verdict must name `{dropped}` as the omission, and named {:?}",
                verdict.missing_authoritative
            );
        }

        // A name the map does not classify costs the class too: the assessment
        // is only as complete as the map, and an artifact carrying something
        // nothing classified is one this function cannot vouch for.
        let mut stale = complete.clone();
        stale.insert("something-the-map-has-never-heard-of.db".to_string());
        assert_eq!(
            assess_backup_class(&stale).class,
            BackupClass::DataSnapshot,
            "an unclassified captured name means the map has gone stale under the artifact, and a \
             stale map cannot certify completeness"
        );
    }

    /// A capture's omission REASON renders under the asset it explains, and a
    /// reason for anything else is dropped.
    ///
    /// # Why the drop is a rule and not a convenience
    ///
    /// The reasons come from a capture's account of its own run; the missing
    /// list is derived here from the map and the artifact. If the two disagree,
    /// the derivation wins — a report that named `operational.db` as captured
    /// and then explained why it was omitted would be contradicting itself two
    /// lines apart, and an operator cannot act on a report that does that.
    #[test]
    fn an_omission_reason_renders_under_its_asset_and_only_for_a_missing_one() {
        let captured: BTreeSet<String> = ["operational.db"].into_iter().map(String::from).collect();
        let verdict = assess_backup_class(&captured).explaining([
            (
                "cas",
                "it holds more than the bounded maximum of 2 members".to_string(),
            ),
            (
                "operational.db",
                "a reason for an asset the artifact HOLDS".to_string(),
            ),
            (
                "not-a-map-row",
                "a reason for a name the map never had".to_string(),
            ),
        ]);

        assert_eq!(
            verdict.omission_reasons.keys().copied().collect::<Vec<_>>(),
            vec!["cas"],
            "only the asset that is actually missing may carry a reason"
        );

        let rendered = format!("{verdict}");
        let cas_line = rendered
            .lines()
            .position(|line| line.trim().starts_with("cas [MainDataDir]"))
            .expect("the omitted `cas` line");
        assert_eq!(
            rendered.lines().nth(cas_line + 1).map(str::trim),
            Some("omitted by this capture: it holds more than the bounded maximum of 2 members"),
            "the reason must render on the line DIRECTLY under the asset it explains — an \
             operator scanning a fourteen-line omission block cannot pair a reason with an asset \
             any other way:\n{rendered}"
        );
        assert!(
            !rendered.contains("a reason for an asset the artifact HOLDS")
                && !rendered.contains("a reason for a name the map never had"),
            "a dropped reason must not reach the report by any other route:\n{rendered}"
        );

        // NON-VACUOUS: the same verdict WITHOUT `explaining` renders the asset
        // and no reason, so the line above is bought by the call.
        let bare = format!("{}", assess_backup_class(&captured));
        assert!(
            bare.contains("cas [MainDataDir]") && !bare.contains("omitted by this capture"),
            "the artifact's own evidence can only say an asset is ABSENT; the reason is the \
             capture's, and a verdict nobody explained must not invent one:\n{bare}"
        );
    }

    /// COUNTEREXAMPLE 1b: an artifact carrying a name the map does not know is
    /// reported, so the map going stale is visible instead of silent.
    #[test]
    fn an_unclassified_captured_name_is_reported() {
        let captured: BTreeSet<String> = ["operational.db", "something_new.db"]
            .into_iter()
            .map(String::from)
            .collect();
        let verdict = assess_backup_class(&captured);
        assert_eq!(verdict.unclassified, vec!["something_new.db".to_string()]);
    }

    /// COUNTEREXAMPLE 2: a snapshot taken out of order is DETECTED.
    #[test]
    fn out_of_rank_capture_is_refused() {
        let token = ConsistencyToken::new(vec![
            ConsistencyEntry {
                asset: "operational.db".into(),
                rank: SnapshotRank::NucleusLast,
                instant_ms: 1_000,
            },
            ConsistencyEntry {
                asset: "cas".into(),
                rank: SnapshotRank::ReferencedContent,
                instant_ms: 1_010,
            },
        ]);
        let error = token.verify().expect_err("reversed ranks must refuse");
        let message = error.to_string();
        assert!(
            message.contains("captured AFTER"),
            "the refusal must name the ordering rule, said: {message}"
        );

        // COUNTERFACTUAL: the same two assets in the correct order pass, so the
        // refusal above is about the ORDER and not about the assets.
        let ok = ConsistencyToken::new(vec![
            ConsistencyEntry {
                asset: "cas".into(),
                rank: SnapshotRank::ReferencedContent,
                instant_ms: 1_000,
            },
            ConsistencyEntry {
                asset: "operational.db".into(),
                rank: SnapshotRank::NucleusLast,
                instant_ms: 1_010,
            },
        ]);
        ok.verify().expect("authoritative-last order verifies");
        assert_eq!(ok.max_skew_ms(), 10);
    }

    /// COUNTEREXAMPLE 2a: a `NotCaptured` asset does not participate in the
    /// ordering predicate at all.
    ///
    /// # Why this is a category argument and not a special case
    ///
    /// The invariant protects REFERENCES — content before anything that can
    /// reference it. A `NotCaptured` asset has no bytes in the artifact, so
    /// nothing a restore places can resolve THROUGH it, so its position in the
    /// capture sequence carries no information the invariant is about. Ranked
    /// `0`, it sorts before `ReferencedContent`, so leaving it in the predicate
    /// would make every capture that touches one refuse itself.
    ///
    /// Non-vacuous in both directions: the SAME entries with the late one
    /// ranked `Derived` instead of `NotCaptured` are refused, so this test is
    /// about the rank and not about the order.
    #[test]
    fn a_not_captured_asset_is_excluded_from_the_ordering_predicate() {
        // The order the tree pass produces: it copies `cas` FIRST unconditionally,
        // so a low-ranked entry that follows it lands late in the sequence with a
        // rank below everything before it.
        // Putting the low-ranked entry FIRST would be vacuous — rank `0` sorts
        // before everything, so that order verifies with or without the filter.
        let entries = |late_rank| {
            vec![
                ConsistencyEntry {
                    asset: "cas".into(),
                    rank: SnapshotRank::ReferencedContent,
                    instant_ms: 1_000,
                },
                ConsistencyEntry {
                    asset: "operational.db".into(),
                    rank: SnapshotRank::NucleusLast,
                    instant_ms: 1_010,
                },
                ConsistencyEntry {
                    asset: "late.db".into(),
                    rank: late_rank,
                    instant_ms: 1_020,
                },
            ]
        };
        ConsistencyToken::new(entries(SnapshotRank::NotCaptured))
            .verify()
            .expect(
                "an asset with no bytes in the artifact cannot be the referent of anything, so its position must not decide the order",
            );

        let error = ConsistencyToken::new(entries(SnapshotRank::Derived))
            .verify()
            .expect_err("a CAPTURED asset out of rank order must still refuse");
        assert!(
            error.to_string().contains("late.db"),
            "the refusal must name the offending asset, said: {error}"
        );
        assert!(
            error.to_string().contains("captured AFTER"),
            "the refusal must still be the ordering rule, said: {error}"
        );
    }

    /// COUNTEREXAMPLE 2b: right order, wrong instants — the defect copy order
    /// alone cannot see.
    #[test]
    fn a_derived_plane_whose_instant_leads_its_authority_is_refused() {
        let token = ConsistencyToken::new(vec![
            // A SYNTHETIC name, not a map row: this test constructs the inversion
            // directly, and the map holds no captured `Derived`-ranked asset to borrow.
            ConsistencyEntry {
                asset: "derived-mirror.db".into(),
                rank: SnapshotRank::Derived,
                instant_ms: 2_000,
            },
            ConsistencyEntry {
                asset: "ledger_events.db".into(),
                rank: SnapshotRank::Authoritative,
                instant_ms: 1_000,
            },
        ]);
        let error = token
            .verify()
            .expect_err("an instant inversion must refuse");
        assert!(
            error.to_string().contains("LEADS"),
            "the refusal must name the inversion, said: {error}"
        );
    }
}
