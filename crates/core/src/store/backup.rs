//! Point-in-time SQLite/config/CAS-tree snapshot + restore for a Kata data
//! directory.
//!
//! This is an explicitly incomplete **data snapshot**, not a recoverable or
//! sealed-full backup of a Kata node. It does not capture jj state, identity or
//! credential material, workflow packs, provider assets, or external rebind
//! obligations, and it reaches only the main's `<data_dir>` — never a worker
//! node's own root.
//!
//! ## The CAS tree is captured with its metadata
//!
//! `cas.db` holds every `cas_objects` row, including `storage = 'file'` rows
//! whose bytes live in the sibling `cas/` DIRECTORY, and `operational.db` holds
//! the AUTHORITATIVE CAS roots object liveness is defined over. A database-only
//! capture would therefore restore a root and its metadata row with the bytes
//! absent.
//!
//! So the bytes are captured too. `discover_captured_trees` is a second
//! discovery pass driven by [`crate::durable_assets::DURABLE_ASSETS`] rather
//! than by a filename rule, `capture_tree` copies each member with its own
//! blake3 digest into `<artifact>/`[`TREES_SUBDIR`], the manifest records the
//! claim and the per-member evidence ([`BackupManifest::tree_roots`] /
//! [`BackupManifest::trees`]), and [`activate_captured_tree`] puts them back
//! member by member. `cas` is `Registration::Backup` in the map and does not
//! appear in the completeness report's omitted list.
//!
//! The backstop is `verify_authoritative_roots_resolve`, which refuses a data
//! directory whose unreleased authoritative roots do not resolve; with the tree
//! captured, that can only be a PARTIAL tree — a strict subset, because objects
//! are immutable and content-addressed. See [`activate_captured_tree`] for why
//! that soundness argument is `cas`'s and does not extend to `vcs.jj_repo`,
//! which stays uncaptured: it lives under an operator-declared root no shipped
//! mechanism resolves.
//!
//! Two properties of that capture are standing rules rather than details of one
//! function:
//!
//! * **A member's CONTENT is bound to its PATH wherever the asset says the path
//!   is derivable.** Checking a member against the digest the manifest records
//!   for it is a check of the manifest against itself, and the manifest is
//!   unauthenticated JSON. For `cas` the path IS a content address, so
//!   [`verify_member_address`] derives it from the bytes — with the manifest as
//!   neither input — at capture and at restore. Which assets have a derivable
//!   path is a field on the map row
//!   ([`crate::durable_assets::TreeMemberAddressing`]), never a name test here.
//! * **A BOUND overrun degrades; an INTEGRITY failure refuses.** The tree pass
//!   runs FIRST, so an error out of it fails the whole `kata backup` — databases
//!   included — which inverts *degrade capacity, refuse correctness* for any
//!   installation that outgrows a tree bound. [`TreeCapture`] carries the rule,
//!   the counter-case, and why an omission that is NAMED is not a silent loss.
//!
//! Operational decisions live in `operational.db`, which also holds the
//! execution-EVIDENCE tables (`execution_evidence`, `execution_evidence_claims`). The
//! delivery database retains derived event bytes plus authoritative cursor/high-water
//! metadata. There is no assignment mirror to capture: the authoritative heavy blob is
//! `operational.db`'s `attempts.assignment_json`. Memory, idempotency and CAS
//! retain their separate authority; the durable-asset map governs capture and
//! restore.
//!
//! This module copies those databases (and optionally the node config) into a
//! database-snapshot artifact and restores only those selected files into a
//! `data_dir`.
//!
//! **With ONE subtraction: `stage_cache.db` is not copied.**
//! *"A snapshot must capture what is on disk"* is the rule this exception is
//! argued against.
//! The stage cache is [`AssetAuthority::Rebuildable`], and the cheap tier a
//! rebuildable asset earns takes no digest — which models LOSING an asset, not
//! receiving an ALTERED one, and nothing rebuilds a database that is present
//! and wrong. The durable tier is not the answer either: it would let a
//! bit-rotted cache refuse the restore of the ledger. See
//! [`artifact_carries_database`] for the full argument and
//! [`clear_rebuildable_databases`] for the restore-side half that keeps a
//! restored node from holding hint rows its peers cannot verify.
//!
//! ## Consistency
//!
//! Each database is copied with SQLite's `VACUUM INTO`, which reads the
//! source inside a single read transaction and writes a fresh, fully
//! checkpointed database file. That yields a consistent snapshot **even
//! while another connection is concurrently writing** — the copy reflects
//! the state as of the transaction start and carries no `-journal` / `-wal` /
//! `-shm` sidecars of its own. Callers that own a live store may still call
//! [`crate::store::SqliteWorkflowStore::checkpoint`] first so its WAL is folded
//! in, but the copy is consistent regardless.
//!
//! Independent database snapshots do not establish a shared capture instant.
//! `backup_copy_order` copies operational authority after delivery metadata;
//! v4 additionally requires the source runtime's backup fence and verification
//! against the captured reference population. No status-adoption path repairs
//! or authorizes a restored execution.
//!
//! ## Restore
//!
//! [`restore_data_dir`] first validates and stages every selected artifact,
//! then activates each captured database into the target `data_dir`, first
//! removing any stale `-journal` / `-wal` / `-shm` sidecars so corrupt or
//! half-written journal state can't shadow the restored main file. Every
//! source/artifact failure therefore occurs before any target mutation.
//!
//! ## Durability (`MANIFEST_VERSION` 2)
//!
//! Target activation is crash-safe and tamper-evident through five durability
//! primitives — content digest, verify, `sync_all`,
//! tmp→fsync→rename→directory-fsync, and a restore journal. Without them a
//! restore could leave a partial target on power loss and could not detect a
//! byte-tampered but structurally valid database at all.
//!
//! See [`durable_publish`] for the ordering. The primitives are not applied
//! uniformly: [`DurabilityTier`] is a function of the durable-asset map's
//! `AssetAuthority`, because paying history-grade cost on an asset nothing
//! reads is the cost that makes backup slow for no correctness gain.
//! The journal lives under the TARGET, never the artifact —
//! [`restore_journal_path`] says why.
//!
//! ## A restore READS its artifact and WRITES its target
//!
//! Nothing on the restore path creates, renames, or removes anything inside
//! `backup_dir`. That is a property an operator can rely on — a mounted
//! snapshot, a directory copied out of an archive, a read-only share are all
//! legitimate artifacts — and
//! `a_read_only_artifact_directory_restores_wholly_and_mutates_nothing` measures
//! it rather than asserting it.
//!
//! ## The manifest's tier is NOT authority for the tier a restore enforces
//!
//! [`restore_tier`] derives it from the map. A manifest is unauthenticated JSON,
//! so a tier read out of one is a tier an attacker chose; see
//! [`refuse_weakened_tier`].
//!
//! ## File-backed CAS bytes round-trip
//!
//! Digests and atomic activation do nothing about an asset that was never
//! captured, so recovery of the CAS bytes is asserted directly:
//! `a_backup_restore_round_trip_recovers_file_backed_cas_bytes`.
//!
//! The ordinary snapshot API remains v2 and cannot earn recoverability. The v4
//! API requires a complete treatment map, generation-bound worker evidence and
//! a trusted runtime verifier of actual captured references and isolated remote
//! closure. Only `VerifiedRecoveryArtifact` carries that verified classification.
//! Restore extracts into an offline target; runtime activation still owes fresh
//! identity, explicit credential/endpoint rebinding and unresolved-effect quarantine.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use kata_types::{KataError, KataResult};

use crate::durable_assets::{
    AssetAuthority, AssetLocation, AssetRoot, CaptureRule, CompletenessVerdict, ConsistencyEntry,
    ConsistencyToken, DURABLE_ASSETS, DurableAsset, SnapshotRank, TreeMemberAddressing,
    assess_backup_class, classify_data_dir_entry,
};

mod checkpoint_files;
mod import_catalog;
mod recovery_assets;
mod workspace_checkpoints;
pub use checkpoint_files::{
    capture_checkpoint_tree, restore_checkpoint_tree, verify_checkpoint_tree,
    verify_materialized_checkpoint_tree,
};
pub use import_catalog::{
    PreparedCloneImport, inherited_worker_generations, prepare_clone_import,
    verify_import_evidence, verify_import_evidence_before,
};
pub use recovery_assets::{
    CapturedRecoveryReferences, ExternalRecoveryGeneration, InheritedRecoveryGeneration,
    RECOVERY_MANIFEST_VERSION, RecoveryAsset, RecoveryCapture, RecoveryMemberSource,
    RecoveryRebindTarget, RecoveryTreatment, RecoveryVerifier, RemoteRecoveryProof,
    VerifiedRecoveryArtifact, WorkerRecoveryReceipt, read_remote_recovery_proof,
    recovery_evidence_root,
};
pub use workspace_checkpoints::{
    MAX_CHECKPOINT_BYTES, RecoveryCheckpointEntry, RecoveryCheckpointTree, RecoverySleepCheckpoint,
    RecoveryWorkspaceCheckpoint, recovery_workspace_checkpoints,
};

/// Subdirectory of a backup artifact holding the copied SQLite databases.
pub const STORES_SUBDIR: &str = "stores";

/// Subdirectory of a backup artifact holding the copied DIRECTORY TREES, one
/// child per [`CapturedTree::name`].
///
/// Separate from [`STORES_SUBDIR`] rather than nested inside it, because
/// [`validate_stores_directory`] enumerates that directory and refuses anything
/// that looks like a SQLite sidecar — a rule about database copies that has
/// nothing to say about a CAS shard. Keeping the two roots disjoint means a
/// tree entry can never be mistaken for a database and vice versa, at the price
/// of one more `create_dir_all`.
pub const TREES_SUBDIR: &str = "trees";

/// Filename the node config is copied to inside a backup artifact.
pub const CONFIG_COPY_NAME: &str = "kata.toml";

/// Filename of the JSON manifest written at the root of every artifact.
pub const MANIFEST_NAME: &str = "backup-manifest.json";

/// Filename of the restore-progress journal a restore writes while it is
/// activating targets. See [`restore_journal_path`] for WHERE it goes and why
/// that is not the artifact directory.
pub const RESTORE_JOURNAL_NAME: &str = "backup-restore-journal.json";

/// The `<data_dir>`-relative directory holding [`RESTORE_JOURNAL_NAME`].
///
/// Already a recognized top-level data-directory root and a
/// [`crate::durable_assets::DURABLE_ASSETS`] row
/// (`AssetLocation::DataDirTree("recovery-generations")`). See
/// [`restore_journal_path`].
pub const RESTORE_JOURNAL_SUBDIR: &str = "recovery-generations";

/// Where a restore of `data_dir` keeps its [`RestoreJournal`].
///
/// # It is NOT in the artifact directory
///
/// A journal published INTO `backup_dir` — the operator's artifact — by
/// [`durable_publish`], which does `File::create` there, would make a restore
/// from a read-only artifact directory FAIL partway through activation and leave
/// the target half-restored: the mixed plane `MANIFEST_VERSION` 2 exists to
/// eliminate.
///
/// # Why the ARTIFACT is the wrong home even when it IS writable
///
/// A BACKUP artifact is operator-supplied — a mounted snapshot, a directory copied out of an archive,
/// a read-only share — and writing to it is wrong on three counts beyond
/// writability: it MUTATES the operator's backup, it is scoped to the artifact
/// rather than to the target so two targets restored from one artifact share one
/// journal, and it makes the *source* of a restore a thing the restore must be
/// able to modify. A restore reads its artifact and writes its target; nothing
/// else.
///
/// # Why not simply `<data_dir>/backup-restore-journal.json`
///
/// Restore work belongs under the existing recovery root, not a new top-level
/// asset family. Boot does not adopt an identity-less restored directory.
/// This module produces a data snapshot, not a bootable recovered authority.
/// Journal placement therefore does not discharge the complete recoverable
/// restore contract or authorize stamping an identity onto restored state.
///
/// # Residue this does NOT remove, disclosed rather than implied
///
/// `<target>.restore-tmp` (see [`activate_staged_file`]) is a top-level `<data_dir>` entry
/// and is foreign to the same inventory. Every in-process failure path removes it; a
/// SIGKILL or power loss between `File::create` and `rename` cannot, and that residue is
/// inherent to publish-through-rename rather than to this placement — `data_dir_lock`'s own
/// `.main-identity-<ulid>.tmp` is the same shape, and the inventory SKIPS that one by
/// prefix. Moving the temporary out of the target's own directory would buy an inventory
/// refusal at the price of making the atomic rename cross-directory, which is the one thing
/// in this module that must not become conditional on layout. So it stays beside its
/// target, and teaching the inventory about restore residue is a change to a shipped
/// production refusal in another crate — named here so it is a decision and not an
/// oversight.
#[must_use]
pub fn restore_journal_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join(RESTORE_JOURNAL_SUBDIR)
        .join(RESTORE_JOURNAL_NAME)
}

/// Suffix of the transient file a capture `VACUUM INTO`s before renaming it
/// into the artifact.
const CAPTURE_TMP_SUFFIX: &str = ".capture-tmp";

/// Suffix of the transient file a restore streams into before renaming it over
/// the target.
const RESTORE_TMP_SUFFIX: &str = ".restore-tmp";

/// The durability treatment a capture and a restore give ONE asset.
///
/// # Authority determines the SHAPE of the guarantee
///
/// The tier is derived from the durable-asset map's
/// [`AssetAuthority`] and from nothing else — not from the filename, not from
/// the file's size, and not from whether it happens to be SQLite. See
/// [`durability_tier`] for the per-variant argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityTier {
    /// The full treatment: `PRAGMA quick_check` and a blake3 content digest at
    /// capture, `sync_all` on the copy, publication by atomic rename with a
    /// directory `fsync`, digest re-verification at restore, atomic activation
    /// at the target, and a [`RestoreJournal`] entry.
    Durable,
    /// Best-effort capture: the bytes are copied and published by rename, and
    /// NOTHING else. No digest is taken, so none is recorded and none is
    /// checked; the copy is not `fsync`ed; activation is a plain overwrite and
    /// earns no journal entry.
    BestEffort,
    /// Not captured at all. Distinct from [`Self::BestEffort`], which still puts
    /// the bytes in the artifact and still writes them to a restored target.
    Excluded,
}

impl DurabilityTier {
    /// How much this tier buys, as a total order — `Excluded` < `BestEffort` <
    /// `Durable`.
    ///
    /// Written out rather than `#[derive(Ord)]`. A derived ordering would follow
    /// DECLARATION order, which is `Durable` < `BestEffort` < `Excluded` — the
    /// exact reverse — so a derive would make [`Self::at_least`] silently accept
    /// every downgrade it exists to refuse, with no diff to look at.
    const fn strength(self) -> u8 {
        match self {
            Self::Excluded => 0,
            Self::BestEffort => 1,
            Self::Durable => 2,
        }
    }

    /// This tier, or `floor` when this tier is weaker.
    #[must_use]
    fn at_least(self, floor: Self) -> Self {
        if self.strength() >= floor.strength() {
            self
        } else {
            floor
        }
    }
}

/// The [`DurabilityTier`] an asset's authority class earns.
///
/// Each arm is argued from the map's own semantics for that variant, quoted
/// from [`AssetAuthority`], rather than by analogy with a neighbouring arm.
///
/// * [`AssetAuthority::Authoritative`] — *"Losing it loses the only copy of
///   something committed."* There is no cheaper correct answer: the artifact is
///   the only remaining copy by hypothesis, so an unverifiable one is not a
///   backup. **`Durable`.**
/// * [`AssetAuthority::Rebuildable`] — *"Reconstructible from an authoritative
///   asset named in `from`. Losing it costs work, never correctness."* The
///   `from` field means the repair procedure for a failed capture is already
///   written down IN THE MAP. Buying a durability proof for something whose
///   recovery instructions are a constant in the source is a uniform cost with
///   no correctness return. **`BestEffort`.**
///
///   That argument is about what a capture should PAY for a rebuildable asset;
///   it does not license CARRYING a rebuildable database. `BestEffort` models
///   LOSS — which rebuildability answers — and not ALTERATION, which it does
///   not: nothing rebuilds a database that is present and wrong. So a
///   rebuildable `*.db` is not carried at all; [`artifact_carries_database`] holds the
///   full argument and [`discover_databases`] is the enforcement point. This arm
///   is still what the TREE pass would read for a rebuildable tree row, and
///   still what `every_authority_class_has_a_stated_and_distinct_tier` measures
///   over the whole enum.
///
///   **NO DATABASE REACHES THE CHEAP TIER.** [`artifact_carries_database`] refuses every
///   `Rebuildable` name at discovery, and [`AssetAuthority`] has no other class that earns
///   it. So [`DurabilityTier::BestEffort`] is unreachable for every database in every
///   artifact this binary writes or reads, and `no_database_can_earn_the_cheap_tier`
///   measures that rather than asserts it. A reader must not take this arm's existence as
///   evidence that any shipped artifact contains a cheap-tier asset.
/// * [`AssetAuthority::Transient`] — *"Never recovery authority; a restore that
///   carries one is carrying a lie about a process that is not running."*
///   `BestEffort` would still put it in the artifact and still write it to the
///   target, which MATERIALIZES that lie for a fraction of the cost rather than
///   avoiding it. Transient is not a cheaper tier of capture; it is the absence
///   of capture. **`Excluded`.**
///
/// An asset the map does not classify at all gets **`Durable`**, and that is
/// decided in [`tier_of_database`] rather than here — see it for why ignorance
/// argues for the expensive tier.
#[must_use]
pub fn durability_tier(authority: AssetAuthority) -> DurabilityTier {
    match authority {
        AssetAuthority::Authoritative => DurabilityTier::Durable,
        AssetAuthority::Rebuildable { .. } => DurabilityTier::BestEffort,
        AssetAuthority::Transient => DurabilityTier::Excluded,
    }
}

/// The [`DurabilityTier`] for a discovered top-level database name.
///
/// # An unclassified database is `Durable`
///
/// [`backup_copy_order`] already sorts a map-unknown database FIRST, on the
/// stated ground that *"the map cannot say what references it"*. The same
/// ignorance argues for the expensive tier here, and in the same direction: the
/// cheap tier is licensed by a KNOWN property (rebuildable from a named source,
/// or read by nothing), and an unregistered name has neither. Defaulting to
/// `BestEffort` would make "nobody registered this" the cheapest class in the
/// system, which is exactly backwards.
fn tier_of_database(name: &str) -> DurabilityTier {
    classify_data_dir_entry(name).map_or(DurabilityTier::Durable, |asset| {
        durability_tier(asset.authority)
    })
}

/// The [`DurabilityTier`] the node config an artifact bundles at
/// [`CONFIG_COPY_NAME`] earns.
///
/// # The map is asked, not restated
///
/// A hand-written `tier: DurabilityTier::Durable` here would be a SECOND
/// classification beside the map: two places to change, and only one of them
/// would fail a test. The row is keyed on the config FLAG rather than on a filename
/// ([`BUNDLED_CONFIG_ASSET_NAME`]), which is why this cannot go through
/// [`classify_data_dir_entry`] — that resolves `<data_dir>` entries and the node
/// config is not one.
///
/// The `None` arm takes `Durable` for exactly the reason
/// [`tier_of_database`] does: the cheap tier is licensed by a KNOWN property,
/// and a name the map does not carry has none.
fn bundled_config_tier() -> DurabilityTier {
    crate::durable_assets::DURABLE_ASSETS
        .iter()
        .find(|asset| asset.location.name() == BUNDLED_CONFIG_ASSET_NAME)
        .map_or(DurabilityTier::Durable, |asset| {
            durability_tier(asset.authority)
        })
}

/// The tier the durable-asset map DERIVES for one asset an artifact carries,
/// which is the tier a restore enforces regardless of what the manifest claims.
///
/// [`validate_database_names`] refuses any database name without a `.db`
/// extension, so the [`CONFIG_COPY_NAME`] arm can never be shadowed by one.
fn derived_tier(name: &str) -> DurabilityTier {
    if name == CONFIG_COPY_NAME {
        bundled_config_tier()
    } else {
        tier_of_database(name)
    }
}

/// The [`DurabilityTier`] the durable-asset map derives for a captured TREE.
///
/// Separate from [`derived_tier`] and deliberately NOT routed through
/// [`classify_data_dir_entry`]: that classifier resolves whatever `<data_dir>`
/// entry a name looks like, so it would happily answer for a tree row and also
/// for a row that is not a tree at all. A tree's tier may only be derived from a
/// row this binary is willing to RESTORE as a tree, which is what
/// [`restorable_tree_asset`] decides.
///
/// The unresolvable arm takes `Durable` for the reason [`tier_of_database`]'s
/// does — the cheap tier is licensed by a KNOWN property — though it is
/// unreachable in practice, because [`validate_tree_records`] refuses an
/// unresolvable tree name before any tier is asked for.
fn derived_tree_tier(name: &str) -> DurabilityTier {
    restorable_tree_asset(name).map_or(DurabilityTier::Durable, |asset| {
        durability_tier(asset.authority)
    })
}

/// One captured asset's durability record inside a [`BackupManifest`].
///
/// Present only from [`MANIFEST_VERSION`] 2. A v1 artifact carries an empty
/// [`BackupManifest::assets`], which is not a defaulted claim of anything — it
/// is the accurate statement that no integrity evidence was recorded, and
/// [`restore_data_dir`] treats it as such.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedAsset {
    /// The copy's filename: a database name relative to [`STORES_SUBDIR`], or
    /// [`CONFIG_COPY_NAME`] for the bundled node config.
    pub name: String,
    /// The tier this copy was captured under.
    pub tier: DurabilityTier,
    /// Lowercase-hex blake3 digest of the captured copy's bytes, or `None` when
    /// the tier did not buy one.
    ///
    /// `Option` rather than an empty string: a manifest must never be able to
    /// suggest a check that nothing performed. `Some` means
    /// "these exact bytes were digested at capture and will be re-digested at
    /// restore"; `None` means "no integrity evidence exists for this asset",
    /// and a restore says so rather than inventing one.
    pub digest: Option<String>,
    /// The copy's length in bytes at capture.
    pub byte_len: u64,
}

/// One file inside a captured [`CapturedTree`].
///
/// A tree has no single byte length and no single digest, which is the whole
/// reason [`CapturedAsset`] cannot describe one: its `digest` and `byte_len` are
/// FILE fields. Integrity for a tree is per-file or it is nothing — a single
/// digest over concatenated bytes says *something moved* and cannot say WHICH
/// object is missing, which is exactly the question a restore of the CAS tree has
/// to answer (`verify_authoritative_roots_resolve` refuses a data directory whose
/// roots reference absent objects, and it names them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedTreeEntry {
    /// Slash-separated path RELATIVE to the tree root, never absolute and never
    /// containing `..`: a durable identity never names a host path.
    pub path: String,
    /// Lowercase-hex blake3 digest of this file's bytes, or `None` when the
    /// tier did not buy one. `Option` for the reason [`CapturedAsset::digest`]
    /// is: a manifest must never suggest a check nothing performed.
    pub digest: Option<String>,
    /// This file's length in bytes at capture.
    pub byte_len: u64,
}

/// One captured DIRECTORY TREE's durability record inside a [`BackupManifest`].
///
/// # What a tree needs that [`CapturedAsset`] cannot express
///
/// Read off the two [`crate::durable_assets::CaptureRule::Tree`] rows the
/// map carries — `cas` (`AssetLocation::DataDirTree("cas")`) and `vcs.jj_repo`
/// (`AssetLocation::ConfigDeclared("vcs.jj_repo")`), both
/// [`crate::durable_assets::AssetAuthority::Authoritative`], both at
/// [`crate::durable_assets::SnapshotRank::ReferencedContent`]:
///
/// * a ROOT, and the root it is relative TO. `cas` hangs off `<data_dir>`;
///   `vcs.jj_repo` hangs off a path the operator names, and
///   [`crate::durable_assets::AssetRoot`] already distinguishes them. Without
///   [`Self::root`] a restore cannot know where to put the bytes back, and a
///   record that assumed `<data_dir>` would silently misplace the jj repo.
/// * the FILE SET. Without it, "the artifact holds three of the four objects"
///   and "the source had three" are the same manifest. `cas`'s layout is
///   `<hex[0..2]>/<hex>` (`CasStore::blob_path`), so the set is not derivable
///   from any rule a reader could apply.
/// * PER-FILE integrity and length — see [`CapturedTreeEntry`].
/// * a digest over the ENTRY LIST ([`Self::entry_digest`]). This is the lesson of
///   the tier downgrade [`refuse_weakened_tier`] closes: per-item evidence whose
///   INDEX is unauthenticated is bypassed by editing the index. Deleting an entry
///   would otherwise make its file un-restored and un-noticed.
/// * bounds — [`Self::entry_count`] and [`Self::total_byte_len`], the tree
///   analogues of [`MAX_DATABASE_COUNT`] and [`MAX_TOTAL_DATABASE_BYTES`], so a
///   hostile manifest cannot turn validation into unbounded I/O.
///
/// # Which mechanism fills it, and the one half not built
///
/// * [`discover_databases`] cannot reach a tree BY TYPE — `!file_type.is_file()`
///   runs before the extension test — so the sibling pass
///   [`discover_captured_trees`], which enumerates `DataDirTree` rows whose
///   [`crate::durable_assets::CaptureRule`] is `Tree`. `discover_databases` was
///   deliberately NOT widened: a function whose name says databases must not
///   start returning trees.
/// * [`restore_data_dir`] does per-entry activation ([`activate_captured_tree`])
///   rather than the single [`activate_staged_file`] call a file asset takes.
///   For `cas` that is sound because objects are immutable and
///   content-addressed, so a partially restored tree is a strict SUBSET and boot
///   already refuses a root whose object is absent. It is NOT sound for
///   `vcs.jj_repo`, whose op-log and index have cross-file invariants a per-file
///   restore can break — which is why [`validate_tree_records`] refuses that
///   name rather than trusting a successor to remember.
///
/// Not built: a resolver for the SECOND root
/// ([`crate::durable_assets::AssetRoot::OperatorDeclared`], where `vcs.jj_repo`
/// lives). It is deferred, and the cost makes deferring right: the repository
/// carries location metadata a restore would have to rewrite, and measured
/// ~36.7 MB against ~10.5 MB for every database combined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedTree {
    /// The tree's durable-asset LOCATION name (`"cas"`, `"vcs.jj_repo"`), never
    /// a host path.
    pub name: String,
    /// The durable root this tree hangs off. A capture that resolves one root
    /// does not reach the others, and a restore that assumed one would misplace
    /// the rest.
    pub root: AssetRoot,
    /// The tier this tree was captured under.
    pub tier: DurabilityTier,
    /// Every captured file, sorted by [`CapturedTreeEntry::path`] so
    /// [`Self::entry_digest`] is reproducible.
    pub entries: Vec<CapturedTreeEntry>,
    /// Number of entries, as an independently checkable bound.
    pub entry_count: u64,
    /// Sum of every entry's `byte_len`.
    pub total_byte_len: u64,
    /// Lowercase-hex blake3 digest over the canonical serialization of
    /// [`Self::entries`], or `None` when the tier did not buy one. It is what
    /// makes the entry LIST tamper-evident rather than merely the files it names.
    pub entry_digest: Option<String>,
}

/// The durable record of how far a restore activation got.
///
/// Under-reporting is the safe asymmetry: the entry is written AFTER the target is
/// durably in place, so a crash in between makes a resume re-activate an asset
/// it cannot prove it finished — never SKIP one it never put back.
///
/// It lives under the TARGET data directory, not beside the artifact — see
/// [`restore_journal_path`] for why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreJournal {
    /// The artifact this journal tracks. A journal naming a different artifact
    /// is discarded rather than misread.
    pub artifact_id: Ulid,
    /// Asset names whose activation completed durably, in activation order.
    pub completed: Vec<String>,
}

/// Manifest describing the contents of an incomplete database-snapshot artifact. Serialized to
/// [`MANIFEST_NAME`] so [`restore_data_dir`] knows exactly which files to
/// restore (and so operators can inspect the snapshot offline).
///
/// # Every field is required
///
/// No field below the `-- v2 --` line carries a serde default: a manifest
/// missing any of them is a hand-edited one, and a default would answer it with
/// silence. The version is read first, by [`ManifestVersionProbe`], so an out-of-window
/// artifact is refused by [`ManifestVersionRefusal`] and never by serde.
///
/// # The version check is the compatibility boundary
///
/// The compatibility break is the version CHECK, not the field set, and it is
/// taken in [`read_manifest`]'s version probe, before any field is decoded.
///
/// The dangerous direction is a manifest written by a tree-capable binary and
/// read by one that cannot place a tree: same version number, no unknown field
/// to trip on, and a restore that reports success while omitting the tree
/// entirely. [`validate_tree_records`] makes that a named refusal: it refuses
/// the tree names this binary cannot place — see that function for why it
/// refuses those names and not every tree name.
///
/// A file record could not carry a tree: `digest` and `byte_len` are FILE
/// fields, and a tree has a root, a file set, and per-file integrity. So the
/// tree vocabulary — [`tree_roots`](Self::tree_roots), [`trees`](Self::trees),
/// [`CapturedTree`] and [`CapturedTreeEntry`] — is part of this version's fixed
/// field set.
///
/// One rule binds every field: a field may not be added without [`ManifestVersionProbe`]
/// being able to read the version WITHOUT it, which is what keeps the refusal for a foreign
/// manifest a named one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    /// Artifact schema version. Bumped if the on-disk layout changes.
    ///
    /// The version records WHICH INTEGRITY CONTRACT the artifact carries, so a
    /// reader accepts exactly the contracts it implements — [`MANIFEST_VERSION`]
    /// and [`RECOVERY_MANIFEST_VERSION`] — and refuses every other version before
    /// decoding, rather than reading an artifact as a contract it does not carry.
    pub version: u32,
    /// Wall-clock creation time, milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// Captured database filenames (relative to [`STORES_SUBDIR`]), sorted.
    pub databases: Vec<String>,
    /// Whether a copy of the node config is bundled at
    /// [`CONFIG_COPY_NAME`].
    pub config_included: bool,
    // -- v2 -----------------------------------------------------------------
    /// A fresh ULID per capture, and the only thing that scopes a
    /// [`RestoreJournal`] to one artifact.
    ///
    /// Always `Some` in a captured artifact: no producer omits it, and the
    /// `None` arm in [`restore_data_dir`] is reachable only by hand-editing
    /// `"artifact_id": null`.
    pub artifact_id: Option<Ulid>,
    /// Non-secret source authority identity, required by the
    /// [`RECOVERY_MANIFEST_VERSION`] clone contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_directory_id: Option<String>,
    /// Per-asset durability record, in capture order.
    pub assets: Vec<CapturedAsset>,
    /// The capture's own [`ConsistencyToken`].
    ///
    /// [`restore_data_dir`] is the check that reads it. It is carried IN the
    /// artifact because the operator running the RESTORE — a different person,
    /// on a different day, holding only the artifact — must be able to see the
    /// order its parts were taken in and how far apart the first and last were.
    ///
    /// `Option` for [`Self::artifact_id`]'s reason, not for a version's: a
    /// capture always writes `Some`.
    pub capture_order: Option<ConsistencyToken>,
    /// Captured tree-asset LOCATION names, sorted — the CLAIM half, exactly as
    /// [`Self::databases`] is for file assets.
    ///
    /// Separate from [`Self::trees`] for the reason the tier downgrade taught:
    /// evidence whose absence is indistinguishable from "there was none" is
    /// evidence that can be deleted. A claim and a record that DISAGREE are
    /// refused in either direction by [`validate_tree_records`] — a claim with no
    /// record tells an operator an asset is covered when nothing will restore it,
    /// and a record with no claim restores an asset the completeness report calls
    /// missing. Both empty means the artifact captured no tree.
    ///
    /// This is the field [`manifest_completeness`] adds to the captured set, and
    /// therefore the field that makes `cas` stop being reported missing.
    pub tree_roots: Vec<String>,
    /// Per-tree durability record — the EVIDENCE half, as [`Self::assets`] is
    /// for file assets. Populated by [`capture_tree`]; see
    /// [`CapturedTree`] for what a tree needs that a [`CapturedAsset`] cannot
    /// express.
    pub trees: Vec<CapturedTree>,
    /// WHICH BINARY produced this artifact. See [`ProducerIdentity`] — it is
    /// provenance, never evidence.
    pub producer: ProducerIdentity,
    /// Required for [`RECOVERY_MANIFEST_VERSION`]. A [`MANIFEST_VERSION`] data
    /// snapshot has no recovery treatment contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_assets: Option<Vec<RecoveryAsset>>,
}

/// Current [`BackupManifest::version`].
///
/// v2 carries [`BackupManifest::assets`] (per-asset tier + digest),
/// [`BackupManifest::artifact_id`] (journal scoping),
/// [`BackupManifest::capture_order`], and the tree vocabulary
/// ([`BackupManifest::tree_roots`] / [`BackupManifest::trees`]) that the
/// [`crate::durable_assets::CaptureRule::Tree`] capture fills in — see
/// [`BackupManifest`]'s "The version check is the compatibility boundary".
pub const MANIFEST_VERSION: u32 = 2;

/// WHICH BINARY wrote this artifact.
///
/// # The question the artifact must answer
///
/// An operator holding an artifact and a failing restore needs to tell whether
/// the artifact came from the binary in front of them or from an older build,
/// and [`MANIFEST_VERSION`] does not help: it moves once per contract change,
/// not once per build. With a version string that does not move per build, the
/// only way to know what wrote an artifact is if the artifact says so.
///
/// # Why these fields and not a git SHA
///
/// The git SHA, dirty flag and build timestamp exist — in
/// `bin/kata/src/build_info.rs`, baked in by that crate's `build.rs`. It
/// is the LEAF BINARY crate, and `kata-core` is below it: `env!`/`cargo:rustc-env`
/// reach only the crate whose build script emitted them, so this module cannot
/// read them and a dependency edge the other way is a cycle. So this records
/// what `kata-core` can prove about the process it is running in; supplying the
/// git identity as a parameter from the binary would change
/// `backup_data_dir`'s signature.
///
/// What that proves is not nothing, and on one host it is strictly more
/// discriminating than the version string would be: the running executable's
/// PATH separates an installed main from a development build, and its
/// length and mtime separate two builds of the same path. A rebuild that changed
/// no bytes at all is indistinguishable, which is the correct answer.
///
/// # What it REFUSES against what it CLAIMS
///
/// It refuses nothing. This is PROVENANCE, recorded in unauthenticated JSON that
/// anyone holding the artifact can rewrite; nothing in restore reads it, and
/// nothing may be cited as verified because of it. It answers "which build
/// probably wrote this", which is a diagnostic question, and it must never be
/// used to answer "may this artifact be trusted", which is
/// [`CapturedAsset::digest`]'s question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerIdentity {
    /// `kata-core`'s own package version — a pre-release number that does not move
    /// per build. Recorded anyway because it is the field that stops being
    /// degenerate the day kata is released, and a reader who finds it absent
    /// cannot tell "unversioned" from "nobody wrote it down".
    pub crate_version: String,
    /// The absolute path of the executable that ran the capture.
    pub executable: String,
    /// That executable's length in bytes.
    pub executable_len: u64,
    /// That executable's mtime, in milliseconds since the Unix epoch — when the
    /// binary was LINKED, which on a machine that rebuilds constantly is the
    /// build identity the version string cannot supply.
    pub executable_mtime_ms: i64,
}

/// The [`ProducerIdentity`] of the process running this capture.
///
/// # Errors
///
/// [`KataError::Storage`] when the process cannot name its own executable or
/// stat it. That is a hard failure and deliberately not a `None`: an artifact
/// whose producer field is absent is indistinguishable from one written by a
/// build that did not record it, which is the state this field exists to end.
/// On Linux this reads `/proc/self/exe`; a host where that fails is a host where
/// a backup should stop and say so.
fn producer_identity() -> KataResult<ProducerIdentity> {
    let exe = std::env::current_exe().map_err(|error| {
        KataError::Storage(format!(
            "backup: the capturing process cannot name its own executable ({error}); the \
             manifest would carry no producer identity"
        ))
    })?;
    let metadata = std::fs::metadata(&exe).map_err(|error| {
        KataError::Storage(format!(
            "backup: stat the capturing executable {} failed: {error}",
            exe.display()
        ))
    })?;
    let mtime_ms = metadata
        .modified()
        .map_err(|error| {
            KataError::Storage(format!(
                "backup: read the capturing executable's mtime ({}): {error}",
                exe.display()
            ))
        })?
        .duration_since(std::time::UNIX_EPOCH);
    // A binary dated before 1970 is a clock statement, not a failure: record the
    // negative offset rather than refusing a capture over it.
    let mtime_ms = match mtime_ms {
        Ok(since) => i64::try_from(since.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    };
    Ok(ProducerIdentity {
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
        executable: exe.display().to_string(),
        executable_len: metadata.len(),
        executable_mtime_ms: mtime_ms,
    })
}

/// The [`crate::durable_assets`] location name of the node config an artifact
/// bundles at [`CONFIG_COPY_NAME`].
///
/// The map keys that asset on the CONFIG FLAG that names it
/// (`AssetLocation::ConfigDeclared("--config")`), not on the filename it is
/// copied to, because an [`crate::durable_assets::AssetLocation`] never names
/// an absolute host path. So the manifest's `config_included` boolean cannot
/// be compared to `CONFIG_COPY_NAME` — it has to be translated, and
/// `the_bundled_config_name_resolves_to_an_authoritative_map_row` proves the
/// translation still lands on a row.
const BUNDLED_CONFIG_ASSET_NAME: &str = "--config";

/// The durable-asset map's completeness verdict over the artifact `manifest`
/// describes.
///
/// This structural report never grants v4 recoverability from public manifest
/// fields. Only [`VerifiedRecoveryArtifact::completeness`] does so, after
/// digest, external-generation, and runtime reference/remote-closure checks.
///
/// # Why this exists rather than `assess_backup_class` at each call site
///
/// [`crate::durable_assets::assess_backup_class`] takes the set of asset
/// LOCATION NAMES an artifact contains, and a [`BackupManifest`] does not carry
/// one: it carries `databases` (location names, by luck of the `*.db` glob) plus
/// `config_included`, a BOOLEAN standing in for the location name `--config`.
/// Passing `manifest.databases` straight through therefore reports the node
/// config missing from every artifact that bundles it — an artifact telling an
/// operator to go find a file it is holding. Translating the boolean is the
/// whole of the adaptation, and doing it in ONE place is what stops the backup
/// and restore reports from disagreeing about the same artifact.
///
/// # The verdict is not stored in the manifest
///
/// [`CompletenessVerdict`] **cannot implement `Deserialize`**. Its `missing_authoritative` and
/// `requires_external_rebind` fields are `Vec<&'static str>`, and there is no
/// way to deserialize owned JSON into `&'static str`. Carrying the map's own
/// type would mean changing those fields to `String` in
/// [`crate::durable_assets`] — which ripples into every call site that compares
/// a verdict against a `&'static` map name, including
/// `a_bundled_config_is_not_reported_missing`'s
/// `.contains(&"--config")` — for a field that would then be a SECOND source of
/// truth for a verdict [`assess_backup_class`] already derives correctly from
/// the manifest, offline.
///
/// So the artifact carries the verdict's INPUTS ([`BackupManifest::databases`],
/// [`BackupManifest::config_included`]) and not the verdict. The obligation to
/// surface the incompleteness in the artifact is met by the reports both verbs
/// print from those inputs; what is NOT met is offline inspection by `cat`
/// alone.
/// # `tree_roots` is part of the captured set, and this is where `cas` stops
/// # being reported missing
///
/// [`BackupManifest::tree_roots`] carries durable-asset LOCATION NAMES directly
/// — that is what it is for, and it is why the claim half exists separately
/// from the evidence half. Feeding it in is the whole of what makes a
/// tree-carrying artifact stop telling its operator to go find bytes it is
/// holding. `the_shipped_backup_artifact_is_assessed_as_an_incomplete_data_snapshot`
/// (`crates/core/tests/durable_asset_map.rs`) measures it against a real capture
/// rather than a constructed manifest: it asserts `cas` ABSENT from
/// [`CompletenessVerdict::missing_authoritative`] and re-derives the verdict
/// from the same manifest with only the tree claim dropped, so the absence is
/// measured against the presence.
///
/// # Structural inventory is not verified recovery
///
/// This adapter reads only database names, tree roots and the bundled-config
/// flag. It does not inspect v4 recovery treatments, worker receipts, target
/// rebinding or the verified remote closure. A verified v4 artifact earns its
/// recovery verdict through `VerifiedRecoveryArtifact::completeness`, not by
/// widening these structural inputs.
///
/// The admission rules constrain database names to single-component `*.db`
/// names without `:`, tree roots to `restorable_tree_asset` locations, and the
/// config boolean to `BUNDLED_CONFIG_ASSET_NAME`. These inputs cannot name the
/// five identity, credential, subordinate-worker and repository asset groups.
/// `structural_inventory_alone_cannot_earn_recoverable` maximizes the admitted
/// structural set and pins the exact missing names. Omitting CAS changes that
/// missing set but not this adapter's snapshot class; an omission regression
/// must assert the missing asset rather than a class already forced by other
/// omissions.
///
/// The bound is over admitted structural inputs, not arbitrary public
/// `BackupManifest` values. The same test constructs an inadmissible raw value
/// that reaches every asset. `assess_backup_class` also accepts raw asset sets,
/// and `the_complete_authoritative_set_earns_recoverable_and_one_omission_costs_it`
/// exercises its reachable recovery branch. Neither result substitutes for the
/// v4 artifact's runtime verification.
#[must_use]
pub fn manifest_completeness(manifest: &BackupManifest) -> CompletenessVerdict {
    let mut captured: BTreeSet<String> = manifest.databases.iter().cloned().collect();
    captured.extend(manifest.tree_roots.iter().cloned());
    if manifest.config_included {
        captured.insert(BUNDLED_CONFIG_ASSET_NAME.to_string());
    }
    assess_backup_class(&captured)
}

/// Restore preflight bounds. These are deliberately generous relative to the
/// current store set while still preventing a hostile manifest from turning
/// validation into unbounded allocation, directory traversal, or I/O.
///
/// # [`MAX_MANIFEST_BYTES`] is DERIVED from the tree bounds
///
/// A v2 manifest carries an entry per captured tree member — path, digest,
/// length — so its size is a function of [`MAX_TREE_ENTRIES`] and
/// [`MAX_TREE_COUNT`], not of the ~10 databases. A flat bound would ship the
/// worst available failure: a capture that writes an artifact its own
/// [`read_manifest`] refuses, at somewhere around 3,000 file-backed CAS
/// objects, with the refusal blaming the manifest rather than the bound.
///
/// So the bound is COMPUTED from the tree bounds rather than chosen beside them,
/// and the only free number is
/// [`MAX_TREE_ENTRY_MANIFEST_BYTES`] — a per-entry headroom that
/// `the_manifest_bound_admits_a_maximal_tree_manifest` MEASURES against real
/// serialized output. Raising [`MAX_TREE_ENTRIES`] carries this along
/// automatically; changing the entry SHAPE reds that test.
const MAX_MANIFEST_BYTES: u64 = FLAT_MANIFEST_BYTES
    + (MAX_TREE_COUNT as u64) * (MAX_TREE_ENTRIES as u64) * MAX_TREE_ENTRY_MANIFEST_BYTES
    + workspace_checkpoints::MAX_CHECKPOINT_MANIFEST_BYTES;

/// Everything in a manifest that is not a tree entry: the databases, the asset
/// records, the consistency token, and the JSON scaffolding. The pre-tree bound,
/// kept as the constant term.
const FLAT_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Bytes of pretty-printed JSON one [`CapturedTreeEntry`] may occupy.
///
/// Measured at ~250 for a `cas` entry (a 67-character path, a 64-character
/// digest, a byte length, and the surrounding punctuation and indentation); the
/// headroom is for a longer path. `the_manifest_bound_admits_a_maximal_tree_manifest`
/// is what keeps this a measurement.
const MAX_TREE_ENTRY_MANIFEST_BYTES: u64 = 384;
const MAX_DATABASE_COUNT: usize = 128;
const MAX_STORES_ENTRIES: usize = MAX_DATABASE_COUNT * 4;
const MAX_DATABASE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_TOTAL_DATABASE_BYTES: u64 = 4 * MAX_DATABASE_BYTES;
const MAX_DATABASE_NAME_BYTES: usize = 255;
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const SQLITE_MINIMUM_BYTES: u64 = 100;
static RESTORE_STAGE_NONCE: AtomicU64 = AtomicU64::new(0);

/// The most [`CapturedTree`] records one artifact may carry.
///
/// Bounded by the tree rows in [`crate::durable_assets::DURABLE_ASSETS`].
/// `the_tree_count_bound_matches_the_map` independently checks that inventory;
/// individual tree names still pass through [`restorable_tree_asset`].
const MAX_TREE_COUNT: usize = 3;

/// The most entries one [`CapturedTree`] may carry.
///
/// This is the bound an operator can actually hit: it is the count of
/// file-backed CAS objects (canonical bytes above
/// [`crate::store::cas::INLINE_THRESHOLD`]) in `<data_dir>/cas`. A capture over
/// a larger tree REFUSES and names the count — see [`capture_tree`] — because
/// the alternative is an artifact that silently holds a prefix of an
/// authoritative asset.
///
/// It is paired with [`MAX_MANIFEST_BYTES`] and cannot be raised alone; see
/// that constant.
const MAX_TREE_ENTRIES: usize = 65_536;

/// Longest tree-relative entry path, in bytes. `cas`'s longest is
/// `<2 hex>/<64 hex>` = 67.
const MAX_TREE_PATH_BYTES: usize = 255;

/// Deepest tree-relative entry path, in `/`-separated components. `cas` uses 2
/// (`<shard>/<object>`); the headroom is for a tree with a deeper layout, and
/// the bound exists so a hostile manifest cannot make path joining unbounded.
const MAX_TREE_PATH_COMPONENTS: usize = 8;

/// Largest single captured tree member.
///
/// `pub` for exactly one reason, and it is the only one of the three bounds that
/// has it: `kata_backup_names_the_omitted_tree_and_the_bound_that_omitted_it`
/// overruns this bound through the SHIPPED BINARY, at production bounds, with a
/// sparse file one byte past it — and that fixture has to be built FROM the
/// number. A copied literal would be a hang waiting to happen: raise the bound
/// above the literal and the capture stops tripping it and starts actually
/// copying and hashing a terabyte of zeros.
///
/// [`MAX_TREE_ENTRIES`] and [`MAX_TREE_TOTAL_BYTES`] stay private because no
/// test outside this crate needs either — a bound made `pub` for symmetry is a
/// surface nobody crosses.
pub const MAX_TREE_FILE_BYTES: u64 = MAX_DATABASE_BYTES;

/// Largest total for one captured tree.
const MAX_TREE_TOTAL_BYTES: u64 = MAX_TOTAL_DATABASE_BYTES;

/// The three capacity bounds one [`capture_tree`] call degrades on, carried
/// together.
///
/// # Why all three are parameters and not reads of the constants
///
/// *A claim whose only test would have to materialize 65,537 files is a claim
/// that does not get tested*, and that holds for all three bounds. The entry
/// bound is decided by
/// [`walk_tree_entries`] BEFORE [`capture_tree`] creates the destination root,
/// so an entry-bound omission has nothing to clean up and cannot leave a prefix
/// anywhere. The BYTE bounds are discovered mid-copy, so they are the only way
/// to reach [`TreeCapture::omitted_after_writing`] — the one path in this module
/// that writes members into the artifact and then removes them again.
///
/// Untested, that path is where a `trees/cas/` holding a PREFIX of an
/// authoritative tree survives beside a manifest that claims no tree — the exact
/// state the whole degradation rule exists to prevent, reachable only through
/// the two bounds nothing could drive.
///
/// Every production caller passes [`Self::PRODUCTION`];
/// [`backup_data_dir_with_tree_bounds`] is the only other constructor and it is
/// `test-support`-gated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TreeBounds {
    /// Most capturable members in one tree — [`MAX_TREE_ENTRIES`].
    entries: usize,
    /// Largest single member — [`MAX_TREE_FILE_BYTES`].
    file_bytes: u64,
    /// Largest total across one tree's members — [`MAX_TREE_TOTAL_BYTES`].
    total_bytes: u64,
}

impl TreeBounds {
    /// What every shipped `kata backup` runs at.
    pub(crate) const PRODUCTION: Self = Self {
        entries: MAX_TREE_ENTRIES,
        file_bytes: MAX_TREE_FILE_BYTES,
        total_bytes: MAX_TREE_TOTAL_BYTES,
    };
}

/// Domain separator for [`tree_entry_digest`].
///
/// Without it the digest of an EMPTY entry list is the digest of a fixed short
/// string that anything else could also produce; with it, a value computed here
/// can only have come from this function over this schema.
const TREE_ENTRY_DIGEST_DOMAIN: &[u8] = b"kata.backup.captured-tree.entries.v1";

/// Top-level subdirectories of a captured tree that hold IN-FLIGHT SCRATCH and
/// are never captured, keyed by the tree's location name.
///
/// # Why `cas/tmp` is not a tree member
///
/// [`crate::store::cas::CasStore::put`] writes a blob to
/// `cas/tmp/<hex>.<pid>.<seq>.part`, `fsync`s it, renames it into its shard and
/// `fsync`s the shard — so anything left in `tmp/` is the residue of a write
/// that did NOT complete. Three separate reasons it must not be captured, and
/// only the first is obvious:
///
/// * It is not an object. It has no content address, no `cas_objects` row, and
///   nothing can ever reference it, so capturing it would put bytes into an
///   artifact that nothing in a restored directory could ever name.
/// * It is what [`crate::durable_assets::AssetAuthority::Transient`] describes —
///   *"a restore that carries one is carrying a lie about a process that is not
///   running"* — and [`durability_tier`] gives that class
///   [`DurabilityTier::Excluded`] precisely so the lie is not materialized.
/// * It is the one part of the tree that is NOT immutable. The per-entry
///   soundness argument the tree capture rests on — content-addressed and
///   immutable, so a partial capture is a strict subset — is false of a `.part`
///   file being appended to by a concurrent writer, which a capture would
///   record a digest of a torn prefix of.
///
/// Keyed by NAME and not by a general rule, because the rule is CAS's. A second
/// tree row that needs an exclusion must state its own reason here rather than
/// inherit this one.
const TREE_SCRATCH_SUBDIRS: &[(&str, &[&str])] = &[("cas", &["tmp"])];

/// Databases that are the AUTHORITATIVE plane for some other, DERIVED
/// database also captured by a backup. Copied strictly LAST (after every
/// other discovered database) so every derived mirror's snapshot instant is
/// earlier-than-or-equal-to its authoritative source's — see the
/// module-level "Consistency" section for why that direction is the only
/// safe one.
///
/// `ledger_events.db` is the single-plane ledger event log / status projection.
/// `operational.db` is the authoritative control-plane nucleus: its execution
/// projections and watermark are folded in the SAME commit as the transitions they derive
/// from, so a backup that copied it before a database that mirrors it could capture a
/// mirror whose snapshot instant LEADS the authority, which is the unsafe direction.
/// Extend this list (never the alphabetical sort) if a future plane gains a derived mirror
/// of its own.
///
/// # It does not drive the copy order
///
/// [`backup_copy_order`] sorts by the durable-asset map's
/// [`SnapshotRank`], which subsumes this list. The constant survives as the
/// CROSS-CHECK: it records what the hand-maintained rule asserted, and
/// `the_map_ranks_subsume_the_hand_maintained_authoritative_last_rule` requires
/// the map to still agree with it. Deleting it would leave the derived order
/// with nothing outside itself to be wrong against.
#[allow(dead_code)] // read by the cross-check test above; see the section above.
const AUTHORITATIVE_LAST: &[&str] = &["ledger_events.db", "operational.db"];

/// The snapshot rank the durable-asset map gives a discovered database, or
/// `None` when the map does not classify it.
///
/// An unclassified name is not given a synthetic rank. The map's governing
/// distinction is between what it KNOWS and what it does not, and inventing a
/// position for a database nobody registered would hide exactly the staleness
/// [`crate::durable_assets::assess_backup_class`] reports as `unclassified`.
fn snapshot_rank_of(name: &str) -> Option<SnapshotRank> {
    classify_data_dir_entry(name).map(|asset| asset.snapshot_rank)
}

/// Decide the order in which `databases` are `VACUUM INTO`-copied during a
/// backup: **by the durable-asset map's [`SnapshotRank`]**, then alphabetically
/// within a rank.
///
/// # Not a hand-maintained list
///
/// The rule is one sentence — *an asset is copied before anything that can
/// reference it*. A hand-maintained partition such as [`AUTHORITATIVE_LAST`]
/// plus a comment naming what must NOT join it is two mechanisms, one of them
/// a deliberate omission, both maintained by hand, and neither readable by the
/// registry that states the rule.
///
/// Deriving the order from [`crate::durable_assets::DURABLE_ASSETS`] subsumes
/// both, and the subsumption is checked rather than asserted:
///
/// * there is NO mirror half to order: the authoritative assignment blob is
///   `attempts.assignment_json`, and the execution-evidence tables live in
///   `operational.db`, so the evidence is captured by the nucleus row that already
///   outranks everything. A hand-maintained list is exactly where a wrong belief about
///   which file mirrors which survives; the derivation reads the map instead.
///
/// [`AUTHORITATIVE_LAST`] survives only as the cross-check that the ranks did
/// not drift out from under those claims; see
/// `the_map_ranks_subsume_the_hand_maintained_authoritative_last_rule`.
///
/// An unranked (map-unknown) database sorts FIRST. The map cannot say what
/// references it, so the only safe position is one where nothing the map DOES
/// know can be displaced.
fn backup_copy_order(databases: &[String]) -> Vec<&str> {
    let mut ordered: Vec<&str> = databases.iter().map(String::as_str).collect();
    ordered.sort_by(|left, right| {
        let key = |name: &str| {
            snapshot_rank_of(name).map_or(
                // Sorts before every rank, `NotCaptured` included.
                (0_u8, 0_u8),
                |rank| (1, rank as u8),
            )
        };
        key(left).cmp(&key(right)).then_with(|| left.cmp(right))
    });
    ordered
}

/// Back up every durable SQLite store under `data_dir` into `out_dir`.
///
/// Discovers the top-level `*.db` files in `data_dir` (ignoring `-journal` /
/// `-wal` / `-shm` sidecars) that [`artifact_carries_database`] admits — the
/// map's [`AssetAuthority::Rebuildable`] rows are excluded there rather than
/// carried unverified — copies each into `out_dir/`[`STORES_SUBDIR`] via
/// `VACUUM INTO`, optionally writes the exact validated initial bytes retained
/// by `config` to
/// `out_dir/`[`CONFIG_COPY_NAME`], and writes a [`BackupManifest`] at
/// `out_dir/`[`MANIFEST_NAME`].
///
/// A supplied config must select the same physical `data_dir`. Managers built
/// with [`crate::ConfigManager::from_config`] are rejected because they retain
/// no exact source-byte snapshot.
///
/// `out_dir` is created if absent. Existing store copies inside it are
/// overwritten so re-running a backup to the same path is idempotent.
///
/// # Errors
///
/// Returns `KataError::Config` for a config/data mismatch or missing exact
/// config bytes, `KataError::Storage` on any filesystem or SQLite failure,
/// and `KataError::Serialization` if the manifest cannot be encoded.
pub fn backup_data_dir(
    data_dir: &Path,
    out_dir: &Path,
    config: Option<&crate::ConfigManager>,
) -> KataResult<BackupManifest> {
    backup_data_dir_with_hooks(
        data_dir,
        out_dir,
        config,
        TreeBounds::PRODUCTION,
        || {},
        |_name| {},
    )
    .map(|outcome| outcome.manifest)
}

/// Everything one capture produced.
///
/// # Why the omissions are a RETURN VALUE and not only a manifest field
///
/// A [`TreeCapture::Omitted`] carries a `reason` — which bound, measured against
/// what. A `tracing::warn!` alone would not reach the operator: `run_backup_cmd`
/// installs no subscriber, so on the only path that can produce an omission the
/// reason would be dropped into the no-op global dispatcher, and the operator
/// would be told `cas` was missing and never told why. *"The discriminator is
/// whether the operator is TOLD"* is this degradation's entire justification.
///
/// It rides here rather than in [`BackupManifest`] because it is a fact about
/// this capture RUN, not about the artifact: the artifact's own evidence is that
/// it makes no claim to the asset, which is what a restore reports and all a
/// restore can honestly say. Putting an unauthenticated free-text reason in a
/// hand-editable manifest would also put attacker-chosen text into an operator
/// report, for a fact the report already derives.
///
/// The reason reaches the operator through [`manifest_completeness`]'s verdict
/// via [`crate::durable_assets::CompletenessVerdict::explaining`] — the
/// completeness machinery, annotated — rather than through a second report section beside it.
#[derive(Clone, Debug)]
pub struct CaptureOutcome {
    /// The manifest the artifact carries.
    pub manifest: BackupManifest,
    /// The order and instants the parts were taken in.
    pub consistency: ConsistencyToken,
    /// Assets this capture DEGRADED rather than captured, in capture order.
    /// Empty for every capture that hit no bound.
    pub omitted: Vec<OmittedAsset>,
}

/// One asset a capture left out of the artifact, and why, in the operator's
/// terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OmittedAsset {
    /// The durable-asset map location name, e.g. `cas`.
    pub name: String,
    /// A phrase completing "the asset was omitted because …".
    pub reason: String,
}

/// [`backup_data_dir`], additionally returning the [`ConsistencyToken`] the
/// capture produced.
///
/// # Why the token is also a return value
///
/// The manifest carries the token as [`BackupManifest::capture_order`], and
/// [`restore_data_dir`] checks it. The capture also returns it so `kata backup`
/// can print it at capture time.
///
/// The token is produced HERE, on the shipped path, because a consistency type
/// with no producer is forward vocabulary: a type that claims a property
/// nothing establishes.
///
/// # Errors
///
/// As [`backup_data_dir`].
pub fn backup_data_dir_with_consistency_token(
    data_dir: &Path,
    out_dir: &Path,
    config: Option<&crate::ConfigManager>,
) -> KataResult<CaptureOutcome> {
    backup_data_dir_with_hooks(
        data_dir,
        out_dir,
        config,
        TreeBounds::PRODUCTION,
        || {},
        |_name| {},
    )
}

/// [`backup_data_dir`]'s real body, parameterized over deterministic test
/// hooks around source discovery and each completed `VACUUM INTO` copy, and over
/// the tree BOUNDS.
///
/// [`TreeBounds`] is a parameter for the reason [`walk_tree_entries`]'s
/// `max_entries` is, carried one level further: the behaviour it selects is
/// a DEGRADATION of the whole product path rather than a refusal inside one
/// helper, and the claims worth testing — that the databases still land, that
/// the completeness report names the omission AND the reason, that no partial
/// member survives in `trees/`, that a restore of the artifact does not pretend
/// to hold the bytes — are claims about `backup_data_dir`'s output. Every
/// production caller passes [`TreeBounds::PRODUCTION`].
pub(crate) fn backup_data_dir_with_hooks(
    data_dir: &Path,
    out_dir: &Path,
    config: Option<&crate::ConfigManager>,
    tree_bounds: TreeBounds,
    after_discovery: impl FnOnce(),
    after_copy: impl FnMut(&str),
) -> KataResult<CaptureOutcome> {
    backup_data_dir_with_recovery(
        data_dir,
        out_dir,
        config,
        tree_bounds,
        after_discovery,
        after_copy,
        None,
    )
}

/// Capture a complete v4 artifact under the caller's source backup fence.
/// The verifier must enumerate references from these actual captured files and
/// verify their remote closure; authenticated worker export precedes this call.
pub fn backup_recovery_data_dir(
    data_dir: &Path,
    out_dir: &Path,
    config: Option<&crate::ConfigManager>,
    recovery: &RecoveryCapture,
    verifier: &dyn RecoveryVerifier,
) -> KataResult<VerifiedRecoveryArtifact> {
    if out_dir.join(MANIFEST_NAME).symlink_metadata().is_ok() {
        return Err(KataError::Storage(
            "recovery capture requires an unpublished artifact directory".into(),
        ));
    }
    let captured = backup_data_dir_with_recovery(
        data_dir,
        out_dir,
        config,
        TreeBounds::PRODUCTION,
        || {},
        |_| {},
        Some((recovery, verifier)),
    )?;
    Ok(VerifiedRecoveryArtifact::from_verified(captured.manifest))
}

fn backup_data_dir_with_recovery(
    data_dir: &Path,
    out_dir: &Path,
    config: Option<&crate::ConfigManager>,
    tree_bounds: TreeBounds,
    after_discovery: impl FnOnce(),
    mut after_copy: impl FnMut(&str),
    recovery: Option<(&RecoveryCapture, &dyn RecoveryVerifier)>,
) -> KataResult<CaptureOutcome> {
    // Capture one physical source before discovery. Without this binding, a
    // symlink in an ancestor component can be retargeted between discovery and
    // the per-database opens, producing a manifest from A with bytes from B.
    let data_dir = data_dir.canonicalize().map_err(|error| {
        KataError::Storage(format!(
            "backup: resolve source data directory {} failed: {error}",
            data_dir.display()
        ))
    })?;
    let mut databases = discover_databases(&data_dir)?;
    databases.sort();
    validate_database_names(&databases)?;
    // The SECOND discovery pass, driven by the durable-asset map rather than by
    // a filename rule. See the "tree capture and restore" section for why
    // widening `discover_databases` was the wrong fix.
    let tree_sources = discover_captured_trees(&data_dir)?;
    let config_snapshot = config
        .map(|config| validated_config_snapshot(config, &data_dir))
        .transpose()?;
    after_discovery();

    let stores_dir = out_dir.join(STORES_SUBDIR);
    create_real_directory(
        &stores_dir,
        "backup",
        "an artifact's own store directory may not be a link to somewhere else, or the databases \
         it claims live outside the directory an operator archives and restores from",
    )?;

    // The token's instants are `capture_base_ms + monotonic elapsed`, NOT
    // repeated wall-clock reads. A wall clock can step backwards mid-capture
    // (NTP, an operator setting the date), and a backwards step would make the
    // token report an instant inversion that the capture did not commit — a
    // refusal caused by the clock rather than by the copy. The base is read once
    // so the recorded instants are still comparable to `created_at_ms`.
    let capture_base_ms = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let capture_started = std::time::Instant::now();
    let mut consistency_entries = Vec::with_capacity(databases.len() + tree_sources.len());
    let mut assets = Vec::with_capacity(databases.len() + 1);
    let mut any_durable = false;

    // TREES FIRST, and that is the ordering rule rather than a convenience.
    // Every tree row ranks `SnapshotRank::ReferencedContent` (1) and every
    // captured database ranks `Derived` (2) or higher, so `ConsistencyToken`
    // requires it: an asset must be captured before anything that can reference
    // it. Concretely, `cas.db`'s `cas_objects` rows and `operational.db`'s
    // `cas_roots` both point AT these bytes, and an artifact holding a root
    // whose object is absent is the state `verify_authoritative_roots_resolve`
    // refuses at boot.
    let mut trees = Vec::with_capacity(tree_sources.len());
    let mut tree_roots = Vec::with_capacity(tree_sources.len());
    let mut omitted: Vec<OmittedAsset> = Vec::new();
    if !tree_sources.is_empty() {
        let trees_dir = out_dir.join(TREES_SUBDIR);
        create_real_directory(
            &trees_dir,
            "backup",
            "an artifact's own tree directory may not be a link to somewhere else; see \
             `DirectoryState` for the artifact this produced",
        )?;
        for (asset, source_root) in &tree_sources {
            let name = asset.location.name();
            let tier = durability_tier(asset.authority);
            if tier == DurabilityTier::Excluded {
                // Unreachable at HEAD — both `CaptureRule::Tree` rows are
                // `Authoritative`. Refusing beats skipping for the reason the
                // database arm below states: a skip drops the asset with nothing
                // anywhere saying one was dropped.
                return Err(KataError::Storage(format!(
                    "backup: tree {name} is classified Transient by the durable-asset map and \
                     has no capture disposition"
                )));
            }
            match capture_tree(source_root, &trees_dir, asset, tier, tree_bounds)? {
                TreeCapture::Captured(tree) => {
                    any_durable |= tier == DurabilityTier::Durable;
                    trees.push(tree);
                    tree_roots.push(name.to_string());
                    consistency_entries.push(ConsistencyEntry {
                        asset: name.to_string(),
                        rank: asset.snapshot_rank,
                        instant_ms: capture_base_ms.saturating_add(
                            i64::try_from(capture_started.elapsed().as_millis())
                                .unwrap_or(i64::MAX),
                        ),
                    });
                }
                // DEGRADED, not failed. No claim, no record, and no consistency
                // entry — the token orders assets the artifact HOLDS, and an
                // entry for one it does not would make the capture order a
                // fiction. `manifest_completeness` reports the asset missing
                // from the absence of the claim, so both operator reports name
                // it without this path writing a second channel. See
                // `TreeCapture` for the rule and the counter-case.
                //
                // The REASON is returned to the caller. The `tracing::warn!`
                // below is not the operator channel: on `kata backup` — the
                // only path that can produce an omission — it goes to the no-op
                // global dispatcher because the verb installs no subscriber. It
                // stays because it is correct wherever a subscriber exists. See
                // `CaptureOutcome`.
                TreeCapture::Omitted { reason } => {
                    tracing::warn!(
                        asset = name,
                        reason = %reason,
                        "backup: omitting an authoritative tree from this artifact; the \
                         completeness report names it as missing and a restore of this artifact \
                         will not resolve its references"
                    );
                    omitted.push(OmittedAsset {
                        name: name.to_string(),
                        reason,
                    });
                }
            }
        }
        // `any_durable` is false when every tree was OMITTED, so a degraded
        // capture fsyncs each member's bytes, unlinks them again in
        // `TreeCapture::omitted_after_writing`, and never fsyncs the directory
        // whose entries it unlinked — while the manifest that claims no tree IS
        // published durably. That asymmetry is deliberate. The reasoning, because a durability
        // decision with no failing case has to carry one:
        //
        // * The claim is the manifest, and it is published durably, last, and
        //   names no tree. No post-crash state of `trees/` can turn into a
        //   claim, so the property this whole path exists for — an artifact
        //   never claims a tree it does not carry — does not depend on this
        //   fsync in either direction.
        // * The only state the missing fsync can produce is a surviving
        //   `trees/<name>/` residue beside a manifest claiming no tree. That is
        //   the SAME state a failed `remove_dir_all` produces with no crash at
        //   all, which the module admits on purpose (the result is discarded)
        //   and which `a_removal_the_filesystem_refuses_still_leaves_an_artifact_claiming_no_tree`
        //   measures end to end: the artifact stays honest and a restore of it
        //   does not place the residue.
        // * Nothing reads it. On the restore side `TREES_SUBDIR` is only ever
        //   joined with a tree name the MANIFEST supplies, and only
        //   `validate_stores_directory` enumerates a directory — `stores/`. An
        //   unclaimed `trees/` entry is unreachable, not merely unclaimed.
        //
        // So the fsync would buy "an artifact readable at all carries no
        // residue" — except when the removal failed, which is admitted. A
        // conditional property no reader may rely on is not a property, and
        // adding a durability operation that establishes none, in a module where
        // every one of them establishes one, invites the next reader to conclude
        // the removal is ordered against the manifest publish. It is not.
        //
        // What would flip this: an artifact-level invariant that `trees/` holds
        // ONLY what the manifest claims (say, a restore that enumerates it and
        // refuses a stranger). Then the fsync goes in AND the `remove_dir_all`
        // failure becomes fatal — they buy the property together or not at all,
        // because the failed removal reaches the identical state without a
        // crash.
        //
        // A verifier ran 60 SIGKILLs across this window and produced no
        // violation, which is consistent with the above and proves nothing on
        // its own; the argument is what decides it.
        if any_durable {
            fsync_dir(&trees_dir)?;
        }
    }
    tree_roots.sort();

    for name in backup_copy_order(&databases) {
        let tier = tier_of_database(name);
        if tier == DurabilityTier::Excluded {
            // Unreachable, and measured to be so by
            // `no_rebuildable_or_transient_asset_is_reachable_by_database_discovery`
            // in `crates/core/tests/backup_durability_tests.rs`. Refusing
            // beats skipping: a skip would drop the name out of `databases`
            // with nothing anywhere saying an asset was dropped, and this arm
            // can only be reached by a future map edit that gives a Transient
            // row a `*.db` name.
            //
            // TRANSIENT-only: `artifact_carries_database` removes `Rebuildable` names at discovery
            // and leaves `Transient` ones to arrive here, deliberately. The two are not one case. A
            // rebuildable database not being carried is a disposition the map licenses and states a
            // rebuild for; a Transient database reaching a capture at all means the map grew a
            // `*.db` row for something *"a restore that carries one is carrying a lie about"*, and
            // that is a programming error whose right answer is a loud stop rather than a quiet
            // omission.
            return Err(KataError::Storage(format!(
                "backup: discovered database {name} is classified Transient by the durable-asset \
                 map, and a restore that carries one is carrying a lie about a process that is \
                 not running; it has no capture disposition"
            )));
        }
        any_durable |= tier == DurabilityTier::Durable;
        let src = data_dir.join(name);
        assets.push(capture_database(&src, &stores_dir, name, tier)?);
        // Recorded AFTER the copy completes: the snapshot instant a restore has
        // to reason about is the point the bytes stopped changing, not the point
        // the copy was requested.
        if let Some(rank) = snapshot_rank_of(name) {
            consistency_entries.push(ConsistencyEntry {
                asset: name.to_string(),
                rank,
                instant_ms: capture_base_ms.saturating_add(
                    i64::try_from(capture_started.elapsed().as_millis()).unwrap_or(i64::MAX),
                ),
            });
        }
        after_copy(name);
    }
    // ONE directory fsync for the whole `stores/` tree rather than one per
    // asset.
    //
    // Safe because nothing outside this function may observe `stores/` until the
    // manifest is published, and the manifest is published strictly after this
    // point. The renames are ordered against each other by the loop; they need
    // only be durable before the CLAIM that they happened. Skipped entirely when
    // no asset earned the durable tier, so a best-effort-only artifact still
    // pays no fsync at all.
    if any_durable {
        fsync_dir(&stores_dir)?;
    }
    let consistency = ConsistencyToken::new(consistency_entries);
    // The capture checks its OWN order before it publishes a manifest an
    // operator will trust. This can only fire if `backup_copy_order` and the
    // ranks it sorts by disagree — i.e. if a future edit reintroduces a
    // hand-maintained order — and refusing beats writing an artifact whose parts
    // were taken in an order a restore cannot reconstruct.
    consistency.verify()?;

    let config_included = if let Some(config_snapshot) = config_snapshot {
        // ASKED of the map, never asserted about it; see `bundled_config_tier`
        // for why a literal with a comment saying the map agrees is a defect.
        let tier = bundled_config_tier();
        let bytes = config_snapshot.as_bytes();
        durable_publish(
            out_dir,
            CONFIG_COPY_NAME,
            bytes,
            "validated config snapshot",
        )?;
        assets.push(CapturedAsset {
            name: CONFIG_COPY_NAME.to_string(),
            tier,
            digest: (tier == DurabilityTier::Durable)
                .then(|| hex_digest(blake3::hash(bytes).as_bytes())),
            byte_len: bytes.len() as u64,
        });
        true
    } else {
        false
    };

    let mut manifest = BackupManifest {
        version: MANIFEST_VERSION,
        created_at_ms: now_ms(),
        databases,
        config_included,
        artifact_id: Some(Ulid::new()),
        assets,
        capture_order: Some(consistency.clone()),
        // Written explicitly rather than by `..Default::default()` so adding a
        // field to the manifest cannot pick up a silent default at the one site
        // that constructs a real artifact.
        tree_roots,
        trees,
        producer: producer_identity()?,
        recovery_assets: None,
        source_directory_id: None,
    };
    if let Some((recovery, verifier)) = recovery {
        recovery_assets::finish_capture(out_dir, &mut manifest, recovery, verifier)?;
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| KataError::Serialization(format!("backup: encode manifest: {e}")))?;
    // LAST, and durably: every copy above is durable and digested before the
    // manifest exists, so an interrupted capture leaves an artifact that is UNCLAIMABLE
    // rather than one that advertises copies it does not have. The reverse order
    // — or a bare `std::fs::write` with no ordering and no fsync — could publish
    // a manifest whose copies a power loss had not reached.
    durable_publish(out_dir, MANIFEST_NAME, &manifest_bytes, "manifest")?;

    Ok(CaptureOutcome {
        manifest,
        consistency,
        omitted,
    })
}

/// Capture ONE database into the artifact at its tier.
///
/// Both tiers `VACUUM INTO` a `.capture-tmp` beside the destination and publish
/// by rename. The rename is retained for `BestEffort` because it costs nothing
/// measurable next to the copy itself and removes a whole failure mode (an
/// interrupted capture overwriting a good previous copy of the same artifact
/// with a half-written one — `backup_data_dir` is documented idempotent to the
/// same `out_dir`, so that is a reachable state, not a hypothetical).
///
/// What the DURABLE tier adds, and what `BestEffort` therefore does not pay:
/// `PRAGMA quick_check` on the copy, a blake3 digest of its bytes, and
/// `sync_all` on the copy before it is renamed.
fn capture_database(
    src: &Path,
    stores_dir: &Path,
    name: &str,
    tier: DurabilityTier,
) -> KataResult<CapturedAsset> {
    let dst = stores_dir.join(name);
    let tmp = suffixed_path(&dst, CAPTURE_TMP_SUFFIX);
    // `VACUUM INTO` refuses an existing destination, and a `.capture-tmp` here is
    // residue of an interrupted earlier capture to this same artifact. Clearing
    // it is `vacuum_into`'s job — through `claim_owned_path`, which refuses an
    // obstruction instead of writing through it. An `if tmp.exists()` guard here
    // would RESOLVE the path and answer `false` for a dangling symlink, skipping
    // the removal at exactly the input that needs it. See `create_owned_file`
    // for the enumeration.
    vacuum_into(src, &tmp).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;

    let record = (|| -> KataResult<CapturedAsset> {
        // `stores` is this module's OWN component and `<out_dir>` above it is
        // the operator's, which is the split `ProvenDir::open` binds. The
        // `std::fs::metadata(&tmp)` this replaces resolved the whole path and
        // followed a link at the final component, and the `digest_file` below
        // it opened that path a SECOND time — see `ProvenDir::open_source_file`
        // for the window a proven descriptor does not have.
        let stores_root = ProvenDir::open(
            stores_dir,
            "backup",
            "an artifact's own stores directory may not be a link to somewhere else",
        )?;
        let tmp_name = suffixed_name(OsStr::new(name), CAPTURE_TMP_SUFFIX);
        let (tmp_file, byte_len) = stores_root.open_source_file(
            &tmp_name,
            MAX_DATABASE_BYTES,
            "backup",
            "capture temporary",
        )?;
        let digest = match tier {
            DurabilityTier::Durable => {
                // Refuse at CAPTURE. An artifact that records a digest of bytes that were
                // already corrupt is an artifact whose verify will pass forever.
                validate_sqlite(&tmp).map_err(|e| {
                    KataError::Storage(format!(
                        "backup: captured copy {name} failed its integrity check at capture: {e}"
                    ))
                })?;
                // The HANDLE this function already holds, digested and then
                // `fsync`ed — so the bytes recorded, the bytes made durable and
                // the bytes whose length was measured are one inode, reached
                // once.
                let digest = hex_digest(&digest_reader(&tmp_file, &tmp)?);
                tmp_file.sync_all().map_err(|e| {
                    KataError::Storage(format!("backup: fsync {} failed: {e}", tmp.display()))
                })?;
                Some(digest)
            }
            // No digest is taken, so none is recorded. See `CapturedAsset::digest`.
            DurabilityTier::BestEffort => None,
            DurabilityTier::Excluded => unreachable!("excluded assets are refused before capture"),
        };
        Ok(CapturedAsset {
            name: name.to_string(),
            tier,
            digest,
            byte_len,
        })
    })()
    .inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;

    std::fs::rename(&tmp, &dst).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        KataError::Storage(format!(
            "backup: publish captured copy {} -> {} failed: {e}",
            tmp.display(),
            dst.display()
        ))
    })?;
    Ok(record)
}

/// Restore the SQLite/config subset of a `data_dir` from an incomplete data
/// snapshot produced by [`backup_data_dir`].
///
/// Reads the manifest at `backup_dir/`[`MANIFEST_NAME`], creates
/// `data_dir` if absent, and copies each captured database back into it —
/// first deleting any stale `<name>-journal` / `<name>-wal` / `<name>-shm`
/// sidecar so a
/// corrupt WAL from a wiped/half-written data_dir cannot shadow the
/// restored main database. If the artifact bundled a config and
/// `restore_config_to` is `Some`, the config copy is restored there only when
/// its target-context `node.data_dir` resolves to this exact `data_dir`.
///
/// Existing files in an identity-less `data_dir` are overwritten. A target
/// containing `main-identity.json` is refused before artifact staging or target
/// mutation: a data snapshot is not authority to roll back an identified main.
/// Callers still own writer exclusion; `kata restore` supplies it through
/// installed-lifecycle coordination, the discovery lease, and kernel-held
/// data-directory authority.
///
/// # Errors
///
/// Returns `KataError::Config` for an incoherent config restore,
/// `KataError::Storage` on any filesystem failure, and
/// `KataError::Serialization` if the manifest cannot be decoded.
pub fn restore_data_dir(
    backup_dir: &Path,
    data_dir: &Path,
    restore_config_to: Option<&Path>,
) -> KataResult<BackupManifest> {
    restore_data_dir_with_hooks(
        backup_dir,
        data_dir,
        restore_config_to,
        |_name, _tmp| Ok(()),
    )
}

/// [`restore_data_dir`]'s real body, parameterized over a deterministic test
/// hook at the crash boundary that matters.
///
/// `before_activate(name, tmp)` fires when a `Durable` asset's replacement is
/// fully written and `fsync`ed at `tmp` and the target has NOT yet been
/// replaced. Returning `Err` aborts the restore exactly there, in-process.
pub(crate) fn restore_data_dir_with_hooks(
    backup_dir: &Path,
    data_dir: &Path,
    restore_config_to: Option<&Path>,
    before_activate: impl FnMut(&str, &Path) -> KataResult<()>,
) -> KataResult<BackupManifest> {
    restore_data_dir_with_recovery(
        backup_dir,
        data_dir,
        restore_config_to,
        before_activate,
        None,
    )
}

/// Validate a v4 artifact's bytes and runtime closure without mutating a target.
pub fn verify_recovery_artifact(
    backup_dir: &Path,
    verifier: &dyn RecoveryVerifier,
) -> KataResult<VerifiedRecoveryArtifact> {
    let manifest = read_manifest(backup_dir)?;
    recovery_assets::verify(backup_dir, &manifest, verifier)?;
    Ok(VerifiedRecoveryArtifact::from_verified(manifest))
}

/// Extract a verified clone/import artifact into an identity-less offline target.
/// Runtime activation still owes fresh identity, explicit rebinds and quarantine.
pub fn restore_recovery_data_dir(
    backup_dir: &Path,
    data_dir: &Path,
    restore_config_to: Option<&Path>,
    verifier: &dyn RecoveryVerifier,
) -> KataResult<VerifiedRecoveryArtifact> {
    let manifest = restore_data_dir_with_recovery(
        backup_dir,
        data_dir,
        restore_config_to,
        |_, _| Ok(()),
        Some(verifier),
    )?;
    Ok(VerifiedRecoveryArtifact::from_verified(manifest))
}

fn restore_data_dir_with_recovery(
    backup_dir: &Path,
    data_dir: &Path,
    restore_config_to: Option<&Path>,
    mut before_activate: impl FnMut(&str, &Path) -> KataResult<()>,
    verifier: Option<&dyn RecoveryVerifier>,
) -> KataResult<BackupManifest> {
    refuse_identified_restore_target(data_dir)?;
    let manifest = read_manifest(backup_dir)?;
    if manifest.version == RECOVERY_MANIFEST_VERSION {
        let verifier = verifier.ok_or_else(|| {
            KataError::Storage(
                "v4 recovery restore requires runtime reference and remote verification".into(),
            )
        })?;
        recovery_assets::verify(backup_dir, &manifest, verifier)?;
        if data_dir.join("idempotency.db").symlink_metadata().is_ok() {
            return Err(KataError::Storage("verified clone extraction refuses an existing target replay store; preserve interrupted activation offline".into()));
        }
    } else if verifier.is_some() {
        return Err(KataError::Storage(
            "v2 data snapshot cannot become a recoverable artifact".into(),
        ));
    }
    let staged = preflight_and_stage_restore(backup_dir, data_dir, restore_config_to, &manifest)?;

    std::fs::create_dir_all(data_dir).map_err(|e| {
        KataError::Storage(format!(
            "restore: create_dir_all({}) failed: {e}",
            data_dir.display()
        ))
    })?;

    // The OTHER half of `artifact_carries_database`, and it is required rather
    // than tidy.
    //
    // Restore accepts only an identity-less offline extraction target, which may
    // still contain residue from an interrupted extraction. A rebuildable database
    // the artifact deliberately does not carry must not SURVIVE that retry beside
    // authority restored to the capture instant: `capsule_reuse_v1` hints name
    // occurrences `operational.db` owns, and a hint whose plane the restore
    // rolled back points at a source that may no longer be accepted — a miss
    // the operational re-verification answers correctly, but one the node is
    // better without.
    //
    // Removing it is licensed by the same row that licensed not carrying it:
    // `RetentionRule::Reclaimable` is *"reclaimable at any time without
    // correctness loss"*.
    //
    // AFTER the preflight, so an artifact that fails verification still mutates
    // nothing, and BEFORE the trees and databases, so no interleaving leaves the
    // target holding a cache row whose object the restore has already rolled
    // back. Sidecars first and the main file last: a crash between them leaves a
    // valid database missing its most recent WAL frames, which is rebuildable
    // cache content, while the reverse order can leave a stale `-wal` beside a
    // freshly created database.
    clear_rebuildable_databases(data_dir)?;

    // Scoped to ONE artifact by its `artifact_id`, so a journal left by a
    // different artifact's interrupted restore is discarded rather than misread
    // as progress. A v1 artifact has no id and therefore no journal — see
    // `BackupManifest::artifact_id`.
    //
    // Keyed on the TARGET, not on the artifact: `restore_journal_path` explains
    // why, and the artifact directory is opened strictly read-only from here on.
    let mut journal = manifest
        .artifact_id
        .map(|artifact_id| load_or_reset_restore_journal(data_dir, artifact_id))
        .transpose()?;

    // TREES BEFORE DATABASES, mirroring the capture order and for the sharper
    // reason: an interruption here leaves objects with no roots (an orphan,
    // which is safe) rather than roots with no objects (a dangling reference,
    // which is never safe to guess at). Reversing this would
    // put the unsafe side of that asymmetry on the crash path.
    for tree in &manifest.trees {
        let tier = restore_tree_tier(tree);
        activate_captured_tree(backup_dir, data_dir, tree, tier, &mut before_activate)?;
        // The journal entry is a RECORD that this tree completed, not the skip
        // token it is for a file asset: `activate_captured_tree` resumes per
        // MEMBER from the per-member digests, which is a strictly stronger
        // proof than a name in a list. Recording it anyway is what stops the
        // journal from under-reporting an entire asset rather than progress
        // within one.
        record_activation(data_dir, journal.as_mut(), &tree.name, tier)?;
    }

    // The RESUME probe's root, opened once. `<data_dir>` is operator-typed and
    // resolved; every database name under it is one plain component
    // (`validate_database_names`) reached by `openat` with `O_NOFOLLOW`.
    let data_root = ProvenDir::open_operator_root(
        data_dir,
        "restore",
        "a restore's target data directory must be a directory",
    )?;
    for name in &manifest.databases {
        let src = staged.stores_dir().join(name);
        if manifest.version == RECOVERY_MANIFEST_VERSION && name == "idempotency.db" {
            continue;
        }
        let dst = data_dir.join(name);
        let tier = restore_tier(&manifest, name);
        if journal_records_activation(journal.as_ref(), name, &data_root, &manifest)? {
            continue;
        }
        // Clear stale rollback/WAL/SHM sidecars before overwriting the main file.
        // A vacuumed copy is self-contained, so leftover sidecars from the
        // previous (possibly corrupt) database must not survive.
        for sidecar in [
            format!("{name}-journal"),
            format!("{name}-wal"),
            format!("{name}-shm"),
        ] {
            let sidecar_path = data_dir.join(&sidecar);
            match std::fs::remove_file(&sidecar_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(KataError::Storage(format!(
                        "restore: remove stale sidecar {} failed: {e}",
                        sidecar_path.display()
                    )));
                }
            }
        }
        activate_staged_file(&src, &dst, "database", tier, name, &mut before_activate)?;
        record_activation(data_dir, journal.as_mut(), name, tier)?;
    }

    if manifest.config_included
        && let Some(dst) = restore_config_to
    {
        let src = staged.root.join(CONFIG_COPY_NAME);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KataError::Storage(format!(
                    "restore: create config parent {} failed: {e}",
                    parent.display()
                ))
            })?;
        }
        let tier = restore_tier(&manifest, CONFIG_COPY_NAME);
        activate_staged_file(
            &src,
            dst,
            "config",
            tier,
            CONFIG_COPY_NAME,
            &mut before_activate,
        )?;
        record_activation(data_dir, journal.as_mut(), CONFIG_COPY_NAME, tier)?;
    }

    if manifest.version == RECOVERY_MANIFEST_VERSION {
        let deadline = verifier
            .ok_or_else(|| {
                KataError::Storage("recovery extraction requires runtime verifier".into())
            })?
            .deadline();
        recovery_assets::restore_evidence(backup_dir, data_dir, &manifest, deadline)?;
        import_catalog::preserve_source_manifest(data_dir, &manifest)?;
    }

    // Every target is durably in place, so the journal has nothing left to
    // resume. Removing it is what makes its PRESENCE mean "a restore of this
    // artifact was interrupted" — a journal that outlived a successful restore
    // would make the signal unreadable.
    if journal.is_some() {
        clear_restore_journal(data_dir)?;
    }

    Ok(manifest)
}

/// A data snapshot may populate only an identity-less offline target. Identity
/// proves this path already belongs to a runtime generation, and overwriting
/// files beneath it would be an authority rollback that this artifact cannot
/// authorize.
fn refuse_identified_restore_target(data_dir: &Path) -> KataResult<()> {
    let identity = data_dir.join("main-identity.json");
    match std::fs::symlink_metadata(&identity) {
        Ok(_) => Err(KataError::Storage(format!(
            "restore: identified runtime directory {} contains main-identity.json; use a separate identity-less target and preserve both directories offline",
            data_dir.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(KataError::Storage(format!(
            "restore: inspect runtime identity {} failed: {error}",
            identity.display()
        ))),
    }
}

/// The most bytes a restore journal may be.
///
/// [`MAX_DATABASE_COUNT`] database names plus one tree per row in
/// [`DURABLE_ASSETS`] plus the bundled config, each at
/// [`MAX_DATABASE_NAME_BYTES`] with JSON quoting and indentation, plus the
/// `artifact_id` and the object framing. Rounded generously UP, because the
/// number's job is to stop an unbounded read of a file this module did not
/// write, not to be tight.
const MAX_RESTORE_JOURNAL_BYTES: u64 = 64 * 1024;

/// Load this artifact's restore journal, or start a fresh one.
///
/// A journal naming a different artifact is DISCARDED, not merged: its
/// `completed` names would otherwise be read as progress against copies that
/// were never made.
///
/// # A bounded read through a proven descriptor
///
/// `std::fs::read(restore_journal_path(data_dir))` would resolve
/// `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`]`/`[`RESTORE_JOURNAL_NAME`] whole, so a
/// link at either component would read from anywhere, and it would read to EOF,
/// a memory bound this module never states. A journal only ever grants a SKIP
/// that [`journal_records_activation`] must then prove with a digest, so the
/// harm is smaller than the holes [`digest_reader`] names — but it is the same
/// shape.
///
/// The walk is [`ProvenDir`]'s: `<data_dir>` is operator-typed and resolved, the
/// journal subdirectory and the journal itself are `openat`ed with `O_NOFOLLOW`,
/// and an absent or non-plain entry at either is "no journal" rather than a
/// refusal — the same reading the `NotFound` arm always had.
fn load_or_reset_restore_journal(data_dir: &Path, artifact_id: Ulid) -> KataResult<RestoreJournal> {
    let fresh = RestoreJournal {
        artifact_id,
        completed: Vec::new(),
    };
    let path = restore_journal_path(data_dir);
    let data_root = ProvenDir::open_operator_root(
        data_dir,
        "restore",
        "a restore's target data directory must be a directory",
    )?;
    let Some(journal_dir) = data_root.open_child_if_present(
        OsStr::new(RESTORE_JOURNAL_SUBDIR),
        "restore",
        "a restore may not read its own progress journal through a link out of the target data \
         directory",
    )?
    else {
        return Ok(fresh);
    };
    let Some(file) = journal_dir.open_regular(OsStr::new(RESTORE_JOURNAL_NAME), "restore")? else {
        return Ok(fresh);
    };
    // A file over the bound at this name is not a journal this module wrote, and
    // the honest reading is the one the unparseable case already had: NO
    // journal, so every asset is re-copied. Propagating the bound as an error
    // would turn a corrupt progress file into an unrestorable target, which is
    // the trade `read_manifest`'s widened version check already refused once.
    let Ok(bytes) = read_bounded_handle(file, &path, MAX_RESTORE_JOURNAL_BYTES, "restore journal")
    else {
        return Ok(fresh);
    };
    let existing: Option<RestoreJournal> = if bytes.is_empty() {
        None
    } else {
        serde_json::from_slice(&bytes).ok()
    };
    Ok(match existing {
        Some(journal) if journal.artifact_id == artifact_id => journal,
        _ => fresh,
    })
}

/// Read a proven handle to EOF, refusing at `maximum + 1` bytes rather than
/// growing to whatever is on the other end.
///
/// The handle form of [`read_regular_file_bounded`]'s bound. It exists because
/// [`ProvenDir::open_regular`] hands back a descriptor and no length, and a
/// caller that then reads it to EOF has a proven path and an unproven size.
///
/// # Errors
///
/// [`KataError::Storage`] on a read failure or a file over `maximum`.
fn read_bounded_handle(
    file: File,
    display: &Path,
    maximum: u64,
    label: &str,
) -> KataResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut bounded = file.take(maximum + 1);
    bounded.read_to_end(&mut bytes).map_err(|e| {
        KataError::Storage(format!(
            "restore: read {label} {} failed: {e}",
            display.display()
        ))
    })?;
    if bytes.len() as u64 > maximum {
        return Err(KataError::Storage(format!(
            "restore: {label} {} exceeds bounded maximum {maximum} bytes",
            display.display()
        )));
    }
    Ok(bytes)
}

/// Whether `name` may be SKIPPED because a previous run of this restore already
/// put it in place.
///
/// Two independent conditions, both required: the journal must record the
/// name AND the target must already digest to the captured value. The journal
/// alone is not enough — it is written after the activation, so it can only ever
/// UNDER-report, and an over-reporting journal (a hand-edited one) would
/// otherwise skip an asset that was never put back.
///
/// # The FILE resume probe carries the TREE resume probe's proof
///
/// `target.exists()` — which RESOLVES — followed by a path digest would be
/// satisfied by `<data_dir>/<database>` being a symlink to a file OUTSIDE the
/// target whose bytes are the captured ones: [`restore_data_dir`] would return
/// `Ok` with a LINK where the database should be — a restore reporting success
/// having placed nothing.
///
/// So it is [`ProvenDir::open_regular`], as the tree probe is: [`validate_database_names`]
/// has already refused every name that is not one plain component, so `name` is
/// an `openat` argument with nothing to resolve, and absent / symlink /
/// reader-less FIFO are all "the target does not already hold this" — `Ok(false)`
/// — which is the honest answer for a resume rather than a refusal.
fn journal_records_activation(
    journal: Option<&RestoreJournal>,
    name: &str,
    data_root: &ProvenDir,
    manifest: &BackupManifest,
) -> KataResult<bool> {
    let Some(journal) = journal else {
        return Ok(false);
    };
    if !journal.completed.iter().any(|done| done == name) {
        return Ok(false);
    }
    let Some(asset) = asset_record(manifest, name) else {
        return Ok(false);
    };
    let Some(expected) = &asset.digest else {
        return Ok(false);
    };
    let target_name = OsStr::new(name);
    let Some(present) = data_root.open_regular(target_name, "restore")? else {
        return Ok(false);
    };
    let display = data_root.child_path(target_name);
    Ok(&hex_digest(&digest_reader(present, &display)?) == expected)
}

/// Record one completed activation in the journal, durably.
///
/// A `BestEffort` asset earns no entry: the journal exists so a resume can skip
/// work it can PROVE was done, and the proof is the digest that tier did not
/// buy. Re-copying it on resume is the correct fallback and costs one copy.
fn record_activation(
    data_dir: &Path,
    journal: Option<&mut RestoreJournal>,
    name: &str,
    tier: DurabilityTier,
) -> KataResult<()> {
    let Some(journal) = journal else {
        return Ok(());
    };
    if tier != DurabilityTier::Durable {
        return Ok(());
    }
    if !journal.completed.iter().any(|done| done == name) {
        journal.completed.push(name.to_string());
    }
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|e| KataError::Serialization(format!("restore: encode restore journal: {e}")))?;
    // Created lazily, on the FIRST durable activation, so a restore that
    // journals nothing (a v1 artifact, or an all-best-effort one) leaves no
    // directory behind that it never used.
    let dir = data_dir.join(RESTORE_JOURNAL_SUBDIR);
    create_real_directory(
        &dir,
        "restore",
        "a restore may not write its own progress journal through a symlink out of the target \
         data directory",
    )?;
    durable_publish(&dir, RESTORE_JOURNAL_NAME, &bytes, "restore journal")
}

/// Remove a completed restore's journal, and `fsync` the directory so the
/// removal is durable.
///
/// The [`RESTORE_JOURNAL_SUBDIR`] directory itself is left in place: every
/// durable boot creates it anyway, and removing a root the adoption inventory
/// names would be this module reaching outside what it owns.
fn clear_restore_journal(data_dir: &Path) -> KataResult<()> {
    let path = restore_journal_path(data_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => fsync_dir(&data_dir.join(RESTORE_JOURNAL_SUBDIR)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(KataError::Storage(format!(
            "restore: remove restore journal {} failed: {e}",
            path.display()
        ))),
    }
}

/// Why an artifact's manifest version is outside the window this binary reads.
///
/// # Two directions, because they name OPPOSITE recourse
///
/// One merged "unsupported manifest version" refusal would send half the operators who read
/// it to the wrong side of the problem: a TOO-OLD artifact needs a NEW artifact (there is
/// no upgrade path for the bytes), while a TOO-NEW artifact needs a NEWER BINARY (the bytes
/// are fine and this build cannot interpret them). The in-tree precedent is
/// `kata_transport::control_fence::ControlRefusal::ProtocolTooNew`, which was split from
/// `UnfencedCommander` for exactly this reason and says so.
///
/// # What it REFUSES against what its name CLAIMS
///
/// It refuses on the version FIELD alone. It claims nothing about whether the
/// artifact is otherwise well formed — [`validate_database_names`],
/// [`validate_asset_records`] and [`validate_tree_records`] are separate and run
/// after — and nothing about AUTHENTICITY: the manifest is unauthenticated JSON,
/// so an attacker holding an artifact can write any version number they like.
/// The window is a compatibility fence, not an integrity one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManifestVersionRefusal {
    /// Not a supported contract, and below the newest one — an artifact written
    /// by an older kata, whose contract this binary does not implement.
    TooOld {
        /// The version the artifact claims.
        found: u32,
    },
    /// Above [`RECOVERY_MANIFEST_VERSION`] — an artifact written by a newer kata.
    TooNew {
        /// The version the artifact claims.
        found: u32,
    },
}

impl ManifestVersionRefusal {
    /// The refusal for `found`, or `None` for a supported contract.
    ///
    /// A total function over `u32` whose only parameters are the two supported
    /// versions: exactly [`MANIFEST_VERSION`] and [`RECOVERY_MANIFEST_VERSION`]
    /// pass, anything above the newer is `TooNew`, and everything else is
    /// `TooOld`. `0` is `TooOld`, which is the honest answer: it is a version no
    /// kata ever wrote, and "take a new backup" is what the operator can act on.
    const fn of(found: u32) -> Option<Self> {
        if found == MANIFEST_VERSION || found == RECOVERY_MANIFEST_VERSION {
            None
        } else if found > RECOVERY_MANIFEST_VERSION {
            Some(Self::TooNew { found })
        } else {
            Some(Self::TooOld { found })
        }
    }

    /// A stable, lowercase label — the sibling fences' `as_str` idiom, so a log
    /// or metric can separate the two populations an operator must treat
    /// differently.
    const fn as_str(self) -> &'static str {
        match self {
            Self::TooOld { .. } => "manifest_too_old",
            Self::TooNew { .. } => "manifest_too_new",
        }
    }
}

impl fmt::Display for ManifestVersionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooOld { found } => write!(
                f,
                "restore: backup manifest version {found} is not one of the supported versions \
                 {MANIFEST_VERSION} and {RECOVERY_MANIFEST_VERSION} this binary reads, and is BELOW \
                 the newest of them ({} label); the artifact was written by an older kata whose integrity \
                 contract this build no longer implements, and there is no migration — take a \
                 NEW backup with this binary. This is the OPPOSITE recourse from a too-new \
                 artifact, which needs a NEWER BINARY and not a new artifact",
                self.as_str()
            ),
            Self::TooNew { found } => write!(
                f,
                "restore: backup manifest version {found} is ABOVE the \
                 supported versions {MANIFEST_VERSION} and {RECOVERY_MANIFEST_VERSION} this binary reads \
                 ({} label); the artifact is fine and THIS BINARY is too old to interpret it — \
                 it may carry required structure this build cannot see, and guessing is how a \
                 restore silently drops an asset. Upgrade the BINARY to one that reads \
                 {found}. This is the OPPOSITE recourse from a too-old artifact, which needs a \
                 new artifact and not a new binary",
                self.as_str()
            ),
        }
    }
}

/// The one field [`read_manifest`] decodes BEFORE it decodes the manifest.
///
/// # Why the version is read twice
///
/// [`BackupManifest`] is `deny_unknown_fields` and its fields are REQUIRED, so a
/// manifest from another version fails decode with a serde error — `missing
/// field `producer`` — which is the wrong thing to show an operator holding an
/// artifact from an older kata. Reading the version first makes
/// [`ManifestVersionRefusal`] the refusal for every out-of-window artifact,
/// whatever its field set, and that is a MECHANISM rather than a rule: no future
/// field can accidentally move the diagnosis back into serde, because serde
/// never sees an out-of-window manifest.
#[derive(Deserialize)]
struct ManifestVersionProbe {
    /// The claimed schema version, and nothing else. Unknown fields are ignored
    /// here BY DESIGN — this struct's whole job is to read one field out of a
    /// document whose shape this binary may not know.
    version: u32,
}

/// Read + decode the [`BackupManifest`] at `backup_dir/`[`MANIFEST_NAME`].
///
/// # Exactly two versions are readable
///
/// [`MANIFEST_VERSION`] (an ordinary data snapshot) and
/// [`RECOVERY_MANIFEST_VERSION`] (a recovery artifact) are distinct contracts with
/// distinct restore doors. Every other version is refused by
/// [`ManifestVersionRefusal`] before decoding, in one of two directions, because
/// the two directions are the part an operator acts on: above the newer contract
/// needs a newer BINARY, anything else needs a new ARTIFACT.
///
/// # Errors
///
/// Returns `KataError::Storage` if the manifest is missing/unreadable or its
/// version is outside the readable window, and `KataError::Serialization` if it
/// cannot be decoded.
pub fn read_manifest(backup_dir: &Path) -> KataResult<BackupManifest> {
    let manifest_path = backup_dir.join(MANIFEST_NAME);
    let bytes = read_regular_file_bounded(&manifest_path, MAX_MANIFEST_BYTES, "manifest")?;
    // The VERSION decides which decoder is even applicable, so it is read before
    // the decode rather than out of its result.
    let probe: ManifestVersionProbe = serde_json::from_slice(&bytes)
        .map_err(|e| KataError::Serialization(format!("restore: decode manifest version: {e}")))?;
    if let Some(refusal) = ManifestVersionRefusal::of(probe.version) {
        return Err(KataError::Storage(refusal.to_string()));
    }
    let manifest: BackupManifest = serde_json::from_slice(&bytes)
        .map_err(|e| KataError::Serialization(format!("restore: decode manifest: {e}")))?;
    validate_database_names(&manifest.databases)?;
    validate_asset_records(&manifest)?;
    Ok(manifest)
}

/// Check that [`BackupManifest::assets`] describes exactly what the artifact
/// claims to hold, and that no record claims a tier it did not pay for.
///
/// Every refusal here is about a HAND-EDITED manifest, which is the only way any
/// of these states arises: a capture cannot produce them.
///
/// # The coverage rule is the one that matters
///
/// The obvious checks are "no record for an asset the artifact does not hold"
/// and "no `Durable` record without a digest". Both are real, and both are
/// defeated by DELETING the `assets` array: [`verify_captured_digest`] is a
/// no-op when there is no record to compare against, so a v2 artifact stripped
/// of its records would restore with the weak checks while still saying
/// `"version": 2`. So a v2 manifest must carry a record for EVERY database it
/// lists, and for the bundled config when it claims one.
///
/// # And the coverage rule alone is bypassed by a ONE-FIELD edit
///
/// Coverage says a record must EXIST; it says nothing about what the record may
/// claim. Editing one authoritative asset's record to
/// `"tier": "best_effort", "digest": null` leaves coverage satisfied, satisfies
/// *"a `Durable` record carries a digest"* vacuously, and gives
/// [`verify_captured_digest`] nothing to compare — restoring tampered bytes in
/// silence. [`refuse_weakened_tier`] closes it: the tier is DERIVED from the
/// durable-asset map and the manifest may only match it or exceed it. See
/// [`restore_tier`] for why derivation rather than clamping.
///
/// # The rules are UNCONDITIONAL
///
/// Every readable manifest carries integrity evidence, so no version gate scopes
/// the coverage and tier rules: a condition with no version left to discriminate
/// is a switch waiting to be flipped the wrong way.
///
/// # What this does NOT defend against, stated so nobody reads more into it
///
/// The manifest is unauthenticated JSON. The digests detect **bit-rot and
/// tampering of the captured COPIES**, which is the failure a backup actually
/// meets; they are not a signature over the artifact, and nothing here should be
/// cited as one. A signed manifest is a different asset class (a sealed backup)
/// with a key-management contract this module does not own.
///
/// A downgrade by rewriting `"version"` is closed by [`read_manifest`]'s version
/// probe, not by anything in this function: every unsupported version is
/// refused before decoding.
fn validate_asset_records(manifest: &BackupManifest) -> KataResult<()> {
    if manifest.version != RECOVERY_MANIFEST_VERSION && manifest.source_directory_id.is_some() {
        return Err(KataError::Storage(
            "v2 cannot carry a recovery source directory identity".into(),
        ));
    }
    let recovery_members = match (manifest.version, &manifest.recovery_assets) {
        (RECOVERY_MANIFEST_VERSION, _) => recovery_assets::validate_treatments(manifest)?,
        (_, Some(_)) => {
            return Err(KataError::Storage(
                "v2 cannot carry recovery treatments".into(),
            ));
        }
        (_, None) => BTreeSet::new(),
    };
    for name in &manifest.databases {
        let Some(record) = asset_record(manifest, name) else {
            return Err(KataError::Storage(format!(
                "restore: manifest version {} lists database {name:?} and records no \
                 durability entry for it; a readable artifact carries one per asset, and an \
                 absent entry would silently downgrade the integrity checks",
                manifest.version
            )));
        };
        refuse_weakened_tier(record)?;
    }
    match (
        manifest.config_included,
        asset_record(manifest, CONFIG_COPY_NAME),
    ) {
        (true, None) => {
            return Err(KataError::Storage(format!(
                "restore: manifest version {} bundles a config and records no durability \
                 entry for it",
                manifest.version
            )));
        }
        (true, Some(record)) => refuse_weakened_tier(record)?,
        (false, _) => {}
    }
    // NOT scoped by version. This is a CAPABILITY-and-coherence check, not a
    // schema one: letting the version number decide would make rewriting
    // `"version"` a way around every rule in it.
    validate_tree_records(manifest)?;
    let mut seen = HashSet::with_capacity(manifest.assets.len());
    for asset in &manifest.assets {
        let is_config = asset.name == CONFIG_COPY_NAME && manifest.config_included;
        if !is_config
            && !manifest.databases.contains(&asset.name)
            && !recovery_members.contains(&asset.name)
        {
            return Err(KataError::Storage(format!(
                "restore: manifest records asset {:?}, which the artifact does not claim to \
                 contain",
                asset.name
            )));
        }
        if !seen.insert(asset.name.as_str()) {
            return Err(KataError::Storage(format!(
                "restore: manifest records asset {:?} twice",
                asset.name
            )));
        }
        match asset.tier {
            DurabilityTier::Durable if asset.digest.is_none() => {
                return Err(KataError::Storage(format!(
                    "restore: manifest claims asset {:?} was captured durably and records no \
                     digest for it; a durable record with no integrity evidence is a claim \
                     nothing measured",
                    asset.name
                )));
            }
            DurabilityTier::Excluded => {
                return Err(KataError::Storage(format!(
                    "restore: manifest records asset {:?} as excluded, and an excluded asset is \
                     not captured at all",
                    asset.name
                )));
            }
            _ => {}
        }
        if let Some(digest) = &asset.digest
            && (digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(KataError::Storage(format!(
                "restore: manifest digest for asset {:?} is not 64 lowercase hex characters",
                asset.name
            )));
        }
    }
    // The capture's own order proof, re-checked here because the manifest is
    // operator-readable JSON and this is the restore-side reader
    // `backup_data_dir_with_consistency_token`'s doc promised.
    if let Some(order) = &manifest.capture_order {
        order.verify()?;
    }
    Ok(())
}

/// Refuse a record whose claimed tier is WEAKER than the one the durable-asset
/// map derives for that asset.
///
/// Equal is fine and STRONGER is fine — see [`restore_tier`] for why the map is
/// a floor rather than an equality. Only the downgrade direction is an attack,
/// because only the downgrade direction removes a check.
fn refuse_weakened_tier(record: &CapturedAsset) -> KataResult<()> {
    let derived = derived_tier(&record.name);
    if record.tier.strength() < derived.strength() {
        return Err(KataError::Storage(format!(
            "restore: manifest claims asset {:?} was captured at tier {:?}, and the durable-asset \
             map derives {derived:?} for it from its `AssetAuthority`; a manifest-supplied tier is \
             not authority for the tier a restore enforces, and accepting the weaker claim would \
             drop the integrity check the stronger one requires",
            record.name, record.tier
        )));
    }
    Ok(())
}

/// The manifest's durability record for `name`, if it has one.
fn asset_record<'a>(manifest: &'a BackupManifest, name: &str) -> Option<&'a CapturedAsset> {
    manifest.assets.iter().find(|asset| asset.name == name)
}

/// The tier `name` will be RESTORED at.
///
/// # A manifest-supplied tier is an ATTACKER-supplied tier
///
/// Returning `asset.tier` — the manifest's own claim — would make the tier the
/// artifact's rather than the map's at restore time. The manifest is
/// unauthenticated JSON, so hand-editing one authoritative record to
/// `"tier": "best_effort", "digest": null` would satisfy the per-asset coverage
/// rule, satisfy the *"a `Durable` record must carry a digest"* rule vacuously,
/// leave [`verify_captured_digest`] with nothing to compare against, and restore
/// tampered bytes in silence — a one-field edit around the whole integrity
/// contract.
///
/// The tier is derivable from the durable-asset map at restore time
/// ([`derived_tier`]), so it is DERIVED and never read as authority. A weaker
/// claim than the derivation is refused outright, by name, in
/// [`validate_asset_records`] — inside [`read_manifest`], so it fails before any
/// lease, any staging, and any target mutation. A STRONGER claim is honoured
/// rather than clamped down: the map is a FLOOR, and an artifact that paid for
/// more integrity than its row requires must not have that evidence discarded.
///
/// # An asset with no record falls to `BestEffort`
///
/// With no record there is nothing to compare and the floor cannot be applied
/// without inventing a claim. `BestEffort` is the honest reading: without a
/// digest there is nothing to verify, and the atomic activation a `Durable`
/// restore performs would advertise a crash-safety property over bytes whose
/// integrity is unknown. [`validate_asset_records`] refuses a manifest that
/// lists a database or bundles a config without a record, so a manifest that
/// passed [`read_manifest`] does not reach this arm for either.
fn restore_tier(manifest: &BackupManifest, name: &str) -> DurabilityTier {
    asset_record(manifest, name).map_or(DurabilityTier::BestEffort, |asset| {
        asset.tier.at_least(derived_tier(name))
    })
}

/// Re-digest a PROVEN handle and refuse a mismatch against the manifest record.
///
/// `quick_check` alone cannot perform this check AT ALL: it proves a database is structurally a
/// database, and says nothing about whether
/// its rows are the ones that were captured. A byte flipped inside a page
/// payload leaves a perfectly valid SQLite file.
///
/// # It takes no `&Path`
///
/// A path form — a bare `File::open` — would let the artifact's own integrity
/// gate read outside the artifact: for the two ARTIFACT call sites that path is
/// inside a directory an attacker may have prepared. See [`digest_reader`].
/// Every caller opens through the [`ProvenDir`] for the position's parent,
/// so the bytes hashed are the bytes of a descriptor obtained one component at a
/// time and `display` is rendered, never resolved.
fn verify_captured_digest(
    file: impl Read,
    display: &Path,
    asset: &CapturedAsset,
) -> KataResult<()> {
    let Some(expected) = &asset.digest else {
        return Ok(());
    };
    let actual = hex_digest(&digest_reader(file, display)?);
    if &actual != expected {
        return Err(KataError::Storage(format!(
            "restore: captured {} digest {actual} does not match the manifest digest {expected} \
             (corrupt or tampered artifact)",
            asset.name
        )));
    }
    Ok(())
}

/// Perform a bounded, read-only validation of a restore artifact.
///
/// This is suitable for callers that need to reject an invalid artifact
/// before acquiring lifecycle or data-directory authority. It validates the
/// manifest, source topology, sidecar absence, file-size bounds, and SQLite
/// integrity without creating staging or target paths. When the bundled config
/// will be restored, `restore_config_to` must be its eventual absolute target
/// and `expected_data_dir` its absolute database destination. The exact source
/// bytes are semantically validated in that path context and must select the
/// same normalized data directory. Requesting config restoration from an
/// artifact that has no bundled config is rejected.
/// [`restore_data_dir`] repeats the relevant checks on staged bytes under
/// authority; this method is an early fail-closed inspection, not a token that
/// suppresses revalidation.
///
/// # Read-only means read-only, and it does NOT check for writability
///
/// A restore never writes into `backup_dir` (the journal lives under the
/// target; see [`restore_journal_path`]), so there is no writability
/// requirement to check, and refusing a non-writable artifact up front would
/// only forbid a read-only artifact that restores correctly.
///
/// # Errors
///
/// Returns `KataError::Config` for an incoherent config restore,
/// `KataError::Storage` for unsafe, missing, oversized, non-regular, or corrupt
/// artifact content, and `KataError::Serialization` for a malformed manifest.
pub fn preflight_restore_artifact(
    backup_dir: &Path,
    expected_data_dir: &Path,
    restore_config_to: Option<&Path>,
) -> KataResult<BackupManifest> {
    let manifest = read_manifest(backup_dir)?;
    preflight_restore_manifest(backup_dir, expected_data_dir, restore_config_to, manifest)
}

fn preflight_restore_manifest(
    backup_dir: &Path,
    expected_data_dir: &Path,
    restore_config_to: Option<&Path>,
    manifest: BackupManifest,
) -> KataResult<BackupManifest> {
    validate_config_restore_request(&manifest, restore_config_to)?;
    let stores_dir = backup_dir.join(STORES_SUBDIR);
    validate_stores_directory(&stores_dir)?;
    // The operator typed `<backup_dir>`, so every component of it is RESOLVED;
    // `stores` and the bundled config below it are the artifact's own layout and
    // are `openat`ed with `O_NOFOLLOW`. Held for the whole probe so both digest
    // positions below reach their bytes through a proven descriptor rather than
    // through a path a prepared artifact can redirect.
    let artifact_root = ProvenDir::open_operator_root(
        backup_dir,
        "restore",
        "a restore's artifact directory must be a directory",
    )?;
    let stores_root = artifact_root.open_child(
        OsStr::new(STORES_SUBDIR),
        "restore",
        "every database this restore digests lives under it, and a restore may not digest them \
         through a link out of the artifact",
    )?;
    let mut total_database_bytes = 0_u64;
    for name in &manifest.databases {
        reject_ambient_sidecars(&stores_dir, name)?;
        let source = stores_dir.join(name);
        let metadata = regular_source_metadata(&source, MAX_DATABASE_BYTES, "database")?;
        total_database_bytes = total_database_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| {
                KataError::Storage("restore: total database size overflowed".to_string())
            })?;
        validate_total_database_bytes(total_database_bytes)?;
        validate_sqlite(&source)?;
        // The digest, on the ARTIFACT bytes, in the read-only probe — so a
        // tampered artifact is refused before a lifecycle lease, a discovery
        // lease or a data-directory identity can be materialized for it.
        if let Some(asset) = asset_record(&manifest, name) {
            let (file, _) = stores_root.open_source_file(
                OsStr::new(name.as_str()),
                MAX_DATABASE_BYTES,
                "restore",
                "database",
            )?;
            verify_captured_digest(file, &source, asset)?;
        }
        let after = regular_source_metadata(&source, MAX_DATABASE_BYTES, "database")?;
        if !same_file_snapshot(&metadata, &after) {
            return Err(KataError::Storage(format!(
                "restore: database source {} changed during preflight",
                source.display()
            )));
        }
    }
    if manifest.config_included {
        let bundled = backup_dir.join(CONFIG_COPY_NAME);
        // BEFORE the semantic validation, matching `preflight_and_stage_restore`.
        // The order is the operator-facing part: a bundled config that fails to
        // parse can only have been SUBSTITUTED (capture refuses to bundle one it
        // could not load), so "this artifact was modified since capture" is the
        // true diagnosis and `failed to parse` is the misleading one — it reads
        // as a complaint about the operator's own config.
        if let Some(asset) = asset_record(&manifest, CONFIG_COPY_NAME) {
            // Through the proven root, never a bare `File::open` on
            // `<artifact>/kata.toml`: that would follow a link out of the
            // artifact and could be SATISFIED by what it found, and a
            // reader-less FIFO there would hang `kata restore` forever in its
            // first gate. See `digest_reader`.
            let (file, _) = artifact_root.open_source_file(
                OsStr::new(CONFIG_COPY_NAME),
                crate::MAX_CONFIG_FILE_BYTES,
                "restore",
                "bundled config",
            )?;
            verify_captured_digest(file, &bundled, asset)?;
        }
        validate_bundled_config(&bundled, expected_data_dir, restore_config_to)?;
    }
    // Every captured tree member, digested in the artifact, in the probe that
    // runs before any lease is taken — so a tampered CAS object is refused by
    // name before a lifecycle lease, a discovery lease, or a data-directory
    // identity exists for it.
    verify_captured_tree_sources(backup_dir, &manifest)?;
    Ok(manifest)
}

/// A private, same-owner staging tree. Dropping it is best-effort cleanup;
/// none of its paths are restore authority.
struct RestoreStage {
    root: PathBuf,
}

impl RestoreStage {
    fn create() -> KataResult<Self> {
        for _ in 0..64 {
            let nonce = RESTORE_STAGE_NONCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("kata-restore-stage-{}-{nonce}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(&root) {
                Ok(()) => {
                    let stage = Self { root };
                    std::fs::create_dir(stage.stores_dir()).map_err(|e| {
                        KataError::Storage(format!(
                            "restore: create staging stores directory failed: {e}"
                        ))
                    })?;
                    return Ok(stage);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(KataError::Storage(format!(
                        "restore: create private staging directory failed: {e}"
                    )));
                }
            }
        }
        Err(KataError::Storage(
            "restore: could not allocate a unique private staging directory".to_string(),
        ))
    }

    fn stores_dir(&self) -> PathBuf {
        self.root.join(STORES_SUBDIR)
    }
}

impl Drop for RestoreStage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn preflight_and_stage_restore(
    backup_dir: &Path,
    expected_data_dir: &Path,
    restore_config_to: Option<&Path>,
    manifest: &BackupManifest,
) -> KataResult<RestoreStage> {
    validate_config_restore_request(manifest, restore_config_to)?;
    let stores_dir = backup_dir.join(STORES_SUBDIR);
    validate_stores_directory(&stores_dir)?;

    let stage = RestoreStage::create()?;
    let stage_stores = stage.stores_dir();
    // `<tmpdir>` is the operator's (`TMPDIR`, `/tmp`, both commonly links);
    // `<stage>` and `stores` under it are this process's own, made moments ago
    // at `0700` with a fresh nonce, and are bound with `O_NOFOLLOW`. The digests
    // below read through these descriptors rather than re-joining the paths.
    let stage_root = ProvenDir::open(
        &stage.root,
        "restore",
        "a restore's private staging directory may not be a link to somewhere else",
    )?;
    let stage_stores_root = stage_root.open_child(
        OsStr::new(STORES_SUBDIR),
        "restore",
        "a restore's private staging stores directory may not be a link to somewhere else",
    )?;
    let mut total_database_bytes = 0_u64;
    for name in &manifest.databases {
        reject_ambient_sidecars(&stores_dir, name)?;
        let src = stores_dir.join(name);
        let dst = stage_stores.join(name);
        let bytes = stage_regular_file(&src, &dst, MAX_DATABASE_BYTES, "database")?;
        reject_ambient_sidecars(&stores_dir, name)?;
        total_database_bytes = total_database_bytes.checked_add(bytes).ok_or_else(|| {
            KataError::Storage("restore: total database size overflowed".to_string())
        })?;
        validate_total_database_bytes(total_database_bytes)?;
        validate_sqlite(&dst)?;
        // On the STAGED bytes, not the artifact's: these are the exact bytes
        // that will be activated, so this is what proves the thing that lands at
        // the target is the thing that was captured. The read-only preflight
        // digests the artifact instead, and neither is a token for the other.
        if let Some(asset) = asset_record(manifest, name) {
            let (file, _) = stage_stores_root.open_source_file(
                OsStr::new(name.as_str()),
                MAX_DATABASE_BYTES,
                "restore",
                "staged database",
            )?;
            verify_captured_digest(file, &dst, asset)?;
        }
    }
    validate_stores_directory(&stores_dir)?;

    if manifest.config_included {
        stage_regular_file(
            &backup_dir.join(CONFIG_COPY_NAME),
            &stage.root.join(CONFIG_COPY_NAME),
            crate::MAX_CONFIG_FILE_BYTES,
            "config",
        )?;
        if let Some(asset) = asset_record(manifest, CONFIG_COPY_NAME) {
            let (file, _) = stage_root.open_source_file(
                OsStr::new(CONFIG_COPY_NAME),
                crate::MAX_CONFIG_FILE_BYTES,
                "restore",
                "staged config",
            )?;
            verify_captured_digest(file, &stage.root.join(CONFIG_COPY_NAME), asset)?;
        }
        validate_bundled_config(
            &stage.root.join(CONFIG_COPY_NAME),
            expected_data_dir,
            restore_config_to,
        )?;
    }

    // Trees are verified IN PLACE rather than staged into `RestoreStage`.
    //
    // Staging exists so a database's bytes are proven readable and intact
    // before the target is touched, and it pays for that with one full extra
    // copy. For a CAS tree that copy is the whole asset — potentially the
    // largest thing in the artifact — and it buys strictly less than it does
    // for a database: `activate_captured_tree` hashes each member as it streams
    // it to the target and refuses before the rename, so the bytes that land are
    // proven regardless. What staging WOULD buy is the ordering property, and
    // this read-only pass buys that directly.
    verify_captured_tree_sources(backup_dir, manifest)?;

    Ok(stage)
}

/// What is at a path that this module is about to read a directory from or write
/// a directory into.
///
/// # ONE predicate, because the rule was spelled three times and the fourth site forgot it
///
/// Three call sites carried their own hand-written `symlink_metadata` +
/// `is_symlink() || !is_dir()` block with its own message:
/// [`discover_captured_trees`] for `<data_dir>/<tree>`,
/// [`validate_stores_directory`] for `<artifact>/stores`, and
/// [`verify_captured_tree_sources`] for `<artifact>/trees`. The capture's
/// DESTINATION root, `<artifact>/trees/<tree>`, had a bare `create_dir_all` —
/// which returns `Ok` for a symlink that resolves to a directory. A capture into
/// an artifact whose `trees/cas` was a symlink therefore copied, fsynced and
/// renamed every member THROUGH it and published a manifest claiming `cas` with
/// a full entry list and the right byte total, while the bytes sat outside the
/// directory an operator archives, ships to the recovery host, and restores
/// from. Nothing was forged and no manifest was edited; the artifact simply was
/// not self-contained, and said nothing about it.
///
/// A rule written out n times is a rule the (n+1)th site forgets, and this is
/// the (n+1)th site. The predicate is IDENTICAL at every one of them — *a
/// symlink at the final component is refused, never followed* — and only two
/// things vary: whether ABSENT is an admissible answer, and the sentence saying
/// why this caller needs a real directory. Those are the two arities and the
/// `requirement` parameter below, so a fifth site is a call rather than a
/// remembered rule.
///
/// The operator-named endpoints are deliberately NOT routed through this:
/// `restore_data_dir`'s target and `backup_data_dir`'s source are paths the
/// operator typed, and the source is instead CANONICALIZED once so that every
/// later open resolves the same physical directory. What this guards is the
/// artifact's own internal layout, which is this module's to lay out.
///
/// # This predicate lstats the FINAL COMPONENT ONLY
///
/// The sentence here read *"where no component may be a link to somewhere
/// else"*, and [`directory_state`] has never checked more than the last one. The
/// two agree only because of a fact about the current layout rather than about
/// this function: `cas` is the sole [`crate::durable_assets::CaptureRule::Tree`]
/// row this binary restores, its members are depth-2 (`<shard>/<hex>`), and this
/// module creates every intermediate level top-down through
/// [`create_real_directory`] — `<artifact>`, `stores/`, `trees/`, `trees/<name>`,
/// `trees/<name>/<shard>` — so each component IS checked, one call at a time, by
/// the caller that creates it. The sentence is narrowed to what the predicate
/// does, and the layout property is stated as the caller obligation it is.
///
/// # Nested tree members go through [`ProvenDir`], not this predicate
///
/// [`walk_tree_entries`] admits [`MAX_TREE_PATH_COMPONENTS`] levels, so a
/// SOURCE `cas/` holding `aa/bb/member` is an input the capture accepts. A
/// predicate that guards only `dst.parent()` leaves `aa` to be resolved by every
/// syscall and checked by none, and only [`verify_member_address`] has anything
/// to say about the shape — AFTER the bytes are written. Measured against that
/// form: a capture created a directory outside the artifact, wrote 300,000
/// bytes of an authoritative member onto an inode outside it, and truncated then
/// unlinked the file that was already there. See [`ProvenDir`].
///
/// Two mechanisms close it. [`ProvenDir`] is the `openat(2)` walk
/// from an `O_NOFOLLOW|O_DIRECTORY` handle — which is what also closes the TOCTOU
/// window noted on [`create_real_directory`] — and
/// [`verify_member_path_shape`] refuses a member path the addressing rule cannot
/// produce before the parent is created. Either alone closes the escape; they are independent on
/// purpose, because a
/// [`crate::durable_assets::TreeMemberAddressing::PathOpaque`] row has no shape
/// to check (its member paths are whatever the source directory holds) and is
/// therefore carried entirely by the walk.
///
/// **What still routes through this predicate**, and why it is still here: the
/// non-tree DIRECTORY positions — `<artifact>/stores`, `<artifact>/trees` on the
/// CAPTURE side, the restore journal's directory, and the source-side roots
/// [`discover_captured_trees`] validates. Each is a single component under a
/// prefix this module or the operator already owns, with no member path beneath
/// it, so the final-component predicate says everything there is to say. The
/// tree positions do not use it.
///
/// Intermediate components are unresolvable rather than checked on the READ
/// sides too: the restore-side `trees` / `trees/<tree>` positions are
/// [`ProvenDir::open_child`], not [`require_real_directory`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryState {
    /// Nothing exists at the path.
    Absent,
    /// A real directory whose final component is not a symlink.
    Real,
}

/// [`DirectoryState`] at `path`, refusing anything that is neither.
///
/// `stage` is `"backup"` or `"restore"`; `requirement` completes "… is not a
/// real directory; `<requirement>`".
///
/// # Errors
///
/// [`KataError::Storage`] if the path cannot be inspected, or resolves to a
/// symlink or a non-directory.
fn directory_state(path: &Path, stage: &str, requirement: &str) -> KataResult<DirectoryState> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DirectoryState::Absent),
        Err(e) => {
            return Err(KataError::Storage(format!(
                "{stage}: inspect {} failed: {e}",
                path.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(KataError::Storage(format!(
            "{stage}: {} is not a real directory; {requirement}",
            path.display()
        )));
    }
    Ok(DirectoryState::Real)
}

/// [`directory_state`] for a caller that also requires the directory to EXIST.
///
/// # Errors
///
/// As [`directory_state`], plus [`KataError::Storage`] when nothing is there.
fn require_real_directory(path: &Path, stage: &str, requirement: &str) -> KataResult<()> {
    match directory_state(path, stage, requirement)? {
        DirectoryState::Real => Ok(()),
        DirectoryState::Absent => Err(KataError::Storage(format!(
            "{stage}: {} does not exist; {requirement}",
            path.display()
        ))),
    }
}

/// Create the directory at `path`, refusing whatever non-directory is already
/// there.
///
/// # `mkdir(2)` first, and only then the predicate
///
/// `create_dir_all` reports success for a symlink that resolves to a directory,
/// so a check afterwards inspects the link's TARGET, and a check before it is a
/// rule with a window in it. `mkdir(2)` never resolves the final
/// component: it returns `EEXIST` for a symlink rather than creating anything
/// through it. So the `Ok` arm below is a directory THIS call made, at the FINAL
/// COMPONENT it named, and the lstat predicate is demoted to deciding what an
/// EXISTING entry is.
///
/// **It binds the final component only.** `mkdir(2)` does not resolve its last
/// component and DOES resolve every one above it, so the parent is a PATH this
/// call walks, not a directory it holds. Whatever that path resolves to at the
/// instant of the `mkdir` is where the directory lands — which is how a symlink
/// at an intermediate component of a member's parent would put an authoritative
/// member's bytes outside the artifact. See [`ProvenDir`] for the form that has
/// no path to resolve.
///
/// **TOCTOU, stated rather than implied.** The `AlreadyExists` arm still lstats
/// and then hands the PATH to callers who open things underneath it, so a
/// same-instant swap between the two is not refused. That window is unreachable
/// for the threat this exists to stop — an obstruction PRE-PLACED in an artifact
/// directory before the run starts. Closing it needs the `openat(2)` walk
/// carrying directory file descriptors instead of paths, and that walk
/// ([`ProvenDir`]) carries every tree position; the callers left here
/// are single components under a prefix with nothing beneath them. The FILE
/// writes have no such window; see [`create_owned_file`].
///
/// A missing ANCESTOR is the one case that still falls back to `create_dir_all`,
/// and it is reachable at exactly one call site: `<out_dir>/stores`, whose parent
/// is the artifact path the OPERATOR typed and which `backup_data_dir` is
/// documented to create. That prefix is the operator-named carve-out
/// [`DirectoryState`] describes, and following a symlink inside it is required
/// rather than refused (`/tmp` and `/home` are links on real hosts). Every level
/// BELOW it is created top-down by this function.
///
/// # Errors
///
/// As [`directory_state`], plus [`KataError::Storage`] if the directory cannot
/// be created.
fn create_real_directory(path: &Path, stage: &str, requirement: &str) -> KataResult<()> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            require_real_directory(path, stage, requirement)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                KataError::Storage(format!(
                    "{stage}: {} has no parent directory to create",
                    path.display()
                ))
            })?;
            std::fs::create_dir_all(parent).map_err(|e| {
                KataError::Storage(format!(
                    "{stage}: create_dir_all({}) failed: {e}",
                    parent.display()
                ))
            })?;
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    require_real_directory(path, stage, requirement)
                }
                Err(e) => Err(KataError::Storage(format!(
                    "{stage}: create_dir({}) failed: {e}",
                    path.display()
                ))),
            }
        }
        Err(e) => Err(KataError::Storage(format!(
            "{stage}: create_dir({}) failed: {e}",
            path.display()
        ))),
    }
}

/// Every position this module TOUCHES inside the artifact, the restore stage or
/// the restore target, and what a pre-placed obstruction at each one can do.
///
/// # THE QUESTION THAT GENERATED THIS LIST, so a reader can tell what it is not
///
/// > *Every position where this module OPENS, READS, WRITES, CREATES, RENAMES,
/// > REMOVES or STATS a path inside the ARTIFACT, the restore STAGE, or the
/// > restore TARGET.*
///
/// # IT IS INDEXED BY CALL SITE, not by POSITION
///
/// A table of POSITIONS misses a SECOND COMMAND at a position it already
/// carries: `<artifact>/`[`CONFIG_COPY_NAME`] is both read
/// ([`read_regular_file_bounded`]) and digested ([`preflight_restore_artifact`]),
/// and `<data_dir>/<database>` is written, activated, and read by the resume
/// probe. A reader checking a position table finds the position listed and
/// guarded while the second call site is not.
///
/// So the index is the CALL SITE. Every path-naming call in the module maps
/// to exactly one row, and a position reached by two commands gets two rows.
/// Mechanically:
///
/// ```text
/// # pass 1 — the raw calls (62 outside `mod tests`)
/// $ rg -n 'File::(open|create)|OpenOptions|std::fs::(read|write|copy|rename|remove_file|remove_dir_all|create_dir|create_dir_all|symlink_metadata|metadata|read_dir)|DirBuilder|rustix::fs::(openat|open|mkdirat|renameat|unlinkat)|\.exists\(\)|Connection::open' \
///      crates/core/src/store/backup.rs
///
/// # pass 2 — calls to this module's OWN path-naming helpers (115), because a
/// # helper is a call site's command too, and pass 1 alone attributes every
/// # position reached through `ProvenDir` to `ProvenDir` instead of the caller
/// $ rg -n '\b(create_real_directory|create_owned_file|claim_owned_path|remove_file_if_present|read_regular_file_bounded|read_bounded_handle|stage_regular_file|regular_source_metadata|validate_sqlite|validate_sqlite_header|durable_publish|fsync_dir|digest_reader|activate_staged_file|copy_staged_file|open_child_if_present|open_source_file|open_regular|rename_within|open_member_parents|require_real_directory|directory_state|reject_ambient_sidecars|validate_stores_directory|discover_databases|walk_tree_entries|vacuum_into|verify_captured_digest|ProvenDir::open)' \
///      crates/core/src/store/backup.rs
/// ```
///
/// **Pass 2 is the one that matters and is the one an eyeball derivation skips.**
/// Pass 1 sees `rustix::fs::openat` eight times, all of them inside `ProvenDir`,
/// and says nothing about WHICH positions reach them. The 115 hits of pass 2 are
/// what map a function to a position; the tables below are grouped by the
/// FUNCTION that makes the call, in source order, so a reader can walk the two
/// greps against the tables and find a row for every hit.
///
/// The `Command` column is what the position is actually reached by, verified
/// against the code rather than remembered: a row that names the wrong command
/// describes a guard the call site does not run.
///
/// # DIRECTORIES
///
/// | Call site | Position | Command | Guarded by |
/// |---|---|---|---|
/// | [`backup_data_dir_with_hooks`] | `<artifact>/stores` | `mkdir` | [`create_real_directory`] |
/// | [`backup_data_dir_with_hooks`] | `<artifact>/trees` | `mkdir` | [`create_real_directory`] |
/// | [`backup_data_dir_with_hooks`] | `<artifact>/stores`, `<artifact>/trees` (durability) | `open` + `fsync` | [`fsync_dir`]; read-only |
/// | [`capture_database`] | `<artifact>/stores` (digest + fsync of the tmp) | `open` (`O_NOFOLLOW`) | [`ProvenDir::open`] |
/// | [`discover_captured_trees`] | `<data_dir>/<tree>` (capture source) | `lstat` | [`directory_state`] |
/// | [`walk_tree_entries`] | `<data_dir>/<tree>/…` (capture source, below the root) | `read_dir` + `lstat` | itself; REFUSES a symlink at any level |
/// | [`capture_tree`] | `<artifact>/trees` | `open` (`O_NOFOLLOW`) | [`ProvenDir::open`] — final component ours, prefix the operator's |
/// | [`capture_tree`] | `<artifact>/trees/<tree>` | `mkdirat`+`openat` | [`ProvenDir::child`] |
/// | [`capture_tree`] | `<artifact>/trees/<tree>/<shard>` | `mkdirat`+`openat` | [`open_member_parents`] under [`ParentWalk::Create`] |
/// | [`TreeCapture::omitted_after_writing`] | `<artifact>/trees/<tree>` (removal of an omitted tree) | `remove_dir_all` | resolves no final component; best-effort by design |
/// | [`preflight_restore_artifact`] | `<artifact>` (read) | `open` (`O_DIRECTORY`, operator-typed) | [`ProvenDir::open_operator_root`] |
/// | [`preflight_restore_artifact`] | `<artifact>/stores` (digest walk) | `openat` | [`ProvenDir::open_child`] |
/// | [`validate_stores_directory`] | `<artifact>/stores` (inventory) | `lstat` + `read_dir` | itself; two call sites in [`preflight_and_stage_restore`], one in [`preflight_restore_artifact`] |
/// | [`RestoreStage::create`] | `<stage>` (private restore stage root) | `mkdir` with a fresh nonce | refuses an existing entry of ANY type by construction, and retries |
/// | [`RestoreStage::create`] | `<stage>/stores` | `mkdir` | a fresh `0700` directory this process just made, so `mkdir(2)` on a single component under it is the whole check |
/// | [`RestoreStage`]`::drop` | `<stage>` (drop) | `remove_dir_all` | resolves no final component; best-effort cleanup |
/// | [`preflight_and_stage_restore`] | `<stage>` (digest walk) | `open` (`O_NOFOLLOW`) | [`ProvenDir::open`] |
/// | [`preflight_and_stage_restore`] | `<stage>/stores` (digest walk) | `openat` | [`ProvenDir::open_child`] |
/// | [`verify_captured_tree_sources`] | `<artifact>` (read) | `open` (`O_DIRECTORY`, operator-typed) | [`ProvenDir::open_operator_root`] |
/// | [`verify_captured_tree_sources`] | `<artifact>/trees`, `<artifact>/trees/<tree>` (read) | `openat` | [`ProvenDir::open_child`] |
/// | [`verify_captured_tree_sources`] | `<artifact>/trees/<tree>/<shard>` (read) | `openat` | [`open_member_parents`] under [`ParentWalk::Existing`] |
/// | [`activate_captured_tree`] | `<artifact>` (read) | `open` (`O_DIRECTORY`, operator-typed) | [`ProvenDir::open_operator_root`] |
/// | [`activate_captured_tree`] | `<artifact>/trees`, `<artifact>/trees/<tree>` (read) | `openat` | [`ProvenDir::open_child`] |
/// | [`activate_captured_tree`] | `<artifact>/trees/<tree>/<shard>` (read) | `openat` | [`open_member_parents`] under [`ParentWalk::Existing`] |
/// | [`activate_captured_tree`] | `<data_dir>` (restore target) | `open` (`O_DIRECTORY`, operator-typed) | [`ProvenDir::open_operator_root`] |
/// | [`activate_captured_tree`] | `<data_dir>/<tree>` (restore target) | `mkdirat`+`openat` | [`ProvenDir::child`] |
/// | [`activate_captured_tree`] | `<data_dir>/<tree>/<shard>` (restore target) | `mkdirat`+`openat` | [`open_member_parents`] under [`ParentWalk::Create`] |
/// | [`activate_captured_tree`] | `<data_dir>`, `<data_dir>/<tree>`, each `<shard>` (durability) | `fsync` on the PROVEN descriptor | [`ProvenDir::sync`] |
/// | [`restore_data_dir_with_hooks`] | `<data_dir>` (create) | `create_dir_all` | resolves every component; operator-typed target ([`DirectoryState`]'s carve-out) |
/// | [`restore_data_dir_with_hooks`] | `<data_dir>` (resume probe root) | `open` (`O_DIRECTORY`, operator-typed) | [`ProvenDir::open_operator_root`] |
/// | [`restore_data_dir_with_hooks`] | `<config parent>` (create) | `create_dir_all` | operator-typed destination |
/// | [`load_or_reset_restore_journal`] | `<data_dir>` (journal read root) | `open` (`O_DIRECTORY`, operator-typed) | [`ProvenDir::open_operator_root`] |
/// | [`load_or_reset_restore_journal`] | `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`] (read) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_child_if_present`] — absence is "no journal", a link is a refusal |
/// | [`record_activation`] | `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`] (create) | `mkdir` | [`create_real_directory`] |
/// | [`record_activation`] | `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`] (durability) | `open` + `fsync` | [`fsync_dir`] via [`durable_publish`] |
/// | [`clear_restore_journal`] | `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`] (durability) | `open` + `fsync` | [`fsync_dir`] |
/// | [`activate_staged_file`] | `<data_dir>` (durability) | `open` + `fsync` | [`fsync_dir`] |
/// | [`durable_publish`] | `<artifact>`, `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`] (durability) | `open` + `fsync` | [`fsync_dir`] |
///
/// The `mkdirat`+`openat` and `openat` rows are the tree positions. A
/// path-based `mkdir` or `open` binds its FINAL component and RESOLVES
/// everything above it, which is why a symlink at an intermediate component of a
/// member's parent reached outside the artifact on the write sides and read from
/// outside it on the read sides. See [`ProvenDir`].
///
/// `<stage>/stores` is a bare `std::fs::create_dir` in [`RestoreStage::create`]:
/// exactly the kind of position a hand-maintained table loses, so it has a row.
///
/// # FILES
///
/// | Call site | Position | Command | Guarded by |
/// |---|---|---|---|
/// | [`capture_tree`] | `<data_dir>/<tree>/…/<member>` (capture source, read) | `lstat` then `open` | the walk above; the same-path race is the `NotFound`-continue arm |
/// | [`capture_tree`] | `<data_dir>/<tree>/…/<member>` (capture source, race re-probe) | `exists` | resolves; it only decides `continue` vs. report, never what is written. DECLARED below |
/// | [`copy_hashing`] | `<artifact>/trees/<tree>/<shard>/<member>.capture-tmp` | `openat` (`O_NOFOLLOW`) | [`ProvenDir::create_owned_file`] |
/// | [`capture_tree`] | `<artifact>/trees/<tree>/<shard>/<member>` (publish) | `renameat` | [`ProvenDir::rename_within`] — neither operand's final component is resolved |
/// | [`capture_tree`] | `<artifact>/trees/<tree>/<shard>/<member>.capture-tmp` (cleanup, 5 sites) | `unlinkat` | [`ProvenDir::remove_file`] |
/// | [`verify_member_address`] | `<artifact>/trees/<tree>/<shard>/<member>` (address derivation) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_source_file`]; a NARROWING, not a closed hole — see its doc |
/// | [`vacuum_into`] | `<artifact>/stores/<database>.capture-tmp` (claim) | `open` (`O_NOFOLLOW`) then `unlink` | [`claim_owned_path`] |
/// | [`vacuum_into`] | `<artifact>/stores/<database>.capture-tmp` (SQLite's write) | SQLite's own `open` | [`claim_owned_path`] — see below |
/// | [`vacuum_into`] | `<artifact>/stores/<database>.capture-tmp-journal` | SQLite's own `open` | **not kata's** — see below |
/// | [`capture_database`] | `<artifact>/stores/<database>.capture-tmp` (size + digest + fsync) | `openat` (`O_NOFOLLOW`), then `fstat`/`read`/`fsync` on THAT descriptor | [`ProvenDir::open_source_file`] + [`digest_reader`] |
/// | [`validate_sqlite_header`] | `<artifact>/stores/<database>.capture-tmp` (SQLite header probe) | `lstat` then `open` | [`regular_source_metadata`]. DECLARED below |
/// | [`capture_database`] | `<artifact>/stores/<database>.capture-tmp` -> `<artifact>/stores/<database>` (publish) | `rename` | destination's final component is not resolved, so an obstruction there is DESTROYED rather than followed |
/// | [`capture_database`] | `<artifact>/stores/<database>.capture-tmp` (cleanup, 3 sites) | `remove_file` | resolves no final component |
/// | [`durable_publish`] | `<artifact>/`[`MANIFEST_NAME`]`.restore-tmp` / [`CONFIG_COPY_NAME`]`.restore-tmp` | `open` (`O_NOFOLLOW`) | [`create_owned_file`] |
/// | [`durable_publish`] | `<artifact>/`[`MANIFEST_NAME`] / [`CONFIG_COPY_NAME`] (publish) | `rename` | as the `stores` publish row |
/// | [`durable_publish`] | the same `.restore-tmp` names (cleanup, 2 sites) | `remove_file` | resolves no final component |
/// | [`read_manifest`] | `<artifact>/`[`MANIFEST_NAME`] (content) | `lstat` then `open` | [`read_regular_file_bounded`] via [`regular_source_metadata`]. DECLARED below |
/// | [`validate_bundled_config`] | `<artifact>/`[`CONFIG_COPY_NAME`] or `<stage>/`[`CONFIG_COPY_NAME`] (content) | `lstat` then `open` | same. DECLARED below |
/// | [`preflight_restore_artifact`] | `<artifact>/stores/<database>` (size, twice: before and after) | `lstat` | [`regular_source_metadata`] + [`same_file_snapshot`] |
/// | [`preflight_restore_artifact`] | `<artifact>/stores/<database>` (SQLite probe) | `lstat` then `open` | [`validate_sqlite_header`]. DECLARED below |
/// | [`preflight_restore_artifact`] | `<artifact>/stores/<database>` (DIGEST) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_source_file`] + [`verify_captured_digest`] |
/// | [`preflight_restore_artifact`] | `<artifact>/`[`CONFIG_COPY_NAME`] (DIGEST) | `openat` (`O_NOFOLLOW`) | same; never a bare `File::open` — see [`digest_reader`] |
/// | [`reject_ambient_sidecars`] | `<artifact>/stores/<database><sidecar>` (stat) | `lstat` | itself; refuses `-wal`/`-shm`/`-journal` beside a captured database |
/// | [`stage_regular_file`] | `<artifact>/stores/<database>` / `<artifact>/`[`CONFIG_COPY_NAME`] (read) | `lstat` then `open` | [`regular_source_metadata`] + [`validate_opened_source`]. DECLARED below |
/// | [`stage_regular_file`] | `<stage>/stores/<database>` / `<stage>/`[`CONFIG_COPY_NAME`] (write) | `open` (`create_new`) | into a private `0700` directory |
/// | [`preflight_and_stage_restore`] | `<stage>/stores/<database>` / `<stage>/`[`CONFIG_COPY_NAME`] (DIGEST) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_source_file`] + [`verify_captured_digest`] |
/// | [`verify_captured_tree_sources`] | `<artifact>/trees/<tree>/<shard>/<member>` (read + digest) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_source_file`] + [`digest_reader`] |
/// | [`activate_captured_tree`] | `<data_dir>/<tree>/<shard>/<member>` (resume probe, read) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_regular`] + [`digest_reader`] |
/// | [`activate_captured_tree`] | `<artifact>/trees/<tree>/<shard>/<member>` (copy source) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_source_file`] |
/// | [`copy_hashing`] | `<data_dir>/<tree>/<shard>/<member>.restore-tmp` | `openat` (`O_NOFOLLOW`) | [`ProvenDir::create_owned_file`] |
/// | [`activate_captured_tree`] | `<data_dir>/<tree>/<shard>/<member>.restore-tmp` -> `<member>` (activate) | `renameat` | [`ProvenDir::rename_within`] |
/// | [`activate_captured_tree`] | the same `.restore-tmp` (cleanup, 5 sites) | `unlinkat` | [`ProvenDir::remove_file`] |
/// | [`journal_records_activation`] | `<data_dir>/<database>` (resume probe, read + DIGEST) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_regular`] + [`digest_reader`]; never `exists` + a bare `File::open` |
/// | [`restore_data_dir_with_hooks`] | `<data_dir>/<database><sidecar>` (removal) | `remove_file` | clearing `-wal`/`-shm` beside a replaced database; resolves no final component |
/// | [`activate_staged_file`] | `<stage>/…` (read) | `open` | inside a private `0700` directory this process created |
/// | [`activate_staged_file`] | `<data_dir>/<database>.restore-tmp` | `open` (`O_NOFOLLOW`) | [`create_owned_file`] |
/// | [`activate_staged_file`] | `<data_dir>/<database>.restore-tmp` -> `<data_dir>/<database>` (activate) | `rename` | as the publish rows |
/// | [`activate_staged_file`] | the same `.restore-tmp` (cleanup, 3 sites) | `remove_file` | resolves no final component |
/// | [`copy_staged_file`] | `<data_dir>/<database>` (cheap tier) | `remove_file` then `open` (`create_new`) | `O_CREAT\|O_EXCL` refuses symlink, hardlink and FIFO alike |
/// | [`load_or_reset_restore_journal`] | `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`]`/`[`RESTORE_JOURNAL_NAME`] (read) | `openat` (`O_NOFOLLOW`) | [`ProvenDir::open_regular`] + [`read_bounded_handle`]; bounded, never a bare `std::fs::read` |
/// | [`durable_publish`] | `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`]`/`[`RESTORE_JOURNAL_NAME`]`.restore-tmp` | `open` (`O_NOFOLLOW`) | [`create_owned_file`] |
/// | [`clear_restore_journal`] | `<data_dir>/`[`RESTORE_JOURNAL_SUBDIR`]`/`[`RESTORE_JOURNAL_NAME`] (removal) | `remove_file` | resolves no final component |
/// | [`discover_databases`] | `<data_dir>` (capture inventory) | `read_dir` | the operator's own data directory; the walk classifies, it does not open |
///
/// The obstruction each write position admits without its guard is the same
/// three every time — symlink, hardlink, FIFO — which is why the mechanism is
/// one function ([`create_owned_file`]) rather than a flag at each site, and why
/// `every_file_the_artifact_writes_refuses_a_pre_placed_obstruction` drives the
/// seven reachable staging positions against all three — including the CONFIG
/// row, which needs a bundled config to be reached at all and so is easy to
/// leave enumerated and undriven while the loop stays green.
///
/// The `rename` / `remove_file` rows are here because the QUESTION asks for
/// them, not because they need a guard: neither call resolves its final
/// component, so both are answered by the "already safe by their own command"
/// section below. Listing them is what stops the next reader concluding a
/// position is absent from the table because it is unreachable.
///
/// # DECLARED LIMITS
///
/// What the call-site derivation surfaced and the module does NOT close, each
/// with its command, what it does not protect against, and the measurement.
/// Every item below is reachable, is described rather than fixed, and says what
/// evidence would change that.
///
/// 1. **`lstat`-then-`open` survives at five call sites**, all of them on
///    `<artifact>` metadata and databases: [`read_manifest`] and
///    [`validate_bundled_config`] (via [`read_regular_file_bounded`]),
///    [`stage_regular_file`] on both source kinds, [`validate_sqlite_header`],
///    and [`preflight_restore_artifact`]'s size probes. The window is between
///    the `lstat` and the `open`, and it is NARROWED, not closed:
///    [`validate_opened_source`] re-checks `dev`/`ino`/`nlink`/type on the
///    OPENED descriptor and [`revalidate_source_after_read`] `lstat`s again
///    afterwards, so a swap is detected — but a swap to a **reader-less FIFO**
///    between the two calls still BLOCKS in `open(2)` before any of that runs,
///    because none of these carries `O_NONBLOCK`. [`ProvenDir::open_source_file`]
///    does, which is why the digest positions moved to it and these have not:
///    they need the `<artifact>/stores` parent proven at four more call sites,
///    which is a bigger change than should land unmeasured.
/// 2. **[`capture_tree`]'s SOURCE members are read by path**, under
///    [`walk_tree_entries`]'s `read_dir`+`lstat` walk rather than under a
///    descriptor. This is the operator's live data directory, not an artifact,
///    and the walk that produced the list refuses a symlink at every level — but
///    the `lstat` and the `File::open` are two resolutions of the same path, and
///    the `if !src.exists()` race re-probe after a failed copy is a third.
///    Nothing an attacker places there is more authoritative than the data
///    directory they already own, which is why this ranks below (1).
/// 3. **The descriptor reserve does not model the CALLER.**
///    [`TREE_MEMBER_DIRECTORY_RESERVE`] is 32, derived from a measured walk
///    overhead of 8 (capture) / 9 (preflight) / 10 (restore) descriptors in a
///    test process holding four. An in-process `kata serve` holds a SQLite pool,
///    a tokio reactor and every worker's pipes, and this constant sees none of
///    them: a caller holding more than `soft_limit - budget - 32` descriptors
///    can still reach `EMFILE` inside the walk. Raising the reserve is what
///    REFUSED a legitimate 222-shard capture at `ulimit -n 282` whose real peak
///    is 230, so the number is not moved without a measurement of a real
///    in-process caller.
/// 4. **[`RestoreStage`]'s own layout is `mkdir`/`create_new` by path**, not
///    `mkdirat`. The stage root is a fresh `0700` directory with a per-process
///    nonce and the parent is the operator's `TMPDIR`, so the exposure is a
///    same-uid race inside a directory this process just created; the digests
///    over the staged bytes DO go through [`ProvenDir`] now.
///
/// # Why this list is in the code
///
/// Guarding every DIRECTORY position is not enough: an artifact escapes through
/// a FILE too. A dangling symlink at
/// `<artifact>/trees/cas/<shard>/<hex>.capture-tmp` followed by a path-based
/// `File::create` writes the member somewhere else, and `rename(2)` — which does
/// not follow symlinks — then moves THE LINK into the artifact. Measured against
/// that form, the capture returned `Ok` with an [`CapturedTree::entry_digest`]
/// identical to the honest capture of the same fixture. No check over the
/// artifact can distinguish them, because as far as the manifest is concerned
/// nothing is wrong; the bytes are simply somewhere else.
///
/// A list of positions that lives only in someone's head grows a hole the
/// moment a new kind of position (a staging file, not a directory) appears. The
/// enumeration is written down here, derived from `grep`ing the module for every
/// command that creates or replaces something, so the next position is added to
/// a list that exists.
///
/// The enumeration is necessary and not sufficient. Every row here is a leaf,
/// and every guard binds a leaf; the components BETWEEN the artifact root and
/// the leaf are resolved by the syscalls. The answer to those is not another
/// row — it is [`ProvenDir`], which makes the intermediate components
/// unresolvable rather than checked, on the write sides and the READ sides
/// alike.
///
/// # FILES already safe by their own command, and why each is
///
/// * `<artifact>/stores/<database>.capture-tmp` — SQLite's `VACUUM INTO`, whose `open(2)`
///   this module cannot pass flags to. [`vacuum_into`] runs [`claim_owned_path`], which is
///   this same open followed by an `unlink(2)`, so the refusal is identical and only the
///   TOCTOU differs (one `unlink`-to-`open` gap, stated there). An `if path.exists()` guard
///   would not do: it is FALSE for a dangling symlink and skips the removal at precisely
///   the input that needs it.
/// * `<artifact>/stores/<database>.capture-tmp-journal` — SQLite's rollback
///   journal for that same `VACUUM INTO`, and **the one position in the artifact
///   whose guarantee is not kata's**. Nothing in this module names the file, so
///   [`claim_owned_path`] never sees it and no flag of ours reaches it. It is
///   safe because `libsqlite3-sys` 0.39.1 vendors SQLite 3.54.1, whose
///   `unixOpen` ORs `O_NOFOLLOW` into `openFlags` for every file it opens
///   (`sqlite3.c:47326`). Measured: a dangling symlink there fails the capture
///   and writes nothing through the link
///   (`the_sqlite_journal_beside_a_staged_database_is_guarded_by_sqlite_and_not_by_kata`,
///   which also asserts the capture REACHES the position so the arm cannot pass
///   vacuously). A SQLite upgrade that dropped the flag reopens this position,
///   and that test is the only thing in this repository that would notice.
/// * `<data_dir>/<database>` and `<data_dir>/`[`CONFIG_COPY_NAME`] on the cheap
///   tier — [`copy_staged_file`] unlinks and then opens `create_new`, i.e.
///   `O_CREAT|O_EXCL`, which refuses a symlink, a hardlink and a FIFO alike.
/// * `<stage>/stores/<database>` — [`stage_regular_file`] opens `create_new` into
///   a private `0700` directory this process just made under a unique nonce.
/// * Every `rename(2)` — the destination is replaced atomically and neither
///   operand's final component is resolved, so a symlink at the target is
///   DESTROYED rather than followed. This is exactly why the staging-file escape
///   was invisible: the link moved INTO the artifact.
/// * Every `remove_file`/`remove_dir_all` — neither resolves the final component.
///
/// # Positions this module writes that are NOT part of its own layout
///
/// Listed rather than omitted, so a reader can tell "considered and out of
/// scope" from "not enumerated":
///
/// * `<data_dir>` and `<out_dir>` THEMSELVES — the roots, which the operator
///   typed. Following a link inside an operator-named prefix is REQUIRED rather
///   than refused (`/tmp` and `/home` are links on real hosts); see
///   [`DirectoryState`].
/// * `restore_config_to`'s parent directory, created by
///   [`restore_data_dir_with_hooks`]. Also operator-typed; the config file at the
///   end of it lands through [`activate_staged_file`] and is therefore covered.
///
/// # The mechanism, and why `O_NOFOLLOW` and not `create_new`
///
/// `create_new` (`O_CREAT|O_EXCL`) refuses a symlink by construction too, and it
/// would ALSO refuse every legitimate resume: `backup_data_dir` is documented
/// idempotent to one `out_dir` and [`activate_staged_file`] says in its own body
/// that refusing because a crash left a `.restore-tmp` is a restore that cannot
/// resume. `O_NOFOLLOW` constrains the final component's TYPE without
/// constraining its EXISTENCE, so residue is replaced and a link is refused.
///
/// `O_NOFOLLOW` alone is not enough, and the two extra checks are the reason this
/// is one function rather than a flag at six call sites:
///
/// * a **hardlink** is a directory entry, not a link object, so `O_NOFOLLOW`
///   admits it and the write reaches an inode named somewhere else; `st_nlink`
///   on the OPENED descriptor is what refuses it;
/// * a **FIFO** is not a symlink either, and `open(2)` for writing on one with no
///   reader BLOCKS FOREVER — an availability fault, and the worst kind, since a
///   hung `kata backup` reports nothing at all. Measured: an
///   `O_WRONLY|O_CREAT|O_TRUNC` open on a reader-less FIFO did not return inside
///   a 5s budget, while adding `O_NOFOLLOW|O_NONBLOCK` returned `ENXIO` (errno 6)
///   at once — and on a dangling symlink, `ELOOP` (errno 40). The `is_file()`
///   check turns a device node or socket into a refusal. `O_NONBLOCK` is then
///   CLEARED before the descriptor is returned: its job was the open, every
///   caller writes with `write_all` or `io::copy`, and neither retries an
///   `EAGAIN`.
///
/// All three checks are made on the FILE DESCRIPTOR the write will use, not on
/// the path, so unlike [`create_real_directory`] there is no window between the
/// check and the write.
///
/// **`O_NOFOLLOW` binds the final component and nothing above it**, which is the
/// half this section did not say. For a leaf directly under a directory this
/// module owns that is the whole story; for a member at
/// `<shard>/<hex>.capture-tmp` it is not, because `<shard>` sits between the
/// proven root and the leaf and `open(2)` resolves it. That is why the tree
/// positions go through [`ProvenDir::create_owned_file`], whose `openat(2)` takes
/// a SINGLE COMPONENT relative to a descriptor — leaving no intermediate
/// component to resolve — and re-uses [`own_opened_file`] so the three checks
/// and the post-check truncation are the same code, not a second copy of the
/// rule.
///
/// **`O_TRUNC` is deliberately NOT among the flags**: `open(2)` applies `O_TRUNC`
/// before returning, so truncating at open would refuse the hardlink arm with
/// the right message and ALREADY have emptied the inode on the other end of it.
/// The refusal would destroy a file outside the artifact. The truncation
/// is a `set_len(0)` on the descriptor after the checks pass.
///
/// # Errors
///
/// [`KataError::Storage`] if the path resolves to anything but a regular file
/// this process owns outright, or if it cannot be created.
fn create_owned_file(path: &Path, stage: &str, requirement: &str) -> KataResult<File> {
    // NOT `.truncate(true)`. `O_TRUNC` is applied by `open(2)` itself, BEFORE any
    // check this function can make, so it would refuse a hardlink correctly and
    // have already emptied the inode on the other end of it — turning a refused
    // write into a destroyed file outside the artifact. The
    // truncation happens below, on the descriptor, once the checks have passed;
    // `ftruncate(2)` resolves no path.
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    // Off unix there is no `O_NOFOLLOW` to hand `open`, so the refusal degrades
    // from a mechanism to a PREDICATE with a check-to-open window — stated here
    // rather than left as a silent difference in guarantee between targets. The
    // `nlink`/`is_file` checks below still run on the descriptor.
    #[cfg(not(unix))]
    if let Ok(existing) = std::fs::symlink_metadata(path)
        && (existing.file_type().is_symlink() || !existing.is_file())
    {
        return Err(KataError::Storage(format!(
            "{stage}: {} is not a real regular file; {requirement}",
            path.display()
        )));
    }
    let file = options.open(path).map_err(|e| {
        KataError::Storage(format!(
            "{stage}: create {} failed: {e}; {requirement}",
            path.display()
        ))
    })?;
    own_opened_file(file, path, stage, requirement)
}

/// The three descriptor checks and the truncation, on a descriptor a caller has
/// already opened with the flags [`create_owned_file`] documents.
///
/// Split out so the `openat(2)` form ([`ProvenDir::create_owned_file`]) runs the
/// SAME checks as the path form rather than a copy of them: `path` is used for
/// rendering only — every check below is `fstat`/`fcntl`/`ftruncate` on the
/// descriptor, which resolves nothing.
///
/// # Errors
///
/// As [`create_owned_file`].
fn own_opened_file(file: File, path: &Path, stage: &str, requirement: &str) -> KataResult<File> {
    let opened = file.metadata().map_err(|e| {
        KataError::Storage(format!(
            "{stage}: inspect created {} failed: {e}",
            path.display()
        ))
    })?;
    if !opened.is_file() {
        return Err(KataError::Storage(format!(
            "{stage}: {} is not a real regular file; {requirement}",
            path.display()
        )));
    }
    #[cfg(unix)]
    if opened.nlink() != 1 {
        return Err(KataError::Storage(format!(
            "{stage}: {} is a hard link to an inode with {} names; {requirement}",
            path.display(),
            opened.nlink()
        )));
    }
    // `O_NONBLOCK` did its ENTIRE job at `open`: it is what turns a reader-less
    // FIFO from a permanent hang into `ENXIO`. The descriptor that reaches this
    // line has been proven a singly-linked regular file, so the flag now has no
    // job at all and is pure liability — `io::copy` specializes `File -> File`
    // onto `copy_file_range`/`sendfile`, and `write_all` retries only on
    // `Interrupted`, so an `EAGAIN` from either would surface as a capture or
    // restore failure with no cause an operator could act on. On Linux an 8 MiB
    // `write` and a `copy_file_range` to a non-blocking regular file both
    // complete normally (measured), so clearing the flag puts the descriptor
    // back the way the rest of the module expects to find it rather than
    // relying on leaving it on happening to be harmless.
    #[cfg(unix)]
    {
        let flags = rustix::fs::fcntl_getfl(&file).map_err(|e| {
            KataError::Storage(format!(
                "{stage}: read open flags of {} failed: {e}",
                path.display()
            ))
        })?;
        rustix::fs::fcntl_setfl(&file, flags - rustix::fs::OFlags::NONBLOCK).map_err(|e| {
            KataError::Storage(format!(
                "{stage}: clear O_NONBLOCK on {} failed: {e}",
                path.display()
            ))
        })?;
    }
    file.set_len(0).map_err(|e| {
        KataError::Storage(format!("{stage}: truncate {} failed: {e}", path.display()))
    })?;
    Ok(file)
}

/// A directory this module has PROVEN, carried as the DESCRIPTOR it proved
/// rather than as the path it opened.
///
/// # A check binds a NAME; the write reaches an INODE
///
/// A path-based guard binds the FINAL path component only, and that is not a
/// matter of how carefully it is written — it is what the syscalls do. `mkdir(2)` does not resolve
/// its last component but DOES resolve
/// every one above it; `O_NOFOLLOW` likewise constrains only the last. So a
/// symlink at an INTERMEDIATE component of a member's parent path was followed
/// by [`create_real_directory`] and by [`create_owned_file`] alike, and neither
/// of them is wrong about the component it checks.
///
/// **Measured at production bounds, against the path form.**
/// [`walk_tree_entries`] admits [`MAX_TREE_PATH_COMPONENTS`] levels, so a member
/// at `aa/bb/member` under `cas/` is an input the capture accepts. With
/// `<artifact>/trees/cas/aa` a symlink out of the artifact, the path form of
/// `kata backup` created `<escape>/bb` — a directory OUTSIDE the artifact —
/// opened the pre-existing `<escape>/bb/member.capture-tmp` through the link,
/// `set_len(0)`-ed it, wrote the full 300,000 bytes of the member onto that
/// inode, then failed [`verify_member_address`] and UNLINKED it: *a refusal
/// that destroyed a file outside the artifact*.
/// `a_symlink_inside_a_member_path_destroys_nothing_outside_the_artifact`
/// pins that this form does not. The SOURCE walk decides a member's depth, and
/// only [`verify_member_address`] — which runs after the bytes are already
/// written — has anything to say about the shape.
///
/// # A path that is never resolved cannot be redirected
///
/// So the mechanism is not a longer check: open the root once, then create and open each
/// level with `mkdirat`/`openat` RELATIVE TO THE PROVEN PARENT, and stage every
/// member with `openat` relative to a proven directory. A single-component name
/// handed to `*at(2)` has no intermediate component to redirect, and the
/// descriptor a caller writes through IS the object that was checked — so
/// unlike the lstat-then-`mkdir` predicate this replaces there is no window
/// between the check and the write. That closes the directory TOCTOU
/// [`create_real_directory`] states as residual, for the tree positions.
///
/// ## The READ sides carry it too
///
/// A read side that joins full paths is redirected the same way: with
/// `<artifact>/trees/cas/<shard>` replaced by a symlink to a directory outside
/// the artifact holding the real object, a path-joining preflight and restore
/// both report success while every authoritative CAS byte restored comes from
/// OUTSIDE the artifact (measured). So [`verify_captured_tree_sources`] and
/// [`activate_captured_tree`] read through [`Self::open_child`] (the
/// `mkdirat`-free twin of [`Self::child`]), [`ParentWalk::Existing`] and
/// [`Self::open_source_file`].
///
/// ## The heading is true of the TREE POSITIONS, and that is all it claims
///
/// The heading is a claim about a mechanism, and the mechanism reaches the
/// positions the enumeration puts it at — every tree position on both sides,
/// plus the four digest positions, the database resume probe and the restore
/// journal. It does NOT reach:
///
/// * [`capture_tree`]'s SOURCE members, read at `source_root.join(relative)`
///   under a `read_dir`-and-`lstat` walk ([`walk_tree_entries`]) rather than
///   under a descriptor. That side is the operator's live data directory, not an
///   artifact, and the walk that produced the list is the same walk that refuses
///   a symlink at every level;
/// * `<artifact>/stores/<database>` for its SIZE and its SQLite probe
///   ([`regular_source_metadata`], [`validate_sqlite_header`]), which still
///   `lstat` a path and then open it;
/// * `<artifact>/`[`MANIFEST_NAME`] and `<artifact>/`[`CONFIG_COPY_NAME`] for
///   their CONTENT ([`read_regular_file_bounded`]), same shape;
/// * every `rename`, `remove_file` and `remove_dir_all` outside the tree
///   positions, which resolve intermediate components by construction.
///
/// Each of those is stated with its residue in the module's `DECLARED LIMITS`
/// block. A heading that overclaims is worse than one that underclaims: it is
/// precisely what a reader would use to conclude an uncovered position is
/// covered.
///
/// # What it costs, measured
///
/// 20,000 members across the 256 `cas` shards, each arm run twice and
/// alternated so neither pays the cold-page tax:
///
/// * the path form (`create_real_directory` + [`create_owned_file`] +
///   `rename`): **47.5-47.7 us/member**;
/// * this form (`mkdirat`+`openat` per shard, `openat`+`renameat` per member,
///   plus [`verify_member_path_shape`]): **50.5-51.0 us/member**;
/// * **delta +2.9 to +3.5 us/member**, against a real durable capture of a
///   2,000-object CAS tree measured at **1232-1279 us/member** — so **~0.25%**.
///
/// The delta is NOT syscalls. A fourth arm timed the userspace bookkeeping alone
/// — the shape check, the relative-path build, the `BTreeMap` lookup, with every
/// directory already open — at **3.17-3.19 us/member**, which is the whole of
/// it. `openat(dirfd, "<one component>")` walks one component where
/// `open(AT_FDCWD, "<artifact>/trees/cas/<shard>/<hex>.capture-tmp")` walked
/// five, so the kernel side is at worst free; the price is two `PathBuf`
/// allocations and two map lookups per member, and it buys a position that
/// cannot be redirected.
///
/// ## Carrying it into the READ sides costs NEGATIVE time
///
/// 2,000 members, both forms compiled into ONE binary and selected per lap so
/// the arms genuinely ALTERNATE. Separate runs measure nothing: the reference
/// host's capture number drifted 1,137 -> 1,691 us/member between two builds
/// that differ by one `lstat` per member, so any cross-build delta is swamped.
///
/// The clean signal is [`preflight_restore_artifact`], because it is the read
/// pass with no writes under it:
///
/// * this form: **119.95-121.35 us/member** (median 120.4), 14 alternated laps;
/// * the path form it replaces (`lstat` then `open` on the full
///   `<artifact>/trees/cas/<shard>/<hex>`): **122.09-125.23** (median 122.3);
/// * **delta -1.0 to -4.9 us/member, median about -2.0** — the `openat` walk is
///   FASTER, by about 1.6% of the read pass.
///
/// Faster for the reason the fourth arm above already found, applied to reads:
/// `openat` walks ONE component where the path form walked five, and the
/// descriptor form folds the type and size checks into the `fstat` it was going
/// to make anyway, replacing the path form's separate `lstat`. The two `fcntl`
/// calls that clear `O_NONBLOCK` are more than paid for by that.
///
/// The full [`restore_data_dir`] delta is BELOW THE NOISE FLOOR of the
/// reference host and is reported as such rather than as a number: the same 14
/// laps swing from -173 to +137 us/member with no trend, against a real durable
/// restore of **1,021-1,276 us/member**, because that path is fsync-bound. The
/// write sides cost ~0.25% and the read sides hand about 0.17% of a restore
/// back; the two together are under a tenth of a percent.
///
/// # What is deliberately unchanged
///
/// * **`O_EXCL` is still refused.** `mkdirat` tolerating `EEXIST` and the file
///   open carrying `O_CREAT` without `O_EXCL` is what keeps a resume legitimate;
///   see [`create_owned_file`] for the argument.
/// * **Truncation is still `ftruncate(2)` after the checks**, never `O_TRUNC` at
///   open, and the `st_nlink == 1` refusal still runs on the opened descriptor —
///   [`own_opened_file`] is the same code for both forms rather than a copy.
/// * **Operator-typed roots are still resolved.** [`Self::open_operator_root`]
///   deliberately omits `O_NOFOLLOW`: `/tmp` and `/home` are symlinks on real
///   hosts, so refusing a link inside a prefix the operator typed would refuse
///   ordinary installations. The carve-out is [`DirectoryState`]'s, unchanged.
///
/// # The non-unix build degrades to the predicate, and says so
///
/// There is no `openat(2)` to call, so off unix every method below falls back to
/// the path form — the same degradation [`create_owned_file`] already documents
/// for `O_NOFOLLOW`, stated rather than left as a silent difference in guarantee
/// between targets.
struct ProvenDir {
    /// Rendered in refusals and used for NOTHING else. A [`ProvenDir`] never
    /// re-resolves it: the moment the path is walked a second time the proof is
    /// gone and the window is back.
    display: PathBuf,
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
}

/// The `mkdirat` mode, matching `std::fs::create_dir`'s `0o777` — the umask
/// narrows it, exactly as it does for every other directory this module makes.
#[cfg(unix)]
const PROVEN_DIR_MODE: rustix::fs::Mode = rustix::fs::Mode::RWXU
    .union(rustix::fs::Mode::RWXG)
    .union(rustix::fs::Mode::RWXO);

impl ProvenDir {
    /// Open `path` as a walk root whose FINAL component this module owns.
    ///
    /// The last component is bound with `O_NOFOLLOW`; everything above it is
    /// resolved, which is what the operator-typed prefix requires. `<out_dir>/`
    /// [`TREES_SUBDIR`] is the shape: `trees` is ours, `<out_dir>` is theirs.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] if the path is absent, is a symlink, or is not a
    /// directory.
    fn open(path: &Path, stage: &str, requirement: &str) -> KataResult<Self> {
        #[cfg(unix)]
        {
            let fd = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|errno| directory_open_error(errno, path, stage, requirement))?;
            Ok(Self {
                display: path.to_path_buf(),
                fd,
            })
        }
        #[cfg(not(unix))]
        {
            require_real_directory(path, stage, requirement)?;
            Ok(Self {
                display: path.to_path_buf(),
            })
        }
    }

    /// Open `path` as a walk root the OPERATOR typed, resolving every component
    /// including the last.
    ///
    /// Following a link inside an operator-named prefix is REQUIRED rather than
    /// refused; see [`DirectoryState`] for why that carve-out exists and why it
    /// stops at the first component this module chose.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] if the path is absent or does not resolve to a
    /// directory.
    fn open_operator_root(path: &Path, stage: &str, requirement: &str) -> KataResult<Self> {
        #[cfg(unix)]
        {
            let fd = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|errno| directory_open_error(errno, path, stage, requirement))?;
            Ok(Self {
                display: path.to_path_buf(),
                fd,
            })
        }
        #[cfg(not(unix))]
        {
            if !path.is_dir() {
                return Err(KataError::Storage(format!(
                    "{stage}: {} is not a directory; {requirement}",
                    path.display()
                )));
            }
            Ok(Self {
                display: path.to_path_buf(),
            })
        }
    }

    /// The path this directory was opened at, for rendering only.
    fn path(&self) -> &Path {
        &self.display
    }

    /// `<self>/<name>`, for rendering only.
    fn child_path(&self, name: &OsStr) -> PathBuf {
        self.display.join(name)
    }

    /// Create `name` under this proven directory if it is absent, and open it —
    /// proving it in turn.
    ///
    /// `EEXIST` from `mkdirat` is tolerated and the `openat` decides what is
    /// there: `O_DIRECTORY|O_NOFOLLOW` admits a real directory and returns
    /// `ELOOP` for a symlink and `ENOTDIR` for anything else. `name` is a single
    /// component, so there is no intermediate component for either call to
    /// resolve.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] if the entry cannot be created, or is not a real
    /// directory.
    fn child(&self, name: &OsStr, stage: &str, requirement: &str) -> KataResult<Self> {
        let display = self.child_path(name);
        #[cfg(unix)]
        {
            match rustix::fs::mkdirat(&self.fd, name, PROVEN_DIR_MODE) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(errno) => {
                    return Err(KataError::Storage(format!(
                        "{stage}: create_dir({}) failed: {}",
                        display.display(),
                        io::Error::from(errno)
                    )));
                }
            }
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|errno| directory_open_error(errno, &display, stage, requirement))?;
            Ok(Self { display, fd })
        }
        #[cfg(not(unix))]
        {
            create_real_directory(&display, stage, requirement)?;
            Ok(Self { display })
        }
    }

    /// Open an EXISTING `name` under this proven directory, creating nothing —
    /// proving it in turn.
    ///
    /// The READ direction of [`Self::child`]. Same `openat` with the same flags
    /// and the same refusal vocabulary, without the `mkdirat`: a reader has no
    /// business creating a level of somebody else's artifact, and an absent one
    /// is a refusal rather than a directory this call invents.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] if the entry is absent, is a symlink, or is not a
    /// directory.
    fn open_child(&self, name: &OsStr, stage: &str, requirement: &str) -> KataResult<Self> {
        let display = self.child_path(name);
        #[cfg(unix)]
        {
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|errno| directory_open_error(errno, &display, stage, requirement))?;
            Ok(Self { display, fd })
        }
        #[cfg(not(unix))]
        {
            require_real_directory(&display, stage, requirement)?;
            Ok(Self { display })
        }
    }

    /// [`Self::open_child`] where ABSENCE is an answer rather than a refusal.
    ///
    /// [`load_or_reset_restore_journal`] is the caller: a target data directory
    /// with no [`RESTORE_JOURNAL_SUBDIR`] is the ordinary first-restore case, so
    /// `ENOENT` there means "no journal", while `ELOOP` and `ENOTDIR` still mean
    /// "somebody put something else at the name" and are refusals. That split is
    /// why this cannot be `open_child(..).ok()`, which would swallow all three.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] if the entry exists and is a symlink or is not a
    /// directory.
    fn open_child_if_present(
        &self,
        name: &OsStr,
        stage: &str,
        requirement: &str,
    ) -> KataResult<Option<Self>> {
        #[cfg(unix)]
        {
            match rustix::fs::openat(
                &self.fd,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(fd) => Ok(Some(Self {
                    display: self.child_path(name),
                    fd,
                })),
                Err(rustix::io::Errno::NOENT) => Ok(None),
                Err(errno) => Err(directory_open_error(
                    errno,
                    &self.child_path(name),
                    stage,
                    requirement,
                )),
            }
        }
        #[cfg(not(unix))]
        {
            let display = self.child_path(name);
            if !display.exists() {
                return Ok(None);
            }
            require_real_directory(&display, stage, requirement)?;
            Ok(Some(Self { display }))
        }
    }

    /// Open `name` for READING as a bounded plain file, relative to this proven
    /// directory, returning the handle and its length.
    ///
    /// The `openat(2)` form of [`regular_source_metadata`], and the read-side
    /// twin of [`Self::create_owned_file`]. Every check is made on the OPENED
    /// descriptor — `is_file()` and the size bound — so the bytes a caller
    /// digests are the bytes of the object that was checked, with no path left
    /// to re-resolve between the two. `regular_source_metadata` `lstat`s a PATH
    /// and the caller then opens that path again; that is the window this form
    /// does not have.
    ///
    /// `O_NONBLOCK` is carried for the reason [`create_owned_file`] states — a
    /// reader-less FIFO would otherwise block forever — and is cleared before
    /// the handle is returned, because `io::copy` does not retry `EAGAIN`.
    ///
    /// # `O_NOFOLLOW` is what makes the OPENED descriptor an object IN this
    /// directory
    ///
    /// **Invariant.** The bytes returned are the bytes of the object at `name`
    /// under this descriptor, never the bytes of something a link at `name`
    /// points at.
    ///
    /// **Failure mode, and why it is invisible without the flag.** The checks
    /// below run on the opened descriptor, and that is exactly why they cannot
    /// substitute for it: `fstat(2)` through a FOLLOWED symlink reports the
    /// TARGET, so `is_file()` is true and the size bound passes on a member
    /// whose bytes live outside the artifact. Every downstream check agrees with
    /// it too — the per-member digest, the recorded `byte_len`, the entry digest
    /// and the content address are all properties of the linked-to bytes. No
    /// post-open assertion can recover the distinction; only the open can refuse
    /// it. Measured with the flag removed: [`preflight_restore_artifact`]
    /// returns `Ok` on an artifact whose sole `cas` member is a link to a file
    /// outside it, and [`restore_data_dir`] then places those bytes.
    ///
    /// **Enforcement.** `OFlags::NOFOLLOW` at the `openat`, whose `ELOOP` joins
    /// `ENXIO` in the "is not a real regular file" vocabulary
    /// [`regular_source_metadata`] established. The `#[cfg(not(unix))]` arm
    /// reaches the same refusal by an `lstat`, hand-written separately.
    ///
    /// The FILES and DIRECTORIES tables above credit six positions to this
    /// function as `openat` (`O_NOFOLLOW`); the `Errno::LOOP` arm of the error
    /// map below is the tell that the flag is present, because `ELOOP` is
    /// unreachable from an `openat` without `O_NOFOLLOW`.
    ///
    /// **Proof.** `a_member_that_is_a_link_to_the_real_object_outside_the_artifact_is_refused`
    /// and `the_artifact_s_integrity_gate_is_not_satisfiable_from_outside_the_artifact`
    /// in `crates/core/tests/backup_durability_tests.rs` drive the member and
    /// the bundled-config positions; `every_proven_dir_openat_carries_o_nofollow`
    /// below refuses a future site that drops the flag again. That one is a
    /// BACKTICKED name and not an intra-doc link on purpose: it lives in
    /// `#[cfg(test)] mod tests`, which does not exist during a rustdoc build, so
    /// a bracket link to it would not resolve.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] if the entry is absent, is a symlink, is not a
    /// plain file, or is larger than `maximum`.
    fn open_source_file(
        &self,
        name: &OsStr,
        maximum: u64,
        stage: &str,
        label: &str,
    ) -> KataResult<(File, u64)> {
        let display = self.child_path(name);
        #[cfg(unix)]
        let file = {
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|errno| match errno {
                // `ELOOP` is a symlink and `ENXIO` a reader-less FIFO; both are
                // "not a real regular file" in the vocabulary
                // `regular_source_metadata` established, and neither is an
                // object. `ELOOP` is reachable only because of the `O_NOFOLLOW`
                // above; this arm was dead without it.
                rustix::io::Errno::LOOP | rustix::io::Errno::NXIO => KataError::Storage(format!(
                    "{stage}: {label} source {} is not a real regular file",
                    display.display()
                )),
                other => KataError::Storage(format!(
                    "{stage}: inspect {label} source {} failed: {}",
                    display.display(),
                    io::Error::from(other)
                )),
            })?;
            File::from(fd)
        };
        #[cfg(not(unix))]
        let file = {
            let existing = std::fs::symlink_metadata(&display).map_err(|e| {
                KataError::Storage(format!(
                    "{stage}: inspect {label} source {} failed: {e}",
                    display.display()
                ))
            })?;
            if existing.file_type().is_symlink() {
                return Err(KataError::Storage(format!(
                    "{stage}: {label} source {} is not a real regular file",
                    display.display()
                )));
            }
            File::open(&display).map_err(|e| {
                KataError::Storage(format!(
                    "{stage}: inspect {label} source {} failed: {e}",
                    display.display()
                ))
            })?
        };
        let opened = file.metadata().map_err(|e| {
            KataError::Storage(format!(
                "{stage}: inspect {label} source {} failed: {e}",
                display.display()
            ))
        })?;
        if !opened.is_file() {
            return Err(KataError::Storage(format!(
                "{stage}: {label} source {} is not a real regular file",
                display.display()
            )));
        }
        if opened.len() > maximum {
            return Err(KataError::Storage(format!(
                "{stage}: {label} source {} size {} exceeds bounded maximum {maximum}",
                display.display(),
                opened.len()
            )));
        }
        #[cfg(unix)]
        {
            let flags = rustix::fs::fcntl_getfl(&file).map_err(|e| {
                KataError::Storage(format!(
                    "{stage}: read open flags of {} failed: {e}",
                    display.display()
                ))
            })?;
            rustix::fs::fcntl_setfl(&file, flags - rustix::fs::OFlags::NONBLOCK).map_err(|e| {
                KataError::Storage(format!(
                    "{stage}: clear O_NONBLOCK on {} failed: {e}",
                    display.display()
                ))
            })?;
        }
        let len = opened.len();
        Ok((file, len))
    }

    /// [`create_owned_file`] at `name`, relative to this proven directory.
    ///
    /// # Errors
    ///
    /// As [`create_owned_file`].
    fn create_owned_file(&self, name: &OsStr, stage: &str, requirement: &str) -> KataResult<File> {
        let display = self.child_path(name);
        #[cfg(unix)]
        {
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR
                    .union(rustix::fs::Mode::WUSR)
                    .union(rustix::fs::Mode::RGRP)
                    .union(rustix::fs::Mode::ROTH),
            )
            .map_err(|errno| {
                KataError::Storage(format!(
                    "{stage}: create {} failed: {}; {requirement}",
                    display.display(),
                    io::Error::from(errno)
                ))
            })?;
            own_opened_file(File::from(fd), &display, stage, requirement)
        }
        #[cfg(not(unix))]
        {
            create_owned_file(&display, stage, requirement)
        }
    }

    /// Open `name` for READING if it is a plain file, `None` if it is absent or
    /// is anything else.
    ///
    /// The resume proof in [`activate_captured_tree`] digests the member the
    /// target already holds. A path form would be a `stat`-then-`open`; here
    /// both are bound to this descriptor and the type check
    /// is made on the OPENED handle, so a member the target holds cannot be
    /// swapped for a link between deciding to skip it and proving the skip.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] on a read failure that is neither absence nor a
    /// refused type.
    fn open_regular(&self, name: &OsStr, stage: &str) -> KataResult<Option<File>> {
        let display = self.child_path(name);
        #[cfg(unix)]
        let file = {
            match rustix::fs::openat(
                &self.fd,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(fd) => File::from(fd),
                // Absent, a symlink (`ELOOP`), or a reader-less FIFO (`ENXIO`) —
                // all three mean "the target does not already hold this member",
                // and the copy below re-establishes what is there.
                Err(
                    rustix::io::Errno::NOENT
                    | rustix::io::Errno::LOOP
                    | rustix::io::Errno::NXIO
                    | rustix::io::Errno::NOTDIR,
                ) => return Ok(None),
                Err(errno) => {
                    return Err(KataError::Storage(format!(
                        "{stage}: inspect {} failed: {}",
                        display.display(),
                        io::Error::from(errno)
                    )));
                }
            }
        };
        #[cfg(not(unix))]
        let file = match File::open(&display) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(KataError::Storage(format!(
                    "{stage}: inspect {} failed: {e}",
                    display.display()
                )));
            }
        };
        let metadata = file.metadata().map_err(|e| {
            KataError::Storage(format!(
                "{stage}: inspect {} failed: {e}",
                display.display()
            ))
        })?;
        Ok(metadata.is_file().then_some(file))
    }

    /// `renameat(2)` both operands inside this proven directory.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] naming both operands.
    fn rename_within(&self, from: &OsStr, to: &OsStr, stage: &str, what: &str) -> KataResult<()> {
        #[cfg(unix)]
        {
            rustix::fs::renameat(&self.fd, from, &self.fd, to).map_err(|errno| {
                KataError::Storage(format!(
                    "{stage}: {what} {} -> {} failed: {}",
                    self.child_path(from).display(),
                    self.child_path(to).display(),
                    io::Error::from(errno)
                ))
            })
        }
        #[cfg(not(unix))]
        {
            std::fs::rename(self.child_path(from), self.child_path(to)).map_err(|e| {
                KataError::Storage(format!(
                    "{stage}: {what} {} -> {} failed: {e}",
                    self.child_path(from).display(),
                    self.child_path(to).display()
                ))
            })
        }
    }

    /// Best-effort `unlinkat(2)` of this module's own staging file.
    ///
    /// Mirrors the `let _ = std::fs::remove_file(&tmp)` the error paths used:
    /// the staging file is residue either way and a failure to remove it must
    /// not replace the error that is being reported.
    fn remove_file(&self, name: &OsStr) {
        #[cfg(unix)]
        {
            let _ = rustix::fs::unlinkat(&self.fd, name, rustix::fs::AtFlags::empty());
        }
        #[cfg(not(unix))]
        {
            let _ = std::fs::remove_file(self.child_path(name));
        }
    }

    /// `fsync` this directory so the renames inside it are durable.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] naming the directory.
    fn sync(&self, stage: &str) -> KataResult<()> {
        #[cfg(unix)]
        {
            rustix::fs::fsync(&self.fd).map_err(|errno| {
                KataError::Storage(format!(
                    "{stage}: fsync directory {} failed: {}",
                    self.display.display(),
                    io::Error::from(errno)
                ))
            })
        }
        #[cfg(not(unix))]
        {
            fsync_dir(&self.display)
        }
    }
}

/// Render an `openat(2)` failure on a directory in the vocabulary the
/// path-based predicate uses, so one refusal message covers both forms.
///
/// `ELOOP` is what `O_NOFOLLOW` returns for a symlink and `ENOTDIR` is what
/// `O_DIRECTORY` returns for everything else that exists — both are
/// [`directory_state`]'s *"is not a real directory"*, and `ENOENT` is its
/// *"does not exist"*.
#[cfg(unix)]
fn directory_open_error(
    errno: rustix::io::Errno,
    path: &Path,
    stage: &str,
    requirement: &str,
) -> KataError {
    match errno {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => KataError::Storage(format!(
            "{stage}: {} is not a real directory; {requirement}",
            path.display()
        )),
        rustix::io::Errno::NOENT => KataError::Storage(format!(
            "{stage}: {} does not exist; {requirement}",
            path.display()
        )),
        other => KataError::Storage(format!(
            "{stage}: open directory {} failed: {}; {requirement}",
            path.display(),
            io::Error::from(other)
        )),
    }
}

/// The ceiling on [`tree_member_directory_budget`], independent of how generous
/// the host's descriptor limit is.
///
/// A tree spanning more than a thousand distinct directories is a shape no row
/// in the map produces and no operator is waiting on, so the walk stops there
/// even where the kernel would permit far more.
const TREE_MEMBER_DIRECTORY_CEILING: usize = 1024;

/// Descriptors held back for everything the process owns that is NOT the shard
/// caches: `stdio`, the roots above the shards, the member being read, the
/// member being written, the open SQLite connections, and whatever the async
/// runtime holds.
///
/// # A measurement, not a guess
///
/// A reserve that is too large refuses legitimate work: with a reserve of 128,
/// at `ulimit -n 282` a 222-shard capture derives a budget of 154 and is
/// REFUSED, while its real peak is 230, comfortably inside 282. A bound that
/// refuses work the host can do is the same defect as one that admits work it
/// cannot, pointed the other way.
///
/// Measured on the reference host, 222 shards / 501 members, sampling `/proc/self/fd`
/// during a real `backup_data_dir` / `restore_data_dir` / `preflight_restore_artifact`:
///
/// * capture peak **230** — 222 shards + **8**;
/// * preflight peak **231** — 222 shards + **9**;
/// * restore peak **454** — 222 shards TWICE (see [`DirectoryBudget`]) + **10**.
///
/// So the walk's own overhead is 8-10 descriptors, and 32 is that measurement
/// with 3x headroom, rounded to a power of two.
///
/// **What 32 does NOT model is the CALLER.** The measurement above was taken in
/// a test process holding four descriptors; an in-process `kata serve` holds a
/// SQLite pool, a tokio reactor and every worker's pipes, and this constant
/// cannot see any of them. That residue is DECLARED at the module's
/// `DECLARED LIMITS` block rather than papered over with a bigger number,
/// because a bigger number refuses the 222-shard capture.
#[cfg(unix)]
const TREE_MEMBER_DIRECTORY_RESERVE: u64 = 32;

/// The most DISTINCT directories one tree's members may span, and therefore the
/// most directory descriptors one [`capture_tree`], [`activate_captured_tree`]
/// or [`verify_captured_tree_sources`] call holds open at a time.
///
/// A cached [`ProvenDir`] per level is what buys one `mkdirat` per shard instead
/// of one per member, and the price is an open file descriptor per level held
/// for the length of the tree. That is a RESOURCE, so it gets a bound rather
/// than an assumption: without one, a tree whose members each sit in their own
/// directory would hold up to [`MAX_TREE_ENTRIES`] descriptors and fail on
/// `EMFILE` part-way through a write — a failure with nothing to do with what
/// went wrong.
///
/// # It is not a flat `1024`, which is the ONE number it could not be
///
/// **1,024 is the soft `RLIMIT_NOFILE` most Linux distributions ship.** A bound
/// set exactly at the limit fires only after the limit does, so on a
/// default-limits host the process runs out of descriptors FIRST and the
/// operator gets precisely the `EMFILE`-mid-write failure this bound exists to
/// convert into a named refusal. A host with a 1,048,576 soft limit cannot
/// observe that: every value passes there.
///
/// So it is DERIVED: the soft limit the kernel reports, less
/// [`TREE_MEMBER_DIRECTORY_RESERVE`], capped at
/// [`TREE_MEMBER_DIRECTORY_CEILING`]. On the common 1,024-limit host that is
/// 992, which leaves the reserve free for everything else the process holds; on
/// a host with a large limit it is the ceiling. An unlimited soft limit (`RLIM_INFINITY`) is the
/// ceiling too.
///
/// # It is a JOINT bound, never a per-cache one
///
/// This number is the budget for a WALK, not for a cache, and
/// [`activate_captured_tree`] walks two trees at once — the artifact's (read)
/// and the target's (write) — holding a cache for each. Handing each cache the
/// full budget independently lets a 256-shard `cas` at `RLIMIT_NOFILE=512` pass
/// both checks at 256 and then hold 512 directory descriptors plus the roots and
/// the two members in flight: `EMFILE`, from inside the bound whose entire
/// purpose is to convert that into a named refusal. Measured: a 222-shard
/// restore's peak is 454, which is 222 TWICE plus 10. [`DirectoryBudget`] is
/// what makes the count joint.
///
/// Read ONCE per process. `setrlimit(2)` can lower the limit under a running
/// program, and re-reading it per member would put a syscall on the hot path to
/// track a value nothing in this binary changes; the refusal names the number it
/// used, so a bound derived from a stale limit is still a bound an operator can
/// act on.
///
/// The shipped `cas` row cannot approach the ceiling, by two independent facts:
/// its shards are `<2 hex>`, so there are at most 256 of them, and
/// [`verify_member_path_shape`] refuses any member path that is not exactly two
/// components. 256 also fits under the DERIVED budget on a 1,024-limit host,
/// which is what makes deriving safe rather than a new way to refuse an ordinary
/// capture. The bound is here for the row that comes after it — a
/// [`crate::durable_assets::TreeMemberAddressing::PathOpaque`] tree's shape is
/// the operator's filesystem's, not this module's.
fn tree_member_directory_budget() -> usize {
    static BUDGET: OnceLock<usize> = OnceLock::new();
    *BUDGET.get_or_init(|| {
        #[cfg(unix)]
        {
            tree_member_directory_budget_from(
                rustix::process::getrlimit(rustix::process::Resource::Nofile).current,
            )
        }
        #[cfg(not(unix))]
        {
            TREE_MEMBER_DIRECTORY_CEILING
        }
    })
}

/// [`tree_member_directory_budget`]'s arithmetic, over a soft limit the caller
/// supplies rather than the one this host reports.
///
/// Split out so the derivation is FALSIFIABLE on a host whose limit makes the
/// defect invisible. On a host reporting 1,048,576, an assertion of the form
/// *"the budget leaves the reserve free under the real limit"* passes for a flat
/// `1024` constant and for every other value. Feeding 1,024 in directly is what
/// separates the two.
///
/// `None` is `RLIM_INFINITY`.
#[cfg(unix)]
fn tree_member_directory_budget_from(soft: Option<u64>) -> usize {
    match soft {
        None => TREE_MEMBER_DIRECTORY_CEILING,
        Some(soft) => usize::try_from(soft.saturating_sub(TREE_MEMBER_DIRECTORY_RESERVE))
            .unwrap_or(TREE_MEMBER_DIRECTORY_CEILING)
            .min(TREE_MEMBER_DIRECTORY_CEILING),
    }
}

/// Whether [`open_member_parents`] may CREATE a level it does not find.
///
/// # The walk has two directions
///
/// Two sides write — [`capture_tree`]'s destination and
/// [`activate_captured_tree`]'s target — and two READ
/// ([`verify_captured_tree_sources`], and the SOURCE half of
/// `activate_captured_tree`). A position list built from *"every WRITE
/// position"* alone leaves the read sides joining full paths. The walk is the
/// same walk in both directions; only this answer differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParentWalk {
    /// `mkdirat` a missing level, then `openat` it. The WRITE direction: this
    /// module is laying out a directory it owns.
    Create,
    /// `openat` only. The READ direction: a level this module did not find is a
    /// refusal, never a directory a reader invents inside somebody else's
    /// artifact.
    Existing,
}

/// The descriptors ONE operation's shard caches hold, counted ACROSS the caches
/// rather than within each.
///
/// # A per-cache bound is not a bound on a two-cache walk
///
/// `opened.len() >= tree_member_directory_budget()` is the right question only
/// where there is one cache. [`activate_captured_tree`] has two — the artifact's
/// shards (read) and the target's (write) — so a per-cache check lets a
/// 256-shard `cas` at `RLIMIT_NOFILE=512` derive a budget of 480, pass 256
/// twice, and hold 512 directory descriptors: the `EMFILE` mid-restore that the
/// bound exists to convert into a named refusal, admitted from inside the bound.
/// Measured: a 222-shard restore peaks at 454 open descriptors, which is 222
/// twice plus 10.
///
/// One of these is constructed per OPERATION and shared by every cache that
/// operation holds live at once. [`capture_tree`] and
/// [`verify_captured_tree_sources`] hold one cache each;
/// `activate_captured_tree` shares one budget between its two.
struct DirectoryBudget {
    limit: usize,
    held: usize,
}

impl DirectoryBudget {
    /// A budget at [`tree_member_directory_budget`], holding nothing yet.
    fn new() -> Self {
        Self {
            limit: tree_member_directory_budget(),
            held: 0,
        }
    }

    /// Claim one directory descriptor, or refuse by name.
    ///
    /// # Errors
    ///
    /// [`KataError::Storage`] naming the joint bound and the remedy.
    fn claim(&mut self, root: &ProvenDir, stage: &str) -> KataResult<()> {
        if self.held >= self.limit {
            let limit = self.limit;
            return Err(KataError::Storage(format!(
                "{stage}: tree under {} spans more than the bounded maximum of {limit} \
                 directories; each one is held open for the length of the tree and running out \
                 of descriptors mid-write is a failure that says nothing about what is wrong. A \
                 restore walks the artifact AND the target, so both sides count against this one \
                 number. The bound is derived from this host's soft RLIMIT_NOFILE less \
                 {TREE_MEMBER_DIRECTORY_RESERVE} for everything else the process holds, so \
                 raising that limit raises it (up to {TREE_MEMBER_DIRECTORY_CEILING})",
                root.path().display()
            )));
        }
        self.held += 1;
        Ok(())
    }
}

/// Open every level of `parent` under `root`, caching each by its
/// root-relative path so a shard is proven ONCE.
///
/// The caller indexes `opened` afterwards rather than taking a reference back:
/// the map owns the descriptors, and the fsync loop needs the whole set anyway
/// — one `mkdirat` per DISTINCT shard instead of one per member, which is the
/// trade [`TREE_MEMBER_DIRECTORY_CEILING`] bounds.
///
/// `parent` has been through [`tree_entry_relative_path`], so every component is
/// [`Component::Normal`]; the non-normal arm refuses rather than assuming,
/// because a `..` reaching here would be the one input this whole walk exists to
/// stop.
///
/// # Errors
///
/// [`KataError::Storage`] if any level is not a real directory, cannot be
/// created (or is absent under [`ParentWalk::Existing`]), or if the caches
/// sharing `budget` span more directories than [`DirectoryBudget`] admits.
fn open_member_parents(
    root: &ProvenDir,
    opened: &mut BTreeMap<PathBuf, ProvenDir>,
    parent: &Path,
    walk: ParentWalk,
    budget: &mut DirectoryBudget,
    stage: &str,
    requirement: &str,
) -> KataResult<()> {
    let mut walked = PathBuf::new();
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err(KataError::Storage(format!(
                "{stage}: refusing to walk {} under {}: it is not a sequence of plain components",
                parent.display(),
                root.path().display()
            )));
        };
        let next = walked.join(name);
        if !opened.contains_key(&next) {
            budget.claim(root, stage)?;
            let here = if walked.as_os_str().is_empty() {
                root
            } else {
                proven_parent(opened, &walked, root, stage)?
            };
            let child = match walk {
                ParentWalk::Create => here.child(name, stage, requirement)?,
                ParentWalk::Existing => here.open_child(name, stage, requirement)?,
            };
            opened.insert(next.clone(), child);
        }
        walked = next;
    }
    Ok(())
}

/// The proven directory a member's parent is: `root` itself for a member that
/// sits directly under it, otherwise the cached handle for that relative path.
///
/// # Errors
///
/// [`KataError::Storage`] if the cache does not hold `parent`.
fn member_parent<'a>(
    root: &'a ProvenDir,
    opened: &'a BTreeMap<PathBuf, ProvenDir>,
    parent: &Path,
    stage: &str,
) -> KataResult<&'a ProvenDir> {
    if parent.as_os_str().is_empty() {
        Ok(root)
    } else {
        proven_parent(opened, parent, root, stage)
    }
}

/// The cached [`ProvenDir`] at `relative`, or a refusal.
///
/// # Never `&opened[relative]`, which is a PANIC in a storage module
///
/// `BTreeMap`'s `Index` panics on a miss, and both indexing sites sat on a walk
/// whose relative paths come from a manifest an attacker may have written — so
/// the one thing a miss must never do is unwind through a capture or a restore.
/// Every caller has just walked the same path, so a miss is unreachable today
/// and this is the arm that keeps it a refusal if it ever stops being.
///
/// # Errors
///
/// [`KataError::Storage`] naming the level that is missing.
fn proven_parent<'a>(
    opened: &'a BTreeMap<PathBuf, ProvenDir>,
    relative: &Path,
    root: &ProvenDir,
    stage: &str,
) -> KataResult<&'a ProvenDir> {
    opened.get(relative).ok_or_else(|| {
        KataError::Storage(format!(
            "{stage}: internal: {} under {} was not proven before it was used; refusing rather \
             than resolving it as a path",
            relative.display(),
            root.path().display()
        ))
    })
}

/// `<name><suffix>` as a single path component.
fn suffixed_name(name: &OsStr, suffix: &str) -> OsString {
    let mut raw = name.to_os_string();
    raw.push(suffix);
    raw
}

/// `remove_file` that treats an absent path as success.
///
/// `unlink(2)` never resolves the final component, so this removes a symlink, a
/// FIFO or a device node rather than writing through one.
fn remove_file_if_present(path: &Path, stage: &str, label: &str) -> KataResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(KataError::Storage(format!(
            "{stage}: remove {label} {} failed: {e}",
            path.display()
        ))),
    }
}

/// Prove `path` is a name THIS process may write a plain file at, and then leave
/// it free for a writer that takes no `open(2)` flags from us.
///
/// [`vacuum_into`] is that writer: SQLite opens the `VACUUM INTO` destination
/// itself, so `O_NOFOLLOW` cannot be handed to it. Rather than settle for an
/// `lstat` predicate at the one position the mechanism cannot reach, this runs
/// the SAME [`create_owned_file`] open — whose flags refuse a symlink (`ELOOP`)
/// and a reader-less FIFO (`ENXIO`) outright, and whose descriptor checks refuse
/// a hard link, a device node and a socket — and then `unlink(2)`s the empty file
/// it just created, so SQLite's open lands on a free name.
///
/// **The residual window is one `unlink`-to-`open` gap** and is stated rather
/// than papered over: a concurrent writer could re-plant an obstruction inside
/// it. It is unreachable for the threat this exists to stop, which is something
/// left in an artifact directory BEFORE the capture starts, and it is strictly
/// smaller than the `if path.exists()` guard this replaces — that one RESOLVED
/// the path, answered `false` for a dangling symlink, and skipped the removal at
/// exactly the input that needed it, so SQLite created the database through the
/// link and `rename(2)` moved the link into the artifact.
fn claim_owned_path(path: &Path, stage: &str, requirement: &str) -> KataResult<()> {
    drop(create_owned_file(path, stage, requirement)?);
    remove_file_if_present(path, stage, "claimed staging path")
}

fn validate_total_database_bytes(total_database_bytes: u64) -> KataResult<()> {
    if total_database_bytes > MAX_TOTAL_DATABASE_BYTES {
        return Err(KataError::Storage(format!(
            "restore: total database size {total_database_bytes} exceeds bounded maximum {MAX_TOTAL_DATABASE_BYTES}"
        )));
    }
    Ok(())
}

fn validate_database_names(databases: &[String]) -> KataResult<()> {
    if databases.len() > MAX_DATABASE_COUNT {
        return Err(KataError::Storage(format!(
            "restore: manifest database count {} exceeds bounded maximum {MAX_DATABASE_COUNT}",
            databases.len()
        )));
    }
    let mut names = HashSet::with_capacity(databases.len());
    for name in databases {
        let path = Path::new(name);
        let mut components = path.components();
        let only_component = components.next();
        let is_single_normal = matches!(only_component, Some(Component::Normal(value)) if value == OsStr::new(name))
            && components.next().is_none();
        let is_database = path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("db"));
        if name.is_empty()
            || name.len() > MAX_DATABASE_NAME_BYTES
            || !is_single_normal
            || !is_database
            || name.contains(['/', '\\', ':'])
        {
            return Err(KataError::Storage(format!(
                "restore: unsafe database name {name:?} in manifest"
            )));
        }
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(KataError::Storage(format!(
                "restore: duplicate database name {name:?} in manifest"
            )));
        }
    }
    Ok(())
}

fn validate_stores_directory(stores_dir: &Path) -> KataResult<()> {
    require_real_directory(
        stores_dir,
        "restore",
        "every database this restore reads lives under it, and a restore may not read them \
         through a link out of the artifact",
    )?;
    let entries = std::fs::read_dir(stores_dir).map_err(|e| {
        KataError::Storage(format!(
            "restore: enumerate stores directory {} failed: {e}",
            stores_dir.display()
        ))
    })?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_STORES_ENTRIES {
            return Err(KataError::Storage(format!(
                "restore: stores directory entry count exceeds bounded maximum {MAX_STORES_ENTRIES}"
            )));
        }
        let entry = entry.map_err(|e| {
            KataError::Storage(format!(
                "restore: enumerate stores directory entry failed: {e}"
            ))
        })?;
        if let Some(name) = entry.file_name().to_str()
            && (name.ends_with("-journal") || name.ends_with("-wal") || name.ends_with("-shm"))
        {
            return Err(KataError::Storage(format!(
                "restore: ambient SQLite sidecar {} is forbidden in the backup artifact",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn reject_ambient_sidecars(stores_dir: &Path, name: &str) -> KataResult<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = stores_dir.join(format!("{name}{suffix}"));
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                return Err(KataError::Storage(format!(
                    "restore: ambient SQLite sidecar {} is forbidden in the backup artifact",
                    sidecar.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(KataError::Storage(format!(
                    "restore: inspect SQLite sidecar {} failed: {e}",
                    sidecar.display()
                )));
            }
        }
    }
    Ok(())
}

fn read_regular_file_bounded(path: &Path, maximum: u64, label: &str) -> KataResult<Vec<u8>> {
    let metadata = regular_source_metadata(path, maximum, label)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        KataError::Storage(format!(
            "restore: {label} {} is too large for this host",
            path.display()
        ))
    })?;
    let file = File::open(path).map_err(|e| {
        KataError::Storage(format!(
            "restore: open {label} {} failed: {e}",
            path.display()
        ))
    })?;
    validate_opened_source(path, &metadata, &file, maximum, label)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut bounded = file.take(maximum + 1);
    bounded.read_to_end(&mut bytes).map_err(|e| {
        KataError::Storage(format!(
            "restore: read {label} {} failed: {e}",
            path.display()
        ))
    })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(KataError::Storage(format!(
            "restore: {label} {} changed while being read",
            path.display()
        )));
    }
    revalidate_source_after_read(path, &metadata, bounded.get_ref(), label)?;
    Ok(bytes)
}

fn stage_regular_file(src: &Path, dst: &Path, maximum: u64, label: &str) -> KataResult<u64> {
    let metadata = regular_source_metadata(src, maximum, label)?;
    let input = File::open(src).map_err(|e| {
        KataError::Storage(format!(
            "restore: open {label} {} failed: {e}",
            src.display()
        ))
    })?;
    validate_opened_source(src, &metadata, &input, maximum, label)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| {
            KataError::Storage(format!(
                "restore: create staged {label} {} failed: {e}",
                dst.display()
            ))
        })?;
    let mut bounded = input.take(maximum + 1);
    let copied = io::copy(&mut bounded, &mut output).map_err(|e| {
        KataError::Storage(format!(
            "restore: stage {label} {} failed: {e}",
            src.display()
        ))
    })?;
    output.flush().map_err(|e| {
        KataError::Storage(format!(
            "restore: flush staged {label} {} failed: {e}",
            dst.display()
        ))
    })?;
    if copied != metadata.len() {
        return Err(KataError::Storage(format!(
            "restore: {label} {} changed while being staged",
            src.display()
        )));
    }
    revalidate_source_after_read(src, &metadata, bounded.get_ref(), label)?;
    Ok(copied)
}

fn regular_source_metadata(
    path: &Path,
    maximum: u64,
    label: &str,
) -> KataResult<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| {
        KataError::Storage(format!(
            "restore: inspect {label} source {} failed: {e}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KataError::Storage(format!(
            "restore: {label} source {} is not a real regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(KataError::Storage(format!(
            "restore: {label} source {} size {} exceeds bounded maximum {maximum}",
            path.display(),
            metadata.len()
        )));
    }
    Ok(metadata)
}

fn validate_opened_source(
    path: &Path,
    path_metadata: &std::fs::Metadata,
    file: &File,
    maximum: u64,
    label: &str,
) -> KataResult<()> {
    let opened = file.metadata().map_err(|e| {
        KataError::Storage(format!(
            "restore: inspect opened {label} source {} failed: {e}",
            path.display()
        ))
    })?;
    if !opened.is_file() || opened.len() > maximum || !same_file_snapshot(path_metadata, &opened) {
        return Err(KataError::Storage(format!(
            "restore: {label} source {} changed before it could be staged",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn revalidate_source_after_read(
    path: &Path,
    original: &std::fs::Metadata,
    opened_file: &File,
    label: &str,
) -> KataResult<()> {
    let opened_after = opened_file.metadata().map_err(|e| {
        KataError::Storage(format!(
            "restore: restat opened {label} source {} failed: {e}",
            path.display()
        ))
    })?;
    let path_after = std::fs::symlink_metadata(path).map_err(|e| {
        KataError::Storage(format!(
            "restore: restat {label} source {} after reading failed: {e}",
            path.display()
        ))
    })?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || !same_file_snapshot(original, &opened_after)
        || !same_file_snapshot(original, &path_after)
    {
        return Err(KataError::Storage(format!(
            "restore: {label} source {} changed while being read",
            path.display()
        )));
    }
    Ok(())
}

fn validate_sqlite(path: &Path) -> KataResult<()> {
    validate_sqlite_header(path)?;
    let result = crate::inspect_optional_immutable_sqlite(
        path,
        "restore artifact database",
        |connection| {
            connection
                .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
                .map_err(|e| {
                    KataError::Storage(format!(
                        "restore: SQLite integrity check {} failed: {e}",
                        path.display()
                    ))
                })
        },
    )?
    .ok_or_else(|| {
        KataError::Storage(format!(
            "restore: database source {} disappeared during inspection",
            path.display()
        ))
    })?;
    if result != "ok" {
        return Err(KataError::Storage(format!(
            "restore: SQLite integrity check {} reported {result:?}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_sqlite_header(path: &Path) -> KataResult<()> {
    let metadata = regular_source_metadata(path, MAX_DATABASE_BYTES, "database")?;
    let mut file = File::open(path).map_err(|e| {
        KataError::Storage(format!(
            "restore: open SQLite artifact {} for header validation failed: {e}",
            path.display()
        ))
    })?;
    validate_opened_source(path, &metadata, &file, MAX_DATABASE_BYTES, "database")?;
    let length = metadata.len();
    if length < SQLITE_MINIMUM_BYTES {
        return Err(KataError::Storage(format!(
            "restore: SQLite artifact {} is truncated: {length} bytes; minimum is {SQLITE_MINIMUM_BYTES}",
            path.display()
        )));
    }
    let mut header = [0_u8; SQLITE_HEADER.len()];
    file.read_exact(&mut header).map_err(|e| {
        KataError::Storage(format!(
            "restore: read SQLite header {} failed: {e}",
            path.display()
        ))
    })?;
    revalidate_source_after_read(path, &metadata, &file, "database")?;
    if &header != SQLITE_HEADER {
        return Err(KataError::Storage(format!(
            "restore: SQLite artifact {} has an invalid file header",
            path.display()
        )));
    }
    Ok(())
}

fn validated_config_snapshot<'a>(
    config: &'a crate::ConfigManager,
    data_dir: &Path,
) -> KataResult<&'a str> {
    if !config.path().is_absolute() {
        return Err(KataError::Config(format!(
            "backup requires an absolute validated config path, got {}",
            config.path().display()
        )));
    }
    let content = config.initial_content().ok_or_else(|| {
        KataError::Config(
            "backup requires the exact validated initial config bytes; ConfigManager::from_config has no byte snapshot"
                .to_string(),
        )
    })?;
    let source_data_dir = data_dir.canonicalize().map_err(|error| {
        KataError::Storage(format!(
            "backup: resolve data directory {} failed: {error}",
            data_dir.display()
        ))
    })?;
    let initial_config =
        crate::ConfigManager::load_initial_snapshot(config.path(), content.to_owned())?;
    let configured_path = initial_config.snapshot().node.data_dir.clone();
    let configured_data_dir = configured_path.canonicalize().map_err(|error| {
        KataError::Config(format!(
            "backup cannot resolve configured node.data_dir {}: {error}",
            configured_path.display()
        ))
    })?;
    if source_data_dir != configured_data_dir {
        return Err(KataError::Config(format!(
            "backup data directory {} does not match configured node.data_dir {}",
            source_data_dir.display(),
            configured_data_dir.display()
        )));
    }
    Ok(content)
}

fn validate_config_restore_request(
    manifest: &BackupManifest,
    restore_config_to: Option<&Path>,
) -> KataResult<()> {
    if restore_config_to.is_some() && !manifest.config_included {
        return Err(KataError::Config(
            "config restoration was requested, but the artifact contains no bundled config"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_bundled_config(
    path: &Path,
    expected_data_dir: &Path,
    restore_config_to: Option<&Path>,
) -> KataResult<()> {
    let bytes = read_regular_file_bounded(path, crate::MAX_CONFIG_FILE_BYTES, "bundled config")?;
    let text = String::from_utf8(bytes).map_err(|e| {
        KataError::Storage(format!(
            "restore: bundled config {} is not UTF-8: {e}",
            path.display()
        ))
    })?;
    if let Some(target) = restore_config_to {
        if !target.is_absolute() {
            return Err(KataError::Storage(format!(
                "restore: config target must be absolute for semantic preflight: {}",
                target.display()
            )));
        }
        if !expected_data_dir.is_absolute() {
            return Err(KataError::Storage(format!(
                "restore: data directory must be absolute when restoring config: {}",
                expected_data_dir.display()
            )));
        }
        let config = crate::ConfigManager::load_initial_snapshot(target, text)?;
        let configured_data_dir =
            resolve_existing_data_dir_identity(&config.snapshot().node.data_dir);
        let expected_data_dir = resolve_existing_data_dir_identity(expected_data_dir);
        if configured_data_dir != expected_data_dir {
            return Err(KataError::Config(format!(
                "bundled config node.data_dir {} does not match restore data directory {}",
                configured_data_dir.display(),
                expected_data_dir.display()
            )));
        }
    } else {
        toml::from_str::<toml::Value>(&text).map_err(|e| {
            KataError::Storage(format!(
                "restore: bundled config {} is not valid TOML: {e}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn resolve_existing_data_dir_identity(path: &Path) -> PathBuf {
    let normalized = lexical_normalize(path);
    normalized.canonicalize().unwrap_or(normalized)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Put ONE staged copy at its target, at `tier`.
///
/// # `Durable` — the target is never partially written
///
/// tmp → fsync → rename → directory fsync. A power loss at ANY point leaves the target either
/// wholly the old file or wholly the new one; the partial bytes exist only in
/// `<target>.restore-tmp`, which nothing reads and which the next run replaces.
///
/// # `BestEffort` — a plain overwrite, deliberately
///
/// A plain remove-then-stream. It CAN leave a partial target, and for a
/// `Rebuildable` asset that is the correct trade: the repair is to rebuild it, and
/// it is what stops a restore paying an fsync and a second full write for bytes a
/// rebuild replaces.
fn activate_staged_file(
    src: &Path,
    dst: &Path,
    label: &str,
    tier: DurabilityTier,
    name: &str,
    before_activate: &mut impl FnMut(&str, &Path) -> KataResult<()>,
) -> KataResult<()> {
    if tier != DurabilityTier::Durable {
        return copy_staged_file(src, dst, label);
    }
    let parent = dst.parent().ok_or_else(|| {
        KataError::Storage(format!(
            "restore: {label} target {} has no parent directory",
            dst.display()
        ))
    })?;
    let tmp = suffixed_path(dst, RESTORE_TMP_SUFFIX);
    // TRUNCATING and not `create_new`: `<target>.restore-tmp` is residue of an
    // interrupted earlier restore to this same target, and refusing to proceed
    // because a crash left one is a restore that cannot resume from the exact
    // state the journal exists to resume from. `create_owned_file` keeps that
    // property — it constrains the staging path's TYPE, never its existence —
    // while refusing the link, hard link or pipe a bare `File::create` wrote
    // straight through. See its enumeration.
    let mut output = create_owned_file(
        &tmp,
        "restore",
        &format!(
            "a restore may not stage {label} {} through a link, a hard link or a pipe: the bytes \
             would land outside the target data directory while the rename moved the obstruction \
             in",
            dst.display()
        ),
    )?;
    let staged = (|| -> io::Result<()> {
        let mut input = File::open(src)?;
        io::copy(&mut input, &mut output)?;
        output.sync_all()
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(KataError::Storage(format!(
            "restore: stage {label} target {} failed: {e}",
            dst.display()
        )));
    }
    before_activate(name, &tmp).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    // No `remove_file(dst)` first: `rename(2)` replaces atomically, and removing
    // the target would open exactly the window this function exists to close.
    std::fs::rename(&tmp, dst).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        KataError::Storage(format!(
            "restore: activate {label} target {} failed: {e}",
            dst.display()
        ))
    })?;
    fsync_dir(parent)
}

fn copy_staged_file(src: &Path, dst: &Path, label: &str) -> KataResult<()> {
    match std::fs::remove_file(dst) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(KataError::Storage(format!(
                "restore: remove existing {label} target {} failed: {e}",
                dst.display()
            )));
        }
    }
    let mut input = File::open(src).map_err(|e| {
        KataError::Storage(format!(
            "restore: open staged {label} {} failed: {e}",
            src.display()
        ))
    })?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|e| {
            KataError::Storage(format!(
                "restore: create {label} target {} failed: {e}",
                dst.display()
            ))
        })?;
    io::copy(&mut input, &mut output).map_err(|e| {
        KataError::Storage(format!(
            "restore: copy staged {label} {} -> {} failed: {e}",
            src.display(),
            dst.display()
        ))
    })?;
    output.flush().map_err(|e| {
        KataError::Storage(format!(
            "restore: flush {label} target {} failed: {e}",
            dst.display()
        ))
    })?;
    Ok(())
}

/// The `<data_dir>` `*.db` names the durable-asset map classes
/// [`AssetAuthority::Rebuildable`].
///
/// This is the set [`discover_databases`] refuses to put in an artifact and the
/// set [`restore_data_dir_with_hooks`] clears from its target. Both halves are
/// enumerated from [`DURABLE_ASSETS`] rather than named here, so a future
/// rebuildable database inherits both without a second edit, and neither half
/// can drift from the other.
///
/// Today it is exactly `stage_cache.db`. The map's other `Rebuildable` rows are
/// trees (`recovery-generations`) or non-`.db` files
/// (`installed-main.shutdown.json`), none of which this pass reaches.
fn rebuildable_data_dir_databases() -> impl Iterator<Item = &'static str> {
    DURABLE_ASSETS
        .iter()
        .filter_map(|asset| match asset.location {
            AssetLocation::DataDirFile(name)
                if matches!(asset.authority, AssetAuthority::Rebuildable { .. })
                    && Path::new(name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("db")) =>
            {
                Some(name)
            }
            _ => None,
        })
}

/// Whether a discovered top-level `*.db` name goes into the artifact AT ALL.
///
/// # The invariant, the failure mode, the enforcement point, the proof
///
/// * **INVARIANT** — an artifact never carries a database the durable-asset map
///   classes [`AssetAuthority::Rebuildable`].
/// * **FAILURE MODE** — [`durability_tier`] gives `Rebuildable` the
///   [`DurabilityTier::BestEffort`] treatment: no `PRAGMA quick_check`, no
///   digest at capture, and therefore no digest to check at restore. That models
///   LOSS, and rebuildability answers loss. It does not model ALTERATION, and
///   nothing rebuilds a database that is PRESENT and wrong — a restored node
///   reads it as valid. `stage_cache.db`, the one such row, is read on the live
///   reuse path: `capsule_reuse_v1` is a HINT into the operational plane, so an
///   altered row is a miss or a failed re-verification — never a wrong answer —
///   but an unverified copy still has no business being installed.
/// * **WHY NOT THE DURABLE TIER INSTEAD**, which also closes that hole: because
///   then a bit-rotted CACHE would refuse the restore of the LEDGER, and a hint's
///   integrity must never block the restore of a plane that matters.
///   Carried-and-cheap and carried-and-expensive are both wrong for
///   this class, which leaves the disposition the class already licenses:
///   *"Losing it costs work, never correctness"*. So it is not carried, and the
///   row's `from` field is the repair procedure.
/// * **ENFORCEMENT POINT** — [`discover_databases`], the ONE site that produces
///   the set. Every consumer ([`backup_copy_order`], [`validate_database_names`],
///   [`capture_database`], [`BackupManifest::databases`], the `stores/` layout)
///   reads that set, so the defect is unreachable rather than forbidden by a
///   rule each of them could forget.
/// * **PROOF** — `no_rebuildable_or_transient_asset_is_reachable_by_database_discovery`
///   in `crates/core/tests/backup_durability_tests.rs` runs a real
///   [`backup_data_dir`] over a data directory holding a real `stage_cache.db`
///   and reads the artifact back.
///
/// # This is not the SKIP the `Excluded` arm argues against
///
/// [`backup_data_dir_with_hooks`] refuses rather than skips a `Transient`
/// database, on the ground that *"a skip would drop the name out of `databases`
/// with nothing anywhere saying an asset was dropped"*. That argument is about a
/// name the capture WAS licensed to take vanishing between discovery and the
/// manifest. This is the opposite case: the map is the standing record both that
/// the asset is not carried and of what rebuilds it, and
/// [`crate::durable_assets::assess_backup_class`] — the function that decides
/// whether an artifact is complete — is derived from that same map and reports
/// no omission, because a rebuildable asset is not one.
///
/// # What it REFUSES against what the absence CLAIMS
///
/// It refuses exactly the names [`classify_data_dir_entry`] resolves to a
/// `Rebuildable` row (sidecar- and prefix-folding included). The artifact claims
/// nothing about them at all — no manifest entry, no `stores/` file, no
/// consistency entry — which is the honest claim and the only one a restore can
/// act on. The gap, stated because it is real: an artifact carries no positive
/// record of the DECISION, so an operator reading only the manifest cannot tell
/// "not captured because rebuildable" from "this node never had one". Nothing
/// today needs to: the map answers it for every name, and
/// [`manifest_completeness`] is derived from the map rather than from the
/// manifest alone.
fn artifact_carries_database(name: &str) -> bool {
    !matches!(
        classify_data_dir_entry(name).map(|asset| asset.authority),
        Some(AssetAuthority::Rebuildable { .. })
    )
}

/// Remove from a restore TARGET every database an artifact deliberately does not
/// carry because the map calls it [`AssetAuthority::Rebuildable`].
///
/// See the call site in [`restore_data_dir_with_hooks`] for the ordering
/// argument and for why leaving one behind is worse than not carrying it. The
/// name set is [`rebuildable_data_dir_databases`], so this and the capture-side
/// refusal read the same map fact and cannot diverge — measured by
/// `the_capture_and_the_restore_refuse_the_same_rebuildable_set`.
///
/// Idempotent: a missing file is a success, so a restore into a fresh directory
/// and a re-run over an interrupted one both do the right thing.
///
/// `remove_file` is deliberate on both edges. On a SYMLINK it unlinks the link
/// and never the target, which is the direction this module wants everywhere —
/// a restore may not reach outside the data directory to delete something. On a
/// DIRECTORY it fails, and the restore fails with it: a `<data_dir>` entry
/// wearing a database's name as a directory is a state nothing here should
/// resolve by guessing.
fn clear_rebuildable_databases(data_dir: &Path) -> KataResult<()> {
    for name in rebuildable_data_dir_databases() {
        for stale in [
            format!("{name}-journal"),
            format!("{name}-wal"),
            format!("{name}-shm"),
            name.to_string(),
        ] {
            let path = data_dir.join(&stale);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(KataError::Storage(format!(
                        "restore: clear rebuildable database {} failed: {e}",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Enumerate the top-level `*.db` files in `data_dir` the artifact carries,
/// ignoring `-journal` / `-wal` / `-shm` sidecars and every name
/// [`artifact_carries_database`] refuses.
///
/// # A DIRECTORY is unreachable here by TYPE, not by policy
///
/// Stated in the code rather than left to be rediscovered, because the module-level "The
/// CAS tree is captured with its metadata" section above describes the CONSEQUENCE and this
/// function is the CAUSE, and a reader who arrives here first sees only an extension
/// filter.
///
/// The `!file_type.is_file()` skip below runs BEFORE the `.db` extension test,
/// so no directory entry can ever reach it. `<data_dir>/cas` is unreachable
/// here, and would stay unreachable if it were renamed `cas.db/`. The same is
/// true of every other directory.
///
/// **That is not a gap.** Widening the extension filter would not capture the
/// CAS tree, and neither would any rule expressible in this loop: capturing a
/// directory needs a capture MECHANISM, which is a SEPARATE pass —
/// [`discover_captured_trees`] — driven by
/// [`crate::durable_assets::CaptureRule::Tree`] rows. This function's contract
/// is deliberately narrow: everything downstream of it
/// ([`backup_copy_order`], [`validate_database_names`], [`capture_database`],
/// the `stores/` layout) is written against a `*.db` FILE, and a `discover`
/// that sometimes returned a directory would make every one of them a place to
/// get it wrong.
///
/// `recovery-generations/` remains uncaptured, correctly:
/// [`crate::durable_assets::DURABLE_ASSETS`] rows it with `CaptureRule::Excluded`,
/// so the tree pass does not select it either, and a directory the map does not
/// row at all is selected by neither pass.
fn discover_databases(data_dir: &Path) -> KataResult<Vec<String>> {
    let read_dir = std::fs::read_dir(data_dir).map_err(|e| {
        KataError::Storage(format!(
            "backup: read_dir({}) failed: {e}",
            data_dir.display()
        ))
    })?;
    let mut out = Vec::new();
    for entry in read_dir {
        let entry =
            entry.map_err(|e| KataError::Storage(format!("backup: read dir entry failed: {e}")))?;
        let file_type = entry
            .file_type()
            .map_err(|e| KataError::Storage(format!("backup: stat dir entry failed: {e}")))?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_db = Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("db"));
        // The map is ASKED, at the one site that produces this set. See
        // `artifact_carries_database` for why a rebuildable database is neither
        // carried cheaply nor carried expensively.
        if is_db && artifact_carries_database(name) {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

// -- tree capture and restore ------------------------------------------------
//
// # Why this is a SECOND pass and not a widened `discover_databases`
//
// [`discover_databases`] cannot reach a directory by TYPE, and the fix is not to
// teach it to: a function whose name says databases must not start returning
// trees, and every consumer of its output (`backup_copy_order`,
// `validate_database_names`, `capture_database`, the `stores/` layout) is
// written against a `*.db` FILE. So the tree set comes from a sibling pass with
// its own bounds, its own artifact root, and its own manifest vocabulary.
//
// # The set is DERIVED from the durable-asset map, never from a filename
//
// [`discover_captured_trees`] enumerates map rows — `AssetLocation::DataDirTree`
// carrying `CaptureRule::Tree` — so what gets captured is decided in
// `crate::durable_assets` and nowhere else. Today that is exactly `cas`. A
// hard-coded `"cas"` here would be shorter and would put a second authority
// beside the map: two places to change, and only one of them would fail a test.
//
// # `vcs.jj_repo` is the row this pass deliberately does NOT reach
//
// It is the map's other `CaptureRule::Tree` row and it is
// `AssetLocation::ConfigDeclared`, so it hangs off
// [`AssetRoot::OperatorDeclared`] — a root nothing in the tree resolves. The
// filter above excludes it by SHAPE rather than by name, and
// [`restorable_tree_asset`] refuses a manifest that claims it, by name. Its
// capture stays deferred until a resolver for the operator-declared root
// exists, and the per-entry activation below is unsound for it anyway: see
// [`activate_captured_tree`].

/// The map rows this binary captures as trees.
///
/// The filter is two conditions and both are load-bearing:
/// [`CaptureRule::Tree`] says the asset IS a tree, and
/// [`AssetLocation::DataDirTree`] says it hangs off the one root
/// [`backup_data_dir`] resolves. Dropping the second would sweep `vcs.jj_repo`
/// into a capture that has no path to resolve it.
fn capturable_tree_assets() -> impl Iterator<Item = &'static DurableAsset> {
    DURABLE_ASSETS.iter().filter(|asset| {
        matches!(asset.capture, CaptureRule::Tree { .. })
            && matches!(asset.location, AssetLocation::DataDirTree(_))
    })
}

/// What the MAP says a tree row's member paths claim about their own bytes.
///
/// ASKED of the row, never decided here. The alternative — `if tree.name ==
/// "cas"` at the two sites that need it — would be a second classification of
/// `cas` living beside [`DURABLE_ASSETS`], and a third content-addressed tree
/// would then have to be found in both places.
///
/// The non-`Tree` arm REFUSES instead of assuming
/// [`TreeMemberAddressing::PathOpaque`]. It is unreachable — every caller
/// resolves its asset through [`capturable_tree_assets`], which filters on the
/// variant — and a default here would be a silent downgrade of exactly the check
/// this function exists to supply.
///
/// # Errors
///
/// [`KataError::Storage`] if the row is not a [`CaptureRule::Tree`] row.
fn tree_member_addressing(asset: &DurableAsset) -> KataResult<TreeMemberAddressing> {
    match asset.capture {
        CaptureRule::Tree { members } => Ok(members),
        other => Err(KataError::Storage(format!(
            "backup: durable-asset row {:?} is being handled as a tree and its capture rule is \
             {other:?}; refusing rather than assuming the weaker addressing rule, which would \
             drop the content-to-path binding a content-addressed store needs",
            asset.location.name()
        ))),
    }
}

/// Bind one tree member's CONTENT to the PATH it is recorded at.
///
/// # The check this makes, and why the per-member digest does not
///
/// The per-member digest checks a member's bytes against the digest the
/// manifest records FOR THAT MEMBER, never against the member's PATH. For an
/// opaque tree that is all integrity can mean. For `cas` the path is a content
/// ADDRESS, and a manifest is unauthenticated JSON — so an artifact could carry
/// object X's bytes at object Y's address with Y's entry rewritten to X's
/// digest and length and [`CapturedTree::entry_digest`] recomputed over the
/// edited list, and every per-member check in the artifact would agree.
///
/// The manifest is not authenticated as a whole and this does not make it so —
/// the same forgery still works on the DATABASE records, whose names carry no
/// derivable relation to their contents. This closes the case where the relation
/// IS derivable, which is the case a check can be built for.
///
/// The scheme itself is [`crate::store::cas`]'s
/// ([`crate::store::cas::blob_relative_path_of_handle`]); this function knows
/// only that a rule applies and what to do when it is broken.
///
/// # The handle form is a TOCTOU NARROWING, not a closed hole — say it plainly
///
/// The address is derived through [`ProvenDir::open_source_file`] +
/// `blob_relative_path_of_handle`, from a descriptor obtained one component at
/// a time, so no level of the path can be redirected between the walk and the
/// hash. What it is NOT is the closure of a reachable exploit. Both call sites —
/// here in [`verify_captured_tree_sources`] and in [`capture_tree`] — already
/// hold a proven parent, so a path form's only window would be between the
/// caller's own `open_source_file` and a re-open of the SAME single component
/// under the SAME proven descriptor. Measured: a path form here leaves every
/// test in the module green, which is the honest report of a narrowing.
///
/// It is kept because it costs one `openat` and removes the second resolution
/// outright, and it is DESCRIBED as a narrowing because a reader who takes it
/// for a fix will not look for the residue — which is the class of mistake the
/// enumeration above this exists to stop.
///
/// # Errors
///
/// [`KataError::Storage`] naming the tree, the recorded path, and the address
/// the bytes actually require.
fn verify_member_address(
    addressing: TreeMemberAddressing,
    tree_name: &str,
    entry_path: &str,
    parent: &ProvenDir,
    file_name: &OsStr,
    maximum: u64,
    stage: &str,
) -> KataResult<()> {
    match addressing {
        TreeMemberAddressing::PathOpaque => Ok(()),
        TreeMemberAddressing::CasObject => {
            // The bytes are reached by `openat` relative to the descriptor the
            // caller proved, never by re-resolving a path. A `&Path` here would
            // derive the RESTORE-side address from whatever
            // `<artifact>/trees/<tree>/<shard>/<member>` resolved to on a second
            // open. See `verify_captured_tree_sources`.
            let bytes_at = parent.child_path(file_name);
            let (file, _) = parent.open_source_file(file_name, maximum, stage, "tree member")?;
            let required = crate::store::cas::blob_relative_path_of_handle(file, &bytes_at)?;
            if required == entry_path {
                return Ok(());
            }
            Err(KataError::Storage(format!(
                "{stage}: tree {tree_name} member {entry_path:?} holds bytes whose content \
                 address is {required:?}; the durable-asset map rows this tree's members as \
                 content-addressed, so the path IS the address and a store fed this member would \
                 serve bytes under an address they do not hash to"
            )))
        }
    }
}

/// Refuse a member path the addressing rule CANNOT PRODUCE, before anything is
/// created and before a single byte is written.
///
/// # The independent second kill, and why the ordering is the whole point
///
/// [`verify_member_address`] runs AFTER [`copy_hashing`] on capture and BEFORE
/// any target mutation on restore. That asymmetry — not any difference in the
/// path handling, which is identical on the two sides — is exactly why the
/// capture side was exploitable by a symlink at an intermediate component and
/// the restore side was not: on capture the refusal arrives once the parent has
/// been created and the bytes are already on somebody else's inode.
///
/// The full address check cannot be moved earlier, because it needs the STAGED
/// bytes — the copy is what could have diverged, so hashing the source instead
/// would be checking the wrong thing. The SHAPE can. For
/// [`TreeMemberAddressing::CasObject`] a member path is
/// [`crate::store::cas::blob_relative_path`]'s `<2 hex>/<64 hex>`, so any
/// component count other than 2 is a path the rule could not have emitted, and
/// that is decidable from the string alone.
///
/// So a deep member is refused at the point the list is read, and
/// [`ProvenDir`]'s `openat(2)` walk refuses the link independently. Two
/// mechanisms, either of which alone closes the escape;
/// `a_cas_member_path_shape_the_addressing_rule_cannot_produce_is_refused`
/// pins this one on its own.
///
/// [`TreeMemberAddressing::PathOpaque`] admits any shape, and must: an opaque
/// tree's member paths are whatever the source directory holds. Its depth is
/// bounded by [`MAX_TREE_PATH_COMPONENTS`] and its intermediate components are
/// bound by the `openat(2)` walk, which is the other half of why there are two.
///
/// # Errors
///
/// [`KataError::Storage`] naming the tree, the path, and the shape the rule
/// requires.
fn verify_member_path_shape(
    addressing: TreeMemberAddressing,
    tree_name: &str,
    entry_path: &str,
    stage: &str,
) -> KataResult<()> {
    match addressing {
        TreeMemberAddressing::PathOpaque => Ok(()),
        TreeMemberAddressing::CasObject => {
            let components = entry_path.split('/').count();
            if components == 2 {
                return Ok(());
            }
            Err(KataError::Storage(format!(
                "{stage}: tree {tree_name} member {entry_path:?} has {components} path components; \
                 the durable-asset map rows this tree's members as content-addressed, so a member \
                 path is exactly `<2 hex>/<64 hex>` and no addressing rule in this binary can \
                 produce this one"
            )))
        }
    }
}

/// The map row a manifest's tree NAME refers to, if this binary can restore it.
///
/// `None` covers two distinct artifacts and the caller renders both: a name the
/// map does not carry at all, and a name it carries as a tree under a root this
/// binary cannot resolve (`vcs.jj_repo`). Neither may be restored, and neither
/// may be silently skipped — a restore that reports success while omitting an
/// authoritative tree is exactly what this refusal exists to prevent.
fn restorable_tree_asset(name: &str) -> Option<&'static DurableAsset> {
    capturable_tree_assets().find(|asset| asset.location.name() == name)
}

/// The trees present under `data_dir`, as `(map row, source root)`.
///
/// A row whose directory is ABSENT is not returned, and that is the honest
/// answer rather than a zero-entry capture: a data directory with no `cas/` has
/// no CAS byte tree, and claiming to have captured one would put a name in
/// [`BackupManifest::tree_roots`] that [`manifest_completeness`] then reports as
/// covered. A directory that EXISTS and is empty IS returned and captured with
/// zero entries — that is a different fact ("the tree was captured; it held no
/// file-backed object") and an operator is entitled to it.
///
/// A symlink at the row's name is refused rather than followed, through
/// [`DirectoryState`] — the same predicate the artifact's own `stores/`,
/// `trees/` and `trees/<name>` are held to. A capture that followed one would
/// read bytes from outside the data directory and record them under a
/// `<data_dir>`-relative name.
///
/// # Errors
///
/// [`KataError::Storage`] if a row's name resolves to something that is neither
/// absent nor a real directory.
fn discover_captured_trees(data_dir: &Path) -> KataResult<Vec<(&'static DurableAsset, PathBuf)>> {
    let mut discovered = Vec::new();
    for asset in capturable_tree_assets() {
        let name = asset.location.name();
        let root = data_dir.join(name);
        if directory_state(
            &root,
            "backup",
            &format!(
                "the durable-asset map rows {name:?} as a directory tree and a capture may not \
                 follow a symlink out of the data directory to satisfy it"
            ),
        )? == DirectoryState::Absent
        {
            continue;
        }
        discovered.push((asset, root));
    }
    Ok(discovered)
}

/// Top-level names under a tree root that hold in-flight scratch.
fn tree_scratch_subdirs(name: &str) -> &'static [&'static str] {
    TREE_SCRATCH_SUBDIRS
        .iter()
        .find(|(tree, _)| *tree == name)
        .map_or(&[], |(_, skipped)| *skipped)
}

/// Enumerate every capturable regular file under a tree root, as sorted
/// tree-relative slash-separated paths.
///
/// Sorted so [`tree_entry_digest`] is reproducible; `read_dir` order is a
/// filesystem detail and two captures of the same tree must produce the same
/// index.
///
/// Skips, each for a stated reason:
///
/// * the scratch subdirectories [`TREE_SCRATCH_SUBDIRS`] names;
/// * this module's own in-flight `.capture-tmp` / `.restore-tmp` residue;
/// * a socket or device node — not an object, and a copy cannot reproduce one;
/// * a name that is not valid UTF-8, which no CAS object has (they are hex).
///
/// **A SYMLINK is refused rather than skipped.** "Not an object" is true of
/// what a symlink IS and wrong about what to do with one: a link at a SHARD
/// hides the whole subtree beneath it, and a skipping capture would publish a
/// manifest claiming the tree with `entry_count: 0`. The measurement and the
/// discriminator are at the refusal itself.
///
/// Exceeding `max_entries` is NOT an error here: it returns
/// [`WalkOutcome::OverEntryBound`] and stops walking, and [`capture_tree`] turns
/// that into an omission. See [`TreeCapture`] for the rule and the counter-case.
///
/// # Errors
///
/// [`KataError::Storage`] on any read failure, or on a path that exceeds
/// [`MAX_TREE_PATH_BYTES`] / [`MAX_TREE_PATH_COMPONENTS`].
///
/// `max_entries` is a PARAMETER rather than a read of [`MAX_TREE_ENTRIES`], and
/// the only production caller passes that constant. It is injectable because the
/// behaviour it guards is a claim this module makes in prose — *a capture over an
/// oversized tree omits it and names the omission* — and a claim whose only test
/// would have to materialize 65,537 files is a claim that does not get tested.
/// `an_oversized_tree_is_omitted_and_the_databases_are_still_captured` drives it
/// at a small bound; `the_manifest_bound_admits_a_maximal_tree_manifest` is what
/// pins the real constant to the manifest bound it has to fit inside. Both names
/// are BACKTICKED and not intra-doc links because both live in
/// `#[cfg(test)] mod tests`, which no rustdoc build sees, so nothing checks
/// them: a rename must update them by hand.
fn walk_tree_entries(
    root: &Path,
    tree_name: &str,
    prefix: &str,
    depth: usize,
    max_entries: usize,
    out: &mut Vec<String>,
) -> KataResult<WalkOutcome> {
    if depth > MAX_TREE_PATH_COMPONENTS {
        return Err(KataError::Storage(format!(
            "backup: tree {tree_name} nests deeper than {MAX_TREE_PATH_COMPONENTS} components at \
             {prefix:?}"
        )));
    }
    let read_dir = std::fs::read_dir(root).map_err(|e| {
        KataError::Storage(format!("backup: read_dir({}) failed: {e}", root.display()))
    })?;
    let mut children: Vec<(String, bool)> = Vec::new();
    for entry in read_dir {
        let entry = entry
            .map_err(|e| KataError::Storage(format!("backup: read tree entry failed: {e}")))?;
        let file_type = entry
            .file_type()
            .map_err(|e| KataError::Storage(format!("backup: stat tree entry failed: {e}")))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if depth == 0 && tree_scratch_subdirs(tree_name).contains(&name) {
            continue;
        }
        // THIS MODULE'S OWN in-flight scratch, at any depth. An interrupted
        // restore leaves `<member>.restore-tmp` inside a shard directory —
        // `activate_captured_tree` unlinks it on every error path it can see,
        // and a power loss is not one of them. The same three reasons
        // `TREE_SCRATCH_SUBDIRS` gives for `cas/tmp` apply: it is not an object,
        // nothing references it, and it is the one thing in the tree that is not
        // immutable.
        //
        // It is skipped rather than captured because capturing it is what turns
        // crash residue into a REFUSAL: for a content-addressed tree these bytes
        // do not hash to the path they sit at, so `verify_member_address` would
        // fail the whole backup over a partial file the store already ignores.
        if name.ends_with(RESTORE_TMP_SUFFIX) || name.ends_with(CAPTURE_TMP_SUFFIX) {
            continue;
        }
        // REFUSED, not skipped. A skip is how a capture publishes a claim to a
        // tree it does not hold: measured with `<data_dir>/cas/<shard>` replaced
        // by a symlink to the real shard directory, a skipping `backup_data_dir`
        // returned `Ok` with `tree_roots: ["cas"]` and a `CapturedTree` carrying
        // `entry_count: 0, total_byte_len: 0`. That is the "claims what it does
        // not hold" shape the tree capture exists to eliminate, arriving through
        // UNDER-capture instead of through a redirected write, and the operator
        // is told nothing: the completeness report reads the CLAIM, and the
        // claim is there.
        //
        // A symlink is not an object and not reproducible by a copy, and that
        // is no reason to skip it. `discover_captured_trees` already refuses the identical
        // input at the tree ROOT; refusing at every level below it is the same
        // rule, not a new one, and `TreeCapture`'s discriminator puts it here:
        // a bound overrun is capacity and DEGRADES, and a tree that is not the
        // shape the map says it is, is correctness and REFUSES. Nothing kata
        // writes under a tree root is ever a link — `CasStore::put` renames a
        // regular file into place — so no legitimate capture reaches this arm.
        if file_type.is_symlink() {
            return Err(KataError::Storage(format!(
                "backup: tree {tree_name} holds a symlink at {:?}; the durable-asset map rows this \
                 tree as a directory of objects, a copy cannot reproduce a link, and skipping it \
                 would publish an artifact claiming the tree while silently omitting everything \
                 under it",
                if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{prefix}/{name}")
                }
            )));
        }
        if file_type.is_dir() {
            children.push((name.to_string(), true));
        } else if file_type.is_file() {
            children.push((name.to_string(), false));
        }
    }
    children.sort();
    for (name, is_dir) in children {
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if relative.len() > MAX_TREE_PATH_BYTES {
            return Err(KataError::Storage(format!(
                "backup: tree {tree_name} entry path {relative:?} exceeds {MAX_TREE_PATH_BYTES} \
                 bytes"
            )));
        }
        if is_dir {
            if walk_tree_entries(
                &root.join(&name),
                tree_name,
                &relative,
                depth + 1,
                max_entries,
                out,
            )? == WalkOutcome::OverEntryBound
            {
                // Propagated immediately rather than continued: past the bound
                // the walk is only making a list the caller will throw away.
                return Ok(WalkOutcome::OverEntryBound);
            }
        } else {
            if out.len() >= max_entries {
                return Ok(WalkOutcome::OverEntryBound);
            }
            out.push(relative);
        }
    }
    Ok(WalkOutcome::Complete)
}

/// Whether [`walk_tree_entries`] enumerated the whole tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalkOutcome {
    /// Every capturable member is in `out`.
    Complete,
    /// The tree holds more than `max_entries` capturable members, so `out` holds
    /// a PREFIX and must not be captured from. Not an error — see
    /// [`TreeCapture`].
    OverEntryBound,
}

/// Validate one tree-relative entry path and return it as a relative
/// [`PathBuf`].
///
/// The manifest is unauthenticated JSON, so this is the only thing standing
/// between `"../../etc/shadow"` in an `entries` array and a write outside the
/// target. Refuses: an absolute path, any `.`/`..`/root/prefix component, a
/// backslash (which is a separator on the platforms this may one day run on and
/// is a legal filename byte on this one), an empty component, and anything over
/// the length/depth bounds.
///
/// # Errors
///
/// [`KataError::Storage`] naming the offending path.
fn tree_entry_relative_path(tree_name: &str, path: &str) -> KataResult<PathBuf> {
    let refuse = |why: &str| {
        Err(KataError::Storage(format!(
            "restore: tree {tree_name} entry path {path:?} is unsafe ({why}); a manifest is \
             unauthenticated JSON and a tree entry may only name a bounded relative path inside \
             its own root"
        )))
    };
    if path.is_empty() || path.len() > MAX_TREE_PATH_BYTES {
        return refuse("empty or over the length bound");
    }
    if path.contains('\\') || path.contains('\0') {
        return refuse("contains a backslash or NUL");
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > MAX_TREE_PATH_COMPONENTS {
        return refuse("deeper than the component bound");
    }
    let mut relative = PathBuf::new();
    for component in components {
        if component.is_empty() || component == "." || component == ".." {
            return refuse("has an empty, current-directory, or parent-directory component");
        }
        relative.push(component);
    }
    // Belt AND braces: the string checks above are what produce the readable
    // refusal, and this is what proves the RESULT is what they claimed — a
    // sequence of plain components and nothing else.
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return refuse("does not resolve to a sequence of plain path components");
    }
    Ok(relative)
}

/// The digest over a tree's entry LIST.
///
/// This is what makes per-member evidence trustworthy. Per-item digests whose
/// INDEX is unauthenticated are bypassed by editing the index: delete an entry
/// and its file is neither restored nor missed, because nothing else in the
/// artifact records that it existed. [`refuse_weakened_tier`] closes the same
/// shape one level up.
///
/// The encoding is explicit and length-prefixed rather than
/// `serde_json::to_vec`, so the value cannot change because a serializer changed
/// its formatting. Every field of every entry is covered, in order, with a
/// domain separator in front.
fn tree_entry_digest(entries: &[CapturedTreeEntry]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TREE_ENTRY_DIGEST_DOMAIN);
    hasher.update(&(entries.len() as u64).to_le_bytes());
    for entry in entries {
        hasher.update(&(entry.path.len() as u64).to_le_bytes());
        hasher.update(entry.path.as_bytes());
        match &entry.digest {
            Some(digest) => {
                hasher.update(&[1_u8]);
                hasher.update(&(digest.len() as u64).to_le_bytes());
                hasher.update(digest.as_bytes());
            }
            None => {
                hasher.update(&[0_u8]);
            }
        }
        hasher.update(&entry.byte_len.to_le_bytes());
    }
    hex_digest(hasher.finalize().as_bytes())
}

/// Stream an already-opened source into a newly created `dst_name` INSIDE a
/// proven directory, hashing the bytes as they pass.
///
/// ONE pass, deliberately. Copying and then digesting the copy leaves a window
/// in which the two disagree; digesting the SOURCE and then copying leaves a
/// window in which the source changed. Hashing the stream means the returned
/// digest is over exactly the bytes that were written, with no window at all.
///
/// `sync` is the [`DurabilityTier::Durable`] half: the bytes are `fsync`ed
/// before the caller renames.
///
/// The destination is a `.capture-tmp` inside the artifact or a `.restore-tmp`
/// inside the restore target, so it is opened through
/// [`ProvenDir::create_owned_file`]: a bare `File::create` follows a symlink at
/// the leaf, and a path-based [`create_owned_file`] binds the final component
/// and resolves `<shard>` above it on every open. See [`create_owned_file`] and
/// [`ProvenDir`].
///
/// **The SOURCE is a handle rather than a path.** Opening `src` here would make
/// the restore side re-resolve `<artifact>/trees/<tree>/<shard>/<member>` on
/// every member — the READ mirror of the write this function never does.
/// `src_display` is rendered in errors and resolved by nothing.
///
/// # Errors
///
/// [`KataError::Storage`] on any I/O failure, if the source exceeds `maximum`,
/// or if the destination is not a plain file this process owns outright.
fn copy_hashing(
    mut input: impl Read,
    src_display: &Path,
    dst_parent: &ProvenDir,
    dst_name: &OsStr,
    maximum: u64,
    sync: bool,
    label: &str,
) -> KataResult<([u8; 32], u64)> {
    let mut output = dst_parent.create_owned_file(
        dst_name,
        label,
        "a staged copy may not be written through a link, a hard link or a pipe: the bytes would \
         land outside the directory this stage publishes into while the rename moved the \
         obstruction in",
    )?;
    let dst = dst_parent.child_path(dst_name);
    let dst = dst.as_path();
    let src = src_display;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    let mut total = 0_u64;
    loop {
        let read = input.read(&mut buffer).map_err(|e| {
            KataError::Storage(format!("{label}: read {} failed: {e}", src.display()))
        })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > maximum {
            return Err(KataError::Storage(format!(
                "{label}: {} exceeds bounded maximum {maximum}",
                src.display()
            )));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(|e| {
            KataError::Storage(format!("{label}: write {} failed: {e}", dst.display()))
        })?;
    }
    output
        .flush()
        .map_err(|e| KataError::Storage(format!("{label}: flush {} failed: {e}", dst.display())))?;
    if sync {
        output.sync_all().map_err(|e| {
            KataError::Storage(format!("{label}: fsync {} failed: {e}", dst.display()))
        })?;
    }
    Ok((*hasher.finalize().as_bytes(), total))
}

/// Capture ONE tree into the artifact at its tier, returning its manifest
/// record.
///
/// Publishes every member through the same tmp -> `fsync` -> rename that
/// [`capture_database`] uses, for the same reason: [`backup_data_dir`] is
/// documented idempotent to one `out_dir`, so an interrupted capture must not
/// overwrite a good previous copy with a half-written one.
///
/// The directory `fsync`s are batched to one per directory the capture wrote
/// into, as the `stores/` fsync is, and safe for the same reason: nothing outside this function may
/// observe the artifact until the manifest is published, and the manifest is
/// published strictly last.
///
/// # A member that vanishes mid-capture is DROPPED, not fatal
///
/// No kata path deletes a CAS object, but the blob tree is a directory an
/// operator can touch. An entry that vanishes while this runs is omitted from the
/// record, which is sound for exactly the reason per-entry activation is: the
/// objects are immutable and content-addressed, so what the artifact holds is a
/// strict SUBSET of what the source held, and a missing ORPHAN is safe while a
/// dangling reference is not — boot's dangling-root verification refuses
/// the latter.
///
/// # A member whose bytes do not hash to its own path is FATAL
///
/// The map rows this tree's member addressing, and for `cas` it is
/// [`TreeMemberAddressing::CasObject`] — the path is the address. A source
/// member that fails [`verify_member_address`] is not an object at all; the live
/// store cannot serve it, and capturing it would put bytes into an artifact
/// under an address they do not hash to, which is precisely the state the
/// restore-side check refuses. Refusing HERE turns "your disaster-recovery
/// artifact is unrestorable, discovered on the day you need it" into "your live
/// CAS holds a corrupt object, named, today". That is a correctness fault, not a
/// capacity one, and the rule below is what keeps the two apart.
///
/// # A DESTINATION that is not a real directory is FATAL
///
/// [`discover_captured_trees`] refuses a symlink at the source root and this
/// refuses one at `<artifact>/trees/<name>` and at each `<shard>` beneath it. A
/// bare `create_dir_all` reports success for a symlink that resolves to a
/// directory, so a capture into such an artifact would publish a manifest
/// claiming the tree while every member sat outside the directory an operator
/// archives and restores from. See [`DirectoryState`].
///
/// **A directory check alone does not close it**: with every directory guarded,
/// an obstruction at the MEMBER'S STAGING FILE — `<shard>/<hex>.capture-tmp` —
/// escapes through a path-based `File::create`, and `rename(2)` then moves the
/// link into the artifact under an `entry_digest` byte-identical to the honest
/// run. [`create_owned_file`] carries the full enumeration of write positions
/// this module owns and the mechanism that closes them.
///
/// **Nor does guarding every leaf.** A symlink at an INTERMEDIATE component of a
/// member's parent — `aa` in a member at `aa/bb/member`, which
/// [`walk_tree_entries`] admits — is resolved by `mkdir(2)` and by `O_NOFOLLOW`
/// alike, because both bind their LAST component only. So the destination root
/// and every level below it are created and opened through [`ProvenDir`], relative to a
/// descriptor, and
/// [`verify_member_path_shape`] independently refuses a member path the
/// addressing rule cannot produce before any of it runs.
///
/// # Errors
///
/// [`KataError::Storage`] on any filesystem failure, when a member's bytes do
/// not satisfy the addressing rule the map states for this tree, or when the
/// destination root is not a real directory. Exceeding a BOUND is not an error —
/// see [`TreeCapture`].
fn capture_tree(
    source_root: &Path,
    trees_dir: &Path,
    asset: &'static DurableAsset,
    tier: DurabilityTier,
    bounds: TreeBounds,
) -> KataResult<TreeCapture> {
    let name = asset.location.name();
    let addressing = tree_member_addressing(asset)?;
    let mut relative_paths = Vec::new();
    if walk_tree_entries(
        source_root,
        name,
        "",
        0,
        bounds.entries,
        &mut relative_paths,
    )? == WalkOutcome::OverEntryBound
    {
        // Nothing has been written into the artifact yet — the walk runs before
        // the destination root is created — so the omission costs no cleanup.
        return Ok(TreeCapture::Omitted {
            reason: format!(
                "it holds more than the bounded maximum of {} capturable members",
                bounds.entries
            ),
        });
    }

    // `trees` is this module's own component and `<out_dir>` above it is the
    // operator's, which is exactly the split `ProvenDir::open` binds: the last
    // component with `O_NOFOLLOW`, everything above it resolved.
    let trees_root = ProvenDir::open(
        trees_dir,
        "backup",
        "an artifact's own tree directory may not be a link to somewhere else",
    )?;
    let member_requirement = format!(
        "a capture may not write tree {name:?} members through a symlink out of the artifact"
    );
    // The DESTINATION side of the same rule `discover_captured_trees` applies to
    // the source. It is not a bound, so it refuses rather than degrading: a
    // destination that is a link out of the artifact is a correctness fault, and
    // there is no smaller true artifact to fall back to.
    let destination = trees_root.child(
        OsStr::new(name),
        "backup",
        &format!(
            "a capture may not write tree {name:?} through a symlink out of the artifact; the \
             manifest would claim the asset while the bytes lived where a copy of the artifact \
             cannot reach them"
        ),
    )?;
    let destination_root = destination.path().to_path_buf();

    let durable = tier == DurabilityTier::Durable;
    // Keyed by the member-relative directory path and holding the PROVEN
    // descriptor for it, so a shard is created and proven once and the fsync
    // loop below has the set it needs without re-resolving any path.
    let mut shards: BTreeMap<PathBuf, ProvenDir> = BTreeMap::new();
    // ONE cache, so the joint budget reads exactly as the per-cache one did.
    let mut budget = DirectoryBudget::new();
    let mut entries: Vec<CapturedTreeEntry> = Vec::with_capacity(relative_paths.len());
    let mut total_byte_len = 0_u64;
    for relative in relative_paths {
        // BEFORE the parent is created and before a byte is written — see
        // `verify_member_path_shape` for why the shape check can move here and
        // the full address check cannot.
        verify_member_path_shape(addressing, name, &relative, "backup")?;
        let relative_path = tree_entry_relative_path(name, &relative)?;
        let src = source_root.join(&relative_path);
        let source_metadata = match std::fs::symlink_metadata(&src) {
            Ok(metadata) => metadata,
            // Reclaimed between the walk and the copy; see the doc above.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(KataError::Storage(format!(
                    "backup: stat tree member {} failed: {e}",
                    src.display()
                )));
            }
        };
        if !source_metadata.is_file() {
            continue;
        }
        if source_metadata.len() > bounds.file_bytes {
            // A BOUND, so the tree degrades rather than failing the backup —
            // and the whole tree goes, not just this member: a tree record
            // missing one member is a claim to hold an asset while holding part
            // of it, which is the dangling reference the artifact must never
            // carry.
            return Ok(TreeCapture::omitted_after_writing(
                &destination_root,
                format!(
                    "member {relative:?} is {} bytes, over the bounded per-member maximum of {}",
                    source_metadata.len(),
                    bounds.file_bytes
                ),
            ));
        }
        // Every level of the member's parent, created and opened relative to the
        // level above it — so the shard whose descriptor the write uses is the
        // shard that was proven, with no path left for anything to redirect.
        // Still one `mkdirat` per DISTINCT shard rather than one per member: the
        // map already had to hold the set for the fsync loop below.
        let parent_relative = relative_path.parent().unwrap_or(Path::new(""));
        open_member_parents(
            &destination,
            &mut shards,
            parent_relative,
            ParentWalk::Create,
            &mut budget,
            "backup",
            &member_requirement,
        )?;
        let parent = member_parent(&destination, &shards, parent_relative, "backup")?;
        let Some(file_name) = relative_path.file_name() else {
            return Err(KataError::Storage(format!(
                "backup: tree {name} member {relative:?} names no file"
            )));
        };
        // The SOURCE handle, opened once here rather than in `copy_hashing`, so
        // the `symlink_metadata` above describes the path this handle came
        // from; the same `NotFound` race arm covers both.
        let source_file = match File::open(&src) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(KataError::Storage(format!(
                    "backup: open tree member {} failed: {e}",
                    src.display()
                )));
            }
        };
        let tmp_name = suffixed_name(file_name, CAPTURE_TMP_SUFFIX);
        let copied = copy_hashing(
            source_file,
            &src,
            parent,
            &tmp_name,
            bounds.file_bytes,
            durable,
            "backup",
        );
        let (digest, byte_len) = match copied {
            Ok(copied) => copied,
            Err(error) => {
                parent.remove_file(&tmp_name);
                if !src.exists() {
                    // Same race, observed one layer later.
                    continue;
                }
                return Err(error);
            }
        };
        total_byte_len = total_byte_len.checked_add(byte_len).ok_or_else(|| {
            KataError::Storage(format!("backup: tree {name} total size overflowed"))
        })?;
        if total_byte_len > bounds.total_bytes {
            parent.remove_file(&tmp_name);
            // The third BOUND, and the third omission. See the per-member arm
            // above for why the whole tree goes.
            return Ok(TreeCapture::omitted_after_writing(
                &destination_root,
                format!(
                    "its members total more than the bounded maximum of {} bytes",
                    bounds.total_bytes
                ),
            ));
        }
        // The bytes that ACTUALLY went into the artifact, checked against the
        // address they are recorded at — the staged copy rather than the source,
        // because the artifact is what a restore will read and the copy is what
        // could have diverged.
        verify_member_address(
            addressing,
            name,
            &relative,
            parent,
            &tmp_name,
            bounds.file_bytes,
            "backup",
        )
        .inspect_err(|_| {
            parent.remove_file(&tmp_name);
        })?;
        parent
            .rename_within(
                &tmp_name,
                file_name,
                "backup",
                "publish captured tree member",
            )
            .inspect_err(|_| parent.remove_file(&tmp_name))?;
        entries.push(CapturedTreeEntry {
            path: relative,
            // No digest is taken on the cheap tier, so none is recorded. See
            // `CapturedAsset::digest` for why that is an `Option` and not an
            // empty string.
            digest: durable.then(|| hex_digest(&digest)),
            byte_len,
        });
    }
    if durable {
        destination.sync("backup")?;
        for shard in shards.values() {
            shard.sync("backup")?;
        }
    }
    // Sorted by `walk_tree_entries` already; re-sorted here so the invariant
    // `entry_digest` depends on is enforced at the point it is depended on
    // rather than three functions away.
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(TreeCapture::Captured(CapturedTree {
        name: name.to_string(),
        root: asset.location.root(),
        tier,
        entry_count: entries.len() as u64,
        total_byte_len,
        entry_digest: durable.then(|| tree_entry_digest(&entries)),
        entries,
    }))
}

/// What one [`capture_tree`] call did.
///
/// # The rule: a BOUND overrun degrades, an INTEGRITY failure refuses
///
/// [`capture_tree`] runs BEFORE any database copy, so a tree bound treated as a
/// hard error would fail the entire `kata backup`, databases included, for a
/// node with 65,537 file-backed objects — about 6.4 GiB of blobs, a large but
/// ordinary installation. That turns a partial success into a total failure,
/// which is exactly backwards: **degrade capacity, refuse correctness.** An
/// oversized tree is a capacity problem; the databases are still capturable and
/// the operator still needs them.
///
/// # The counter-case, which is real, and what decides it
///
/// There is an honest reading where refusing is right. The tree capture exists
/// to eliminate a SILENT loss: an artifact that carries `cas.db`'s object rows
/// and none of the bytes, restores clean, and fails later at the `cas` reader.
/// An artifact missing its CAS bytes is that artifact.
///
/// It is not, and the discriminator is whether the operator is TOLD. A silent
/// loss is one where nothing in the artifact, the manifest, or either report
/// says the bytes are absent, so there is no moment at which an operator could
/// act. An omission taken HERE is announced in three
/// places that all derive from one fact ([`BackupManifest::tree_roots`] does not
/// name the tree):
///
/// * [`manifest_completeness`] resolves the captured set against the map, so
///   `cas` appears in `missing_authoritative` — the completeness machinery,
///   reused rather than a second channel invented beside it;
/// * both `kata backup` and `kata restore` print that list, so the operator who
///   TAKES the backup and the operator who RESTORES it are told independently;
/// * the artifact makes no tree claim and carries no tree record, so a restore
///   of it cannot silently succeed as though the bytes were there — the
///   `cas_roots` rows it restores do not resolve, and
///   `verify_authoritative_roots_resolve` refuses that data directory at boot,
///   by name.
///
/// The CLASS is not part of that. An omission-free capture of the same source is
/// assessed `DataSnapshot` too, because
/// the structural [`manifest_completeness`] adapter cannot reach another class
/// from admitted structural inventory alone —
/// see `structural_inventory_alone_cannot_earn_recoverable`. The three
/// bullets above are the whole of what an operator gets, and they are enough;
/// this snapshot class is unchanged across the degradation and carries none of
/// it. The separate verified v4 recovery path is not subject to this claim.
///
/// The `reason` above is not written into the artifact; it is returned in
/// [`CaptureOutcome::omitted`] and rendered onto the completeness block's own
/// line for the asset. See [`CaptureOutcome`] for why it is a fact about the
/// RUN rather than a manifest field, and why a `tracing::warn!` on a verb with
/// no subscriber is not a channel.
///
/// An INTEGRITY failure gets none of this, and must not: a member whose bytes do
/// not hash to its own address is a corrupt store, not a large one, and there is
/// no smaller true artifact to fall back to.
enum TreeCapture {
    /// The tree is in the artifact and this is its manifest record.
    Captured(CapturedTree),
    /// The tree is NOT in the artifact, the artifact makes no claim to it, and
    /// `reason` says why in the operator's terms.
    Omitted {
        /// A phrase completing "the tree was omitted because …".
        reason: String,
    },
}

impl TreeCapture {
    /// [`Self::Omitted`], after removing whatever the abandoned capture had
    /// already written into the artifact.
    ///
    /// The partial copy is removed rather than left: it is bytes an operator
    /// pays to store and transfer that no manifest names, and a later reader
    /// finding a populated `trees/cas/` beside a manifest that claims no tree
    /// would have to guess which one is lying. A failure to remove it is
    /// deliberately NOT fatal — the artifact is already honest without the
    /// removal, and turning tidy-up into an error would re-create the total
    /// failure this whole path exists to avoid.
    fn omitted_after_writing(destination_root: &Path, reason: String) -> Self {
        // `remove_dir_all` and not a per-member unlink: the shard directories
        // this capture created are residue too, and `trees/` must come out of a
        // degraded capture exactly as empty as it went in.
        //
        // Deleting this line is what
        // `an_oversized_member_omits_the_tree_and_removes_the_members_already_published`
        // and `a_tree_over_the_total_byte_bound_is_removed_whole_including_its_shard_directories`
        // measure. With it commented out they report two and one surviving
        // members respectively, published into an artifact whose manifest claims
        // no tree.
        let _ = std::fs::remove_dir_all(destination_root);
        Self::Omitted { reason }
    }
}

/// Check every [`CapturedTree`] record for internal coherence and for a claim
/// this binary can honour.
///
/// It refuses a tree claim this binary cannot place — not every tree claim: a
/// `vcs.jj_repo` record is unrestorable here, a `cas` record is not, and
/// [`restorable_tree_asset`] is where that judgement lives.
///
/// Every other rule here is about a HAND-EDITED manifest; a capture cannot
/// produce any of these states:
///
/// * **claim and evidence must agree.** [`BackupManifest::tree_roots`] is what
///   [`manifest_completeness`] reports as captured and
///   [`BackupManifest::trees`] is what a restore acts on. A name in one and not
///   the other either tells an operator an asset is covered when nothing will
///   restore it, or restores an asset the completeness report says is missing.
/// * **the root is DERIVED, never read.** `cas` under `<data_dir>` and
///   `vcs.jj_repo` under an operator-named path are the case
///   [`CapturedTree::root`] exists for, and a manifest-supplied root would let
///   an edit redirect a restore's writes by one field.
/// * **the tier may not be weakened**, exactly as [`refuse_weakened_tier`] says
///   for a file asset, and for the same reason: the weaker claim is the one that
///   removes a check.
/// * **the index must match [`CapturedTree::entry_digest`]**. This is the
///   property that makes the per-member digests worth having.
///
/// # Errors
///
/// [`KataError::Storage`] naming the tree and the rule it broke.
fn validate_tree_records(manifest: &BackupManifest) -> KataResult<()> {
    if manifest.trees.len() > MAX_TREE_COUNT || manifest.tree_roots.len() > MAX_TREE_COUNT {
        return Err(KataError::Storage(format!(
            "restore: manifest claims more than {MAX_TREE_COUNT} trees; the durable-asset map \
             carries {MAX_TREE_COUNT} `CaptureRule::Tree` rows in total"
        )));
    }
    let claimed: BTreeSet<&str> = manifest.tree_roots.iter().map(String::as_str).collect();
    if claimed.len() != manifest.tree_roots.len() {
        return Err(KataError::Storage(
            "restore: manifest lists a tree root twice".to_string(),
        ));
    }
    let recorded: BTreeSet<&str> = manifest
        .trees
        .iter()
        .map(|tree| tree.name.as_str())
        .collect();
    if recorded.len() != manifest.trees.len() {
        return Err(KataError::Storage(
            "restore: manifest records a tree twice".to_string(),
        ));
    }
    // The FIRST disagreement, named. Reporting one is enough to refuse and is
    // what an operator can act on; the set is bounded by `MAX_TREE_COUNT`
    // anyway, so there is no case where a list would say more.
    if let Some(name) = claimed.symmetric_difference(&recorded).next() {
        return Err(KataError::Storage(format!(
            "restore: manifest tree claim and tree evidence disagree about {name:?}; \
             `tree_roots` is what the completeness report counts as captured and `trees` is what \
             a restore acts on, so a name in one and not the other is either a covered asset \
             nothing restores or a restored asset the report calls missing"
        )));
    }

    for tree in &manifest.trees {
        let Some(asset) = restorable_tree_asset(&tree.name) else {
            let known = DURABLE_ASSETS
                .iter()
                .any(|asset| asset.location.name() == tree.name);
            return Err(KataError::Storage(format!(
                "restore: manifest claims tree asset {:?}, which this binary cannot restore ({}). \
                 Restoring the rest would report success while omitting the asset entirely",
                tree.name,
                if known {
                    "the durable-asset map rows it under a durable root no capture or restore \
                     mechanism in this binary resolves"
                } else {
                    "the durable-asset map carries no `CaptureRule::Tree` row for that name"
                }
            )));
        };
        if tree.root != asset.location.root() {
            return Err(KataError::Storage(format!(
                "restore: manifest records tree {:?} under root {:?}, and the durable-asset map \
                 derives {:?} for it; a manifest-supplied root is not authority for where a \
                 restore writes",
                tree.name,
                tree.root,
                asset.location.root()
            )));
        }
        let derived = durability_tier(asset.authority);
        if tree.tier.strength() < derived.strength() {
            return Err(KataError::Storage(format!(
                "restore: manifest claims tree {:?} was captured at tier {:?}, and the \
                 durable-asset map derives {derived:?} for it from its `AssetAuthority`; \
                 accepting the weaker claim would drop the per-member integrity check the \
                 stronger one requires",
                tree.name, tree.tier
            )));
        }
        if tree.tier == DurabilityTier::Excluded {
            return Err(KataError::Storage(format!(
                "restore: manifest records tree {:?} as excluded, and an excluded asset is not \
                 captured at all",
                tree.name
            )));
        }
        if tree.entries.len() > MAX_TREE_ENTRIES {
            return Err(KataError::Storage(format!(
                "restore: manifest tree {:?} lists {} entries, over the bounded maximum \
                 {MAX_TREE_ENTRIES}",
                tree.name,
                tree.entries.len()
            )));
        }
        if tree.entry_count != tree.entries.len() as u64 {
            return Err(KataError::Storage(format!(
                "restore: manifest tree {:?} claims {} entries and lists {}",
                tree.name,
                tree.entry_count,
                tree.entries.len()
            )));
        }
        let durable = tree.tier == DurabilityTier::Durable;
        let mut total_byte_len = 0_u64;
        let mut previous: Option<&str> = None;
        for entry in &tree.entries {
            tree_entry_relative_path(&tree.name, &entry.path)?;
            if let Some(previous) = previous
                && previous >= entry.path.as_str()
            {
                return Err(KataError::Storage(format!(
                    "restore: manifest tree {:?} lists {:?} after {previous:?}; entries must be \
                     strictly ascending by path, which is what makes the entry digest \
                     reproducible and what stops a duplicate path being activated twice",
                    tree.name, entry.path
                )));
            }
            previous = Some(entry.path.as_str());
            if entry.byte_len > MAX_TREE_FILE_BYTES {
                return Err(KataError::Storage(format!(
                    "restore: manifest tree {:?} entry {:?} claims {} bytes, over the bounded \
                     maximum {MAX_TREE_FILE_BYTES}",
                    tree.name, entry.path, entry.byte_len
                )));
            }
            total_byte_len = total_byte_len.checked_add(entry.byte_len).ok_or_else(|| {
                KataError::Storage(format!(
                    "restore: manifest tree {:?} total size overflowed",
                    tree.name
                ))
            })?;
            if total_byte_len > MAX_TREE_TOTAL_BYTES {
                return Err(KataError::Storage(format!(
                    "restore: manifest tree {:?} totals more than the bounded maximum \
                     {MAX_TREE_TOTAL_BYTES}",
                    tree.name
                )));
            }
            match &entry.digest {
                Some(digest)
                    if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) => {}
                Some(_) => {
                    return Err(KataError::Storage(format!(
                        "restore: manifest tree {:?} digest for entry {:?} is not 64 lowercase \
                         hex characters",
                        tree.name, entry.path
                    )));
                }
                None if durable => {
                    return Err(KataError::Storage(format!(
                        "restore: manifest claims tree {:?} was captured durably and records no \
                         digest for entry {:?}; integrity for a tree is per-member or it is \
                         nothing",
                        tree.name, entry.path
                    )));
                }
                None => {}
            }
        }
        if total_byte_len != tree.total_byte_len {
            return Err(KataError::Storage(format!(
                "restore: manifest tree {:?} claims {} total bytes and its entries sum to \
                 {total_byte_len}",
                tree.name, tree.total_byte_len
            )));
        }
        match &tree.entry_digest {
            Some(expected) => {
                let actual = tree_entry_digest(&tree.entries);
                if &actual != expected {
                    return Err(KataError::Storage(format!(
                        "restore: manifest tree {:?} entry list digests to {actual} and the \
                         manifest records {expected}; the entry list has been edited since \
                         capture, and per-member digests over an unauthenticated index prove \
                         nothing about the members that index no longer names",
                        tree.name
                    )));
                }
            }
            None if durable => {
                return Err(KataError::Storage(format!(
                    "restore: manifest claims tree {:?} was captured durably and records no \
                     entry-list digest; the index would then be editable without evidence",
                    tree.name
                )));
            }
            None => {}
        }
    }
    Ok(())
}

/// The tier `tree` will be RESTORED at — derived from the map, floored, never
/// read as authority. See [`restore_tier`] for the full argument.
fn restore_tree_tier(tree: &CapturedTree) -> DurabilityTier {
    tree.tier.at_least(derived_tree_tier(&tree.name))
}

/// Verify every captured tree member IN THE ARTIFACT, without writing anything.
///
/// Runs before any target mutation, on both restore paths, so a tampered or
/// bit-rotted tree object is a refusal that NAMES the object rather than a
/// partially restored tree. That ordering is what preserves the module's
/// standing property — every source/artifact failure occurs before any target
/// mutation — now that an asset with many members is in the artifact.
///
/// It costs one extra read of the tree. The alternative, verifying only at
/// activation, would leave the ordinary failure (a corrupt artifact) discovered
/// halfway through writing the target.
///
/// # This is a READ side, and it resolves no full path
///
/// A position list derived from *"every WRITE position"* has no row below
/// `<artifact>/trees/<tree>`, because this function writes nothing. Measured
/// against a full-path form, with `<artifact>/trees/cas/<shard>` replaced by a
/// symlink to a directory outside the artifact holding the real object: this
/// function, [`preflight_restore_artifact`] — the gate `kata restore` runs
/// FIRST — and [`restore_data_dir`] all succeeded, placing every authoritative
/// CAS byte, read from OUTSIDE the artifact, into the operator's target. Nothing
/// was forged; the artifact was simply not the thing whose bytes were verified,
/// and an operator restoring from an archived copy of it gets a target missing
/// every object.
///
/// So every level is [`ProvenDir`]: the artifact root is opened as the
/// operator-typed path it is, `trees` and `<tree>` with
/// [`ProvenDir::open_child`], each member's parent through
/// [`open_member_parents`] under [`ParentWalk::Existing`], and the member itself
/// with [`ProvenDir::open_source_file`]. The bytes digested are the bytes of a
/// descriptor obtained one component at a time from a proven parent, so there is
/// no path left for a link at any level to redirect.
///
/// # Errors
///
/// [`KataError::Storage`] naming the tree, the member, and what disagreed.
fn verify_captured_tree_sources(backup_dir: &Path, manifest: &BackupManifest) -> KataResult<()> {
    if manifest.trees.is_empty() {
        return Ok(());
    }
    // The operator typed `<backup_dir>`, so every component of it is RESOLVED —
    // the same carve-out `activate_captured_tree` takes for `<data_dir>`, and
    // for the same reason (`/tmp` and `/home` are links on real hosts). The
    // carve-out stops at `trees`, which is this module's own component.
    let artifact_root = ProvenDir::open_operator_root(
        backup_dir,
        "restore",
        "a restore's artifact directory must be a directory",
    )?;
    let trees_root = artifact_root.open_child(
        OsStr::new(TREES_SUBDIR),
        "restore",
        &format!(
            "the manifest claims {} captured tree(s), and a restore may not read them through a \
             link out of the artifact",
            manifest.trees.len()
        ),
    )?;
    for tree in &manifest.trees {
        // The per-TREE root, not just `trees/`. This guarded the parent only,
        // and the gap was the mirror image of the capture-side one: a symlinked
        // `<artifact>/trees/cas` made `restore_data_dir` SUCCEED while reading
        // authoritative CAS bytes from outside the artifact — exactly what this
        // function's own requirement string says it prevents. `<shard>` below it
        // was the same hole one level further down; see the doc above.
        let member_requirement = format!(
            "the manifest claims tree {:?} and a restore may not read its members through a link \
             out of the artifact",
            tree.name
        );
        // `validate_tree_records` refuses every name without a map row, so this
        // is a single plain component by the time it is used as one.
        let root = trees_root.open_child(OsStr::new(&tree.name), "restore", &member_requirement)?;
        // `validate_tree_records` has already refused every name this binary
        // cannot place, so the row resolves; the addressing rule comes from it
        // rather than from the tree's name.
        let addressing = restorable_tree_asset(&tree.name)
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "restore: tree {:?} reached source verification without a durable-asset row",
                    tree.name
                ))
            })
            .and_then(tree_member_addressing)?;
        let mut shards: BTreeMap<PathBuf, ProvenDir> = BTreeMap::new();
        // PER TREE, because the cache is per tree: the previous tree's
        // descriptors are dropped with its map before this one opens any.
        let mut budget = DirectoryBudget::new();
        for entry in &tree.entries {
            let relative = tree_entry_relative_path(&tree.name, &entry.path)?;
            let parent_relative = relative.parent().unwrap_or(Path::new(""));
            open_member_parents(
                &root,
                &mut shards,
                parent_relative,
                ParentWalk::Existing,
                &mut budget,
                "restore",
                &member_requirement,
            )?;
            let parent = member_parent(&root, &shards, parent_relative, "restore")?;
            let Some(file_name) = relative.file_name() else {
                return Err(KataError::Storage(format!(
                    "restore: tree {} member {:?} names no file",
                    tree.name, entry.path
                )));
            };
            let path = parent.child_path(file_name);
            let (file, byte_len) = parent
                .open_source_file(file_name, MAX_TREE_FILE_BYTES, "restore", "tree member")
                .map_err(|error| {
                    KataError::Storage(format!(
                        "restore: tree {} member {:?} is missing or unreadable in the artifact: \
                         {error}",
                        tree.name, entry.path
                    ))
                })?;
            if byte_len != entry.byte_len {
                return Err(KataError::Storage(format!(
                    "restore: tree {} member {:?} is {} bytes in the artifact and {} in the \
                     manifest",
                    tree.name, entry.path, byte_len, entry.byte_len
                )));
            }
            if let Some(expected) = &entry.digest {
                // The HANDLE, not the path: `digest_file` would open
                // `root.join(relative)` a second time and hand a link at any
                // level the chance the walk above just took away.
                let actual = hex_digest(&digest_reader(file, &path)?);
                if &actual != expected {
                    return Err(KataError::Storage(format!(
                        "restore: tree {} member {:?} digests to {actual} and the manifest \
                         records {expected} (corrupt or tampered artifact)",
                        tree.name, entry.path
                    )));
                }
            }
            // The bytes agree with what the MANIFEST says about them. That is
            // every per-member check, and it is satisfiable by a manifest
            // that was edited to agree with forged bytes. This is the one that
            // is not: it derives the path the bytes REQUIRE and compares it to
            // the path they are recorded at, with the manifest as neither input.
            //
            verify_member_address(
                addressing,
                &tree.name,
                &entry.path,
                parent,
                file_name,
                MAX_TREE_FILE_BYTES,
                "restore",
            )?;
        }
    }
    Ok(())
}

/// Put one captured tree's members at their targets, one member at a time.
///
/// # PER-ENTRY activation, and why that is sound HERE and not in general
///
/// A file asset is activated by one [`activate_staged_file`] call, so the target
/// is wholly the old file or wholly the new one. A tree has no such single
/// rename available: `rename(2)` cannot atomically swap a populated directory
/// for another without leaving the old one somewhere, and a restore that
/// replaced the whole directory would destroy objects the target already holds
/// and the artifact does not.
///
/// So members land one at a time, and a failure part-way leaves a PARTIAL tree.
/// For `cas` that is sound, and the argument is specific to this asset rather
/// than to trees:
///
/// 1. **Objects are immutable and content-addressed.** A member is named by the
///    blake3 of its own bytes (`CasStore::blob_path`), so a member that is
///    present is necessarily correct — there is no version of an object to be
///    behind, and no half of one to be inconsistent with another half.
/// 2. **A partial tree is therefore a strict SUBSET**, never a mixture. Every
///    object present is exactly the object the artifact captured.
/// 3. **A missing object is the SAFE side of the asymmetry** — orphan bytes are
///    safe, dangling references are not — and it is not silent:
///    `crate::operational::cas_liveness::verify_authoritative_roots_resolve`
///    refuses a data directory whose
///    unreleased authoritative roots do not resolve, at boot, naming them.
/// 4. **Trees are restored BEFORE the databases** that reference them, so a
///    failure here leaves objects with no roots (safe) rather than roots with no
///    objects (not).
///
/// **None of that transfers to `vcs.jj_repo`, and a successor extending this
/// must meet the argument rather than reuse it.** A jj repository's op-log,
/// index, and store are mutable files with cross-file invariants: a partial
/// restore is a MIXTURE, not a subset, and nothing at boot refuses one.
/// [`validate_tree_records`] refuses that name for exactly this reason, so the
/// restriction is enforced and not merely documented.
///
/// # A member the target already holds is SKIPPED, and the skip is a PROOF
///
/// The per-member digest is re-computed against the target. Equal means the
/// bytes already there are the bytes the artifact captured — again because the
/// object is content-addressed — so the copy is redundant. That is what makes a
/// resumed restore cost one read per already-present object instead of a read
/// and a write, and it is a stronger resume condition than the
/// [`RestoreJournal`] can offer a tree: a journal entry names an ASSET, and a
/// tree needs the answer per MEMBER.
///
/// # Errors
///
/// [`KataError::Storage`] on any filesystem failure or digest mismatch.
fn activate_captured_tree(
    backup_dir: &Path,
    data_dir: &Path,
    tree: &CapturedTree,
    tier: DurabilityTier,
    before_activate: &mut impl FnMut(&str, &Path) -> KataResult<()>,
) -> KataResult<()> {
    debug_assert_eq!(
        tree.root,
        AssetRoot::MainDataDir,
        "validate_tree_records refuses every other root before this point"
    );
    // The SOURCE side, through the same walk as the target. Reading every member at
    // `backup_dir.join(TREES_SUBDIR).join(&tree.name).join(relative)` would let a symlink
    // at `<shard>` inside the artifact put the bytes a restore places under the operator's
    // CAS addresses somewhere outside the artifact those addresses came from. The artifact
    // root is the path the operator typed and is resolved; `trees` and everything below it
    // are this module's own layout and are not.
    let artifact_root = ProvenDir::open_operator_root(
        backup_dir,
        "restore",
        "a restore's artifact directory must be a directory",
    )?;
    let source_requirement = format!(
        "a restore may not read tree {:?} members through a link out of the artifact",
        tree.name
    );
    let source_root = artifact_root
        .open_child(OsStr::new(TREES_SUBDIR), "restore", &source_requirement)?
        .open_child(OsStr::new(&tree.name), "restore", &source_requirement)?;
    let addressing = restorable_tree_asset(&tree.name)
        .ok_or_else(|| {
            KataError::Storage(format!(
                "restore: tree {:?} reached activation without a durable-asset row",
                tree.name
            ))
        })
        .and_then(tree_member_addressing)?;
    // The operator typed `<data_dir>`, so every component of it is RESOLVED —
    // `/tmp` and `/home` are symlinks on real hosts. The carve-out stops here:
    // every component below is `openat`ed with `O_NOFOLLOW` relative to this
    // descriptor.
    let data_root = ProvenDir::open_operator_root(
        data_dir,
        "restore",
        "a restore's target data directory must be a directory",
    )?;
    // MANIFEST-DERIVED, so `DirectoryState`'s carve-out for "paths the operator
    // typed" does not reach it: the operator typed `<data_dir>` and the artifact
    // supplied the component below it. A bare `create_dir_all` would let a
    // symlink at `<data_dir>/cas` place every authoritative object outside the
    // target data directory — the shape `capture_tree` refuses at the mirror
    // position.
    let target = data_root.child(
        OsStr::new(&tree.name),
        "restore",
        &format!(
            "a restore may not place tree {:?} through a symlink out of the target data \
             directory; the objects would live where the node that boots against this data \
             directory cannot reach them",
            tree.name
        ),
    )?;
    let member_requirement = format!(
        "a restore may not place tree {:?} members through a symlink out of the target data \
         directory",
        tree.name
    );
    let durable = tier == DurabilityTier::Durable;
    // Same shape as `capture_tree`: the proven descriptor per DISTINCT shard,
    // which is also the set the fsync loop needs. TWO caches, because there are
    // two trees being walked — the artifact's (read) and the target's (write) —
    // and ONE budget shared between them, because the process holds both sets at
    // once. Bounding them independently is what let a 256-shard `cas` hold 512
    // directory descriptors under a 512 limit; see `DirectoryBudget`.
    let mut shards: BTreeMap<PathBuf, ProvenDir> = BTreeMap::new();
    let mut source_shards: BTreeMap<PathBuf, ProvenDir> = BTreeMap::new();
    let mut budget = DirectoryBudget::new();

    for entry in &tree.entries {
        // The manifest is unauthenticated JSON, so a member path out of one is a
        // path an attacker chose. `verify_captured_tree_sources` already ran the
        // full address check before this function was reached; this is the SHAPE
        // half, restated on the side that mutates the target so the property does
        // not depend on that call ordering. See `verify_member_path_shape`.
        verify_member_path_shape(addressing, &tree.name, &entry.path, "restore")?;
        let relative = tree_entry_relative_path(&tree.name, &entry.path)?;
        let parent_relative = relative.parent().unwrap_or(Path::new(""));
        open_member_parents(
            &target,
            &mut shards,
            parent_relative,
            ParentWalk::Create,
            &mut budget,
            "restore",
            &member_requirement,
        )?;
        let parent = member_parent(&target, &shards, parent_relative, "restore")?;
        let Some(file_name) = relative.file_name() else {
            return Err(KataError::Storage(format!(
                "restore: tree {} member {:?} names no file",
                tree.name, entry.path
            )));
        };
        if let Some(expected) = &entry.digest
            && let Some(present) = parent.open_regular(file_name, "restore")?
            && &hex_digest(&digest_reader(present, &parent.child_path(file_name))?) == expected
        {
            continue;
        }
        // The artifact side of the same walk, opened only once the resume proof
        // above has decided this member actually has to be copied.
        open_member_parents(
            &source_root,
            &mut source_shards,
            parent_relative,
            ParentWalk::Existing,
            &mut budget,
            "restore",
            &source_requirement,
        )?;
        let source_parent =
            member_parent(&source_root, &source_shards, parent_relative, "restore")?;
        let src = source_parent.child_path(file_name);
        let (source_file, _) = source_parent.open_source_file(
            file_name,
            MAX_TREE_FILE_BYTES,
            "restore",
            "tree member",
        )?;
        let tmp_name = suffixed_name(file_name, RESTORE_TMP_SUFFIX);
        let tmp = parent.child_path(&tmp_name);
        let (digest, byte_len) = copy_hashing(
            source_file,
            &src,
            parent,
            &tmp_name,
            MAX_TREE_FILE_BYTES,
            durable,
            "restore",
        )
        .inspect_err(|_| parent.remove_file(&tmp_name))?;
        let landed = hex_digest(&digest);
        let mismatch = match &entry.digest {
            Some(expected) if &landed != expected => Some(expected.clone()),
            _ => None,
        };
        if let Some(expected) = mismatch {
            parent.remove_file(&tmp_name);
            return Err(KataError::Storage(format!(
                "restore: tree {} member {:?} landed as {landed} and the manifest records \
                 {expected}; the bytes that reached the target are not the bytes that were \
                 captured",
                tree.name, entry.path
            )));
        }
        if byte_len != entry.byte_len {
            parent.remove_file(&tmp_name);
            return Err(KataError::Storage(format!(
                "restore: tree {} member {:?} copied {byte_len} bytes and the manifest records {}",
                tree.name, entry.path, entry.byte_len
            )));
        }
        before_activate(&format!("{}/{}", tree.name, entry.path), &tmp)
            .inspect_err(|_| parent.remove_file(&tmp_name))?;
        parent
            .rename_within(&tmp_name, file_name, "restore", "activate tree member")
            .inspect_err(|_| parent.remove_file(&tmp_name))?;
    }
    if durable {
        // The tree ROOT's own directory entry lives in `data_dir`, so that is
        // what has to be `fsync`ed for the root to survive a power loss — not
        // the root itself.
        data_root.sync("restore")?;
        target.sync("restore")?;
        for shard in shards.values() {
            shard.sync("restore")?;
        }
    }
    Ok(())
}

/// Copy a single SQLite database from `src` to `dst` via `VACUUM INTO`.
///
/// The destination must not already exist (SQLite refuses to overwrite),
/// so any prior copy is removed first. The source is opened read-write but
/// only read from; `VACUUM INTO` runs inside a read transaction, so this is
/// safe against concurrent writers on `src`.
///
/// `VACUUM INTO` is the one write in this module whose `open(2)` takes no flags
/// from us, so the destination is cleared through [`claim_owned_path`] — the same
/// [`create_owned_file`] open every other write position uses, followed by an
/// `unlink(2)`. What that buys over the `if dst.exists()` guard it replaces: that
/// one RESOLVED the path, answered `false` for a dangling symlink, and left
/// SQLite creating the copy through the link.
fn vacuum_into(src: &Path, dst: &Path) -> KataResult<()> {
    claim_owned_path(
        dst,
        "backup",
        "a copy may not be vacuumed through a link, a hard link or a pipe: the bytes would land \
         outside the directory this stage publishes into while the rename moved the obstruction in",
    )?;
    let conn = Connection::open_with_flags(
        src,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| {
        KataError::Storage(format!("backup: open source {} failed: {e}", src.display()))
    })?;
    // `VACUUM INTO` takes a filename expression; a bound parameter is
    // supported, but we build an escaped single-quoted literal so the
    // statement is unambiguous across sqlite builds. Single quotes in the
    // path (rare, but legal on unix) are escaped by doubling.
    let dst_str = dst.to_string_lossy().replace('\'', "''");
    conn.execute_batch(&format!("VACUUM INTO '{dst_str}'"))
        .map_err(|e| {
            KataError::Storage(format!(
                "backup: VACUUM INTO {} from {} failed: {e}",
                dst.display(),
                src.display()
            ))
        })?;
    Ok(())
}

// -- durability primitives ---------------------------------------------------
//
// The ORDERING is the load-bearing part: **write to tmp, fsync the FILE, rename,
// then fsync the DIRECTORY.** A rename is only atomic once the directory entry
// holding it is durable, so a version that stops after the file fsync is the
// classic almost-right one: the bytes survive and the name that reaches them may
// not.

/// Publish `bytes` at `dir/name` durably: stream into a `name + RESTORE_TMP`
/// beside it, `fsync` the file, `rename` it into place (atomic — a reader sees
/// the old bytes or the new bytes, never a splice of both), then `fsync` the
/// DIRECTORY so the rename itself survives a power loss.
fn durable_publish(dir: &Path, name: &str, bytes: &[u8], label: &str) -> KataResult<()> {
    let path = dir.join(name);
    let tmp = suffixed_path(&path, RESTORE_TMP_SUFFIX);
    // `create_owned_file` and not `File::create`: this publishes the MANIFEST,
    // the bundled config and the restore journal, so a link at the staging name
    // would put an artifact's own claim outside the artifact. See its enumeration
    // for the full position list.
    let mut file = create_owned_file(
        &tmp,
        "backup",
        "an artifact may not publish its own metadata through a link, a hard link or a pipe",
    )?;
    let staged = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(KataError::Storage(format!(
            "backup: stage {label} {} failed: {e}",
            path.display()
        )));
    }
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        KataError::Storage(format!(
            "backup: publish {label} {} failed: {e}",
            path.display()
        ))
    })?;
    fsync_dir(dir)
}

// There is no `fsync_file(&Path)`: `capture_database` holds the proven
// descriptor for the `.capture-tmp` it digested and calls `sync_all` on THAT,
// so the bytes measured, the bytes hashed and the bytes made durable are one
// inode reached once, instead of three separate resolutions of the same path.

/// `fsync` a directory so a rename inside it is durable.
fn fsync_dir(dir: &Path) -> KataResult<()> {
    File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|e| {
            KataError::Storage(format!(
                "backup: fsync directory {} failed: {e}",
                dir.display()
            ))
        })
}

/// `<path><suffix>`.
fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = path.to_path_buf().into_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

/// blake3 a handle the caller has already PROVEN and opened. `path` is rendered
/// in errors and never resolved.
///
/// # There is no path form of this, deliberately
///
/// A path form — a bare `File::open` with no `lstat`, no size bound and no
/// `O_NONBLOCK` — would reopen two holes:
///
/// * [`preflight_restore_artifact`] digesting `<artifact>/`[`CONFIG_COPY_NAME`]
///   with NOTHING in front: a symlink there makes the artifact's own integrity
///   gate hash bytes from OUTSIDE the artifact and be SATISFIED by them, and a
///   reader-less FIFO there HANGS `kata restore` forever, in the first gate,
///   before any lease and with no output.
/// * [`journal_records_activation`] resuming a DATABASE after a
///   `target.exists()` — which RESOLVES. With a matching journal,
///   [`restore_data_dir`] would return `Ok` while `<data_dir>/<database>` stayed
///   a symlink to a file outside the target: a restore reporting success having
///   placed nothing.
///
/// Both are reached through a [`ProvenDir`] descriptor
/// ([`ProvenDir::open_source_file`] / [`ProvenDir::open_regular`]). A hardened
/// path form would be one a new call site could reintroduce the window
/// through.
///
/// # Errors
///
/// [`KataError::Storage`] on a read failure.
fn digest_reader(mut source: impl Read, path: &Path) -> KataResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    io::copy(&mut source, &mut hasher).map_err(|e| {
        KataError::Storage(format!(
            "backup: read {} for digest failed: {e}",
            path.display()
        ))
    })?;
    Ok(*hasher.finalize().as_bytes())
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

use kata_types::time::now_ms;

// There is no pre-upgrade snapshot: a durable shape change on every plane is
// REFUSAL PLUS A FRESH DATA DIRECTORY (`OPERATIONAL_SCHEMA_VERSION`'s note), which
// never rewrites a database in place and so has nothing to snapshot.

/// Integration-test seam for the restore crash boundary.
///
/// `test-support` is disabled in shipped builds, so no production caller can
/// select it. It exists because the boundary this hook brackets — "the
/// replacement is durable at `<target>.restore-tmp` and the target has not been
/// replaced" — is the one a partial-target claim has to be measured at, and
/// `crates/core/tests/` cannot reach a `pub(crate)` function.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn restore_data_dir_aborting_before_activation(
    backup_dir: &Path,
    data_dir: &Path,
    restore_config_to: Option<&Path>,
    before_activate: impl FnMut(&str, &Path) -> KataResult<()>,
) -> KataResult<BackupManifest> {
    restore_data_dir_with_hooks(backup_dir, data_dir, restore_config_to, before_activate)
}

/// Integration-test seam for the tree BOUNDS.
///
/// # It takes all three because the byte bounds are the ones that matter
///
/// [`MAX_TREE_ENTRIES`] = 65,536 is decided BEFORE the destination root exists,
/// so an entry-bound omission writes nothing and removes nothing.
/// [`MAX_TREE_FILE_BYTES`] (1 TiB) and [`MAX_TREE_TOTAL_BYTES`] (4 TiB) are
/// discovered mid-copy and are the only way to reach
/// [`TreeCapture::omitted_after_writing`] — the removal path — whose artifact-
/// level consequences (`trees/` left with no partial member, no tree claim, the
/// databases still captured) are claims about `backup_data_dir`'s OUTPUT and
/// belong in `crates/core/tests/backup_durability_tests.rs`, which calls this.
///
/// The alternative for the byte bounds is a fixture holding a terabyte, which is
/// how a claim about a degradation path stays a claim.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn backup_data_dir_with_tree_bounds(
    data_dir: &Path,
    out_dir: &Path,
    max_entries: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> KataResult<CaptureOutcome> {
    backup_data_dir_with_hooks(
        data_dir,
        out_dir,
        None,
        TreeBounds {
            entries: max_entries,
            file_bytes: max_file_bytes,
            total_bytes: max_total_bytes,
        },
        || {},
        |_name| {},
    )
}

/// Integration-test seam that RE-SEALS a hand-edited entry list.
///
/// Named for what it is FOR. A test that edits `entries` and leaves
/// [`CapturedTree::entry_digest`] alone is refused by
/// [`validate_tree_records`]'s index check, which is the right refusal and the
/// wrong one to be measuring when the property under test is something else
/// entirely. An attacker holding an artifact can recompute this digest — it is
/// unkeyed, and [`CapturedTree`]'s own doc says the manifest is unauthenticated
/// JSON — so a test that could not would be modelling a weaker adversary than
/// the real one.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[must_use]
pub fn reseal_tree_entry_digest(entries: &[CapturedTreeEntry]) -> String {
    tree_entry_digest(entries)
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;
