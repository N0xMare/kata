//! Declared portable artifacts.
//!
//! # Invariant
//!
//! `operational.db` is authoritative for WHICH artifact references this node
//! authorized; the CAS owns the bytes. So exactly two durable facts live here and
//! nothing else does: the `artifacts` row, and the `cas_roots` row that retains the
//! object the row names. Both commit in ONE writer transaction, because a row naming
//! bytes nothing retains is a dangling reference and an unreferenced object is an
//! artifact nobody can materialize.
//!
//! # Identity
//!
//! `artifact_id` is [`ArtifactRef`]'s id, which folds `(object_id, size_bytes,
//! privacy)` field-wise under the execution-contract domain tag. **It does not fold an
//! owner, so neither does the row.**
//!
//! An owner column would make that contradiction reachable rather than theoretical.
//! Two executions whose stages write byte-identical `/out` trees produce ONE
//! `artifact_id`; so do two capsules mapping the canonical EMPTY tree at `/out`, which
//! is every capsule this plane assembles. The second declarer would be refused as a
//! "divergent re-declaration" for having a different owner — a content address made to
//! carry a retention obligation it cannot express.
//!
//! So the split is:
//!
//! * the `artifacts` ROW is a NODE-LEVEL CONTENT CLAIM: *this node authorized this
//!   `(object, size, privacy)` reference and reads its object this `kind`*. One row per
//!   artifact id, no owner;
//! * `cas_roots` carries OWNERSHIP, one row per `(owner, artifact_object, object)`.
//!   Declaring an artifact a second owner also wants is an idempotent row plus that
//!   owner's own root.
//!
//! Neither is ever released or deleted: kata has no artifact release verb and no CAS
//! collection, so a declaration is permanent for the life of the data directory.
//!
//! `idx_artifacts_object` (UNIQUE) has one reason: two ids over one object can differ
//! only in privacy (object and size are fixed by the bytes), and the same bytes declared
//! both as a public artifact and as a private one discharge the private classification
//! through the public twin.
//!
//! # No per-manifest index is owed, and this is why
//!
//! A TREE artifact's manifest names member objects. No index over those members is
//! owed here, because there is no row to index: the members are not rows, they are
//! CONTENT of the manifest object the artifact's own root names, and every reader of
//! them reads that content. A `artifact_members` table would be a second answer to a
//! question the manifest bytes already answer exactly, and the two could disagree.
//!
//! What IS owed, and is not implied by the above, is the per-OBJECT uniqueness
//! described under "Identity"; see `idx_artifacts_object`'s comment in the DDL for the
//! full argument.
//!
//! # Trust boundary
//!
//! ADR-0001 trust boundary 2: bytes are preserved before durable references. It is
//! carried the way every other root in this plane carries it — through a
//! [`DurableObject`] receipt, which only `CasStore::put_durable` can mint and only
//! after the bytes are fsync-durable. [`ArtifactDeclaration::for_durable_object`]
//! additionally refuses an [`ArtifactRef`] whose object or size DISAGREES with the
//! receipt, so a row cannot describe one object while its root retains another, and
//! [`ArtifactDeclaration::for_durable_tree`] is the ONLY way to a `kind='tree'` row —
//! it re-derives the address from the manifest, because a tree row whose object does
//! not parse would mislead every reader of it, permanently.
//!
//! [`DurableObject`]: crate::store::cas::DurableObject

use kata_types::cache::object_id_for_canonical_bytes;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
use kata_types::tree_artifact::TreeManifest;
use kata_types::tree_delta::TreeDelta;
use rusqlite::{OptionalExtension, Transaction, params};

use super::records::ARTIFACT_OBJECT_ROOT_PURPOSE;
use super::repo::upsert_cas_root;
use super::{CasRootOwner, CasRootSpec, OperationalDb};

/// HOW the object a row names is to be read.
///
/// Three arms, because three are representable: the object either IS the
/// artifact's bytes, or it is a `kata_types::tree_artifact::TreeManifest` naming
/// member objects, or it is a `kata_types::tree_delta::TreeDelta` whose `Write`
/// nodes name member objects. The distinction is not cosmetic — a `Tree` or
/// `TreeDelta` artifact's members must stay reachable through the object's
/// CONTENT for as long as the object is retained, which is the one place in
/// this plane where reachability is not row existence alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// The object is the artifact's bytes.
    Blob,
    /// The object is a tree manifest whose entries name member objects.
    Tree,
    /// The object is a tree delta whose `Write` nodes name member objects.
    TreeDelta,
}

impl ArtifactKind {
    /// The stable on-disk `kind` label. Never an integer discriminant: reordering the
    /// arms must not be able to alias one kind onto the other.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::TreeDelta => "tree_delta",
        }
    }

    fn from_stored(label: &str) -> KataResult<Self> {
        match label {
            "blob" => Ok(Self::Blob),
            "tree" => Ok(Self::Tree),
            "tree_delta" => Ok(Self::TreeDelta),
            other => Err(KataError::Storage(format!(
                "operational.db artifacts.kind {other:?} is outside the declared vocabulary \
                 (blob, tree, tree_delta)"
            ))),
        }
    }
}

fn privacy_from_stored(label: &str) -> KataResult<ArtifactPrivacy> {
    match label {
        "public" => Ok(ArtifactPrivacy::Public),
        "private" => Ok(ArtifactPrivacy::Private),
        other => Err(KataError::Storage(format!(
            "operational.db artifacts.privacy {other:?} is outside the declared vocabulary \
             (public, private)"
        ))),
    }
}

/// A complete artifact declaration, constructible only from a durable object.
///
/// # Enforcement
///
/// The fields are private and the only constructors are
/// [`ArtifactDeclaration::for_durable_object`] (a BLOB) and
/// [`ArtifactDeclaration::for_durable_tree`] (a TREE), both of which take a
/// [`DurableObject`]
/// receipt — the same shape `CasRootSpec::for_object` uses, and for the same reason: a
/// declaration naming bytes that were never written is UNCONSTRUCTIBLE rather than
/// merely discouraged. The root spec is built inside the constructor, so no caller can
/// present a row and a root that describe different objects.
///
/// [`ArtifactKind`] is NOT a parameter of either one; it is decided by WHICH
/// constructor ran. A `Tree` row is a promise to every reader that the object parses
/// as a tree manifest, and the tree constructor keeps that promise by re-deriving the
/// address from the manifest — see its own docs for why a caller-supplied `kind` was
/// the wrong shape.
///
/// [`DurableObject`]: crate::store::cas::DurableObject
#[derive(Clone, Debug)]
pub struct ArtifactDeclaration {
    artifact_id: [u8; 32],
    object_id: [u8; 32],
    size_bytes: u64,
    privacy: ArtifactPrivacy,
    kind: ArtifactKind,
    /// The CALLER's retention claim: `(owner, artifact_object, authoritative,
    /// Object(object_id))`. The owner exists ONLY here — the `artifacts` row
    /// carries none — so this field is the whole of what a declaration says about who
    /// is retaining the bytes.
    object_root: CasRootSpec,
}

impl ArtifactDeclaration {
    /// Declare `reference` over an object whose bytes are PROVEN durable.
    ///
    /// # Crash boundary
    ///
    /// The only window this verb opens is K8 —
    /// `operational.after_cas_object_durable_before_root` — and it already fires, at
    /// the end of `CasStore::put_durable`, which is the sole producer of the receipt
    /// this constructor requires. Nothing else here crosses a durability edge: the row
    /// and its root commit together.
    ///
    /// There is deliberately NO `after_tree_members_durable_before_manifest_durable`
    /// boundary here. That edge is real, but it belongs to the code that
    /// PUBLISHES a tree — member blobs, then the manifest — and no writer in this
    /// module does: `declare_artifact` is handed one already-durable manifest. A
    /// seam registered here would model a window no transaction in this build can be
    /// interrupted in, which is a kill point that proves nothing. It attaches with the
    /// snapshotter that publishes members.
    ///
    /// # There is no `kind` parameter
    ///
    /// This constructor builds a [`ArtifactKind::Blob`] declaration and nothing else.
    /// `kind: Tree` is UNREACHABLE from here, because a `Tree` row is a promise to every
    /// reader that the object's bytes PARSE as a
    /// [`TreeManifest`](kata_types::tree_artifact::TreeManifest). A caller cannot be
    /// trusted to have checked that, and a parameter it could get wrong is exactly the
    /// shape that would let it. [`Self::for_durable_tree`] takes the manifest itself and
    /// re-derives the address from it, so a `Tree` row whose object is not a manifest is
    /// unconstructible rather than merely discouraged.
    ///
    /// # Failure
    ///
    /// Refuses an [`ArtifactRef`] whose `object_id` or `size_bytes` disagrees with the
    /// receipt. That is the refused set, and it is the whole point of taking both: a
    /// reference is a CLAIM about an object's address and length, the receipt is the
    /// CAS's answer for the bytes it actually wrote, and a declaration that recorded
    /// the claim while rooting the answer would produce a row whose id cannot be
    /// re-derived from the bytes anyone materializes.
    pub fn for_durable_object(
        reference: &ArtifactRef,
        owner: CasRootOwner,
        durable: &crate::store::cas::DurableObject,
    ) -> KataResult<Self> {
        Self::checked(reference, ArtifactKind::Blob, owner, durable)
    }

    /// Declare a TREE artifact from the MANIFEST itself.
    ///
    /// # Invariant
    ///
    /// THE BYTES ARE RE-DERIVED, NOT TAKEN ON TRUST. The address is recomputed from
    /// `manifest.manifest_bytes()` — the same single spelling a publisher must have
    /// passed to `put_durable` — and refused unless it equals the receipt's object id
    /// and length. So a `Tree` row can only exist over an object whose bytes THIS
    /// BUILD can serialize a `TreeManifest` to, which is what makes every manifest
    /// reader's parse total rather than hopeful. A row is never released or deleted, so a
    /// `Tree` row over non-manifest bytes could not be repaired by any verb.
    ///
    /// `privacy` is a parameter and the manifest is not asked for it: privacy is a
    /// CLASSIFICATION the declaring caller makes, the one part of the reference the
    /// manifest cannot supply. Everything else — the object id, the length, and
    /// therefore the [`ArtifactRef`] and the artifact id — is derived here, so there is
    /// no reference for a caller to present that could disagree with the bytes.
    ///
    /// # Failure
    ///
    /// Refuses a manifest that does not serialize, and refuses a receipt whose object
    /// id or size is not the canonical address and length of `manifest`'s bytes. That
    /// is the refused set.
    pub fn for_durable_tree(
        manifest: &TreeManifest,
        privacy: ArtifactPrivacy,
        owner: CasRootOwner,
        durable: &crate::store::cas::DurableObject,
    ) -> KataResult<Self> {
        let bytes = manifest.manifest_bytes()?;
        let address = object_id_for_canonical_bytes(&bytes);
        if address != durable.object_id() {
            return Err(KataError::Validation(format!(
                "tree artifact declaration refused: this manifest's canonical bytes address \
                 {address} but the durability receipt is for {}. A tree row is a promise that the \
                 rooted object PARSES as a tree manifest — so the promise is only made over bytes \
                 re-derived from the manifest itself",
                durable.object_id()
            )));
        }
        if bytes.len() as u64 != durable.size() {
            return Err(KataError::Validation(format!(
                "tree artifact declaration refused: this manifest's canonical bytes are {} long \
                 but the durability receipt recorded {}",
                bytes.len(),
                durable.size()
            )));
        }
        let reference = ArtifactRef::new(address, bytes.len() as u64, privacy);
        Self::checked(&reference, ArtifactKind::Tree, owner, durable)
    }

    /// Declare a TREE DELTA artifact from the DELTA itself.
    ///
    /// # Invariant
    ///
    /// [`Self::for_durable_tree`]'s argument, restated for the delta: the address is
    /// recomputed from `delta.delta_bytes()` — the same single spelling a publisher
    /// must have passed to `put_durable` — and refused unless it equals the receipt's
    /// object id and length. So a `TreeDelta` row can only exist over an object whose
    /// bytes THIS BUILD can serialize a [`TreeDelta`] to, which is what makes every
    /// delta reader's parse total rather than hopeful, for the reason the tree arm
    /// states.
    ///
    /// The delta's own `base` reference contributes to the derived address but is
    /// not separately checked against any row here: whether the delta APPLIES to the
    /// base it names is the adopting caller's verdict (`prepare_adoption`), made
    /// against the `/work` mapping's own artifact, not the declaring verb's.
    ///
    /// # Failure
    ///
    /// Refuses a delta that does not serialize (including one over
    /// [`TreeDelta::MAXIMUM_ENCODED_BYTES`]), and a receipt whose object id or size
    /// is not the canonical address and length of `delta`'s bytes. That is the
    /// refused set.
    pub fn for_durable_delta(
        delta: &TreeDelta,
        privacy: ArtifactPrivacy,
        owner: CasRootOwner,
        durable: &crate::store::cas::DurableObject,
    ) -> KataResult<Self> {
        let bytes = delta.delta_bytes()?;
        let address = object_id_for_canonical_bytes(&bytes);
        if address != durable.object_id() {
            return Err(KataError::Validation(format!(
                "tree delta artifact declaration refused: this delta's canonical bytes address \
                 {address} but the durability receipt is for {}. A tree_delta row is a promise \
                 that the rooted object PARSES as a tree delta — so the promise is only made over \
                 bytes re-derived from the delta itself",
                durable.object_id()
            )));
        }
        if bytes.len() as u64 != durable.size() {
            return Err(KataError::Validation(format!(
                "tree delta artifact declaration refused: this delta's canonical bytes are {} \
                 long but the durability receipt recorded {}",
                bytes.len(),
                durable.size()
            )));
        }
        let reference = ArtifactRef::new(address, bytes.len() as u64, privacy);
        Self::checked(&reference, ArtifactKind::TreeDelta, owner, durable)
    }

    /// The shared body of the three constructors: the reference-versus-receipt refusals and
    /// the root spec. Private, so `kind` is decided by which constructor ran and never
    /// by a caller.
    fn checked(
        reference: &ArtifactRef,
        kind: ArtifactKind,
        owner: CasRootOwner,
        durable: &crate::store::cas::DurableObject,
    ) -> KataResult<Self> {
        if reference.object_id() != durable.object_id() {
            return Err(KataError::Validation(format!(
                "artifact declaration refused: the reference names object {} but the durability \
                 receipt is for {}. The row would not be re-derivable from the bytes the CAS \
                 actually holds",
                reference.object_id(),
                durable.object_id()
            )));
        }
        if reference.size_bytes() != durable.size() {
            return Err(KataError::Validation(format!(
                "artifact declaration refused: the reference claims {} bytes for object {} but \
                 the durability receipt recorded {}. size is folded into the artifact id, so the \
                 id names a length the CAS does not hold",
                reference.size_bytes(),
                reference.object_id(),
                durable.size()
            )));
        }
        Ok(Self {
            artifact_id: reference.id().0.0,
            object_id: reference.object_id().0,
            size_bytes: reference.size_bytes(),
            privacy: reference.privacy(),
            kind,
            object_root: CasRootSpec::for_object(durable, owner, ARTIFACT_OBJECT_ROOT_PURPOSE),
        })
    }

    /// The declared artifact's identity.
    #[must_use]
    pub fn artifact_id(&self) -> [u8; 32] {
        self.artifact_id
    }

    /// The CAS object id of the artifact's bytes (or, for a tree, of its manifest).
    #[must_use]
    pub fn object_id(&self) -> [u8; 32] {
        self.object_id
    }

    /// Whether the object is the bytes or a tree manifest.
    #[must_use]
    pub fn kind(&self) -> ArtifactKind {
        self.kind
    }
}

/// One stored `artifacts` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRow {
    /// The artifact's 32-byte identity, folding object, size and privacy.
    pub artifact_id: [u8; 32],
    /// The CAS object the row names.
    pub object_id: [u8; 32],
    /// The object's byte length.
    pub size_bytes: u64,
    /// The artifact's privacy classification.
    pub privacy: ArtifactPrivacy,
    /// Whether the object is the bytes or a tree manifest.
    pub kind: ArtifactKind,
    /// When the declaration committed.
    pub created_at_ms: i64,
}

impl OperationalDb {
    /// DECLARE an artifact: the `artifacts` row and its object `cas_roots` row, in ONE
    /// transaction.
    ///
    /// # Invariant
    ///
    /// ONE TRANSACTION, TWO ROWS, AND NEITHER IS REDUNDANT. The `cas_roots` row states
    /// which owner asserts the object — the root the dangling-root verifier checks — and
    /// the `artifacts` row is what makes the object an authorized reference rather than
    /// an orphan blob. Split across two commits, either order leaves a state the system
    /// would act on: a row no owner asserts, or a root naming bytes no declaration
    /// describes.
    ///
    /// # Failure — the refused set, stated exactly
    ///
    /// Re-declaring an id that is already stored is an IDEMPOTENT ROW plus this
    /// caller's own root, whether the owner matches or not — see the module docs for
    /// why a second owner over one content address is the NORMAL case and not a
    /// conflict. Three things are refused:
    ///
    /// * a stored row whose `object_id` or `size_bytes` differs. That cannot happen
    ///   through [`ArtifactDeclaration::for_durable_object`] — the id folds both — so
    ///   it means the stored row was written by something that is not this API, and
    ///   converging on it would adopt a forged row;
    /// * a stored row whose `kind` differs: one object claimed to be both bytes and a
    ///   manifest, which every reader of the row would decode differently;
    /// * a stored row whose `privacy` differs. Like the first, unreachable through the
    ///   constructors (privacy is folded too), and refused for the same reason. The
    ///   reachable privacy conflict is a DIFFERENT artifact id over the same
    ///   object, which [`refuse_second_object_claim`] names.
    ///
    /// `created_at_ms` is NOT compared: it is this plane's clock reading, not part of
    /// the caller's declared identity.
    pub fn declare_artifact(&self, declaration: &ArtifactDeclaration) -> KataResult<()> {
        let now = super::now_ms();
        self.in_writer_txn(|tx| declare_artifact_in_tx(tx, declaration, now))
    }
}

/// [`OperationalDb::declare_artifact`]'s body on the CALLER's writer transaction, so a
/// capsule result is declared in the same transaction that accepts it.
pub(super) fn declare_artifact_in_tx(
    tx: &rusqlite::Transaction<'_>,
    declaration: &ArtifactDeclaration,
    now: i64,
) -> KataResult<()> {
    let stored = read_artifact(tx, declaration.artifact_id)?;
    // A stored row for this id cannot collide with itself, so it is the one case
    // the object check may skip; an ABSENT row can collide with a DIFFERENT id over
    // the same object, and without this the collision would surface as a bare
    // SQLite `UNIQUE constraint failed` from the INSERT, which is the raw
    // uniqueness error the DDL comment promises the typed refusal instead of.
    match &stored {
        Some(stored) => refuse_divergent_redeclaration(stored, declaration)?,
        None => refuse_second_object_claim(tx, declaration)?,
    }
    // THIS CALLER'S OWN ROOT, always — before the row, and whether the row is
    // new or already stored. `upsert_cas_root` is idempotent per
    // `(owner, purpose, retention class, object)`, so a second owner gets a
    // second root and the same owner declaring twice gets one.
    upsert_cas_root(tx, &declaration.object_root, now)?;
    match stored {
        // A stored row needs nothing: the content claim is already recorded and
        // this caller's ownership is the root above.
        Some(_) => {}
        None => {
            tx.execute(
                "INSERT INTO artifacts
                     (artifact_id, object_id, size_bytes, privacy, kind, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    declaration.artifact_id.as_slice(),
                    declaration.object_id.as_slice(),
                    i64::try_from(declaration.size_bytes).map_err(|_| {
                        KataError::Validation(format!(
                            "artifact declaration refused: {} bytes does not fit \
                             SQLite's signed 64-bit INTEGER",
                            declaration.size_bytes
                        ))
                    })?,
                    declaration.privacy.as_tag(),
                    declaration.kind.as_str(),
                    now,
                ],
            )
            .map_err(|error| KataError::Storage(format!("insert artifacts row: {error}")))?;
        }
    }
    Ok(())
}

impl OperationalDb {
    /// One artifact by id.
    pub fn artifact(&self, artifact_id: [u8; 32]) -> KataResult<Option<ArtifactRow>> {
        self.with_read(|conn| {
            conn.query_row(
                &format!("{ARTIFACT_COLUMNS} WHERE artifact_id = ?1"),
                params![artifact_id.as_slice()],
                decode_artifact,
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read artifact: {error}")))?
            .transpose()
        })
    }

    /// Every artifact ONE OWNER RETAINS — the set a capsule may still bind from.
    ///
    /// # This reads `cas_roots`
    ///
    /// Ownership is a root and not a column, so the question "which artifacts does
    /// this owner hold" is a join from the owner's `artifact_object` roots onto the
    /// rows their objects name. Served by `idx_cas_roots_owner_artifact`.
    ///
    /// [`CasRootOwner::Node`] selects the node-owned roots (`owner_execution_id IS
    /// NULL`) rather than "all owners": there is no reader here that spans owners,
    /// because retention is per-owner.
    ///
    /// A row can appear for TWO owners now, and that is the correction rather than a
    /// defect: one content claim, two retention obligations.
    pub fn active_artifacts_for(&self, owner: CasRootOwner) -> KataResult<Vec<ArtifactRow>> {
        let owner_bytes = owner.execution_id().map(|id| id.to_bytes());
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "{ARTIFACT_COLUMNS} WHERE object_id IN (
                         SELECT object_digest FROM cas_roots
                          WHERE purpose = '{ARTIFACT_OBJECT_ROOT_PURPOSE}'
                            AND owner_execution_id IS ?1)
                     ORDER BY artifact_id"
                ))
                .map_err(|error| {
                    KataError::Storage(format!("prepare active artifacts: {error}"))
                })?;
            let rows = stmt
                .query_map(params![owner_bytes], decode_artifact)
                .map_err(|error| KataError::Storage(format!("read active artifacts: {error}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    KataError::Storage(format!("collect active artifacts: {error}"))
                })?;
            rows.into_iter().collect()
        })
    }
}

/// The production read projection, exposed so a query-plan test pins the plan of the
/// statement the READER issues rather than of a narrower one it retyped.
///
/// Test-only and `#[doc(hidden)]`: a caller with the string could issue its own
/// unvalidated read, which is exactly what the typed readers exist to prevent.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[must_use]
pub fn debug_artifact_columns() -> &'static str {
    ARTIFACT_COLUMNS
}

/// The one column list every artifact read uses, so a column added to the table
/// cannot reach one reader and miss another.
const ARTIFACT_COLUMNS: &str =
    "SELECT artifact_id, object_id, size_bytes, privacy, kind, created_at_ms FROM artifacts";

/// Decode one row, deferring the fixed-width and vocabulary refusals to [`KataResult`]
/// so a corrupt stored value is a typed storage refusal rather than a panic inside
/// rusqlite's closure.
#[allow(clippy::type_complexity)]
fn decode_artifact(row: &rusqlite::Row<'_>) -> rusqlite::Result<KataResult<ArtifactRow>> {
    let artifact_id: Vec<u8> = row.get(0)?;
    let object_id: Vec<u8> = row.get(1)?;
    let size_bytes: i64 = row.get(2)?;
    let privacy: String = row.get(3)?;
    let kind: String = row.get(4)?;
    let created_at_ms: i64 = row.get(5)?;
    Ok((|| {
        Ok(ArtifactRow {
            artifact_id: digest32(&artifact_id, "artifact_id")?,
            object_id: digest32(&object_id, "object_id")?,
            size_bytes: u64::try_from(size_bytes).map_err(|_| {
                KataError::Storage(format!(
                    "operational.db artifacts.size_bytes is negative ({size_bytes})"
                ))
            })?,
            privacy: privacy_from_stored(&privacy)?,
            kind: ArtifactKind::from_stored(&kind)?,
            created_at_ms,
        })
    })())
}

fn digest32(bytes: &[u8], column: &str) -> KataResult<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db artifacts.{column} must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}

/// Read one artifact inside a writer transaction.
pub(super) fn read_artifact(
    tx: &Transaction<'_>,
    artifact_id: [u8; 32],
) -> KataResult<Option<ArtifactRow>> {
    tx.query_row(
        &format!("{ARTIFACT_COLUMNS} WHERE artifact_id = ?1"),
        params![artifact_id.as_slice()],
        decode_artifact,
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read artifact in txn: {error}")))?
    .transpose()
}

/// Refuse a SECOND artifact over one object — i.e. a DIFFERING PRIVACY.
///
/// # Invariant
///
/// The refused set is exactly *"these bytes are already declared under a different
/// privacy classification"*, and that is the only thing it can be: `artifact_id` folds
/// `(object, size, privacy)`, object and size are fixed by the bytes, so two distinct
/// ids over one object differ in privacy and nothing else. The property it holds is the
/// PRIVATE-ARTIFACT PLANE — the same bytes declared both as a public artifact and as a
/// private one discharge the private classification through the public twin.
///
/// # Why it states ONE reason
///
/// Two owners of one artifact are one row and two roots, so sharing a `cas_roots` row is
/// not a reason this refusal has. The message states the one reason the operator has.
///
/// It is reached when NO row exists for this artifact id. A stored row is the one case it
/// may skip, and only because that row cannot collide with itself — which is what lets a
/// second owner declare content somebody else already claimed without paying for this
/// read.
///
/// # Enforcement
///
/// Two layers, and the pair is the point. `idx_artifacts_object` is a UNIQUE index and is
/// what makes the rule TOTAL against any writer. This check is what makes the refusal
/// legible: it runs first and names the artifact that already holds the object, where the
/// index alone would surface a bare SQLite uniqueness error naming neither id.
fn refuse_second_object_claim(
    tx: &Transaction<'_>,
    declaration: &ArtifactDeclaration,
) -> KataResult<()> {
    let holder: Option<Vec<u8>> = tx
        .query_row(
            "SELECT artifact_id FROM artifacts WHERE object_id = ?1",
            params![declaration.object_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read live artifact by object: {error}")))?;
    let Some(holder) = holder else {
        return Ok(());
    };
    Err(KataError::Validation(format!(
        "operational.db refuses to declare artifact {} over object {}: artifact {} is already \
         declared over the same bytes under a DIFFERENT privacy classification. An artifact id \
         folds object, size and privacy, and the first two are fixed by the bytes, so that is the \
         only way two ids can name one object. The same bytes declared both as a public artifact \
         and as a private one discharge the private classification through the public twin. \
         Declare this one over its own object",
        hex::encode(declaration.artifact_id),
        hex::encode(declaration.object_id),
        hex::encode(&holder)
    )))
}

/// Refuse a re-declaration that disagrees with the stored row. See
/// [`OperationalDb::declare_artifact`]'s failure section for the refused set.
fn refuse_divergent_redeclaration(
    stored: &ArtifactRow,
    declaration: &ArtifactDeclaration,
) -> KataResult<()> {
    let divergent: Vec<&str> = [
        ("object_id", stored.object_id == declaration.object_id),
        ("size_bytes", stored.size_bytes == declaration.size_bytes),
        ("privacy", stored.privacy == declaration.privacy),
        ("kind", stored.kind == declaration.kind),
    ]
    .into_iter()
    .filter_map(|(field, equal)| (!equal).then_some(field))
    .collect();
    if divergent.is_empty() {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses to re-declare artifact {} with a different {}: one artifact id \
         names one object, one length, one privacy classification and one kind. Object, length \
         and privacy are FOLDED INTO the id, so a disagreement in any of them means the stored \
         row was not written by this API and converging on it would adopt a forged row; `kind` \
         is not folded, and a disagreement there is one object claimed to be both bytes and a \
         manifest, which every reader of the row would decode differently. THE OWNER \
         IS NOT IN THIS LIST — a row carries none, and a second owner over one content address \
         is the normal case",
        hex::encode(declaration.artifact_id),
        divergent.join(", ")
    )))
}
