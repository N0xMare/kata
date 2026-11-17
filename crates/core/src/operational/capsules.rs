//! Declared capsules — ADR-0001 trust boundary 3.
//!
//! # Invariant
//!
//! The boundary between main and worker is "an immutable, versioned capsule containing
//! identities, guest paths, budgets, permissions, and artifact/environment references —
//! not main-host paths". [`Capsule`] IS that object and its id folds all of it, so this
//! plane stores exactly three things and nothing else: the id, the coordinates a reader
//! looks one up by, and the CAS object holding the capsule's canonical serialization.
//!
//! THE BYTES ARE THE MAPPING LIST. There is no `capsule_inputs` child table, because
//! `Capsule`'s `Deserialize` recomputes the [`CapsuleId`] from the decoded body and
//! refuses a mismatch — so the mapping list is already tamper-evident in the object the
//! row names, and a column copy of it could only either restate it (dead weight that
//! can disagree) or contradict it.
//!
//! # What this plane refuses, and what it cannot
//!
//! [`OperationalDb::declare_capsule`] refuses a mapping whose artifact has no
//! `artifacts` row, and an `environment_id` with no ACTIVE `nix_environments` row.
//! Those are the two references a capsule carries into another plane, and both are
//! checked against that plane's own rows rather than against the capsule's claim about
//! them.
//!
//! The `environment_id` foreign key (NO ACTION) makes "the environment is DECLARED"
//! structural: an environment a capsule names cannot be deleted out from under it. It
//! deliberately does not and cannot express "and not released" — that is a column state
//! — which is why the typed refusal exists beside it rather than instead of it.
//!
//! # Boundary — PROMOTION is not checked here
//!
//! A capsule may name an environment whose Nix gc root is still UNPROMOTED. That is not
//! an oversight: promotion is a store-side fact the boot reconciler finishes
//! asynchronously, and refusing here would make capsule assembly fail on a window that
//! resolves itself. The obligation lands where the environment plane puts it — issuance
//! must refuse an environment whose root is unpromoted — and a reader must therefore
//! NOT read a stored capsule as "this environment is usable".
//!
//! # Retention
//!
//! A capsule's bytes are asserted by a node-owned authoritative `cas_roots` row written
//! in the declaring transaction, and there is no release verb: a declared capsule's
//! bytes stay for the node's lifetime, like every CAS object (kata has no CAS
//! collection).
//!
//! [`CapsuleId`]: kata_types::execution_contract::CapsuleId

use kata_types::cache::object_id_for_canonical_bytes;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::Capsule;
use rusqlite::{OptionalExtension, Transaction, params};

use super::records::CAPSULE_OBJECT_ROOT_PURPOSE;
use super::repo::upsert_cas_root;
use super::{CasRootOwner, CasRootSpec, OperationalDb};

/// A complete capsule declaration, constructible only from a durable object.
///
/// # Enforcement
///
/// The fields are private and the only constructor is
/// [`CapsuleDeclaration::for_durable_object`], which takes the capsule, ITS CANONICAL
/// BYTES, and a [`DurableObject`] receipt for those bytes — so a declaration naming an
/// object that is not this capsule's serialization is UNCONSTRUCTIBLE rather than
/// merely discouraged.
///
/// [`DurableObject`]: crate::store::cas::DurableObject
#[derive(Clone, Debug)]
pub struct CapsuleDeclaration {
    capsule_id: [u8; 32],
    occurrence_id: [u8; 32],
    prepared_action_id: [u8; 32],
    environment_id: [u8; 32],
    platform_id: [u8; 32],
    capsule_object_id: [u8; 32],
    /// `(artifact id, guest path)` per mapping, kept only so the refusals can NAME the
    /// mapping that failed. The authoritative list is the object's bytes.
    inputs: Vec<([u8; 32], String)>,
    object_root: CasRootSpec,
}

impl CapsuleDeclaration {
    /// Declare `capsule`, whose canonical serialization is `capsule_bytes` and whose
    /// bytes are PROVEN durable by `durable`.
    ///
    /// # Invariant
    ///
    /// THE CAPSULE, THE BYTES AND THE RECEIPT ARE CHECKED AGAINST EACH OTHER, all three
    /// ways, because each pair can disagree on its own:
    ///
    /// * the receipt's object id and size must be the CAS address and length of
    ///   `capsule_bytes` — otherwise the row would name an object holding something
    ///   else;
    /// * `capsule_bytes` must DECODE to a capsule. The decode runs `Capsule`'s own
    ///   `Deserialize`, which recomputes the [`CapsuleId`](kata_types::execution_contract::CapsuleId)
    ///   from the body and refuses a body whose stored id does not match it — so
    ///   tampered bytes are refused here, by the type that owns the derivation, rather
    ///   than by a re-implementation of it;
    /// * the decoded capsule must EQUAL the one presented, so a caller cannot declare
    ///   one capsule while publishing another's bytes.
    ///
    /// # Failure
    ///
    /// Exactly those three: an object id or size disagreeing with the bytes, bytes that
    /// do not decode as a capsule (including bytes whose embedded id was tampered
    /// with), and a decoded capsule that differs from the presented one.
    pub fn for_durable_object(
        capsule: &Capsule,
        capsule_bytes: &[u8],
        durable: &crate::store::cas::DurableObject,
    ) -> KataResult<Self> {
        let address = object_id_for_canonical_bytes(capsule_bytes);
        if address != durable.object_id() {
            return Err(KataError::Validation(format!(
                "capsule declaration refused: the presented bytes address {address} but the \
                 durability receipt is for {}. The row would name an object holding something \
                 other than this capsule",
                durable.object_id()
            )));
        }
        if capsule_bytes.len() as u64 != durable.size() {
            return Err(KataError::Validation(format!(
                "capsule declaration refused: the presented bytes are {} long but the durability \
                 receipt recorded {}",
                capsule_bytes.len(),
                durable.size()
            )));
        }
        let decoded: Capsule = serde_json::from_slice(capsule_bytes).map_err(|error| {
            KataError::Validation(format!(
                "capsule declaration refused: the presented bytes do not decode as a capsule \
                 ({error}). Capsule's own Deserialize recomputes the capsule id from the body, so \
                 this is where a tampered id is caught"
            ))
        })?;
        if &decoded != capsule {
            return Err(KataError::Validation(format!(
                "capsule declaration refused: the presented bytes decode to capsule {} but the \
                 declaration is for {}. One declaration names one capsule and publishes its own \
                 serialization",
                decoded.id().0,
                capsule.id().0
            )));
        }
        Ok(Self {
            capsule_id: capsule.id().0.0,
            occurrence_id: capsule.occurrence().0.0,
            prepared_action_id: capsule.action().0.0,
            environment_id: capsule.environment().0.0,
            platform_id: capsule.platform().0.0,
            capsule_object_id: address.0,
            inputs: capsule
                .inputs()
                .iter()
                .map(|mapping| {
                    (
                        mapping.artifact.0.0,
                        mapping.guest_path.as_str().to_string(),
                    )
                })
                .collect(),
            object_root: CasRootSpec::for_object(
                durable,
                CasRootOwner::Node,
                CAPSULE_OBJECT_ROOT_PURPOSE,
            ),
        })
    }

    /// The declared capsule's identity.
    #[must_use]
    pub fn capsule_id(&self) -> [u8; 32] {
        self.capsule_id
    }

    /// The CAS object id of the capsule's canonical serialization.
    #[must_use]
    pub fn capsule_object_id(&self) -> [u8; 32] {
        self.capsule_object_id
    }
}

/// One stored `capsules` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsuleRow {
    /// The capsule's 32-byte identity, folding every field of the capsule.
    pub capsule_id: [u8; 32],
    /// The occurrence the capsule was assembled for.
    pub occurrence_id: [u8; 32],
    /// The prepared action it carries.
    pub prepared_action_id: [u8; 32],
    /// The declared Nix environment it binds.
    pub environment_id: [u8; 32],
    /// The platform it was assembled for.
    pub platform_id: [u8; 32],
    /// The CAS object holding its canonical serialization.
    pub capsule_object_id: [u8; 32],
    /// When the declaration committed.
    pub created_at_ms: i64,
}

impl OperationalDb {
    /// DECLARE a capsule: the `capsules` row and its node-owned authoritative object
    /// `cas_roots` row, in ONE transaction.
    ///
    /// # Invariant
    ///
    /// ONE TRANSACTION, TWO ROWS, AND NEITHER IS REDUNDANT — the same argument as
    /// [`Self::declare_artifact`]'s. The reference checks run inside the same
    /// transaction as the insert, so an environment released concurrently cannot be
    /// released between the check and the row.
    ///
    /// # Failure
    ///
    /// This is the refused set, stated exactly:
    ///
    /// * an `environment_id` with no `nix_environments` row at all, or whose row is
    ///   RELEASED. A capsule must name a declared, unreleased environment: binding a
    ///   released one would produce an immutable record of an authorization that had
    ///   already been withdrawn. (The foreign key makes the first half structural; the
    ///   second half is a column state no FK can express.) PROMOTION is deliberately
    ///   not checked — see the module docs;
    /// * any [`GuestMapping`](kata_types::execution_contract::GuestMapping) whose
    ///   artifact is unknown, or has a row no live root asserts. The refusal names
    ///   the artifact AND its guest path, because an operator reading it needs to know
    ///   which mount failed, not only which digest;
    /// * a re-declaration whose stored row disagrees with the presented one. A capsule
    ///   id folds every field of the capsule, so a disagreement means the stored row was
    ///   written by something that is not this API, and converging on it would adopt a
    ///   forged row. An IDENTICAL re-declare is an idempotent no-op.
    ///
    /// `created_at_ms` is NOT compared: it is this plane's clock reading, not part of
    /// the caller's declared identity.
    pub fn declare_capsule(&self, declaration: &CapsuleDeclaration) -> KataResult<()> {
        let now = super::now_ms();
        self.in_writer_txn(|tx| {
            if let Some(stored) = read_capsule(tx, declaration.capsule_id)? {
                return refuse_divergent_redeclaration(&stored, declaration);
            }
            refuse_inactive_environment(tx, declaration)?;
            refuse_unmapped_artifact(tx, declaration)?;
            upsert_cas_root(tx, &declaration.object_root, now)?;
            tx.execute(
                "INSERT INTO capsules
                     (capsule_id, occurrence_id, prepared_action_id, environment_id, platform_id,
                      capsule_object_id, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    declaration.capsule_id.as_slice(),
                    declaration.occurrence_id.as_slice(),
                    declaration.prepared_action_id.as_slice(),
                    declaration.environment_id.as_slice(),
                    declaration.platform_id.as_slice(),
                    declaration.capsule_object_id.as_slice(),
                    now,
                ],
            )
            .map_err(|error| KataError::Storage(format!("insert capsules row: {error}")))?;
            Ok(())
        })
    }

    /// One capsule by id.
    pub fn capsule(&self, capsule_id: [u8; 32]) -> KataResult<Option<CapsuleRow>> {
        self.with_read(|conn| {
            conn.query_row(
                &format!("{CAPSULE_COLUMNS} WHERE capsule_id = ?1"),
                params![capsule_id.as_slice()],
                decode_capsule,
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read capsule: {error}")))?
            .transpose()
        })
    }
}

/// The one column list every capsule read uses, so a column added to the table cannot
/// reach one reader and miss another.
const CAPSULE_COLUMNS: &str = "SELECT capsule_id, occurrence_id, prepared_action_id, \
                               environment_id, platform_id, capsule_object_id, created_at_ms \
                               FROM capsules";

/// Decode one row, deferring the fixed-width refusals to [`KataResult`] so a corrupt
/// stored blob is a typed storage refusal rather than a panic inside rusqlite's closure.
#[allow(clippy::type_complexity)]
fn decode_capsule(row: &rusqlite::Row<'_>) -> rusqlite::Result<KataResult<CapsuleRow>> {
    let capsule_id: Vec<u8> = row.get(0)?;
    let occurrence_id: Vec<u8> = row.get(1)?;
    let prepared_action_id: Vec<u8> = row.get(2)?;
    let environment_id: Vec<u8> = row.get(3)?;
    let platform_id: Vec<u8> = row.get(4)?;
    let capsule_object_id: Vec<u8> = row.get(5)?;
    let created_at_ms: i64 = row.get(6)?;
    Ok((|| {
        Ok(CapsuleRow {
            capsule_id: digest32(&capsule_id, "capsule_id")?,
            occurrence_id: digest32(&occurrence_id, "occurrence_id")?,
            prepared_action_id: digest32(&prepared_action_id, "prepared_action_id")?,
            environment_id: digest32(&environment_id, "environment_id")?,
            platform_id: digest32(&platform_id, "platform_id")?,
            capsule_object_id: digest32(&capsule_object_id, "capsule_object_id")?,
            created_at_ms,
        })
    })())
}

fn digest32(bytes: &[u8], column: &str) -> KataResult<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db capsules.{column} must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}

/// Read one capsule inside a writer transaction.
fn read_capsule(tx: &Transaction<'_>, capsule_id: [u8; 32]) -> KataResult<Option<CapsuleRow>> {
    tx.query_row(
        &format!("{CAPSULE_COLUMNS} WHERE capsule_id = ?1"),
        params![capsule_id.as_slice()],
        decode_capsule,
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read capsule in txn: {error}")))?
    .transpose()
}

/// Refuse an environment that is not declared, or is declared and RELEASED.
fn refuse_inactive_environment(
    tx: &Transaction<'_>,
    declaration: &CapsuleDeclaration,
) -> KataResult<()> {
    let released: Option<Option<i64>> = tx
        .query_row(
            "SELECT released_at_ms FROM nix_environments WHERE environment_id = ?1",
            params![declaration.environment_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            KataError::Storage(format!("read nix environment for capsule: {error}"))
        })?;
    match released {
        None => Err(KataError::Validation(format!(
            "operational.db refuses to declare capsule {}: it names Nix environment {}, which is \
             not declared on this node. A capsule is an immutable binding, so it may not name an \
             environment this plane never authorized",
            hex::encode(declaration.capsule_id),
            hex::encode(declaration.environment_id)
        ))),
        Some(Some(released_at_ms)) => Err(KataError::Validation(format!(
            "operational.db refuses to declare capsule {}: it names Nix environment {}, which was \
             released at {released_at_ms}. Binding a released environment would record an \
             authorization that had already been withdrawn",
            hex::encode(declaration.capsule_id),
            hex::encode(declaration.environment_id)
        ))),
        Some(None) => Ok(()),
    }
}

/// Refuse any mapping whose artifact is not DECLARED and RETAINED.
///
/// # Two conditions, and the second is the one that matters
///
/// 1. an `artifacts` ROW exists for the id. That is the node's content claim: *this node
///    authorized this `(object, size, privacy)` reference and reads its object this
///    `kind`*. Without it there is nothing the mapping names.
/// 2. a LIVE `artifact_object` root names the row's object. That is what asserts the
///    bytes, and it is checked directly rather than trusted from the row.
///
/// Checking the ROOT rather than the row is what makes this total, and the case that
/// forced it is real: `cas_roots` has `ON DELETE CASCADE` to `programs`, so deleting an
/// execution DELETES its artifact roots outright — no Rust in the path, nothing to
/// re-derive the row's state — and the row cannot cascade with them: a row has no
/// owner, and two executions that produced byte-identical results share one row. So a
/// row over zero live roots is a reachable state.
///
/// The claim this makes is therefore exactly: *at declaration time, at least one owner on
/// this node asserts these bytes*. It is NOT *"the capsule's own owner does"* — a
/// capsule declaration names no owner, so there is nothing here to compare against.
fn refuse_unmapped_artifact(
    tx: &Transaction<'_>,
    declaration: &CapsuleDeclaration,
) -> KataResult<()> {
    for (artifact_id, guest_path) in &declaration.inputs {
        let object: Option<Vec<u8>> = tx
            .query_row(
                "SELECT object_id FROM artifacts WHERE artifact_id = ?1",
                params![artifact_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                KataError::Storage(format!("read artifact for capsule mapping: {error}"))
            })?;
        let refusal = match object {
            None => "is not declared on this node",
            Some(object) => {
                let retained: bool = tx
                    .query_row(
                        &format!(
                            "SELECT EXISTS(SELECT 1 FROM cas_roots
                                            WHERE purpose = '{}'
                                              AND object_digest = ?1)",
                            super::records::ARTIFACT_OBJECT_ROOT_PURPOSE
                        ),
                        params![object],
                        |row| row.get(0),
                    )
                    .map_err(|error| {
                        KataError::Storage(format!("read artifact retention for mapping: {error}"))
                    })?;
                if retained {
                    continue;
                }
                "is declared but no live root asserts its bytes"
            }
        };
        return Err(KataError::Validation(format!(
            "operational.db refuses to declare capsule {}: its mapping at guest path {guest_path} \
             names artifact {}, which {refusal}. A capsule is an immutable binding a worker will \
             materialize from references alone, so every reference must resolve to a declared and \
             RETAINED artifact before the binding is recorded",
            hex::encode(declaration.capsule_id),
            hex::encode(artifact_id)
        )));
    }
    Ok(())
}

/// Refuse a re-declaration that disagrees with the stored row. See
/// [`OperationalDb::declare_capsule`]'s failure section for the refused set.
fn refuse_divergent_redeclaration(
    stored: &CapsuleRow,
    declaration: &CapsuleDeclaration,
) -> KataResult<()> {
    let divergent: Vec<&str> = [
        (
            "occurrence_id",
            stored.occurrence_id == declaration.occurrence_id,
        ),
        (
            "prepared_action_id",
            stored.prepared_action_id == declaration.prepared_action_id,
        ),
        (
            "environment_id",
            stored.environment_id == declaration.environment_id,
        ),
        ("platform_id", stored.platform_id == declaration.platform_id),
        (
            "capsule_object_id",
            stored.capsule_object_id == declaration.capsule_object_id,
        ),
    ]
    .into_iter()
    .filter_map(|(field, equal)| (!equal).then_some(field))
    .collect();
    if divergent.is_empty() {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses to re-declare capsule {} with a different {}: a capsule id folds \
         every field of the capsule, so a disagreement means the stored row was not written by \
         this API. Refusing rather than converging on a row this plane cannot account for",
        hex::encode(declaration.capsule_id),
        divergent.join(", ")
    )))
}
