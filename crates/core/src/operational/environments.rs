//! Declared Nix managed-software environments.
//!
//! # Invariant
//!
//! `operational.db` is authoritative for WHICH closure was authorized; Nix owns
//! realization, transport, store verification and collection (ADR-0001, "Kata owns
//! which exact closure was authorized, its binding and evidence, retention intent,
//! privacy classification, and crash-safe coordination with Nix roots"). So exactly
//! two durable facts live here and nothing else does: the `nix_environments` row,
//! and the node-owned `cas_roots` row that asserts the manifest bytes describing the
//! closure. Both commit in ONE writer transaction, because a row naming manifest
//! bytes no root asserts escapes the dangling-root verifier and an unreferenced
//! manifest is a closure nobody can describe.
//!
//! # Failure mode
//!
//! THE DURABLE STATE MACHINE IS THREE STATES AND TWO NULLABLE INSTANTS, and the
//! unfinished states are the point:
//!
//! ```text
//!   declared (root_promoted_at_ms IS NULL)   -- K15's residue; NOT bindable
//!      -> promoted                           -- bindable
//!         -> released (released_at_ms)        -- manifest root released with it
//!            -> deleted                      -- row gone
//! ```
//!
//! The transitions refuse out of order rather than converging quietly:
//! [`OperationalDb::promote_environment_root`] refuses a released environment,
//! [`OperationalDb::release_environment`] refuses an unpromoted one, and
//! [`OperationalDb::delete_released_environment`] refuses anything not released. That
//! is what makes the two reconciliation indexes' populations mean what their names say
//! — every unpromoted row is unreleased BY REFUSAL, so the unpromoted scan needs no
//! `released_at_ms IS NULL` conjunct and does not quietly claim one.
//!
//! # One live environment per manifest object
//!
//! A manifest root's id DERIVES from
//! `(node, NULL, nix_environment_manifest, authoritative, Object(manifest_object_id))`,
//! so two environments over the same manifest object are not two roots — they are one
//! shared `cas_roots` row. Releasing either would release the row on the other's behalf
//! and leave a live environment whose manifest root no longer asserts it.
//! `idx_nix_environments_manifest_live` (UNIQUE, partial on the
//! live rows) makes that unrepresentable and
//! [`refuse_second_live_manifest_claim`] makes the refusal name both environments.
//! A RELEASED row has relinquished its claim, so re-declaring a manifest after a release
//! or a delete is legitimate and re-acquires the same row.
//!
//! # Trust boundary
//!
//! ADR-0001 trust boundary 5: "a store path or metadata query is not by itself byte
//! verification". Nothing here verifies a closure; this module records an
//! authorization the caller already established and refuses to invent one. The one
//! structural guarantee it does carry is boundary 2's bytes-before-reference
//! ordering, and it carries it the way every other root in this plane does — through
//! a [`DurableObject`] receipt, which only `CasStore::put_durable` can mint and only
//! after the manifest's bytes are fsync-durable.
//!
//! [`DurableObject`]: crate::store::cas::DurableObject

use kata_types::error::{KataError, KataResult};
use rusqlite::{OptionalExtension, Transaction, params};

use super::records::NIX_ENVIRONMENT_MANIFEST_ROOT_PURPOSE;
use super::repo::{release_cas_root, upsert_cas_root};
use super::{CasRootOwner, CasRootSpec, OperationalDb};

/// The refusal token for releasing an environment a non-terminal attempt's capsule binds.
pub const ENVIRONMENT_BOUND_TO_LIVE_ATTEMPT: &str = "environment_bound_to_live_attempt";

/// A complete environment declaration, constructible only from a durable manifest.
///
/// # Enforcement
///
/// The fields are private and the only constructor is
/// [`EnvironmentDeclaration::for_staged_root`], which takes a [`DurableObject`]
/// receipt — the same shape `CasRootSpec::for_object` uses, and for the same reason:
/// a declaration naming manifest bytes that were never written is UNCONSTRUCTIBLE
/// rather than merely discouraged. The root spec is built inside the constructor, so
/// no caller can present a row and a root that describe different objects.
///
/// [`DurableObject`]: crate::store::cas::DurableObject
#[derive(Clone, Debug)]
pub struct EnvironmentDeclaration {
    environment_id: [u8; 32],
    manifest_object_id: [u8; 32],
    manifest_root: CasRootSpec,
    closure_digest: [u8; 32],
    label: String,
    platform_id: [u8; 32],
    root_stage_id: String,
    verification_evidence: Option<Vec<u8>>,
}

impl EnvironmentDeclaration {
    /// Record the store's signatures/deriver evidence beside the row — never identity.
    #[must_use]
    pub fn with_verification_evidence(mut self, evidence: Vec<u8>) -> Self {
        self.verification_evidence = Some(evidence);
        self
    }

    /// Declare `environment_id` over a manifest whose bytes are PROVEN durable, naming the
    /// staging generation `root_stage_id` the caller created its Nix gc root under.
    ///
    /// # Crash boundary
    ///
    /// This is K14's seam's near edge —
    /// `operational.after_nix_root_staged_before_manifest_durable`, the **nix**
    /// family. The near edge is the CALLER's obligation: a `DurableObject` proves the
    /// manifest bytes are durable, and nothing in `kata-core` can prove `nix-store --add-root`
    /// returned, so the seam fires in [`OperationalDb::declare_environment`] where
    /// both facts are named at once rather than here, where only one is.
    ///
    /// # Failure
    ///
    /// Refuses an empty `label` or `root_stage_id` here rather than at the schema
    /// CHECK. The CHECK is the backstop for a forged writer; a typed refusal at the
    /// constructor is what a caller can act on, and it keeps the refusal out of the
    /// middle of someone else's transaction.
    pub fn for_staged_root(
        environment_id: [u8; 32],
        manifest: &crate::store::cas::DurableObject,
        closure_digest: [u8; 32],
        label: &str,
        platform_id: [u8; 32],
        root_stage_id: &str,
    ) -> KataResult<Self> {
        if label.is_empty() {
            return Err(KataError::Validation(
                "a Nix environment declaration requires a non-empty label".to_string(),
            ));
        }
        if root_stage_id.is_empty() {
            return Err(KataError::Validation(
                "a Nix environment declaration requires the staging directory name its Nix gc \
                 root was created under; without it, boot cannot tell a staging generation it \
                 must sweep from the one this declaration owns"
                    .to_string(),
            ));
        }
        Ok(Self {
            environment_id,
            manifest_object_id: manifest.object_id().0,
            manifest_root: CasRootSpec::for_object(
                manifest,
                CasRootOwner::Node,
                NIX_ENVIRONMENT_MANIFEST_ROOT_PURPOSE,
            ),
            closure_digest,
            label: label.to_string(),
            platform_id,
            root_stage_id: root_stage_id.to_string(),
            verification_evidence: None,
        })
    }

    /// The declared environment's identity.
    #[must_use]
    pub fn environment_id(&self) -> [u8; 32] {
        self.environment_id
    }

    /// The CAS object id of the manifest bytes.
    #[must_use]
    pub fn manifest_object_id(&self) -> [u8; 32] {
        self.manifest_object_id
    }

    /// The closure digest the manifest describes.
    #[must_use]
    pub fn closure_digest(&self) -> [u8; 32] {
        self.closure_digest
    }
}

/// One stored `nix_environments` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentRow {
    /// The environment's 32-byte identity.
    pub environment_id: [u8; 32],
    /// The CAS object id of the manifest bytes describing the closure.
    pub manifest_object_id: [u8; 32],
    /// The digest of the closure itself.
    pub closure_digest: [u8; 32],
    /// The operator-facing label.
    pub label: String,
    /// The platform the closure was realized for.
    pub platform_id: [u8; 32],
    /// The staging directory name the Nix gc root was created under.
    pub root_stage_id: String,
    /// When the gc root left staging for its stable path, or `None` while the
    /// environment is NOT bindable and the boot reconciler still owes it a promote.
    pub root_promoted_at_ms: Option<i64>,
    /// When the environment was released, or `None` while it is active.
    pub released_at_ms: Option<i64>,
    /// When the declaration committed.
    pub created_at_ms: i64,
}

impl OperationalDb {
    /// DECLARE an environment: the `nix_environments` row and its node-owned
    /// authoritative manifest `cas_roots` row, in ONE transaction, with
    /// `root_promoted_at_ms = NULL`.
    ///
    /// # Invariant
    ///
    /// ONE TRANSACTION, TWO ROWS, AND NEITHER IS REDUNDANT. The `cas_roots` row is
    /// what asserts the manifest bytes — the root the dangling-root verifier reads
    /// ([`Self::stored_cas_roots`]) — and the `nix_environments` row is what makes the
    /// closure an authorization rather than an orphan blob. Split across two commits,
    /// either order leaves a state the system would act on: a row whose manifest no
    /// root asserts, or a root over a manifest no boot path will ever promote or
    /// release.
    ///
    /// # Crash boundary
    ///
    /// K14 — `operational.after_nix_root_staged_before_manifest_durable`, the **nix**
    /// family — fires HERE, before the transaction opens. That is the one point at which
    /// both halves of the window are named: the STAGING GENERATION IS NAMED in the
    /// declaration and no durable operational reference to the manifest exists yet, so the
    /// manifest's bytes are written but UNREFERENCED. The recovery state is therefore: no
    /// row, no root, and an orphan manifest object that costs disk — nothing any reader
    /// can mistake for an authorized environment.
    ///
    /// This plane holds the staging generation's NAME and nothing else about it. The
    /// on-disk indirect gc root is staged, promoted and swept by `kata_core::environment`,
    /// and the crash proof for the DIRECTORY lives beside that code in
    /// `crates/core/tests/nix_environment_plane.rs`; this boundary's cell
    /// (`cas_root_liveness.rs` K14) proves the operational half only.
    ///
    /// K15 — `operational.after_environment_row_committed_before_root_promoted` —
    /// fires after the commit returns, with the row durable and unpromoted. Its
    /// recovery state is the one [`Self::unpromoted_environments`] exists to return.
    ///
    /// # Failure
    ///
    /// Re-declaring an id that is already stored is an IDEMPOTENT NO-OP when the
    /// stored row's `closure_digest`, `manifest_object_id`, `label`, `platform_id`
    /// and `root_stage_id` all equal the presented ones, and a typed
    /// [`KataError::Validation`] conflict otherwise. That is the refused set exactly:
    ///
    /// * a differing `closure_digest` or `manifest_object_id` is one identity naming
    ///   two closures, which is the whole thing an environment id is for;
    /// * a differing `root_stage_id` is refused rather than accepted-and-overwritten
    ///   because the STORED generation is the one the boot reconciler will promote,
    ///   so overwriting it would strand the recorded directory and promote a
    ///   directory the row never named. A caller that lost its staging generation
    ///   must let the reconciler finish the stored one and sweep its own;
    /// * a RELEASED row refuses every re-declare, identical or not. Release is a
    ///   decision about the closure's retention, and silently un-releasing it here
    ///   would discharge that decision on the operator's behalf.
    ///
    /// The instants are NOT compared: `created_at_ms` is this plane's clock reading,
    /// not part of the caller's declared identity.
    pub fn declare_environment(&self, declaration: &EnvironmentDeclaration) -> KataResult<()> {
        // K14 — the staged Nix gc root exists and nothing durable references the
        // manifest yet. See the crash-boundary section above for why the seam is
        // here and not in `EnvironmentDeclaration::for_staged_root`.
        crate::fault_inject::operational_crash_point(
            "after_nix_root_staged_before_manifest_durable",
        );
        let now = super::now_ms();
        let committed = self.in_writer_txn(|tx| {
            if let Some(stored) = read_environment(tx, declaration.environment_id)? {
                refuse_divergent_redeclaration(&stored, declaration)?;
                return Ok(false);
            }
            refuse_second_live_manifest_claim(tx, declaration)?;
            upsert_cas_root(tx, &declaration.manifest_root, now)?;
            tx.execute(
                "INSERT INTO nix_environments
                     (environment_id, manifest_object_id, closure_digest, label, platform_id,
                      root_stage_id, root_promoted_at_ms, released_at_ms, created_at_ms,
                      verification_evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, ?7, ?8)",
                params![
                    declaration.environment_id.as_slice(),
                    declaration.manifest_object_id.as_slice(),
                    declaration.closure_digest.as_slice(),
                    declaration.label.as_str(),
                    declaration.platform_id.as_slice(),
                    declaration.root_stage_id.as_str(),
                    now,
                    declaration.verification_evidence.as_deref(),
                ],
            )
            .map_err(|error| KataError::Storage(format!("insert nix_environments row: {error}")))?;
            Ok(true)
        })?;
        if committed {
            // K15 — the row is fsync-durable and UNPROMOTED. Nothing downstream has
            // run: the gc root is still in its staging generation.
            crate::fault_inject::operational_crash_point(
                "after_environment_row_committed_before_root_promoted",
            );
        }
        Ok(())
    }

    /// Replace the verification EVIDENCE recorded for `environment_id` — the store's
    /// signatures and deriver as of the latest verification. Not identity: a re-sign
    /// updates this and moves nothing else.
    ///
    /// # Errors
    ///
    /// An unknown environment, and a storage failure.
    pub fn record_environment_evidence(
        &self,
        environment_id: [u8; 32],
        evidence: &[u8],
    ) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            let changed = tx
                .execute(
                    "UPDATE nix_environments SET verification_evidence = ?2 \
                      WHERE environment_id = ?1",
                    params![environment_id.as_slice(), evidence],
                )
                .map_err(|error| {
                    KataError::Storage(format!("record nix environment evidence: {error}"))
                })?;
            if changed == 0 {
                return Err(KataError::Validation(format!(
                    "operational.db has no nix environment {} to record evidence for",
                    hex::encode(environment_id)
                )));
            }
            Ok(())
        })
    }

    /// PROMOTE: record that the environment's Nix gc root left its staging
    /// generation for its stable per-environment path.
    ///
    /// # Failure
    ///
    /// Refuses an unknown id, and refuses a RELEASED environment — a released
    /// environment's root is on its way out, and promoting it would move a root the
    /// release just relinquished. An ALREADY-PROMOTED environment is an idempotent
    /// no-op that does NOT re-stamp the instant, so a retried reconciliation cannot
    /// rewrite when the promotion actually happened.
    pub fn promote_environment_root(
        &self,
        environment_id: [u8; 32],
        promoted_at_ms: i64,
    ) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            let stored = require_environment(tx, environment_id, "promote")?;
            if stored.released_at_ms.is_some() {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to promote the Nix gc root of released environment \
                     {}: the release relinquished that root, so promoting it would move a root \
                     this plane has already given up",
                    hex::encode(environment_id)
                )));
            }
            if stored.root_promoted_at_ms.is_some() {
                return Ok(());
            }
            refuse_instant_before_declaration(
                &stored,
                promoted_at_ms,
                "promote the Nix gc root of",
                "root_promoted_at_ms",
            )?;
            tx.execute(
                "UPDATE nix_environments SET root_promoted_at_ms = ?2
                  WHERE environment_id = ?1 AND root_promoted_at_ms IS NULL",
                params![environment_id.as_slice(), promoted_at_ms],
            )
            .map_err(|error| {
                KataError::Storage(format!("promote nix environment root: {error}"))
            })?;
            Ok(())
        })
    }

    /// RELEASE the environment and, in the SAME transaction, its manifest CAS root.
    ///
    /// # Invariant
    ///
    /// Release is not delete, on both halves. The row stays until
    /// [`Self::delete_released_environment`], and the root stays for good: nothing
    /// deletes a root row or reclaims CAS bytes. It releases through
    /// [`release_cas_root`], which does not re-stamp an already-released root.
    ///
    /// # Failure
    ///
    /// This is the refused set, stated exactly:
    ///
    /// * an UNKNOWN environment id — there is nothing to release, and inventing a
    ///   released row would make a later `delete_released_environment` succeed
    ///   against an environment nobody declared;
    /// * an UNPROMOTED environment. Its root is still in a staging generation the
    ///   boot reconciler owns; releasing it would hand the same root to two owners.
    ///   Drive the reconciliation, or delete the residue, but do not release it;
    /// * an ALREADY-RELEASED environment is an idempotent no-op, not a refusal, and
    ///   does not re-stamp the instant.
    ///
    /// * [`ENVIRONMENT_BOUND_TO_LIVE_ATTEMPT`] — a NON-TERMINAL attempt's capsule binds
    ///   this environment (`attempts.occurrence_id` → `occurrences.capsule_id` →
    ///   `capsules.environment_id`, with the attempt's projected state outside
    ///   [`super::ATTEMPT_TERMINAL_STATES`]). Releasing would let a collection take the
    ///   closure a dispatched container is materializing from. Checked inside the same
    ///   transaction as the release, so an attempt cannot be bound between the check and
    ///   the write.
    ///
    /// What is NOT checked: live evidence claims, which name CAS roots and not
    /// environments — there is no predicate to write over them.
    pub fn release_environment(
        &self,
        environment_id: [u8; 32],
        released_at_ms: i64,
    ) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            let stored = require_environment(tx, environment_id, "release")?;
            if stored.released_at_ms.is_some() {
                return Ok(());
            }
            let live: Option<Vec<u8>> = tx
                .query_row(
                    &format!(
                        "SELECT a.attempt_id FROM attempts a \
                           JOIN occurrences o ON o.occurrence_id = a.occurrence_id \
                           JOIN capsules c ON c.capsule_id = o.capsule_id \
                           LEFT JOIN attempt_projection p ON p.execution_id = a.execution_id \
                            AND p.stage_id = a.stage_id AND p.attempt_ordinal = a.attempt_ordinal \
                          WHERE c.environment_id = ?1 \
                            AND (p.state IS NULL OR p.state NOT IN ({})) LIMIT 1",
                        super::ATTEMPT_TERMINAL_STATES
                            .iter()
                            .map(|state| format!("'{state}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    params![environment_id.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!("read live attempts bound to an environment: {error}"))
                })?;
            if let Some(attempt) = live {
                return Err(KataError::Validation(format!(
                    "{ENVIRONMENT_BOUND_TO_LIVE_ATTEMPT}: Nix environment {} is bound by the capsule \
                     of NON-TERMINAL attempt {}; releasing it would let a collection take the \
                     closure that attempt materializes from. Let it finish (or cancel it) first",
                    hex::encode(environment_id),
                    super::ulid_from_bytes(&attempt)?
                )));
            }
            if stored.root_promoted_at_ms.is_none() {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to release Nix environment {}: its gc root is still \
                     in staging generation {} and the boot reconciler owns it. Promote it (or \
                     delete the residue) rather than releasing a root two owners would then hold",
                    hex::encode(environment_id),
                    stored.root_stage_id
                )));
            }
            refuse_instant_before_declaration(
                &stored,
                released_at_ms,
                "release",
                "released_at_ms",
            )?;
            tx.execute(
                "UPDATE nix_environments SET released_at_ms = ?2
                  WHERE environment_id = ?1 AND released_at_ms IS NULL",
                params![environment_id.as_slice(), released_at_ms],
            )
            .map_err(|error| KataError::Storage(format!("release nix environment: {error}")))?;
            // The manifest root MUST have been live: `declare_environment` committed it in
            // the same transaction as the row, `upsert_cas_root` re-acquires a released
            // root whenever a row is re-declared over it, and
            // `idx_nix_environments_manifest_live` forbids a second live row that could
            // have released it out from under this one. So a `false` here is not
            // idempotence — it is one of those three invariants already broken, and the
            // observable consequence is a live row whose root no longer asserts it. It is
            // reported as `Storage`, which rolls the transaction back and leaves the row
            // unreleased, rather than being swallowed as a no-op.
            let root_id = CasRootSpec::nix_environment_manifest_root_id(stored.manifest_object_id);
            if !release_cas_root(tx, &root_id, released_at_ms)? {
                return Err(KataError::Storage(format!(
                    "operational.db released Nix environment {} but its manifest root {} was \
                     already released or absent. One of three invariants is broken: the declaring \
                     transaction commits row and root together, a re-declaration re-acquires a \
                     released root, and idx_nix_environments_manifest_live forbids a second live \
                     row over one manifest. Refusing the release rather than leaving a live row \
                     whose manifest root no longer asserts it",
                    hex::encode(environment_id),
                    hex::encode(root_id)
                )));
            }
            Ok(())
        })
    }

    /// DELETE a released environment's row.
    ///
    /// # Failure
    ///
    /// Refuses an unknown id and refuses an environment that is not RELEASED. The
    /// refused set is exactly that: deleting an active or unpromoted row would leave
    /// its manifest root retained with no owner able to release it and its staging
    /// generation unattributable — an orphan reference,
    /// reached from the other side.
    ///
    /// The manifest root is deliberately NOT deleted here. It was released by
    /// [`Self::release_environment`] and stays, released: nothing deletes a root row.
    pub fn delete_released_environment(&self, environment_id: [u8; 32]) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            let stored = require_environment(tx, environment_id, "delete")?;
            if stored.released_at_ms.is_none() {
                return Err(KataError::Validation(format!(
                    "operational.db refuses to delete Nix environment {}: it has not been \
                     released, and deleting it would strand its manifest root with no owner able \
                     to release it and its staging generation with nothing able to attribute it",
                    hex::encode(environment_id)
                )));
            }
            tx.execute(
                "DELETE FROM nix_environments WHERE environment_id = ?1",
                params![environment_id.as_slice()],
            )
            .map_err(|error| KataError::Storage(format!("delete nix environment: {error}")))?;
            Ok(())
        })
    }

    /// Every environment whose gc root has not been promoted out of staging — the
    /// boot reconciler's work list.
    ///
    /// Served by `idx_nix_environments_unpromoted`, so the scan is proportional to
    /// the crash window's residue and not to the node's environment history. Every
    /// row here is unreleased by refusal, not by a filter; see the module docs.
    pub fn unpromoted_environments(&self) -> KataResult<Vec<EnvironmentRow>> {
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "{ENVIRONMENT_COLUMNS} WHERE root_promoted_at_ms IS NULL \
                     ORDER BY environment_id"
                ))
                .map_err(|error| {
                    KataError::Storage(format!("prepare unpromoted environments: {error}"))
                })?;
            let rows = stmt
                .query_map([], decode_environment)
                .map_err(|error| {
                    KataError::Storage(format!("read unpromoted environments: {error}"))
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    KataError::Storage(format!("collect unpromoted environments: {error}"))
                })?;
            rows.into_iter().collect()
        })
    }

    /// Every environment that has not been released — the set an issuance gate may
    /// still bind from, once each one's root is promoted.
    ///
    /// Served by `idx_nix_environments_active`. It deliberately returns UNPROMOTED
    /// rows too, with their `root_promoted_at_ms` still `None`: "declared" and
    /// "bindable" are different questions, and filtering here would leave a caller
    /// no way to see an environment that exists and is not yet usable.
    pub fn active_environments(&self) -> KataResult<Vec<EnvironmentRow>> {
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "{ENVIRONMENT_COLUMNS} WHERE released_at_ms IS NULL ORDER BY environment_id"
                ))
                .map_err(|error| {
                    KataError::Storage(format!("prepare active environments: {error}"))
                })?;
            let rows = stmt
                .query_map([], decode_environment)
                .map_err(|error| KataError::Storage(format!("read active environments: {error}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    KataError::Storage(format!("collect active environments: {error}"))
                })?;
            rows.into_iter().collect()
        })
    }

    /// One environment by id, released or not.
    pub fn environment(&self, environment_id: [u8; 32]) -> KataResult<Option<EnvironmentRow>> {
        self.with_read(|conn| {
            conn.query_row(
                &format!("{ENVIRONMENT_COLUMNS} WHERE environment_id = ?1"),
                params![environment_id.as_slice()],
                decode_environment,
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read nix environment: {error}")))?
            .transpose()
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
pub fn debug_environment_columns() -> &'static str {
    ENVIRONMENT_COLUMNS
}

/// The one column list every environment read uses, so a column added to the table
/// cannot reach one reader and miss another.
const ENVIRONMENT_COLUMNS: &str = "SELECT environment_id, manifest_object_id, closure_digest, \
                                   label, platform_id, root_stage_id, root_promoted_at_ms, \
                                   released_at_ms, created_at_ms FROM nix_environments";

/// Decode one row, deferring the fixed-width refusals to [`KataResult`] so a corrupt
/// stored blob is a typed storage refusal rather than a panic inside rusqlite's
/// closure.
#[allow(clippy::type_complexity)]
fn decode_environment(row: &rusqlite::Row<'_>) -> rusqlite::Result<KataResult<EnvironmentRow>> {
    let environment_id: Vec<u8> = row.get(0)?;
    let manifest_object_id: Vec<u8> = row.get(1)?;
    let closure_digest: Vec<u8> = row.get(2)?;
    let label: String = row.get(3)?;
    let platform_id: Vec<u8> = row.get(4)?;
    let root_stage_id: String = row.get(5)?;
    let root_promoted_at_ms: Option<i64> = row.get(6)?;
    let released_at_ms: Option<i64> = row.get(7)?;
    let created_at_ms: i64 = row.get(8)?;
    Ok((|| {
        Ok(EnvironmentRow {
            environment_id: digest32(&environment_id, "environment_id")?,
            manifest_object_id: digest32(&manifest_object_id, "manifest_object_id")?,
            closure_digest: digest32(&closure_digest, "closure_digest")?,
            label,
            platform_id: digest32(&platform_id, "platform_id")?,
            root_stage_id,
            root_promoted_at_ms,
            released_at_ms,
            created_at_ms,
        })
    })())
}

fn digest32(bytes: &[u8], column: &str) -> KataResult<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db nix_environments.{column} must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}

/// Read one environment inside a writer transaction.
fn read_environment(
    tx: &Transaction<'_>,
    environment_id: [u8; 32],
) -> KataResult<Option<EnvironmentRow>> {
    tx.query_row(
        &format!("{ENVIRONMENT_COLUMNS} WHERE environment_id = ?1"),
        params![environment_id.as_slice()],
        decode_environment,
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read nix environment in txn: {error}")))?
    .transpose()
}

/// Read one environment or refuse: `verb` names the operation in the message, so an
/// operator sees which verb found nothing rather than a bare missing-row error.
fn require_environment(
    tx: &Transaction<'_>,
    environment_id: [u8; 32],
    verb: &str,
) -> KataResult<EnvironmentRow> {
    read_environment(tx, environment_id)?.ok_or_else(|| {
        KataError::Validation(format!(
            "operational.db cannot {verb} Nix environment {}: no such environment is declared. \
             This plane never invents a declaration, so there is nothing to act on",
            hex::encode(environment_id)
        ))
    })
}

/// Refuse a SECOND LIVE environment over one manifest object.
///
/// # Invariant
///
/// A manifest root's id is derived from
/// `(node, NULL, nix_environment_manifest, authoritative, Object(manifest_object_id))`,
/// so two environments over the same manifest object derive the SAME `cas_roots` row
/// and SHARE it. [`OperationalDb::release_environment`] would then release that shared
/// row on behalf of one of them — leaving the OTHER environment live with a row that
/// claims to describe a closure whose only manifest root no longer asserts it, which
/// the dangling-root verifier passes over.
///
/// # Enforcement
///
/// Two layers, and the pair is the point. `idx_nix_environments_manifest_live` is a
/// UNIQUE partial index and is what makes the rule TOTAL against any writer. This check
/// is what makes the refusal legible: it runs first and names the environment that
/// already holds the manifest, where the index alone would surface a bare SQLite
/// uniqueness error naming neither id.
///
/// The scope is LIVE rows only, matching the index's predicate: a released row has
/// already relinquished its claim on the root, so re-declaring the same manifest after a
/// release or a delete is legitimate and re-acquires the row through
/// [`upsert_cas_root`].
fn refuse_second_live_manifest_claim(
    tx: &Transaction<'_>,
    declaration: &EnvironmentDeclaration,
) -> KataResult<()> {
    let holder: Option<Vec<u8>> = tx
        .query_row(
            "SELECT environment_id FROM nix_environments
              WHERE manifest_object_id = ?1 AND released_at_ms IS NULL",
            params![declaration.manifest_object_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| {
            KataError::Storage(format!("read live nix environment by manifest: {error}"))
        })?;
    let Some(holder) = holder else {
        return Ok(());
    };
    Err(KataError::Validation(format!(
        "operational.db refuses to declare Nix environment {} over manifest object {}: \
         environment {} is already live over the same manifest, and both would derive the SAME \
         node-owned cas_roots row. Releasing either would then release the other's manifest root. \
         Release (or delete) the existing environment first, or \
         declare this one over its own manifest object",
        hex::encode(declaration.environment_id),
        hex::encode(declaration.manifest_object_id),
        hex::encode(&holder)
    )))
}

/// Refuse an instant that predates the declaration it belongs to.
///
/// The schema CHECKs this too, and that CHECK is the backstop for a forged writer. This
/// is the typed refusal a CALLER can act on: a `CHECK constraint failed` surfaces as
/// `KataError::Storage` naming a constraint expression, which reads like plane damage
/// rather than like the clock argument it actually is.
fn refuse_instant_before_declaration(
    stored: &EnvironmentRow,
    instant_ms: i64,
    verb: &str,
    column: &str,
) -> KataResult<()> {
    if instant_ms >= stored.created_at_ms {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses to {verb} Nix environment {} at {instant_ms}: the declaration \
         committed at {} and {column} may not predate it. An instant before the declaration would \
         make the row's own history non-monotonic, which every reader of these two instants reads \
         as a state it cannot order",
        hex::encode(stored.environment_id),
        stored.created_at_ms
    )))
}

/// Refuse a re-declaration that disagrees with the stored row. See
/// [`OperationalDb::declare_environment`]'s failure section for the refused set.
fn refuse_divergent_redeclaration(
    stored: &EnvironmentRow,
    declaration: &EnvironmentDeclaration,
) -> KataResult<()> {
    if stored.released_at_ms.is_some() {
        return Err(KataError::Validation(format!(
            "operational.db refuses to re-declare released Nix environment {}: release is a \
             retention decision about this closure, and re-declaring would silently un-release it. \
             Delete the released row first if the id is to be reused",
            hex::encode(declaration.environment_id)
        )));
    }
    let divergent: Vec<&str> = [
        (
            "closure_digest",
            stored.closure_digest == declaration.closure_digest,
        ),
        (
            "manifest_object_id",
            stored.manifest_object_id == declaration.manifest_object_id,
        ),
        ("label", stored.label == declaration.label),
        ("platform_id", stored.platform_id == declaration.platform_id),
        (
            "root_stage_id",
            stored.root_stage_id == declaration.root_stage_id,
        ),
    ]
    .into_iter()
    .filter_map(|(field, equal)| (!equal).then_some(field))
    .collect();
    if divergent.is_empty() {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses to re-declare Nix environment {} with a different {}: one \
         environment id names one closure, one manifest and one staging generation. The STORED \
         row is authoritative — its staging generation is the one the boot reconciler will \
         promote — so a caller that lost track of its own must let the reconciler finish and \
         sweep its own directory rather than overwriting the record",
        hex::encode(declaration.environment_id),
        divergent.join(", ")
    )))
}
