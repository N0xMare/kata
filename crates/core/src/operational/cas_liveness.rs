//! The join between `operational.db`'s CAS root authority and the CAS itself.
//!
//! # Invariant
//!
//! Everything here follows from one asymmetry: **orphan object bytes are safe; dangling
//! references are not.** An object nothing points at costs disk — and nothing reclaims
//! it, because kata has no CAS collection. A reference pointing at absent bytes is a lie
//! the system will act on. So startup refuses dangling authoritative roots rather than
//! repairing them ([`verify_authoritative_roots_resolve`]).
//!
//! # Failure mode
//!
//! This module lives here, rather than inside either store, because the join is
//! the thing that must not become a raw cross-module handle: `SqliteWorkflowStore`
//! must not open `operational.db`, and `OperationalDb` must not open `cas.db`.
//! Boot explicitly binds the shared CAS for operational outputs; callers verify
//! root liveness through this function.

use kata_types::error::{KataError, KataResult};
use kata_types::primitives::ObjectId;

use super::OperationalDb;
use crate::store::cas::CasStore;

/// What a dangling-root verification found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RootLivenessReport {
    /// Live authoritative roots over CAS objects, all of which resolved.
    pub objects_verified: u64,
}

/// Refuse if an unreleased authoritative root names an object that does not
/// resolve. Operational-output roots additionally verify bounded object content.
///
/// Used by CLI and API startup before execution resumes. Recovery artifact
/// validation separately checks its captured output-reference closure.
///
/// Bounded by `cas_roots`, never a scan of the CAS itself. It reads every root row
/// (the [`OperationalDb::stored_cas_roots`] accessor) and then *verifies*
/// authoritative ones that remain live. Generic roots use presence verification;
/// operational-output roots verify bytes. A
/// released row (a released Nix environment's manifest root) is visited but not
/// verified.
pub fn verify_authoritative_roots_resolve(
    operational: &OperationalDb,
    cas: &CasStore,
) -> KataResult<RootLivenessReport> {
    /// Name at most this many dangling roots: a restore that lost the whole blob
    /// tree would otherwise produce one unreadable error line per object.
    const NAMED: u64 = 8;

    let mut report = RootLivenessReport::default();
    let mut dangling_total = 0_u64;
    let mut named: Vec<String> = Vec::new();
    for root in operational.stored_cas_roots()? {
        if root.released {
            continue;
        }
        let object_id = ObjectId::from(root.object);
        if root.purpose == super::output::OUTPUT_ROOT_PURPOSE {
            cas.get_verified_bounded(&object_id, super::output::MAX_OUTPUT_BYTES)?;
            report.objects_verified += 1;
            continue;
        }
        if cas.resolves(&object_id)? {
            report.objects_verified += 1;
        } else {
            dangling_total += 1;
            if (named.len() as u64) < NAMED {
                named.push(format!("{} (purpose {})", object_id, root.purpose));
            }
        }
    }
    if dangling_total == 0 {
        return Ok(report);
    }
    Err(KataError::Storage(format!(
        "operational.db holds {dangling_total} authoritative CAS root(s) whose objects \
         do not resolve in the CAS: {}{}. Refusing rather than repairing — a dangling \
         reference is never safe to guess at (an orphan object would be), and the usual \
         cause is a restored artifact that captured cas.db without its cas/ blob tree",
        named.join(", "),
        if dangling_total > NAMED { ", ..." } else { "" }
    )))
}
