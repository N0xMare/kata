//! RESOLVE a capsule dispatch frame into the
//! [`Capsule`] it names, on the worker side.
//!
//! # What this module is
//!
//! [`resolve`] turns a [`CapsuleAssignment`] into a verified [`Capsule`]. It is the
//! worker's trust boundary over a frame it received: the frame is UNTRUSTED INPUT (a
//! standalone `kata-worker` deserializes whatever arrives), so every claim it makes about the
//! capsule is checked against the bytes, and the bytes are checked against their
//! address. Its one production caller is
//! [`crate::capsule_execution::execute_capsule_frame`].
//!
//! # Why the resolver and not the frame owns the refusals
//!
//! A frame's fields can be edited by whoever sent it. A capsule's cannot: `Capsule`'s
//! own `Deserialize` recomputes the [`CapsuleId`](kata_types::execution_contract::CapsuleId)
//! from the decoded body and refuses a body whose stored id disagrees, so tampering
//! with the CONTENT is refused by the type that owns the derivation. What remains for
//! this module is everything that relates the frame to the bytes — which is exactly
//! the set below.

#[cfg(feature = "test-support")]
use kata_core::store::cas::CasStore;
use kata_transport::types::CapsuleAssignment;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::Capsule;

use crate::materialize::BlobSource;

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("capsule frame refused: {reason}"))
}

/// RESOLVE the capsule a frame references, verified against the frame's own claims.
///
/// `source` is any [`BlobSource`] — `LocalCasBlobSource` in production, a test
/// double in a rig — for the same reason `materialize` takes one: the shared-disk
/// assumption is stated at the trait rather than baked into this reader.
///
/// # What the comparison is, and what it is not
///
/// A worker holds a frame and nothing else: there is no worker-side lease carrier
/// independent of the frame to check the frame's `occurrence_id` against. The
/// independent carrier is the BYTES. A capsule is content-addressed and carries its own
/// [`Capsule::occurrence`] folded into its id, and the frame names that id separately
/// from the CAS address it claims to find it at. So this door compares CARRIERS that
/// travelled by different routes (the frame over a socket, the capsule through the
/// content store) — and they are not independent AUTHORITIES: every one of them was
/// written by the main from its one at-rest frame and the capsule it authorized. What
/// the comparison guards is TRANSIT and AT-REST corruption between the main's write
/// and this worker's read, not a main that authorized the wrong thing. The lease epoch
/// rides the same frame and is echoed back on the completion, where the main's ingress
/// fence compares it against `attempts.lease_epoch`.
///
/// # Failure — the refused set, stated exactly
///
/// Five things, each observable on its own:
///
/// 1. **UNKNOWN OBJECT** — the CAS does not hold `frame.capsule.object`. Refused by
///    the store's own verified read, whose refusal names the address.
/// 2. **SIZE MISMATCH** — the stored object's length is not
///    `frame.capsule.size_bytes`. Refused by the store's verified read BEFORE it
///    allocates, which is why the length is on the frame at all: an unbounded read of
///    a length a sender chose is the allocation a hostile frame would aim for. The
///    same read caps at [`Capsule::MAXIMUM_ENCODED_BYTES`], so a frame claiming a
///    gigabyte is refused without reading one.
/// 3. **CORRUPT BYTES** — the object's bytes do not decode as a [`Capsule`]. This arm
///    also catches a TAMPERED BODY, because `Capsule`'s `Deserialize` recomputes the
///    capsule id from the body and refuses a mismatch; the decode error says which.
/// 4. **TAMPERED FRAME ID** — the decoded capsule's id is not `frame.capsule.id`. The
///    bytes are internally consistent and they are a DIFFERENT capsule from the one
///    the frame claims, which is the substitution a content address alone cannot
///    catch: the address names bytes, and the frame names an identity, so both have to
///    be checked or one of them is decoration.
/// 5. **OCCURRENCE MISMATCH** — the decoded capsule's occurrence is not the frame's
///    `occurrence_id`. A sender that wants a worker to run another occurrence's body
///    under this frame has to forge a capsule whose own bytes name the occurrence it
///    claims — at which point it is a different capsule, and the main's authorization
///    is what decided the attempt may run it.
///
/// Nothing else. In particular this function does NOT check that the capsule's
/// environment is present in the local Nix store, that its input artifacts are
/// readable, or that its budgets are satisfiable: those are `materialize`'s and the
/// route's refusals, each already stated at its own door, and a second weaker answer
/// here would be a guarantee wider than its mechanism.
pub fn resolve(source: &dyn BlobSource, frame: &CapsuleAssignment) -> KataResult<Capsule> {
    let bytes = source
        .read_verified(
            frame.capsule.object,
            frame.capsule.size_bytes,
            Capsule::MAXIMUM_ENCODED_BYTES,
        )
        .map_err(|error| {
            refused(&format!(
                "capsule object {} ({} bytes claimed) is not readable from this worker's content \
                 store: {error}",
                frame.capsule.object, frame.capsule.size_bytes
            ))
        })?;

    let capsule: Capsule = serde_json::from_slice(&bytes).map_err(|error| {
        refused(&format!(
            "capsule object {} does not decode as a capsule: {error}. Capsule's own Deserialize \
             recomputes the capsule id from the body, so a tampered BODY is refused here by the \
             type that owns the derivation",
            frame.capsule.object
        ))
    })?;

    if capsule.id() != frame.capsule.id {
        return Err(refused(&format!(
            "capsule object {} holds capsule {} but the frame names capsule {}. The bytes are \
             internally consistent and they are a different capsule: a content address proves \
             WHICH BYTES, and only this comparison proves which CAPSULE",
            frame.capsule.object,
            capsule.id().0,
            frame.capsule.id.0
        )));
    }

    if capsule.occurrence() != frame.occurrence_id {
        return Err(refused(&format!(
            "capsule {} was assembled for occurrence {} but the frame claims occurrence {}. The \
             capsule's bytes carry their own occurrence, folded into their id, so the \
             disagreement is between two carriers that travelled by different routes",
            capsule.id().0,
            capsule.occurrence().0,
            frame.occurrence_id.0
        )));
    }

    Ok(capsule)
}

/// A [`BlobSource`] over a `CasStore` this worker OPENED, for rigs that already hold
/// one.
///
/// # `test-support` ONLY
///
/// Gated, because production has exactly one blob source and it is
/// `materialize::LocalCasBlobSource`: a worker opens `cas.db` read-only FROM PATHS, and
/// a second production door that took an already-open `CasStore` would be a second
/// answer to "how does a worker reach the store" — the shared-disk assumption the
/// trait exists to state once. Behind the feature it cannot become that by accident.
///
/// `materialize::LocalCasBlobSource` opens `cas.db` read-only from paths, which is the
/// production shape. A test that has just PUBLISHED a capsule holds the `CasStore`
/// itself, and making it re-open the same database by path to read back what it just
/// wrote would be a second handle proving nothing about this module. This adapter is
/// that convenience and nothing more; it writes nothing.
#[cfg(feature = "test-support")]
#[derive(Debug)]
pub struct OpenCasBlobSource<'a>(pub &'a CasStore);

#[cfg(feature = "test-support")]
impl BlobSource for OpenCasBlobSource<'_> {
    fn read_verified(
        &self,
        object: kata_types::primitives::ObjectId,
        expected_size: u64,
        maximum: u64,
    ) -> KataResult<Vec<u8>> {
        self.0.get_verified(&object, expected_size, maximum)
    }
}
