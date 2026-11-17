//! The convergence-refusal algebra over execution-identity observations, and the
//! one identity newtype that survives beside it.
//!
//! Distinct from [`crate::identity`], which names the *authentication /
//! membership* plane (public-key ids, worker ids and effect domains, API
//! tokens). This module names the rule that keeps two observations of ONE
//! identity from silently diverging.
//!
//! # The convergence refusal algebra
//!
//! - **Invariant.** An identity has exactly one value. Two surfaces may each
//!   *observe* it (a stored accepted-event digest and a redelivered one); those
//!   observations must agree.
//! - **Failure mode.** Two surfaces present two *different* values for one
//!   identity — a double-producer violation.
//! - **Rule.** [`converge`] folds two `Option` observations: two absents are
//!   absent; one present is authoritative (the other simply has not observed it
//!   yet); two equal presents converge; two *different* presents are a typed
//!   [`Divergence`] refusal that carries BOTH values — the fold never silently
//!   picks a side.
//! - **Enforcement point.** The live enforcement site is the operational event
//!   inbox: one accepted-event slot `(stream, seq)` binds to exactly one event
//!   content digest. A redelivery with the SAME digest is an idempotent ACK; a
//!   redelivery with a DIFFERENT digest is a [`Divergence`] refusal via
//!   [`converge_accepted_event_content`] (`crates/core/src/operational`).

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::primitives::{ContentHash, delegate_display, delegate_from_str};

/// A typed refusal: two present, *different* observations of one identity.
///
/// Carries the RELATION violated and BOTH observed values, so a caller can
/// report exactly what diverged and neither value is silently dropped.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Divergence<T> {
    /// The stable snake_case name of the identity relation whose single-value
    /// invariant was violated (e.g. [`ACCEPTED_EVENT_CONTENT`]).
    pub relation: &'static str,
    /// The first observed value.
    pub left: T,
    /// The second, conflicting observed value.
    pub right: T,
}

impl<T: fmt::Display> fmt::Display for Divergence<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} identity convergence violated: two different observations of one identity \
             ({} != {}); it must have a single producer (divergence refused, not merged)",
            self.relation, self.left, self.right
        )
    }
}

impl<T: fmt::Display + fmt::Debug> std::error::Error for Divergence<T> {}

/// Fold two observations of one identity into its single value, or refuse.
///
/// - **Invariant.** An identity has one value; the fold is the "all present
///   observations agree, else refuse" partial operation with absence
///   ([`None`]) as its identity element.
/// - **Failure mode.** Two present, different observations — a divergence.
/// - **Rule / proof.** `(None, None) → None`; `(Some(x), None)` /
///   `(None, Some(y))` → the present value; `(Some(x), Some(x)) → Some(x)`;
///   `(Some(x), Some(y)), x != y → Err(Divergence { relation, left: x, right: y })`. The
///   fold is commutative, idempotent, and associative where defined, and
///   absorbs `None` — proven exhaustively over an enumerated domain in this
///   module's tests. It never picks a side on divergence: the refusal carries
///   both values.
pub fn converge<T: PartialEq>(
    relation: &'static str,
    left: Option<T>,
    right: Option<T>,
) -> Result<Option<T>, Divergence<T>> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(x), None) | (None, Some(x)) => Ok(Some(x)),
        (Some(x), Some(y)) if x == y => Ok(Some(x)),
        (Some(x), Some(y)) => Err(Divergence {
            relation,
            left: x,
            right: y,
        }),
    }
}

/// Converge two observations of an accepted-event slot's content digest.
///
/// Invariant: one operational event-inbox slot `(stream, seq)` binds to one
/// content digest. LIVE: the event-inbox dedup path folds the stored digest
/// against a redelivered event's digest — equal digests are an idempotent ACK,
/// different digests are a [`Divergence`] refusal the inbox surfaces rather than
/// overwriting the accepted event.
pub fn converge_accepted_event_content(
    left: Option<ContentHash>,
    right: Option<ContentHash>,
) -> Result<Option<ContentHash>, Divergence<ContentHash>> {
    converge(ACCEPTED_EVENT_CONTENT, left, right)
}

/// The relation [`converge_accepted_event_content`] guards: one event-inbox slot
/// `(stream, seq)` binds to one content digest. Named in its [`Divergence`].
pub const ACCEPTED_EVENT_CONTENT: &str = "accepted_event_content";

/// Identity of one invocation's resolved TYPED-INPUT set — the admission
/// digest.
///
/// Wraps the `admission_hash` [`ContentHash`] the operational store mints over
/// the immutable admission record (which carries the resolved, canonically
/// ordered params); `#[serde(transparent)]` keeps it byte-identical to that
/// bare hash. Naming it separates "the digest of the resolved caller inputs"
/// from a bare content hash. Provenance (which face supplied the values) is
/// recorded beside this digest and is NEVER folded into it, so identical inputs
/// from two faces produce one [`AdmissionDigest`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmissionDigest(pub ContentHash);

delegate_display!(AdmissionDigest);
delegate_from_str!(AdmissionDigest, ContentHash);

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u8) -> ContentHash {
        crate::primitives::FixedBytes([seed; 32])
    }

    /// Assert the full convergence law-suite over an enumerated domain of
    /// `Option<T>` observations. Universally quantifying over every element (and
    /// pair, and triple) of a representative domain proves the laws for `T` —
    /// the fold's logic is type-agnostic, so an exhaustive proof over one
    /// domain is a property proof, not a spot check.
    fn assert_converge_laws<T>(domain: &[Option<T>])
    where
        T: PartialEq + Clone + fmt::Debug,
    {
        for a in domain {
            // Idempotency: converge(x, x) == Ok(x) for every x (incl. None).
            let idem = converge("test", a.clone(), a.clone());
            assert_eq!(
                idem.ok(),
                Some(a.clone()),
                "idempotency: converge(x, x) must be Ok(x)"
            );

            for b in domain {
                let ab = converge("test", a.clone(), b.clone());
                let ba = converge("test", b.clone(), a.clone());

                // Commutativity where defined: same defined-ness, and equal Ok
                // values.
                assert_eq!(
                    ab.is_ok(),
                    ba.is_ok(),
                    "commutativity: converge(a,b) and converge(b,a) must agree on defined-ness"
                );
                if let (Ok(x), Ok(y)) = (&ab, &ba) {
                    assert_eq!(x, y, "commutativity: Ok values must match");
                }

                // None-absorption: None folds with X to X, both directions.
                if a.is_none() {
                    assert_eq!(ab.ok(), Some(b.clone()), "None-absorption: (None, X) -> X");
                }
                if b.is_none() {
                    assert_eq!(
                        ba.clone().ok(),
                        Some(a.clone()),
                        "None-absorption: (X, None) -> X"
                    );
                }

                // Divergence: two present, different values always refuse and the
                // refusal carries BOTH values (never picks a side).
                match (a, b) {
                    (Some(x), Some(y)) if x != y => {
                        let d = converge("test", a.clone(), b.clone())
                            .expect_err("distinct present observations must refuse");
                        assert_eq!(&d.left, x, "refusal keeps the left value");
                        assert_eq!(&d.right, y, "refusal keeps the right value");
                    }
                    _ => {
                        // Everything else is defined.
                        assert!(
                            converge("test", a.clone(), b.clone()).is_ok(),
                            "agreeing / absent observations must converge"
                        );
                    }
                }

                // Associativity where defined: left-fold == right-fold over every
                // triple; if any pair diverges the whole fold refuses either way.
                for c in domain {
                    let left = converge("test", a.clone(), b.clone())
                        .and_then(|ab| converge("test", ab, c.clone()));
                    let right = converge("test", b.clone(), c.clone())
                        .and_then(|bc| converge("test", a.clone(), bc));
                    assert_eq!(
                        left.is_ok(),
                        right.is_ok(),
                        "associativity: fold order must not change defined-ness"
                    );
                    if let (Ok(x), Ok(y)) = (&left, &right) {
                        assert_eq!(x, y, "associativity: fold order must not change the value");
                    }
                }
            }
        }
    }

    #[test]
    fn convergence_laws_hold_over_u32() {
        let domain = [None, Some(0u32), Some(1u32), Some(2u32)];
        assert_converge_laws(&domain);
    }

    #[test]
    fn convergence_laws_hold_over_content_hash() {
        let domain = [None, Some(hash(0)), Some(hash(1)), Some(hash(9))];
        assert_converge_laws(&domain);
    }

    #[test]
    fn convergence_laws_hold_over_string() {
        let domain = [
            None,
            Some(String::new()),
            Some("cafe".to_string()),
            Some("f00d".to_string()),
        ];
        assert_converge_laws(&domain);
    }

    #[test]
    fn divergence_never_silently_picks_a_side() {
        let d = converge("test", Some("a"), Some("b")).expect_err("distinct values must refuse");
        assert_eq!(d.left, "a");
        assert_eq!(d.right, "b");
        let msg = d.to_string();
        assert!(msg.contains("convergence violated"), "{msg}");
        assert!(msg.contains('a') && msg.contains('b'), "{msg}");
    }

    #[test]
    fn accepted_event_content_converges_or_refuses() {
        // A same-digest redelivery converges to the single accepted content.
        assert_eq!(
            converge_accepted_event_content(Some(hash(3)), Some(hash(3))).unwrap(),
            Some(hash(3))
        );
        // A different-digest redelivery refuses, carrying both values.
        let refusal = converge_accepted_event_content(Some(hash(1)), Some(hash(2)))
            .expect_err("distinct event digests refuse");
        assert_eq!(refusal.left, hash(1));
        assert_eq!(refusal.right, hash(2));
        assert_eq!(refusal.relation, ACCEPTED_EVENT_CONTENT);
        assert!(
            refusal
                .to_string()
                .starts_with("accepted_event_content identity convergence"),
            "the refusal names its relation: {refusal}"
        );
        // One-sided observations converge to the present value.
        assert_eq!(
            converge_accepted_event_content(Some(hash(4)), None).unwrap(),
            Some(hash(4))
        );
        assert_eq!(
            converge_accepted_event_content(None, Some(hash(5))).unwrap(),
            Some(hash(5))
        );
        assert_eq!(converge_accepted_event_content(None, None).unwrap(), None);
    }

    /// `#[serde(transparent)]` must make the newtype encode byte-for-byte
    /// identically to the raw [`ContentHash`] it wraps, in BOTH the
    /// human-readable (JSON) and the binary (CBOR) profiles — so adopting the
    /// newtype at a persisted field cannot rotate a single stored byte.
    #[test]
    fn admission_digest_is_byte_compatible_with_raw_content_hash() {
        let h = hash(0xAB);
        let wrapped = AdmissionDigest(h);
        let raw_json = serde_json::to_string(&h).unwrap();
        // JSON encodes identically to the raw ContentHash...
        assert_eq!(serde_json::to_string(&wrapped).unwrap(), raw_json);
        // ...and the raw ContentHash JSON decodes back into the newtype.
        let decoded: AdmissionDigest = serde_json::from_str(&raw_json).unwrap();
        assert_eq!(decoded, wrapped);
        // CBOR (binary profile) encodes identically too.
        let mut a = Vec::new();
        let mut b = Vec::new();
        ciborium::into_writer(&wrapped, &mut a).unwrap();
        ciborium::into_writer(&h, &mut b).unwrap();
        assert_eq!(
            a, b,
            "CBOR of the newtype must equal CBOR of the raw ContentHash"
        );
    }
}
