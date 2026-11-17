//! What the EXECUTOR is, as bytes a key can fold: [`ExecutorTerm`], the
//! commitment of the capsule reuse key
//! (`crate::execution_contract::Capsule::reuse_key`) to the machinery that runs a
//! stage rather than to anything a workflow declared.
//!
//! # The content-cache key commits to what the executor DOES
//!
//! The kata seccomp floor — and every other property of the executing machinery
//! — is part of the CONTENT-CACHE KEY, and nothing else: NOT the `containment`
//! axis, NOT the stage contract hash, NOT a routing input. A later property must
//! be able to join without a schema change. On the capsule plane that is this
//! term: every CAPSULE
//! field [`crate::execution_contract::Capsule::reuse_key`] folds is something a
//! workflow declared or a content address of one, and its `platform` field is a
//! fixed profile constant (`crate::node_profile::node_platform`), so without the
//! term a kata build that changed its seccomp deny-list, its pinned youki or its OCI
//! bundle render would adopt results computed under the old fence — at any age,
//! since a `content_cache` source has no age bound.
//!
//! [`ExecutorTerm`] is the reuse key's one non-capsule input. Three rules shape it:
//!
//! * **Derived from behaviour, never from a version string.** Its properties are
//!   the bytes kata hands the runtime; a release that changes none of them keeps
//!   every key. `kata_worker::executor_term` derives them.
//! * **The reuse key ONLY.** It is a parameter of `Capsule::reuse_key` and never a
//!   [`crate::execution_contract::Capsule`] field, so no capsule id, occurrence,
//!   attempt, stage contract hash or `PlatformRef` digest moves when it does —
//!   an executor change must not rotate those identities.
//! * **An ordered bag of NAMED properties.** The term hashes the SORTED
//!   `(name, blake3(bytes))` list under a versioned domain tag, so a later
//!   property joins as one more pair: no type change, no stored-row change, one
//!   cache-wide miss.

use std::collections::BTreeMap;

use crate::{KataError, KataResult, cache::hash_field, primitives::ContentHash};

/// The domain tag [`ExecutorTerm::derive`] folds first. Versioned so a change to
/// HOW properties are folded (not which ones) is a deliberate rotation.
const EXECUTOR_TERM_DOMAIN: &str = "kata.execution_platform.executor_term.v1";

/// The executor's own term in the capsule reuse key. See the module docs.
///
/// Constructed only by [`Self::derive`], so a term in hand always folds at least
/// one named property — a term over nothing would key every executor alike while
/// looking like a commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorTerm(ContentHash);

impl ExecutorTerm {
    /// Fold `properties` — `(name, the exact bytes kata hands the runtime)` — into
    /// one term.
    ///
    /// Each value is digested on its own (`blake3`), the pairs are SORTED by name,
    /// and the domain tag, the pair count and every `(name, digest)` are folded
    /// length-prefixed. The caller's order is therefore not part of the term, and
    /// `("ab", x)` and `("a", "b"‖x)` cannot collide.
    ///
    /// # Refused set
    ///
    /// Exactly three things: an empty property list, an empty property name, and a
    /// name given twice. Everything else is accepted, including an empty value — an
    /// executor property that renders to no bytes is still a fact about the
    /// executor, and it folds differently from a property that is absent.
    ///
    /// # Errors
    ///
    /// [`KataError::Validation`] naming which clause refused.
    pub fn derive(properties: &[(&str, &[u8])]) -> KataResult<Self> {
        if properties.is_empty() {
            return Err(KataError::Validation(
                "an executor term must fold at least one property: a term over nothing keys \
                 every executor alike"
                    .to_owned(),
            ));
        }
        let mut sorted: BTreeMap<&str, [u8; 32]> = BTreeMap::new();
        for (name, value) in properties {
            if name.is_empty() {
                return Err(KataError::Validation(
                    "an executor term property must be named".to_owned(),
                ));
            }
            if sorted
                .insert(name, *blake3::hash(value).as_bytes())
                .is_some()
            {
                return Err(KataError::Validation(format!(
                    "executor term property `{name}` is given twice; one name is one fact"
                )));
            }
        }
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, EXECUTOR_TERM_DOMAIN, &[]);
        hash_field(
            &mut hasher,
            "properties",
            &(sorted.len() as u64).to_le_bytes(),
        );
        for (name, digest) in &sorted {
            hash_field(&mut hasher, name, digest);
        }
        Ok(Self(ContentHash::new(*hasher.finalize().as_bytes())))
    }

    /// The term's digest — what the reuse key folds.
    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The term is a function of the property SET: the caller's order is not in it,
    /// and moving any one value, renaming any one property, or adding one moves it.
    ///
    /// **Would red if:** `derive` folded the properties in the order given, dropped
    /// the name from a pair, or ignored a property.
    #[test]
    fn the_term_is_the_sorted_named_property_set() {
        let term = |properties: &[(&str, &[u8])]| ExecutorTerm::derive(properties).unwrap();
        let base = term(&[("a", b"1"), ("b", b"2")]);
        assert_eq!(
            base,
            term(&[("b", b"2"), ("a", b"1")]),
            "order is not a fact"
        );
        for moved in [
            term(&[("a", b"1"), ("b", b"3")]),
            term(&[("a", b"1"), ("c", b"2")]),
            term(&[("a", b"1"), ("b", b"2"), ("c", b"")]),
            term(&[("a", b"1")]),
        ] {
            assert_ne!(moved, base);
        }
        assert_ne!(
            term(&[("ab", b"x")]),
            term(&[("a", b"bx")]),
            "the name/value boundary is length-prefixed"
        );
    }

    /// Each clause of the refused set fires, and nothing else is refused.
    #[test]
    fn derive_refuses_exactly_its_refused_set() {
        assert!(ExecutorTerm::derive(&[]).is_err(), "no properties");
        assert!(ExecutorTerm::derive(&[("", b"x")]).is_err(), "unnamed");
        let twice = ExecutorTerm::derive(&[("a", b"x"), ("a", b"y")])
            .expect_err("a name given twice")
            .to_string();
        assert!(twice.contains("`a`"), "{twice}");
        assert!(
            ExecutorTerm::derive(&[("a", b"")]).is_ok(),
            "an empty value"
        );
    }
}
