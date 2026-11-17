//! `Seed` newtype + env-driven capture.
//!
//! `Seed::from_env()` reads `KATA_TEST_SEED`. `Seed::random()` falls back
//! to a non-`rand::thread_rng()` source — the contracts brief bans
//! `rand::thread_rng()` in test *bodies* (because entropy leaks
//! reproducibility), and while the distinction between "test infrastructure"
//! and "system under test" lets us sidestep that ban here, we still pick a
//! source the deterministic runtime can't observe so nothing in the SUT
//! accidentally depends on it.
//!
//! The Ulid crate's monotonic clock-based generator is:
//! - available in the workspace already,
//! - not backed by the OS entropy pool,
//! - sufficient to produce two distinct u64s within a single test process.

use std::env;

/// Deterministic test seed — a u64 the `deterministic::Runner` consumes
/// verbatim via `deterministic::Config::seed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Seed(pub u64);

impl Seed {
    /// Read the seed from the `KATA_TEST_SEED` environment variable.
    ///
    /// Returns `None` if the variable is unset or cannot be parsed as `u64`.
    /// Callers typically pair this with `Seed::random` as a fallback.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let raw = env::var("KATA_TEST_SEED").ok()?;
        raw.parse::<u64>().ok().map(Self)
    }

    /// Produce a fresh pseudo-random seed.
    ///
    /// Uses the low 64 bits of a freshly generated `Ulid`, which combines
    /// a monotonic timestamp prefix with a random suffix. Not
    /// cryptographically strong (we don't need that here — this is the
    /// *seed* for a deterministic runtime, so its only job is to differ
    /// across runs to surface scheduling variety in CI) but it comfortably
    /// satisfies "two back-to-back calls return different values."
    #[must_use]
    pub fn random() -> Self {
        let ulid = ulid::Ulid::new();
        // Ulid's raw representation is a u128. Take the low 64 bits so two
        // calls made within the same millisecond still differ via the
        // random suffix. Truncation is intentional.
        #[allow(clippy::cast_possible_truncation)]
        let lo = ulid.0 as u64;
        Self(lo)
    }
}
