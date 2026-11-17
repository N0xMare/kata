//! Pre-shared secret generation for the worker handshake.
//!
//! The local-worker handshake uses a symmetric shared secret persisted on the
//! main at `<data_dir>/home-secret` and distributed to a local worker through
//! `kata-worker provision`. This module exposes a single helper that produces
//! a new one.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;

/// Generate a new shared secret suitable for worker handshakes.
/// Produces 24 random bytes (from `OsRng`) encoded as a 32-char
/// URL-safe base64 string. URL-safe with no padding keeps the
/// result shell-safe (no `+/=`) so operators can paste it into
/// command lines without quoting.
///
/// Stable across invocations only insofar as the caller persists
/// the output — the function itself is non-deterministic.
///
/// **Domain separation:** the shared secret is NOT derived from any
/// `DOMAIN_*` label in `crate::domain`. It is a pre-shared symmetric
/// secret, not a domain-separated signature; comparison at the
/// receiver is a constant-time string compare. The crypto-crate domain
/// labels apply to keyed-hash / signature constructions only.
#[must_use]
pub fn generate_shared_secret() -> String {
    let mut buf = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two consecutive calls must produce different outputs, and both
    /// must be at least 30 characters long (URL-safe base64 of 24 bytes
    /// is 32 chars with no padding).
    #[test]
    fn generate_shared_secret_is_non_trivial() {
        let a = generate_shared_secret();
        let b = generate_shared_secret();
        assert!(a.len() >= 30, "shared secret too short: {} chars", a.len());
        assert!(b.len() >= 30, "shared secret too short: {} chars", b.len());
        assert_ne!(a, b, "two calls must not produce identical secrets");
    }

    /// Pin the exact length at 32 so a future encoding change shows up
    /// as a test failure rather than a silent drift in operator UX.
    #[test]
    fn generate_shared_secret_length_is_32() {
        assert_eq!(generate_shared_secret().len(), 32);
    }

    /// URL-safe, no-padding alphabet only. Specifically forbid `+`,
    /// `/`, and `=` so the result is safe to paste into shell commands
    /// without quoting.
    #[test]
    fn generate_shared_secret_is_shell_safe() {
        let s = generate_shared_secret();
        assert!(!s.contains('+'));
        assert!(!s.contains('/'));
        assert!(!s.contains('='));
    }
}
