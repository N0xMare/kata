//! `kata-crypto` — a BLAKE3 helper and ed25519 signing/verification used
//! throughout the kata runtime.
//!
//! Scope is deliberately narrow:
//!
//! - [`hash`] wraps [`blake3`]'s single-shot hash as a `ContentHash`.
//! - [`sign`] wraps [`ed25519_dalek`] so every fallible call returns
//!   [`kata_types::KataError::Crypto`] instead of panicking, and exposes
//!   lowercase-hex serde representations for keys and signatures.
//! - [`api_token`] mints, verifies, and wire-encodes scoped
//!   [`kata_types::identity::ApiToken`]s — the REST API's application-layer
//!   authorization (signed, scoped bearer token in its own signing domain).
//!
//! blake3 is imported at parity with commonware-cryptography.
//!
//! Hard non-goals: BLS / Schnorr / VRF / zk primitives, commitment or
//! checkpoint construction, key persistence, and commonware-codec impls.

#![forbid(unsafe_code)]

pub mod api_token;
pub mod hash;
pub mod secret;
pub mod sign;

pub use api_token::{
    decode_api_token, encode_api_token, mint_api_token, sign_api_token, verify_api_token,
};
pub use hash::*;
pub use secret::generate_shared_secret;
pub use sign::*;
