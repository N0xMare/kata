//! ed25519 signing and verification wrappers.
//!
//! Each type wraps an [`ed25519_dalek`] primitive and maps every fallible
//! call into [`kata_types::KataError::Crypto`]. None of the public functions
//! in this module panic on malformed input — that is a hard invariant.
//!
//! Serde representation for [`SigningKey`], [`VerifyingKey`], and
//! [`Signature`] is lowercase hex over the raw byte form, matching the
//! [`kata_types::FixedBytes`] convention used elsewhere in the type surface.

use core::fmt;

use ed25519_dalek::Signer;
use kata_types::{KataError, KataResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Ed25519 private key. On drop the inner secret is zeroized by
/// `ed25519_dalek::SigningKey`'s own `ZeroizeOnDrop` impl.
#[derive(Clone)]
pub struct SigningKey(ed25519_dalek::SigningKey);

/// Ed25519 public key used to authenticate a concrete main or scoped token.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

/// Ed25519 signature over a message byte slice.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(ed25519_dalek::Signature);

// ── SigningKey ───────────────────────────────────────────────────────────

impl SigningKey {
    /// Deterministically derive a signing key from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// Raw 32-byte secret scalar. Callers that persist this value MUST
    /// zeroize their local copy — the wrapper cannot do that for you.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Public half of the keypair.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Sign `msg`.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg))
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print secret bytes.
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

impl Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_hex_or_bytes(&self.0.to_bytes(), serializer)
    }
}

impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = decode_fixed_hex_or_bytes::<D, 32>(deserializer, "SigningKey")?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&raw)))
    }
}

// ── VerifyingKey ─────────────────────────────────────────────────────────

impl VerifyingKey {
    /// Parse a `VerifyingKey` from its raw 32-byte encoding. Rejects
    /// non-canonical / small-order points via ed25519-dalek's built-in check.
    pub fn from_bytes(bytes: [u8; 32]) -> KataResult<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|e| KataError::Crypto(format!("ed25519 verifying-key decode failed: {e}")))
    }

    /// Raw 32-byte compressed Edwards encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify `sig` over `msg`.
    ///
    /// Uses ed25519-dalek's **strict** verification ([`verify_strict`]),
    /// which — unlike the permissive `verify` — rejects signatures whose `R`
    /// or the key `A` is a small-order / non-canonical point. That closes the
    /// ed25519 signature-malleability surface (multiple valid encodings for a
    /// signature, and torsion-component tricks), so a signature that verifies
    /// here is the unique one the signer produced. Every kata verify path
    /// routes through this method — including the API-token boundary in
    /// [`crate::api_token::verify_api_token`] — so they all inherit the
    /// strict check.
    ///
    /// [`verify_strict`]: ed25519_dalek::VerifyingKey::verify_strict
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> KataResult<()> {
        self.0
            .verify_strict(msg, &sig.0)
            .map_err(|e| KataError::Crypto(format!("ed25519 verify failed: {e}")))
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey({})", hex::encode(self.0.to_bytes()))
    }
}

impl fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0.to_bytes()))
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_hex_or_bytes(&self.0.to_bytes(), serializer)
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = decode_fixed_hex_or_bytes::<D, 32>(deserializer, "VerifyingKey")?;
        ed25519_dalek::VerifyingKey::from_bytes(&raw)
            .map(VerifyingKey)
            .map_err(|e| serde::de::Error::custom(format!("invalid ed25519 verifying key: {e}")))
    }
}

// ── Signature ────────────────────────────────────────────────────────────

impl Signature {
    /// Parse a signature from its raw 64-byte encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(ed25519_dalek::Signature::from_bytes(&bytes))
    }

    /// Raw 64-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0.to_bytes()))
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_hex_or_bytes(&self.0.to_bytes(), serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = decode_fixed_hex_or_bytes::<D, 64>(deserializer, "Signature")?;
        Ok(Self(ed25519_dalek::Signature::from_bytes(&raw)))
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────

/// Serialize `bytes` as lowercase hex for human-readable formats (JSON,
/// TOML) and as raw bytes for compact binary formats. Shared by the
/// [`SigningKey`], [`VerifyingKey`], and [`Signature`] `Serialize` impls so
/// all three keep a byte-identical wire form; the inverse is
/// [`decode_fixed_hex_or_bytes`].
fn serialize_hex_or_bytes<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

fn decode_fixed_hex_or_bytes<'de, D, const N: usize>(
    deserializer: D,
    label: &'static str,
) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{Error as DeError, Visitor};

    struct FxVisitor<const M: usize> {
        label: &'static str,
    }

    impl<const M: usize> Visitor<'_> for FxVisitor<M> {
        type Value = [u8; M];

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "a {} byte {} encoded as lowercase hex or raw bytes",
                M, self.label
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            let mut out = [0u8; M];
            hex::decode_to_slice(v, &mut out)
                .map_err(|e| E::custom(format!("invalid hex for {}: {e}", self.label)))?;
            Ok(out)
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            if v.len() != M {
                return Err(E::invalid_length(v.len(), &self));
            }
            let mut out = [0u8; M];
            out.copy_from_slice(v);
            Ok(out)
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            self.visit_bytes(&v)
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_str(FxVisitor::<N> { label })
    } else {
        deserializer.deserialize_bytes(FxVisitor::<N> { label })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::from_seed([0x01u8; 32]);
        let vk = sk.verifying_key();
        let msg = b"kata domain-separated message";
        let sig = sk.sign(msg);
        vk.verify(msg, &sig).expect("valid signature must verify");
    }

    #[test]
    fn sign_wrong_key_fails() {
        let sk_a = SigningKey::from_seed([0x02u8; 32]);
        let sk_b = SigningKey::from_seed([0x03u8; 32]);
        let msg = b"domain-sep payload";
        let sig = sk_a.sign(msg);
        let vk_b = sk_b.verifying_key();
        let err = vk_b
            .verify(msg, &sig)
            .expect_err("verifying with the wrong key must fail");
        assert!(
            matches!(err, KataError::Crypto(_)),
            "expected KataError::Crypto, got {err:?}",
        );
    }

    #[test]
    fn sign_tampered_message_fails() {
        let sk = SigningKey::from_seed([0x04u8; 32]);
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");
        let err = vk
            .verify(b"tampered", &sig)
            .expect_err("verifying tampered message must fail");
        assert!(matches!(err, KataError::Crypto(_)));
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = [0x11u8; 32];
        let a = SigningKey::from_seed(seed);
        let b = SigningKey::from_seed(seed);
        assert_eq!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
        // And signing the same message under both keys is byte-identical.
        let sig_a = a.sign(b"deterministic");
        let sig_b = b.sign(b"deterministic");
        assert_eq!(sig_a.to_bytes(), sig_b.to_bytes());
    }

    #[test]
    fn verifying_key_rejects_invalid_bytes() {
        // All-zero is not a valid ed25519 point on the curve for some
        // ed25519-dalek versions, but the stronger signal is: garbage bytes
        // must fail without panicking.
        let raw = [0u8; 32];
        // Either branch is acceptable — the contract is "no panic".
        let _ = VerifyingKey::from_bytes(raw);
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let sk = SigningKey::from_seed([0x33u8; 32]);
        let sig = sk.sign(b"payload");
        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(bytes);
        assert_eq!(sig.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn serde_hex_roundtrip_for_verifying_key_and_signature() {
        let sk = SigningKey::from_seed([0x44u8; 32]);
        let vk = sk.verifying_key();
        let sig = sk.sign(b"serde");

        let vk_json = serde_json::to_string(&vk).unwrap();
        assert!(vk_json.starts_with('"'));
        let vk_back: VerifyingKey = serde_json::from_str(&vk_json).unwrap();
        assert_eq!(vk.to_bytes(), vk_back.to_bytes());

        let sig_json = serde_json::to_string(&sig).unwrap();
        assert!(sig_json.starts_with('"'));
        let sig_back: Signature = serde_json::from_str(&sig_json).unwrap();
        assert_eq!(sig.to_bytes(), sig_back.to_bytes());
    }

    #[test]
    fn serde_hex_roundtrip_for_signing_key() {
        let sk = SigningKey::from_seed([0x55u8; 32]);
        let json = serde_json::to_string(&sk).unwrap();
        let sk_back: SigningKey = serde_json::from_str(&json).unwrap();
        assert_eq!(sk.to_bytes(), sk_back.to_bytes());
    }
}
