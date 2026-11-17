//! Shared primitive helpers — fixed-size byte newtypes and content-addressed
//! identifier aliases.
//!
//! All object identifiers in kata are content-addressed. `ObjectId` is the
//! 32-byte blake3 digest of the canonical encoding of the referenced object
//! and must never be conflated with a monotonic identifier such as a ULID.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Delegate a single-field newtype's [`fmt::Display`] to its inner field
/// (`self.0`). Collapses the identical hand-written `Display` impls on the
/// identifier newtypes (`AdmissionDigest`, ...) that
/// simply forward to the wrapped type. Byte-identical to the impl it
/// replaces.
macro_rules! delegate_display {
    ($ty:ty) => {
        impl ::core::fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}
pub(crate) use delegate_display;

/// Delegate a single-field newtype's [`FromStr`] to its inner type `$inner`,
/// re-wrapping a successful parse via the tuple-struct constructor and
/// forwarding the inner `Err` type verbatim. Byte-identical to the impl it
/// replaces.
macro_rules! delegate_from_str {
    ($ty:ty, $inner:ty) => {
        impl ::core::str::FromStr for $ty {
            type Err = <$inner as ::core::str::FromStr>::Err;
            #[inline]
            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                <$inner as ::core::str::FromStr>::from_str(s).map(Self)
            }
        }
    };
}
pub(crate) use delegate_from_str;

/// A fixed-length byte buffer used as the foundation for every fixed-size
/// identifier and digest in kata.
///
/// Serialization is lowercase hex so that JSON / TOML payloads remain
/// human-readable. The `Display` and `FromStr` implementations match the
/// serde representation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedBytes<N> {
    /// Construct a `FixedBytes` from a raw array.
    #[inline]
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow the wrapped bytes as a slice.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper and return the underlying array.
    #[inline]
    #[must_use]
    pub fn into_array(self) -> [u8; N] {
        self.0
    }

    /// All-zero `FixedBytes`. Primarily useful as a placeholder in tests and
    /// default values.
    #[inline]
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Default for FixedBytes<N> {
    #[inline]
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for FixedBytes<N> {
    #[inline]
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> From<FixedBytes<N>> for [u8; N] {
    #[inline]
    fn from(value: FixedBytes<N>) -> Self {
        value.0
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FixedBytes<{N}>({self})")
    }
}

impl<const N: usize> fmt::Display for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Error returned when parsing a `FixedBytes<N>` from a hex string fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct FixedBytesParseError {
    /// Human-readable description of what went wrong.
    pub reason: &'static str,
}

impl<const N: usize> FromStr for FixedBytes<N> {
    type Err = FixedBytesParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != N * 2 {
            return Err(FixedBytesParseError {
                reason: "hex string length does not match FixedBytes size",
            });
        }
        let mut out = [0u8; N];
        hex::decode_to_slice(s, &mut out).map_err(|_| FixedBytesParseError {
            reason: "invalid hex characters in FixedBytes",
        })?;
        Ok(Self(out))
    }
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{Error as DeError, Visitor};

        struct FbVisitor<const M: usize>;

        impl<'de, const M: usize> Visitor<'de> for FbVisitor<M> {
            type Value = FixedBytes<M>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a {} byte value encoded as bytes or lowercase hex", M)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                FixedBytes::<M>::from_str(v).map_err(|e| E::custom(e.reason))
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
                Ok(FixedBytes(out))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(&v)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = [0u8; M];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(M + 1, &self));
                }
                Ok(FixedBytes(out))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(FbVisitor::<N>)
        } else {
            deserializer.deserialize_bytes(FbVisitor::<N>)
        }
    }
}

/// Content-addressed object identifier (blake3 digest).
pub type ObjectId = FixedBytes<32>;

/// Generic content hash (blake3). Used wherever a type field needs to
/// carry "the hash of something" without the specific semantics of
/// `ObjectId`.
pub type ContentHash = FixedBytes<32>;
