//! BLAKE3 hash helper.

use kata_types::{ContentHash, FixedBytes};

/// Single-shot blake3 hash of `data`, returned as a [`ContentHash`].
#[must_use]
pub fn blake3_bytes(data: &[u8]) -> ContentHash {
    let digest = blake3::hash(data);
    FixedBytes::new(*digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_bytes_matches_direct_hash() {
        let direct = *blake3::hash(b"hello").as_bytes();
        let via = blake3_bytes(b"hello");
        assert_eq!(via.as_bytes(), direct);
    }
}
