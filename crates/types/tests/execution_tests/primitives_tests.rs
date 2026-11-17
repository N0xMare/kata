//! Tests for `crates/types/src/primitives.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::primitives::{FixedBytes, ObjectId};

#[test]
fn hex_roundtrip_display_fromstr() {
    let raw = [0x12u8; 32];
    let fb = FixedBytes::<32>::new(raw);
    let s = fb.to_string();
    assert_eq!(s.len(), 64);
    let back: FixedBytes<32> = s.parse().unwrap();
    assert_eq!(fb, back);
}

#[test]
fn rejects_wrong_length() {
    let bad = "12";
    assert!(bad.parse::<FixedBytes<32>>().is_err());
}

#[test]
fn json_roundtrip_is_hex_string() {
    let fb = FixedBytes::<32>::new([0xab; 32]);
    let j = serde_json::to_string(&fb).unwrap();
    assert!(j.starts_with('"'));
    let back: FixedBytes<32> = serde_json::from_str(&j).unwrap();
    assert_eq!(fb, back);
}

#[test]
fn cbor_roundtrip_is_bytes() {
    let fb = FixedBytes::<32>::new([0x55; 32]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&fb, &mut buf).unwrap();
    let back: FixedBytes<32> = ciborium::de::from_reader(buf.as_slice()).unwrap();
    assert_eq!(fb, back);
}

#[test]
fn object_id_alias_works() {
    let oid: ObjectId = FixedBytes::default();
    assert_eq!(oid.as_bytes().len(), 32);
}
