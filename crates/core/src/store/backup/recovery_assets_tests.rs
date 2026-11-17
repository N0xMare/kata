use super::DeadlineReader;
use std::io::{Cursor, Read as _};
use std::time::{Duration, Instant};

#[test]
fn recovery_deadline_reader_stops_between_chunks_without_reading_successor_bytes() {
    let mut reader = DeadlineReader::new(
        Cursor::new(b"firstsecond"),
        Some(Instant::now() + Duration::from_secs(30)),
    );
    let mut first = [0; 5];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"first");
    reader.deadline = Some(Instant::now());
    assert_eq!(
        reader.read(&mut first).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(
        reader.input.position(),
        5,
        "expired read never reaches the underlying byte source"
    );
}

fn manifest(assets: Vec<super::super::CapturedAsset>) -> super::BackupManifest {
    super::BackupManifest {
        version: super::RECOVERY_MANIFEST_VERSION,
        created_at_ms: 0,
        databases: Vec::new(),
        config_included: false,
        artifact_id: Some(ulid::Ulid::new()),
        source_directory_id: None,
        assets,
        capture_order: None,
        tree_roots: Vec::new(),
        trees: Vec::new(),
        producer: super::super::producer_identity().unwrap(),
        recovery_assets: None,
    }
}

#[test]
fn recovery_member_index_resolves_full_checkpoint_bound_and_refuses_duplicates() {
    let assets: Vec<_> = (0..100_000u64)
        .map(|number| super::super::CapturedAsset {
            name: format!("recovery/jj/checkpoints/{number:06}"),
            tier: super::DurabilityTier::Durable,
            digest: Some("a".repeat(64)),
            byte_len: number,
        })
        .collect();
    let mut manifest = manifest(assets);
    let index = super::MemberIndex::new(&manifest).unwrap();
    let total: u64 = (0..100_000u64)
        .rev()
        .map(|number| {
            index
                .require(&format!("recovery/jj/checkpoints/{number:06}"))
                .unwrap()
                .byte_len
        })
        .sum();
    assert_eq!(total, 99_999 * 100_000 / 2);
    assert!(index.require("absent").is_err());
    manifest.assets.push(manifest.assets[0].clone());
    assert!(super::MemberIndex::new(&manifest).is_err());
}
