//! Pinned identity vectors for `kata_types::nix_environment`.
//!
//! These literals are the external witness for the closure digest and the
//! environment id derived from it: the in-module tests only compare kata's
//! answer to kata's answer, so they cannot see a domain tag, a field name, a
//! field order, or a length prefix change. A diff here means the digest rotated
//! — either intended (bump `NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION` and re-pin
//! every vector) or a defect.
//!
//! The digest is what a cached result and a realised Nix root are keyed on, so a
//! silent rotation would strand every one of them. The schema version is part of
//! the domain tag precisely so a shape change rotates the family by construction
//! rather than by remembering to.

use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, EnvironmentRef, GuestPath, PlatformRef,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION, NarVerification,
    NixEnvironmentManifest, Provenance, RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::{ContentHash, FixedBytes};
use smol_str::SmolStr;

const BASH: &str = "/nix/store/0000000000000000000000000000000a-bash-5.2";
const COREUTILS: &str = "/nix/store/1111111111111111111111111111111b-coreutils-9.5";

/// Two fixed SRI digests. Their VALUES are arbitrary; that they are fixed is the
/// whole point of a golden.
const BASH_NAR: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const COREUTILS_NAR: &str = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

fn store_path(path: &str) -> StorePath {
    StorePath::new(path).expect("a valid store path")
}

fn entry(path: &str, nar_hash: &str, nar_size: u64, references: Vec<u32>) -> ClosureEntry {
    ClosureEntry {
        store_path: store_path(path),
        nar_hash: SmolStr::new(nar_hash),
        nar_size,
        references,
        ca: None,
    }
}

fn policy() -> IntegrityPolicy {
    IntegrityPolicy {
        verify: NarVerification::NarHashOnly,
        sigs_needed: 0,
        required_signers: Vec::new(),
        allow_unsigned_content_addressed: true,
        verify_contents_at_declare: false,
    }
}

/// The pinned platform of the initial qualified profile.
fn platform() -> PlatformRef {
    PlatformRef::new("x86_64-linux", ContentHash::new([0x33; 32]))
}

fn manifest(closure: Vec<ClosureEntry>) -> NixEnvironmentManifest {
    NixEnvironmentManifest::new(
        "bash-and-coreutils",
        platform(),
        Provenance::StorePaths {
            nixpkgs_attribute: SmolStr::new("bashInteractive"),
        },
        vec![store_path(BASH)],
        closure,
        vec![GuestPath::new(format!("{BASH}/bin")).expect("a store-path PATH entry")],
        policy(),
        ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Authoritative,
        },
        "nix-store --realise",
    )
    .expect("the pinned manifest is valid")
}

/// `bash` referencing `coreutils`: a two-entry closure with a real edge.
fn two_entry_closure() -> Vec<ClosureEntry> {
    vec![
        entry(BASH, BASH_NAR, 2_048, vec![1]),
        entry(COREUTILS, COREUTILS_NAR, 4_096, Vec::new()),
    ]
}

#[test]
fn schema_version_is_the_one_these_vectors_were_pinned_under() {
    assert_eq!(NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION, 1);
}

#[test]
fn a_two_entry_closure_digest_is_pinned() {
    assert_eq!(
        manifest(two_entry_closure()).closure_digest().to_string(),
        "db1a31c767eeacd008ef55b52d4014fa7045f6da0e42cb960e70595c1304f650"
    );
}

/// `ca` IS NOT A BYTE CHANGE for the closure digest (signatures and deriver are not in
/// the manifest at all since they left the environment id). Declaring `ca` on every entry
/// leaves the closure digest on the SAME literal
/// as the vector above: a key rotation must not strand a cached result built
/// against a closure nobody rebuilt.
#[test]
fn a_re_signed_closure_keeps_the_pinned_digest() {
    let mut closure = two_entry_closure();
    for entry in &mut closure {
        entry.ca = Some(SmolStr::new("fixed:sha256-zzz"));
    }
    assert_eq!(
        manifest(closure).closure_digest().to_string(),
        "db1a31c767eeacd008ef55b52d4014fa7045f6da0e42cb960e70595c1304f650"
    );
}

/// TRUNCATION IS A BYTE CHANGE. One byte off `bash`'s `nar_size`, everything
/// else identical — a distinct pinned literal, which is the external witness
/// that `nar_size` is folded and that a shorter NAR claiming the same hash
/// cannot wear the same identity (ADR-0001 trust boundary 5).
#[test]
fn a_truncated_nar_size_is_pinned_to_a_different_digest() {
    let mut closure = two_entry_closure();
    closure[0].nar_size -= 1;
    let truncated = manifest(closure);
    assert_eq!(
        truncated.closure_digest().to_string(),
        "3997f54688322ed93ffe0c55c707be2cf6cb23e9540c8ef44484de978c3b5422"
    );
    assert_ne!(
        truncated.closure_digest(),
        manifest(two_entry_closure()).closure_digest()
    );
}

/// The capsule-facing id. Pinned separately from the digest because
/// `EnvironmentRef` folds the digest together with the manifest's CAS id under
/// its OWN domain tag and its own schema version, so either family's tag can
/// rotate independently and this vector sees it.
#[test]
fn the_environment_id_over_the_pinned_closure_is_pinned() {
    let manifest_artifact = ArtifactId(FixedBytes([0x21; 32]));
    let built = manifest(two_entry_closure());
    let reference = built.environment_ref(manifest_artifact);
    assert_eq!(
        reference.id().0.to_string(),
        "5b3369ee93d7b9c63a4b0cd39be147339a63638467bf3e15c434c0a13f96f842"
    );
    assert_eq!(
        reference,
        EnvironmentRef::new(manifest_artifact, built.closure_digest()),
        "the manifest mints exactly the reference a caller would build by hand"
    );
}
