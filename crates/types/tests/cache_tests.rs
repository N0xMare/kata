//! Tests for `crates/types/src/cache.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::cache::{
    ActionManifest, CachePolicy, CasAddress, CasAddressParseError, CasDigestFunction,
    ObjectIdHasher, TokenUsage, cas_address_for_canonical_bytes, object_id_for_canonical_bytes,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::primitives::{ContentHash, FixedBytes};
use smol_str::SmolStr;

#[test]
fn token_usage_roundtrip() {
    let s = serde_json::to_string(&TokenUsage {
        input: 10,
        output: 20,
        cache_read: 7,
        cache_write: 3,
    })
    .unwrap();
    let back: TokenUsage = serde_json::from_str(&s).unwrap();
    assert_eq!(back.input, 10);
    assert_eq!(back.output, 20);
    assert_eq!(back.cache_read, 7);
    assert_eq!(back.cache_write, 3);
}

#[test]
fn token_usage_legacy_decodes_with_zero_cache_fields() {
    // A JSON blob with only `{input, output}` decodes successfully
    // and the cache fields default to 0.
    let raw = r#"{"input":10,"output":20}"#;
    let usage: TokenUsage = serde_json::from_str(raw).unwrap();
    assert_eq!(usage.input, 10);
    assert_eq!(usage.output, 20);
    assert_eq!(usage.cache_read, 0);
    assert_eq!(usage.cache_write, 0);
}

/// The default is the UNAUTHORED state: `CachePolicy::default()`'s one
/// production caller is `kata_workflow`'s `StageFlatFields::join_default`,
/// whose whole contract is that a synthetic join lowers "byte-identically to a
/// minimal authored shell stage" — and a minimal authored stage decodes `""`
/// to `Omitted`.
#[test]
fn cache_policy_default_is_the_unauthored_state() {
    assert_eq!(CachePolicy::default(), CachePolicy::Omitted);
    assert_ne!(
        CachePolicy::default(),
        CachePolicy::Disabled,
        "the default is NOT the exemption: `Disabled` is what an author writes as `no_cache`, \
         and defaulting to it is what made the content cache dead code on every shipped pack"
    );
}

#[test]
fn canonical_object_address_is_deterministic_and_order_insensitive() {
    // Key-insertion order must not change the content address — this is the
    // dedup primitive: semantically-equal values map to ONE object. A naive
    // `serde_json::to_vec` (non-canonical) would hash `{a,b}` and `{b,a}`
    // apart and fail this assertion.
    let ab = serde_json::json!({"a": 1, "b": 2, "nested": {"y": 9, "x": 8}});
    let ba = serde_json::json!({"b": 2, "nested": {"x": 8, "y": 9}, "a": 1});
    let ab_id = object_id_for_canonical_bytes(&canonicalize_args(&ab));
    assert_eq!(
        ab_id,
        object_id_for_canonical_bytes(&canonicalize_args(&ba))
    );

    // A genuine value change rotates the object id.
    let changed = serde_json::json!({"a": 1, "b": 3, "nested": {"y": 9, "x": 8}});
    assert_ne!(
        ab_id,
        object_id_for_canonical_bytes(&canonicalize_args(&changed))
    );

    // The id is a stable 32-byte blake3 digest.
    assert_eq!(ab_id.as_bytes().len(), 32);
}

// ---------------- fine-grained per-action DAG (input + output file sets) ----------------

fn digest(byte: u8) -> ContentHash {
    FixedBytes([byte; 32])
}

/// The manifest round-trips through serde, and an EMPTY manifest (no declared
/// outputs) serializes to the compact `{command}`-only shape — so the additive
/// field never bloats a manifest that only carries a command identity.
#[test]
fn action_manifest_roundtrips_serde() {
    let manifest = ActionManifest::new(
        digest(7),
        vec![SmolStr::new("out/x.json"), SmolStr::new("out/y.json")],
    );
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ActionManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
    assert_eq!(back.content_hash(), manifest.content_hash());

    // No declared outputs → the skip_serializing_if field drops out.
    let bare = ActionManifest::new(digest(3), vec![]);
    let bare_json = serde_json::to_string(&bare).unwrap();
    assert!(
        !bare_json.contains("inputs") && !bare_json.contains("declared_outputs"),
        "an empty manifest must not emit the inputs/declared_outputs keys: {bare_json}"
    );
    let bare_back: ActionManifest = serde_json::from_str(&bare_json).unwrap();
    assert_eq!(bare_back, bare);
}

/// The manifest content hash folds the command and the declared outputs:
/// changing either rotates it, and the declared-output order does not (it is
/// sorted on construction).
#[test]
fn action_manifest_content_hash_folds_command_and_outputs() {
    let base = ActionManifest::new(
        digest(1),
        vec![SmolStr::new("out/a.json"), SmolStr::new("out/b.json")],
    );

    let command_changed = ActionManifest::new(digest(9), base.declared_outputs.clone());
    assert_ne!(base.content_hash(), command_changed.content_hash());

    let outputs_changed = ActionManifest::new(base.command, vec![SmolStr::new("out/c.json")]);
    assert_ne!(base.content_hash(), outputs_changed.content_hash());

    // Declared-output order is normalized on construction → same digest.
    let reordered = ActionManifest::new(
        digest(1),
        vec![SmolStr::new("out/b.json"), SmolStr::new("out/a.json")],
    );
    assert_eq!(base.content_hash(), reordered.content_hash());
}

/// `ObjectIdHasher` — the STREAMING spelling of the CAS content address.
///
/// # Why this test exists
///
/// `ObjectIdHasher` was extracted so a caller that must not read a
/// multi-hundred-megabyte blob into memory can still produce the same address
/// as `object_id_for_canonical_bytes`. The address is
/// `blake3(domain || len_le || payload)`, so the LENGTH is folded before the
/// payload and a streaming caller has to declare it up front, from a stat of
/// the handle it is about to read. `finish()` returning `None` on a fed-count /
/// declared-length disagreement is the stated reason the type exists rather
/// than a bare `blake3::Hasher`: without it, a file that changed size under the
/// read yields a confident address over a length that was never true of those
/// bytes.
///
/// Until this test landed, `rg ObjectIdHasher crates/types/tests
/// crates/core/tests` returned NOTHING — the refusal branch was reachable from
/// no test in the workspace, and only the infallible in-crate caller
/// (`object_id_for_canonical_bytes`, which declares a slice's own length and so
/// can never disagree) exercised the type at all.
///
/// `finish()` yields a `CasAddress` — the PAIR of digest function and digest —
/// rather than a bare `ObjectId`; the assertions carry the pair.
#[test]
fn object_id_hasher_refuses_a_fed_count_that_is_not_the_declared_length() {
    let payload = canonicalize_args(&serde_json::json!({"a": 1, "b": [2, 3]}));
    let one_shot = cas_address_for_canonical_bytes(&payload);

    // HAPPY PATH — a chunked feed of exactly the declared length reproduces the
    // address the non-streaming path computes. Chunked deliberately: the
    // backup capture feeds 128 KiB at a time, so a single `update` call would
    // not exercise the accumulation the real caller depends on.
    let mut streamed = ObjectIdHasher::for_canonical_len(payload.len() as u64);
    for chunk in payload.chunks(3) {
        streamed.update(chunk);
    }
    assert_eq!(
        streamed.finish(),
        Some(one_shot),
        "a stream of the declared length must land on the same address as the one-shot call, or \
         a backup's derived blob path and the store's own path disagree"
    );

    // SHORT FEED — the file shrank under the read. The digest so far is a
    // perfectly good blake3 value; refusing it is the entire contract.
    let mut short = ObjectIdHasher::for_canonical_len(payload.len() as u64);
    short.update(&payload[..payload.len() - 1]);
    assert_eq!(
        short.finish(),
        None,
        "one byte short of the declared length must refuse rather than return an address over a \
         length that was never true of the bytes fed"
    );

    // OVER-FEED — the file grew under the read. The other side of the same
    // disagreement, and the one a `seen >= declared` check would have missed.
    let mut over = ObjectIdHasher::for_canonical_len(payload.len() as u64);
    over.update(&payload);
    over.update(b"!");
    assert_eq!(
        over.finish(),
        None,
        "one byte past the declared length must refuse; a check that only caught the short side \
         would pass this and address bytes it never announced"
    );

    // The refusal is about the COUNT, not about the bytes: the same over-fed
    // byte string, honestly declared, is accepted and addresses to something
    // ELSE. Without this the two `None`s above are satisfiable by a `finish()`
    // that refuses unconditionally.
    let mut honest = ObjectIdHasher::for_canonical_len(payload.len() as u64 + 1);
    honest.update(&payload);
    honest.update(b"!");
    let honest = honest
        .finish()
        .expect("a truthfully declared length must be accepted");
    assert_ne!(
        honest, one_shot,
        "the declared length is FOLDED into the digest, so a longer payload cannot alias the \
         shorter one's address"
    );

    // EMPTY — declared zero, fed nothing. The boundary where `seen == declared`
    // holds without a single `update`, which a `seen > 0` guard would refuse.
    assert_eq!(
        ObjectIdHasher::for_canonical_len(0).finish(),
        Some(cas_address_for_canonical_bytes(b"")),
        "zero declared and zero fed is a legitimate address, not a refusal"
    );
}

/// A CAS address NAMES ITS OWN DIGEST FUNCTION — in the preimage and in the
/// rendering.
///
/// # Why this test exists
///
/// The fix for a shared 64-hex namespace is REAPI's structure — identity is
/// the pair `(digest_function, digest)` — rather than a domain-tag bump, which
/// would have answered the question once and left the next generation asking
/// it again.
///
/// # What it pins
///
/// The preimage byte-for-byte, hand-spelled here rather than taken from the
/// production helper, so a change to the framing that FORGETS to take a new
/// `CasDigestFunction` variant fails here instead of silently re-namespacing
/// every object. And the separation stated as a VALUE: a preimage without the
/// function code (tag ‖ len ‖ bytes) lands somewhere else, so the two schemes
/// cannot alias.
#[test]
fn a_cas_address_names_its_own_digest_function() {
    let payload = b"the canonical bytes".as_slice();
    let address = cas_address_for_canonical_bytes(payload);

    assert_eq!(
        address.function(),
        CasDigestFunction::Blake3,
        "this binary writes under exactly one function"
    );
    assert_eq!(CasDigestFunction::Blake3.code(), 1);
    assert_eq!(CasDigestFunction::Blake3.label(), "blake3");

    // THE PREIMAGE, spelled by hand: domain tag, function code, length, bytes.
    let mut expected = blake3::Hasher::new();
    expected.update(b"kata.cas.object\0");
    expected.update(&[1u8]);
    expected.update(&(payload.len() as u64).to_le_bytes());
    expected.update(payload);
    assert_eq!(
        address.hash().as_bytes(),
        expected.finalize().as_bytes(),
        "the address is blake3(tag || function_code || len_le || bytes); a framing change that \
         did not take a new CasDigestFunction variant would re-namespace every object silently"
    );

    // GENERATION SEPARATION — a scheme with no function code. Its digest over
    // the SAME bytes must be a different value,
    // or the code byte is decorative and the namespace is still shared.
    let mut previous_generation = blake3::Hasher::new();
    previous_generation.update(b"kata.cas.object\0");
    previous_generation.update(&(payload.len() as u64).to_le_bytes());
    previous_generation.update(payload);
    assert_ne!(
        address.hash().as_bytes(),
        previous_generation.finalize().as_bytes(),
        "an address carrying its function must not collide with the address that did not; two \
         generations sharing one 64-hex namespace is the defect this closes"
    );

    // The digest half is what durable rows key on, and it is the SAME address.
    assert_eq!(
        object_id_for_canonical_bytes(payload),
        address.hash(),
        "object_id_for_canonical_bytes is the digest half of the address, not a second scheme"
    );
}

/// The address's RENDERING round-trips, and refuses exactly what it does not
/// emit.
///
/// # Why this test exists
///
/// The rendering is the on-disk blob name and the backup-artifact member path,
/// so it is the half an operator and a future binary read. Two spellings of one
/// address would be two blob paths for one object — the drift class the typed
/// address exists to remove — so the parser must accept precisely what `Display`
/// emits.
///
/// # What it REFUSES, against what the type CLAIMS
///
/// Claim: "a CAS address this binary can address under". Refused: no `.`
/// suffix (a bare digest), an unknown label (which includes
/// every FUTURE generation — a capability statement, not a validity one), a
/// digest that is not 64 characters, and UPPERCASE hex. The last is the one
/// worth naming: uppercase hex is a perfectly good digest and is refused anyway,
/// because hex case is not addressing information and admitting both spellings
/// would give one object two paths.
///
/// The gap, stated: the parser does NOT prove the object exists or that any
/// bytes hash to it. Those are the store's and the backup preflight's checks.
#[test]
fn a_cas_address_round_trips_and_refuses_every_spelling_it_does_not_emit() {
    let address = cas_address_for_canonical_bytes(b"round trip");
    let rendered = address.to_string();

    assert_eq!(
        rendered.len(),
        64 + 1 + "blake3".len(),
        "the rendering is <64 hex>.<label>: {rendered}"
    );
    assert!(
        rendered.ends_with(".blake3"),
        "the function is IN the rendering, or a blob on disk cannot say what verifies it: \
         {rendered}"
    );
    assert!(
        rendered.starts_with(&address.hash().to_string()),
        "the DIGEST comes first, or the 256-way shard on the first two characters degenerates to \
         one bucket per function: {rendered}"
    );
    assert_eq!(
        rendered.parse::<CasAddress>(),
        Ok(address),
        "the parser must accept exactly what Display emits"
    );

    // NO FUNCTION — a bare digest.
    let bare = address.hash().to_string();
    assert!(matches!(
        bare.parse::<CasAddress>(),
        Err(CasAddressParseError::NoFunction(_))
    ));

    // UNKNOWN FUNCTION — a future generation. Refusing is the honest answer: a
    // binary that cannot verify an address must not claim to.
    assert!(matches!(
        format!("{bare}.blake3v2").parse::<CasAddress>(),
        Err(CasAddressParseError::UnknownFunction { .. })
    ));

    // MALFORMED DIGEST — wrong length, and uppercase hex.
    assert!(matches!(
        "abc.blake3".parse::<CasAddress>(),
        Err(CasAddressParseError::MalformedDigest(_))
    ));
    assert!(
        matches!(
            format!("{}.blake3", bare.to_uppercase()).parse::<CasAddress>(),
            Err(CasAddressParseError::MalformedDigest(_))
        ),
        "uppercase hex is a valid digest and is refused anyway: one object with two spellings is \
         one object with two blob paths"
    );

    // The pair is the identity: the same digest under a different function is a
    // different address. Spelled through the constructor because there is only
    // one variant today, which is the degenerate parameter, not a missing one.
    assert_eq!(
        CasAddress::new(CasDigestFunction::Blake3, address.hash()),
        address
    );
    assert_eq!(
        CasDigestFunction::ALL.len(),
        1,
        "a second variant must be added deliberately; kata-core asserts this length at COMPILE \
         time where a cas_objects row is reconstructed into an address"
    );
    assert_eq!(
        CasDigestFunction::from_label("blake3"),
        Some(CasDigestFunction::Blake3)
    );
    assert_eq!(CasDigestFunction::from_label("blake3 "), None);
}
