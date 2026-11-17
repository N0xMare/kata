//! The versioned Nix environment manifest — WHICH exact closure kata authorized.
//!
//! ADR-0001 splits this plane in two, and this module is entirely on kata's
//! side of the split. Nix owns realization, closure transport, store
//! verification mechanisms, and collection. Kata owns which exact closure was
//! authorized, its binding and evidence, retention intent, and privacy
//! classification. Nothing here invokes Nix, reads the store, or performs I/O
//! of any kind: these are pure types plus their hashing discipline, so a
//! manifest can be checked, hashed, published, and refused with no store
//! present.
//!
//! Trust boundary 5 is the reason the shapes look the way they do: "a store
//! path or metadata query is not by itself byte verification". A
//! [`ClosureEntry`] therefore records what kata was TOLD (nar hash, size,
//! `ca`) as data — signatures and deriver are evidence ([`ClosureEvidence`]), outside the id —, and [`IntegrityPolicy`] records separately what
//! kata will REQUIRE before it binds those bytes. This module refuses malformed
//! declarations; it does not and cannot claim any byte was verified.
//!
//! # Identity discipline
//!
//! [`NixEnvironmentManifest::closure_digest`] is computed field-wise through
//! [`hash_field`] under a domain tag from [`domain`], never over a serialized
//! encoding — the same idiom as [`crate::execution_contract`], for the same
//! reason: a serde representation is a presentation detail and would silently
//! rotate the digest the moment field order or a rename changed. The tag
//! carries [`NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION`], so a shape bump rotates
//! the digest by construction rather than by remembering to.
//!
//! # The guest binding is implied, not listed
//!
//! A manifest carries no `guest` mapping list. The binding of a realised
//! closure into a capsule is fully determined by the closure itself: ONE
//! READ-ONLY bind per [`ClosureEntry`], mounted at its own store path, and
//! nothing else. A second, separately authored list of guest paths could only
//! either restate that (dead weight that can disagree with the closure) or
//! contradict it (a store path bound somewhere other than where its own
//! references point, which breaks every absolute `/nix/store` reference
//! compiled into the closure's binaries). `/nix/var` and the Nix daemon socket
//! are never among those binds — ADR-0001: "Ordinary actions do not receive a
//! Nix daemon socket or mutable store authority" — and refusing them is the
//! capsule builder's job, not a field here.

use serde::{Deserialize, Deserializer, Serialize};
use smol_str::SmolStr;

use crate::cache::hash_field;
use crate::execution_contract::{
    ArtifactId, ArtifactPrivacy, EnvironmentRef, GuestPath, PlatformRef,
};
use crate::primitives::ContentHash;
use crate::{KataError, KataResult};

/// Shape version of the Nix environment manifest. It is part of every domain
/// tag in this module, so a bump rotates [`NixEnvironmentManifest::closure_digest`]
/// — and therefore every [`crate::execution_contract::EnvironmentId`] derived
/// from one — by construction.
///
/// * v1 — the initial store-path / closure / integrity-policy / provenance shape.
pub const NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Domain-separation tag for one identity family in this module. The schema
/// version is part of the tag; see the constant.
fn domain(name: &str) -> String {
    format!("kata.{name}.v{NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION}")
}

/// Refuse any `schema_version` other than
/// [`NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION`]. A tolerated foreign version
/// would be a silent compatibility layer: the body would be read under this
/// build's field meanings.
fn current_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION {
        return Err(serde::de::Error::custom(format!(
            "nix environment manifest schema_version {version} is not supported; \
             this build accepts only {NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION}"
        )));
    }
    Ok(version)
}

fn validation(message: String) -> KataError {
    KataError::Validation(message)
}

/// Refuse a NUL or any other ASCII control byte in a metadata string. Control
/// bytes are how a log line, a `nix-store` argument list, or a terminal is
/// smuggled through a field nobody thought was executable.
fn refuse_control_bytes(field: &str, value: &str) -> KataResult<()> {
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(validation(format!(
            "nix environment {field} {value:?} refused: contains a NUL or other ASCII control byte"
        )));
    }
    Ok(())
}

/// The Nix store directory every [`StorePath`] lives directly under. It is one
/// of [`GuestPath`]'s roots, which is what makes [`StorePath::as_guest_path`]
/// total.
pub const NIX_STORE_DIRECTORY: &str = "/nix/store";

/// The nix-base32 alphabet, which is NOT RFC 4648: it omits `e`, `o`, `u`, and
/// `t` so a digest cannot spell an unwanted word, and it is the only alphabet a
/// real store path's 32-character digest uses.
const NIX_BASE32_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Length of the digest component of a store path base name: 160 bits in
/// nix-base32, always exactly 32 characters, never padded.
const STORE_PATH_DIGEST_CHARACTERS: usize = 32;

/// Maximum accepted base-name length (`<digest>-<name>`), matching Nix's own
/// store-path name ceiling, so a path this type accepts cannot be one Nix would
/// refuse to create.
const STORE_PATH_NAME_MAXIMUM_BYTES: usize = 211;

/// An absolute path to one top-level Nix store object.
///
/// # Refused set
///
/// [`StorePath::new`] accepts a path if and only if ALL of the following hold:
/// it begins with exactly `/nix/store/`; the remainder (the base name) is at
/// most 211 bytes and contains no `/`; the base name's first 32 bytes are all
/// from the nix-base32 alphabet `0123456789abcdfghijklmnpqrsvwxyz`; byte 33 is
/// `-`; the name after that `-` is non-empty; and the whole path contains no
/// NUL and no other ASCII control byte. Everything else is refused, including:
/// a relative path, `/nix/store` itself, a path under any other directory
/// (`/nix/other/...`, `/work/...`), a root prefix that is not a path boundary
/// (`/nix/storex/...`), a path deeper than one component
/// (`/nix/store/<hash>-name/bin/sh`), a digest of the wrong length, a digest
/// containing a character outside the alphabet (`e`, `o`, `u`, `t`, `E`, `=`),
/// a missing or misplaced `-`, an empty name, an over-long name, and an
/// embedded control byte.
///
/// A store object's INTERIOR is deliberately not addressable here: a manifest
/// binds whole store objects, and a path into one would be a mount that
/// disagrees with the closure it came from. Interior paths belong in
/// [`NixEnvironmentManifest::path_prepend`], which is a `PATH` entry, not a
/// bind.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StorePath(SmolStr);

impl StorePath {
    pub fn new(path: impl Into<SmolStr>) -> KataResult<Self> {
        let path = path.into();
        let refuse = |reason: &str| {
            Err(validation(format!(
                "nix store path {path:?} refused: {reason}"
            )))
        };
        if path.bytes().any(|byte| byte.is_ascii_control()) {
            return refuse("contains a NUL or other ASCII control byte");
        }
        let Some(base_name) = path.strip_prefix(&format!("{NIX_STORE_DIRECTORY}/")) else {
            return refuse("does not begin with /nix/store/");
        };
        if base_name.len() > STORE_PATH_NAME_MAXIMUM_BYTES {
            return refuse("base name is longer than 211 bytes");
        }
        if base_name.contains('/') {
            return refuse("names something other than a top-level store object");
        }
        let bytes = base_name.as_bytes();
        if bytes.len() < STORE_PATH_DIGEST_CHARACTERS + 2 {
            return refuse("is shorter than <32-character digest>-<non-empty name>");
        }
        let (digest, rest) = bytes.split_at(STORE_PATH_DIGEST_CHARACTERS);
        if !digest.iter().all(|byte| NIX_BASE32_ALPHABET.contains(byte)) {
            return refuse("digest is not 32 nix-base32 characters");
        }
        if rest[0] != b'-' {
            return refuse("digest is not followed by '-'");
        }
        if rest.len() < 2 {
            return refuse("name after '-' is empty");
        }
        Ok(Self(path))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The base name (`<digest>-<name>`) — what Nix itself calls the store
    /// path's name.
    #[must_use]
    pub fn base_name(&self) -> &str {
        // Guaranteed by the constructor: the prefix is present, and it is the
        // only way to build one.
        &self.0[NIX_STORE_DIRECTORY.len() + 1..]
    }

    /// This store path as a guest path.
    ///
    /// TOTAL by construction, not by luck: `/nix/store` is one of
    /// [`GuestPath`]'s roots, and every path this type accepts is
    /// `/nix/store/` plus one non-empty component that contains no `/`, no
    /// control byte, and (because it always contains a `-` at byte 33) is
    /// neither `.` nor `..`. Every clause of `GuestPath`'s refused set is
    /// therefore already excluded by `StorePath`'s.
    #[must_use]
    pub fn as_guest_path(&self) -> GuestPath {
        GuestPath::new(self.0.clone()).unwrap_or_else(|error| {
            unreachable!("a validated store path is a guest path: {error}");
        })
    }

    /// Whether `path` names this store object or something inside it. The
    /// prefix test is at a path boundary, so `/nix/store/<a>-foo` does not
    /// contain `/nix/store/<a>-foobar`.
    fn contains(&self, path: &GuestPath) -> bool {
        let own = self.as_str();
        path.as_str() == own
            || path
                .as_str()
                .strip_prefix(own)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl<'de> Deserialize<'de> for StorePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path = SmolStr::deserialize(deserializer)?;
        Self::new(path).map_err(serde::de::Error::custom)
    }
}

/// Number of base64 characters an SRI `sha256-` digest body always has: 32
/// bytes encode to 44 characters, the last of which is the single `=` pad.
const SRI_SHA256_BODY_CHARACTERS: usize = 44;

/// Refuse anything that is not shaped like an SRI `sha256-<base64>` digest.
///
/// SHAPE ONLY, and the name says so: this checks the prefix, the standard
/// base64 alphabet, the 44-character length, and the single trailing `=` pad.
/// It does not decode the digest and it certainly does not verify that any bytes
/// hash to it — trust boundary 5's "a store path or metadata query is not by
/// itself byte verification" applies to this field above all others.
fn refuse_non_sri_sha256(field: &str, value: &str) -> KataResult<()> {
    let refuse = |reason: &str| {
        Err(validation(format!(
            "nix closure {field} {value:?} refused: {reason}"
        )))
    };
    let Some(body) = value.strip_prefix("sha256-") else {
        return refuse("is not prefixed sha256-");
    };
    if body.len() != SRI_SHA256_BODY_CHARACTERS {
        return refuse("body is not 44 base64 characters");
    }
    let bytes = body.as_bytes();
    if bytes[SRI_SHA256_BODY_CHARACTERS - 1] != b'=' {
        return refuse("body does not end with the single '=' pad of a 32-byte digest");
    }
    if !bytes[..SRI_SHA256_BODY_CHARACTERS - 1]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
    {
        return refuse("body is not standard base64");
    }
    Ok(())
}

/// One store object in an authorized closure, as kata was TOLD it.
///
/// `nar_hash` / `nar_size` are the CLAIM whose enforcement [`IntegrityPolicy`]
/// governs. None of them is a verification result, and this type never pretends
/// otherwise.
///
/// # Content-bearing fields ONLY, because this type is folded into the environment id
///
/// Its serialization is part of the manifest bytes whose CAS address the environment id
/// folds, so every field here is IDENTITY. Only the fields that describe the BYTES are
/// admitted: path, `narHash`, `narSize`, references and `ca`. A store object's
/// SIGNATURES and DERIVER are not here: `nix store sign` or a re-substitution changes
/// them without changing one byte, and when they were folded, an unchanged node
/// declaration refused boot `node_environment_superseded` after a re-sign, with no
/// recourse. They are recorded instead as verification EVIDENCE
/// ([`ClosureEvidence`]), outside the id.
///
/// Decoding refuses an undeclared key, as every level of a manifest's decode does —
/// see [`NixEnvironmentManifestRaw`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureEntry {
    pub store_path: StorePath,
    /// SRI `sha256-<base64>`, validated by SHAPE only — see
    /// [`refuse_non_sri_sha256`].
    pub nar_hash: SmolStr,
    pub nar_size: u64,
    /// Indices into the OWNING closure's entry list. Because
    /// [`NixEnvironmentManifest::new`] sorts the closure, these are indices
    /// into the list AS SUPPLIED and are remapped through the sort permutation;
    /// see that constructor. After construction they are ascending, distinct,
    /// in range, and never the entry's own index.
    pub references: Vec<u32>,
    pub ca: Option<SmolStr>,
}

/// What the store REPORTED about one closure entry at declaration, beyond its content:
/// who signed it and what derived it. Verification EVIDENCE, recorded beside the
/// environment's row and never folded into its id — see [`ClosureEntry`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureEvidence {
    pub store_path: StorePath,
    pub deriver: Option<StorePath>,
    pub signatures: Vec<SmolStr>,
}

/// What kata REQUIRES before it binds a closure's bytes — deliberately a
/// different thing from what the closure CLAIMS (trust boundary 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NarVerification {
    NarHashOnly,
    NarHashAndSignatures,
}

impl NarVerification {
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::NarHashOnly => "nar_hash_only",
            Self::NarHashAndSignatures => "nar_hash_and_signatures",
        }
    }
}

/// # Refused set
///
/// [`IntegrityPolicy::validate`] refuses exactly one thing:
/// [`NarVerification::NarHashAndSignatures`] with `sigs_needed == 0`, which
/// would advertise signature enforcement while requiring no signature. Nothing
/// else is refused here — in particular an empty `required_signers` is legal
/// (any trusted key satisfies the count) and a `sigs_needed` larger than
/// `required_signers.len()` is legal (a count over a wider trusted-key set the
/// realiser holds, which this crate cannot see).
///
/// Decoding refuses a key the type does not declare, on both of its doors: the
/// operator's `[node] environment.integrity_policy` in `kata.toml`, and a manifest's
/// `integrity_policy`. A requirement spelled in a key nothing reads would otherwise be
/// dropped and never enforced. kata's own writer has emitted exactly these five keys
/// since manifest schema 1, so no manifest kata wrote is refused by it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityPolicy {
    pub verify: NarVerification,
    pub sigs_needed: u8,
    pub required_signers: Vec<SmolStr>,
    pub allow_unsigned_content_addressed: bool,
    /// Whether the DECLARE step re-hashes every store object's contents, rather
    /// than trusting the metadata it was handed. Policy, not a result.
    pub verify_contents_at_declare: bool,
}

impl IntegrityPolicy {
    pub fn validate(&self) -> KataResult<()> {
        if matches!(self.verify, NarVerification::NarHashAndSignatures) && self.sigs_needed == 0 {
            return Err(validation(
                "nix integrity policy refused: nar_hash_and_signatures with sigs_needed 0 \
                 would advertise signature enforcement while requiring no signature"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Where the authorized closure CAME FROM. Provenance, never contract material:
/// it is excluded from [`NixEnvironmentManifest::closure_digest`] — see that
/// method for why. Every variant refuses an undeclared key beside its `kind` tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Provenance {
    /// Explicit store paths, plus the nixpkgs attribute they were realised
    /// from. The declare-time default: a flake reference is resolved to store
    /// paths BEFORE a manifest exists, so a manifest never has to re-resolve
    /// anything.
    StorePaths { nixpkgs_attribute: SmolStr },
    Flake {
        flake_ref: SmolStr,
        locked_rev: SmolStr,
        locked_nar_hash: SmolStr,
        attribute: SmolStr,
    },
    /// A supported tree imported into the store from kata's own artifact plane.
    ImportedTree { source_artifact: ArtifactId },
}

impl Provenance {
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::StorePaths { .. } => "store_paths",
            Self::Flake { .. } => "flake",
            Self::ImportedTree { .. } => "imported_tree",
        }
    }
}

/// Whether kata's retention of this environment is the AUTHORITATIVE reason it
/// exists, or a cache entry that may be collected and re-realised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    Authoritative,
    Cache,
}

impl RetentionClass {
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::Cache => "cache",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionIntent {
    pub class: RetentionClass,
}

/// One authorized Nix closure, versioned, with its binding policy and
/// provenance.
///
/// Every field is private and the only constructor is [`Self::new`], so a
/// value of this type always satisfies the invariants that constructor checks.
/// `Deserialize` goes through the same constructor via a raw mirror, so a
/// forged manifest — an unsorted closure, a dangling reference, a root outside
/// its own closure, `Private` privacy, a `PATH` entry pointing outside the
/// closure — is refused on the way in and never becomes a value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NixEnvironmentManifest {
    /// Private: only [`Self::new`] may stamp it, and only
    /// [`NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION`] is stampable.
    schema_version: u32,
    label: SmolStr,
    platform: PlatformRef,
    provenance: Provenance,
    roots: Vec<StorePath>,
    closure: Vec<ClosureEntry>,
    path_prepend: Vec<GuestPath>,
    integrity_policy: IntegrityPolicy,
    privacy: ArtifactPrivacy,
    retention: RetentionIntent,
    realised_by: SmolStr,
}

impl NixEnvironmentManifest {
    /// The ceiling on an environment manifest's encoded bytes, for every reader of one.
    ///
    /// A manifest is a closure description — one entry per store path, each carrying a
    /// NAR hash and its reference indices — so it grows with the closure, not with the
    /// software; 16 MiB is tens of thousands of entries. ONE constant because the main's
    /// authorization (`kata_workflow::authorization`), the node's environment reader
    /// (`kata_core::environment`) and the worker's `plane_index` all read the same
    /// manifest: when the worker's bound was 4 MiB and the main's 16, a manifest between
    /// the two was authorized on the main and then refused on the worker it was
    /// authorized for.
    pub const MAXIMUM_ENCODED_BYTES: u64 = 16 * 1024 * 1024;

    /// # Refused set
    ///
    /// Accepts if and only if ALL of the following hold. Everything else is
    /// refused, with the offending value in the message:
    ///
    /// * `label` and `realised_by` contain no NUL and no other ASCII control
    ///   byte (they are neither required to be non-empty nor length-bounded
    ///   here — the store path type bounds the only field a store cares about);
    /// * the closure carries no two entries with the same `store_path`;
    /// * every `nar_hash` is shaped like SRI `sha256-<base64>`;
    /// * every reference index is `< closure.len()` (CLOSEDNESS), is not the
    ///   referring entry's own index, and appears at most once in that entry;
    /// * every root is present in the closure as an entry's `store_path`;
    /// * `privacy` is [`ArtifactPrivacy::Public`] — private bytes belong in
    ///   kata's artifact plane, which is a different trust boundary with a
    ///   different retention and redaction treatment, and a "private" Nix
    ///   closure would be a claim this plane has no mechanism for;
    /// * every `path_prepend` entry is one of the closure's store paths or is
    ///   under one at a path boundary (a `PATH` naming anything else names a
    ///   directory no bind will exist for);
    /// * [`IntegrityPolicy::validate`] passes.
    ///
    /// # What it normalizes rather than refuses
    ///
    /// * `roots` is sorted and deduplicated. Which order a caller collected its
    ///   roots in is not a fact about the environment.
    /// * `closure` is sorted by `store_path`, and each entry's `references` are
    ///   REMAPPED through that sort permutation and then sorted ascending. So
    ///   `references` on the way IN are indices into the closure as the caller
    ///   supplied it, and on the way OUT are indices into the sorted closure.
    ///   Remapping rather than demanding a pre-sorted input is what keeps the
    ///   sort from silently re-pointing a caller's reference graph at other
    ///   entries.
    /// * `path_prepend` is left exactly as given, order included: it is a
    ///   `PATH`, where order is what decides which `bash` wins.
    pub fn new(
        label: impl Into<SmolStr>,
        platform: PlatformRef,
        provenance: Provenance,
        mut roots: Vec<StorePath>,
        closure: Vec<ClosureEntry>,
        path_prepend: Vec<GuestPath>,
        integrity_policy: IntegrityPolicy,
        privacy: ArtifactPrivacy,
        retention: RetentionIntent,
        realised_by: impl Into<SmolStr>,
    ) -> KataResult<Self> {
        let label = label.into();
        let realised_by = realised_by.into();
        refuse_control_bytes("label", &label)?;
        refuse_control_bytes("realised_by", &realised_by)?;
        integrity_policy.validate()?;

        if privacy == ArtifactPrivacy::Private {
            return Err(validation(
                "nix environment manifest refused: privacy private — private bytes belong in \
                 kata's artifact plane, not in a Nix closure"
                    .to_owned(),
            ));
        }

        let closure = sort_closure(closure)?;

        roots.sort_unstable();
        roots.dedup();
        for root in &roots {
            if !closure.iter().any(|entry| entry.store_path == *root) {
                return Err(validation(format!(
                    "nix environment manifest refused: root {:?} is not present in its own closure",
                    root.as_str()
                )));
            }
        }

        for entry in &path_prepend {
            if !closure
                .iter()
                .any(|closure_entry| closure_entry.store_path.contains(entry))
            {
                return Err(validation(format!(
                    "nix environment manifest refused: path_prepend {:?} is not under any closure \
                     store path",
                    entry.as_str()
                )));
            }
        }

        Ok(Self {
            schema_version: NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION,
            label,
            platform,
            provenance,
            roots,
            closure,
            path_prepend,
            integrity_policy,
            privacy,
            retention,
            realised_by,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub const fn platform(&self) -> &PlatformRef {
        &self.platform
    }

    #[must_use]
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Sorted and deduplicated.
    #[must_use]
    pub fn roots(&self) -> &[StorePath] {
        &self.roots
    }

    /// Sorted by `store_path`, with every `references` index pointing into THIS
    /// slice.
    #[must_use]
    pub fn closure(&self) -> &[ClosureEntry] {
        &self.closure
    }

    /// In authored order, because it is a `PATH`.
    #[must_use]
    pub fn path_prepend(&self) -> &[GuestPath] {
        &self.path_prepend
    }

    #[must_use]
    pub const fn integrity_policy(&self) -> &IntegrityPolicy {
        &self.integrity_policy
    }

    #[must_use]
    pub const fn privacy(&self) -> ArtifactPrivacy {
        self.privacy
    }

    #[must_use]
    pub const fn retention(&self) -> RetentionIntent {
        self.retention
    }

    #[must_use]
    pub fn realised_by(&self) -> &str {
        &self.realised_by
    }

    /// Content address of WHICH BYTES this environment binds.
    ///
    /// Field-wise under [`domain`]`("nix_closure")`, never over a serde
    /// encoding, over the sorted closure's `(store_path, nar_hash, nar_size)`
    /// triples with a length prefix.
    ///
    /// # What is excluded, and why
    ///
    /// * `signatures` and `deriver` — not in the type at all (see [`ClosureEntry`]).
    /// * `ca` — how the bytes could be PRODUCED. Two
    ///   store objects with the same NAR hash are the same bytes whether one
    ///   arrived from a substituter and the other from a local build.
    /// * `integrity_policy` — what kata will REQUIRE before binding. Tightening
    ///   a policy must change what is admitted, not the identity of the bytes
    ///   the old policy admitted.
    /// * `provenance`, `label`, `retention`, `realised_by`, `privacy`,
    ///   `platform`, `path_prepend` — naming, classification, and realisation
    ///   facts. A flake reference re-pinned to the same closure is the same
    ///   closure.
    /// * timestamps — absent from the type entirely, so there is nothing to
    ///   exclude.
    ///
    /// `nar_size` is INCLUDED, deliberately and for the opposite reason:
    /// truncation is a byte change. A digest over the hash alone would let a
    /// shorter NAR claiming the same hash wear the same identity, which is the
    /// exact confusion trust boundary 5 exists to prevent. `roots` are excluded
    /// because a root is a subset marker over entries already hashed here; two
    /// manifests over the same closure with different roots bind the same bytes
    /// and differ only in [`crate::execution_contract::EnvironmentRef`]'s
    /// manifest half.
    #[must_use]
    pub fn closure_digest(&self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("nix_closure"), &[]);
        hash_field(
            &mut hasher,
            "entries",
            &(self.closure.len() as u64).to_le_bytes(),
        );
        for entry in &self.closure {
            hash_field(
                &mut hasher,
                "store_path",
                entry.store_path.as_str().as_bytes(),
            );
            hash_field(&mut hasher, "nar_hash", entry.nar_hash.as_bytes());
            hash_field(&mut hasher, "nar_size", &entry.nar_size.to_le_bytes());
        }
        ContentHash::new(*hasher.finalize().as_bytes())
    }

    /// Canonical bytes for CAS publication.
    ///
    /// `serde_json` of the struct: serde emits a struct's fields in DECLARATION
    /// order, and every sequence field is already in its canonical order BY
    /// CONSTRUCTION ([`Self::new`] sorts `roots` and `closure`; `path_prepend`
    /// is authored order, which IS its canonical order). So there is no
    /// re-canonicalization step here to drift from the one in `new` — the value
    /// cannot be in a non-canonical state to begin with.
    ///
    /// This is the publication encoding, NOT an identity: nothing derives a
    /// content address from these bytes. [`Self::closure_digest`] is taken
    /// field-wise for exactly that reason.
    pub fn manifest_bytes(&self) -> KataResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| {
            KataError::Serialization(format!(
                "nix environment manifest does not serialize: {error}"
            ))
        })
    }

    /// The capsule-facing reference to this environment: the CAS id of
    /// [`Self::manifest_bytes`] paired with [`Self::closure_digest`].
    ///
    /// `manifest` is a parameter rather than a field because publishing the
    /// bytes is what mints it, and this crate performs no I/O.
    #[must_use]
    pub fn environment_ref(&self, manifest: ArtifactId) -> EnvironmentRef {
        EnvironmentRef::new(manifest, self.closure_digest())
    }
}

/// The id an [`EnvironmentRef`] folds for its manifest: the manifest bytes' RAW CAS
/// address, typed as an [`ArtifactId`].
///
/// THE one derivation. The declarer (`kata_core::environment::declare_environment`) mints
/// an environment id through it and the worker's plane index recomputes one through it;
/// see [`ArtifactId`]'s docs for why this is deliberately NOT
/// `ArtifactRef::new(object, size, privacy).id()`.
#[must_use]
pub fn environment_manifest_id(manifest_bytes: &[u8]) -> ArtifactId {
    ArtifactId(crate::cache::cas_address_for_canonical_bytes(manifest_bytes).hash())
}

/// Sort a closure by store path, refuse a duplicate, validate every entry, and
/// remap reference indices through the sort permutation. See
/// [`NixEnvironmentManifest::new`]'s refused set.
fn sort_closure(closure: Vec<ClosureEntry>) -> KataResult<Vec<ClosureEntry>> {
    let length = closure.len();
    // A reference is a `u32`, so an entry count past `u32::MAX` would be a
    // closure whose own reference graph cannot address it. Not one of the
    // refusals the constructor's doc advertises, because no test can build one:
    // this is here so the index width is CHECKED rather than assumed, which is
    // what lets the permutation counter below be a `u32` with no cast.
    if u32::try_from(length).is_err() {
        return Err(validation(format!(
            "nix closure refused: {length} entries cannot be addressed by a u32 reference index"
        )));
    }
    for entry in &closure {
        refuse_non_sri_sha256("nar_hash", &entry.nar_hash)?;
    }
    for (index, entry) in closure.iter().enumerate() {
        for reference in &entry.references {
            if *reference as usize >= length {
                return Err(validation(format!(
                    "nix closure refused: entry {:?} references index {reference}, outside a \
                     closure of {length} entries",
                    entry.store_path.as_str()
                )));
            }
            if *reference as usize == index {
                return Err(validation(format!(
                    "nix closure refused: entry {:?} references itself",
                    entry.store_path.as_str()
                )));
            }
        }
        let mut seen = entry.references.clone();
        seen.sort_unstable();
        let distinct = seen.len();
        seen.dedup();
        if seen.len() != distinct {
            return Err(validation(format!(
                "nix closure refused: entry {:?} repeats a reference",
                entry.store_path.as_str()
            )));
        }
    }

    // Permutation of the SUPPLIED order into store-path order, kept so every
    // reference index can be carried across the sort instead of silently
    // re-pointing at whatever entry landed at its old position.
    let mut order: Vec<usize> = (0..length).collect();
    order.sort_by(|left, right| closure[*left].store_path.cmp(&closure[*right].store_path));
    let mut new_index = vec![0u32; length];
    for (position, supplied) in (0u32..).zip(order.iter()) {
        new_index[*supplied] = position;
    }

    let mut sorted: Vec<ClosureEntry> = order
        .iter()
        .map(|supplied| closure[*supplied].clone())
        .collect();
    if let Some(duplicate) = sorted
        .windows(2)
        .find(|pair| pair[0].store_path == pair[1].store_path)
    {
        return Err(validation(format!(
            "nix closure refused: store path {:?} appears more than once",
            duplicate[0].store_path.as_str()
        )));
    }
    for entry in &mut sorted {
        for reference in &mut entry.references {
            *reference = new_index[*reference as usize];
        }
        entry.references.sort_unstable();
    }
    Ok(sorted)
}

/// Raw mirror of [`NixEnvironmentManifest`]: deserialization re-runs
/// [`NixEnvironmentManifest::new`] over the body, so a forged manifest is
/// refused rather than trusted. The same discipline as
/// [`crate::execution_contract::ArtifactRef`]'s raw mirror; here the
/// constructor validates instead of recomputing an id, so there is no id to
/// compare.
///
/// # Closed at every level
///
/// A key no type declares is refused, not dropped, here and in every kata-written
/// type nested in a manifest: [`ClosureEntry`], [`Provenance`] (each variant),
/// [`IntegrityPolicy`], [`RetentionIntent`] and [`PlatformRef`]'s raw mirror. The
/// rest of the body is scalars, strings and unit enums, which carry no keys. kata's
/// writer is `Serialize` on these same types, so it emits only declared keys. The one
/// shape it ever wrote that this refuses is a closure entry carrying `deriver` and
/// `signatures`, which operational schema 22 moved into [`ClosureEvidence`]; a data
/// directory that old is refused at open (operational.db must carry the current
/// schema stamp), so no manifest a servable data directory holds has them.
///
/// This decode reads kata's OWN manifest bytes. The `nix path-info` decode in
/// `kata_core::environment::nix` reads Nix's output, which kata does not write, and
/// stays open on purpose.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NixEnvironmentManifestRaw {
    /// Read only to refuse a foreign version: `current_schema_version` rejects
    /// anything but this build's, so the value itself is never needed.
    #[serde(rename = "schema_version", deserialize_with = "current_schema_version")]
    _schema_version: u32,
    label: SmolStr,
    platform: PlatformRef,
    provenance: Provenance,
    roots: Vec<StorePath>,
    closure: Vec<ClosureEntry>,
    path_prepend: Vec<GuestPath>,
    integrity_policy: IntegrityPolicy,
    privacy: ArtifactPrivacy,
    retention: RetentionIntent,
    realised_by: SmolStr,
}

impl<'de> Deserialize<'de> for NixEnvironmentManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = NixEnvironmentManifestRaw::deserialize(deserializer)?;
        Self::new(
            raw.label,
            raw.platform,
            raw.provenance,
            raw.roots,
            raw.closure,
            raw.path_prepend,
            raw.integrity_policy,
            raw.privacy,
            raw.retention,
            raw.realised_by,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::json_roundtrip;

    /// A real store path of a packaged environment (`pkgsStatic.busybox`).
    const BUSYBOX: &str = "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";
    const BASH: &str = "/nix/store/0000000000000000000000000000000a-bash-5.2";
    const COREUTILS: &str = "/nix/store/1111111111111111111111111111111b-coreutils-9.5";

    fn store_path(path: &str) -> StorePath {
        StorePath::new(path).expect("a valid store path")
    }

    fn sri(byte: char) -> SmolStr {
        SmolStr::new(format!(
            "sha256-{}=",
            std::iter::repeat_n(byte, 43).collect::<String>()
        ))
    }

    fn entry(path: &str, digest: char, size: u64) -> ClosureEntry {
        ClosureEntry {
            store_path: store_path(path),
            nar_hash: sri(digest),
            nar_size: size,
            references: Vec::new(),
            ca: None,
        }
    }

    fn platform() -> PlatformRef {
        PlatformRef::new("x86_64-linux", ContentHash::new([0x33; 32]))
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

    /// One valid manifest; every refusal test below varies exactly one input.
    fn manifest(
        roots: Vec<StorePath>,
        closure: Vec<ClosureEntry>,
        path_prepend: Vec<GuestPath>,
        privacy: ArtifactPrivacy,
        integrity_policy: IntegrityPolicy,
    ) -> KataResult<NixEnvironmentManifest> {
        NixEnvironmentManifest::new(
            "busybox",
            platform(),
            Provenance::StorePaths {
                nixpkgs_attribute: SmolStr::new("pkgsStatic.busybox"),
            },
            roots,
            closure,
            path_prepend,
            integrity_policy,
            privacy,
            RetentionIntent {
                class: RetentionClass::Authoritative,
            },
            "nix-store --realise",
        )
    }

    fn busybox_manifest() -> NixEnvironmentManifest {
        manifest(
            vec![store_path(BUSYBOX)],
            vec![entry(BUSYBOX, 'A', 1024)],
            vec![GuestPath::new(format!("{BUSYBOX}/bin")).unwrap()],
            ArtifactPrivacy::Public,
            policy(),
        )
        .expect("the positive twin")
    }

    #[test]
    fn the_real_busybox_store_path_is_accepted_and_is_a_guest_path() {
        let path = store_path(BUSYBOX);
        assert_eq!(path.as_str(), BUSYBOX);
        assert_eq!(
            path.base_name(),
            "qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0"
        );
        assert_eq!(path.as_guest_path().as_str(), BUSYBOX);
    }

    /// Refused set: not under `/nix/store/`, `/nix/store` itself, a non-boundary
    /// prefix, an interior path, a wrong-length digest, a digest character
    /// outside nix-base32 (`e`, `o`, `u`, `t`, uppercase), a missing `-`, an
    /// empty name, an over-long name, a control byte, a relative path.
    #[test]
    fn store_path_refuses_non_store_interior_bad_digest_empty_name_and_control_bytes() {
        let digest = "qddzvnv6b0805nkvbqddbswddcfhx814";
        for accepted in [
            BUSYBOX,
            BASH,
            &format!("/nix/store/{digest}-a"),
            &format!("/nix/store/{digest}-{}", "n".repeat(211 - digest.len() - 1)),
        ] {
            StorePath::new(accepted).unwrap_or_else(|error| panic!("{accepted:?}: {error}"));
        }
        for refused in [
            "/work/a",
            "/nix/store",
            "/nix/store/",
            "/nix/storex/{digest}-a",
            &format!("/nix/store/{digest}-busybox/bin/sh"),
            &format!("/nix/store/{}-a", &digest[..31]),
            &format!("/nix/store/{}e-a", &digest[..31]),
            &format!("/nix/store/{}o-a", &digest[..31]),
            &format!("/nix/store/{}u-a", &digest[..31]),
            &format!("/nix/store/{}t-a", &digest[..31]),
            &format!("/nix/store/{}A-a", &digest[..31]),
            &format!("/nix/store/{digest}_a"),
            &format!("/nix/store/{digest}-"),
            &format!("/nix/store/{digest}"),
            &format!("/nix/store/{digest}-{}", "n".repeat(211 - digest.len())),
            &format!("/nix/store/{digest}-a\u{0}"),
            &format!("/nix/store/{digest}-a\u{1b}"),
            "relative",
            "",
        ] {
            assert!(
                StorePath::new(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
        assert!(serde_json::from_str::<StorePath>("\"/work/a\"").is_err());
        assert!(serde_json::from_str::<StorePath>(&format!("\"{BUSYBOX}\"")).is_ok());
    }

    /// Refused set: a `nar_hash` without the `sha256-` prefix, of the wrong
    /// length, without the trailing pad, or outside standard base64.
    #[test]
    fn closure_refuses_a_nar_hash_that_is_not_shaped_like_sri_sha256() {
        assert!(
            manifest(
                vec![store_path(BUSYBOX)],
                vec![entry(BUSYBOX, 'A', 1)],
                Vec::new(),
                ArtifactPrivacy::Public,
                policy(),
            )
            .is_ok()
        );
        let a = |count: usize| "A".repeat(count);
        for refused in [
            String::new(),
            // Wrong algorithm, right shape.
            format!("sha512-{}=", a(43)),
            // No prefix at all.
            format!("{}=", a(43)),
            // 43-character body: one short of a 32-byte digest.
            format!("sha256-{}=", a(42)),
            // 44-character body with no pad: not a 32-byte digest.
            format!("sha256-{}", a(44)),
            // Right length, right pad, a character outside standard base64.
            format!("sha256-{}-=", a(42)),
        ] {
            let mut broken = entry(BUSYBOX, 'A', 1);
            broken.nar_hash = SmolStr::new(&refused);
            let error = manifest(
                vec![store_path(BUSYBOX)],
                vec![broken],
                Vec::new(),
                ArtifactPrivacy::Public,
                policy(),
            )
            .err()
            .unwrap_or_else(|| panic!("{refused:?} must be refused"))
            .to_string();
            assert!(error.contains("nar_hash"), "{refused:?}: {error}");
        }
    }

    /// Refused set: two entries with the same `store_path`.
    #[test]
    fn closure_refuses_a_duplicate_store_path() {
        assert!(
            manifest(
                vec![store_path(BUSYBOX)],
                vec![entry(BUSYBOX, 'A', 1), entry(BASH, 'B', 2)],
                Vec::new(),
                ArtifactPrivacy::Public,
                policy(),
            )
            .is_ok()
        );
        let error = manifest(
            vec![store_path(BUSYBOX)],
            vec![entry(BUSYBOX, 'A', 1), entry(BUSYBOX, 'A', 1)],
            Vec::new(),
            ArtifactPrivacy::Public,
            policy(),
        )
        .expect_err("a duplicate store path must be refused");
        assert!(error.to_string().contains("more than once"), "{error}");
    }

    /// Refused set: a reference index at or past the closure length, an entry
    /// referencing itself, a repeated reference.
    #[test]
    fn closure_refuses_a_dangling_self_and_repeated_reference() {
        let referencing = |references: Vec<u32>| {
            let mut first = entry(BASH, 'B', 2);
            first.references = references;
            manifest(
                vec![store_path(BASH)],
                vec![first, entry(COREUTILS, 'C', 3)],
                Vec::new(),
                ArtifactPrivacy::Public,
                policy(),
            )
        };
        let accepted = referencing(vec![1]).expect("a reference into the closure is accepted");
        assert_eq!(accepted.closure()[0].references, vec![1]);
        for (references, expected) in [
            (vec![2], "outside a closure"),
            (vec![0], "references itself"),
            (vec![1, 1], "repeats a reference"),
        ] {
            let error = referencing(references.clone())
                .err()
                .unwrap_or_else(|| panic!("{references:?} must be refused"))
                .to_string();
            assert!(error.contains(expected), "{references:?}: {error}");
        }
    }

    /// The sort is a permutation, and reference indices ride it: an entry's
    /// references must still name the SAME store paths after `new` reorders the
    /// closure.
    #[test]
    fn sorting_the_closure_remaps_reference_indices_instead_of_repointing_them() {
        // Supplied in reverse store-path order, so the sort really moves things.
        let mut last = entry(COREUTILS, 'C', 3);
        last.references = vec![1]; // -> BASH, at supplied index 1
        let built = manifest(
            vec![store_path(BASH)],
            vec![last, entry(BASH, 'B', 2)],
            Vec::new(),
            ArtifactPrivacy::Public,
            policy(),
        )
        .expect("a reverse-ordered closure is sorted, not refused");
        let closure = built.closure();
        assert_eq!(closure[0].store_path.as_str(), BASH);
        assert_eq!(closure[1].store_path.as_str(), COREUTILS);
        assert_eq!(
            closure[1].references,
            vec![0],
            "coreutils still references bash, at its NEW index"
        );
    }

    /// Refused set: a root that is not an entry's `store_path`.
    #[test]
    fn manifest_refuses_a_root_absent_from_its_own_closure() {
        let error = manifest(
            vec![store_path(BUSYBOX)],
            vec![entry(BASH, 'B', 2)],
            Vec::new(),
            ArtifactPrivacy::Public,
            policy(),
        )
        .expect_err("a root outside the closure must be refused");
        assert!(
            error.to_string().contains("not present in its own closure"),
            "{error}"
        );
        assert!(
            manifest(
                vec![store_path(BASH)],
                vec![entry(BASH, 'B', 2)],
                Vec::new(),
                ArtifactPrivacy::Public,
                policy(),
            )
            .is_ok()
        );
    }

    #[test]
    fn roots_are_sorted_and_deduplicated() {
        let built = manifest(
            vec![store_path(COREUTILS), store_path(BASH), store_path(BASH)],
            vec![entry(BASH, 'B', 2), entry(COREUTILS, 'C', 3)],
            Vec::new(),
            ArtifactPrivacy::Public,
            policy(),
        )
        .expect("duplicate roots are normalized, not refused");
        assert_eq!(
            built
                .roots()
                .iter()
                .map(StorePath::as_str)
                .collect::<Vec<_>>(),
            vec![BASH, COREUTILS]
        );
    }

    /// Refused set: `privacy == Private`.
    #[test]
    fn manifest_refuses_private_privacy_and_accepts_public() {
        assert!(
            manifest(
                vec![store_path(BUSYBOX)],
                vec![entry(BUSYBOX, 'A', 1)],
                Vec::new(),
                ArtifactPrivacy::Public,
                policy(),
            )
            .is_ok()
        );
        let error = manifest(
            vec![store_path(BUSYBOX)],
            vec![entry(BUSYBOX, 'A', 1)],
            Vec::new(),
            ArtifactPrivacy::Private,
            policy(),
        )
        .expect_err("a private nix closure must be refused");
        assert!(error.to_string().contains("artifact plane"), "{error}");
    }

    /// Refused set: a `path_prepend` entry under no closure store path,
    /// including one that matches a store path only as a string prefix rather
    /// than at a path boundary.
    #[test]
    fn manifest_refuses_a_path_prepend_outside_the_closure() {
        let inside = GuestPath::new(format!("{BUSYBOX}/bin")).unwrap();
        assert!(
            manifest(
                vec![store_path(BUSYBOX)],
                vec![entry(BUSYBOX, 'A', 1)],
                vec![inside, GuestPath::new(BUSYBOX).unwrap()],
                ArtifactPrivacy::Public,
                policy(),
            )
            .is_ok()
        );
        for refused in [
            "/work/bin".to_owned(),
            "/nix/store".to_owned(),
            format!("{BUSYBOX}x/bin"),
            format!("{BASH}/bin"),
        ] {
            let error = manifest(
                vec![store_path(BUSYBOX)],
                vec![entry(BUSYBOX, 'A', 1)],
                vec![GuestPath::new(refused.clone()).unwrap()],
                ArtifactPrivacy::Public,
                policy(),
            )
            .err()
            .unwrap_or_else(|| panic!("{refused:?} must be refused"))
            .to_string();
            assert!(
                error.contains("not under any closure"),
                "{refused:?}: {error}"
            );
        }
    }

    /// Refused set: a control byte in `label` or in `realised_by`.
    #[test]
    fn manifest_refuses_control_bytes_in_label_and_realised_by() {
        let build = |label: &str, realised_by: &str| {
            NixEnvironmentManifest::new(
                label,
                platform(),
                Provenance::StorePaths {
                    nixpkgs_attribute: SmolStr::new("pkgsStatic.busybox"),
                },
                vec![store_path(BUSYBOX)],
                vec![entry(BUSYBOX, 'A', 1)],
                Vec::new(),
                policy(),
                ArtifactPrivacy::Public,
                RetentionIntent {
                    class: RetentionClass::Cache,
                },
                realised_by,
            )
        };
        assert!(build("busybox", "nix-store --realise").is_ok());
        assert!(build("busy\u{0}box", "nix-store").is_err());
        assert!(build("busybox", "nix\nstore").is_err());
    }

    /// Refused set: `NarHashAndSignatures` with `sigs_needed == 0`.
    #[test]
    fn integrity_policy_refuses_signature_enforcement_needing_no_signature() {
        let mut signed = policy();
        signed.verify = NarVerification::NarHashAndSignatures;
        signed.sigs_needed = 0;
        assert!(signed.validate().is_err());
        signed.sigs_needed = 1;
        signed
            .validate()
            .expect("one required signature is a policy");
        assert!(
            manifest(
                vec![store_path(BUSYBOX)],
                vec![entry(BUSYBOX, 'A', 1)],
                Vec::new(),
                ArtifactPrivacy::Public,
                signed,
            )
            .is_ok()
        );
        let mut broken = policy();
        broken.verify = NarVerification::NarHashAndSignatures;
        let error = manifest(
            vec![store_path(BUSYBOX)],
            vec![entry(BUSYBOX, 'A', 1)],
            Vec::new(),
            ArtifactPrivacy::Public,
            broken,
        )
        .expect_err("the manifest re-validates its policy");
        assert!(error.to_string().contains("sigs_needed 0"), "{error}");
    }

    #[test]
    fn re_signing_does_not_move_the_closure_digest_but_truncation_does() {
        let base = busybox_manifest();
        let digest = base.closure_digest();

        let mut re_signed = vec![entry(BUSYBOX, 'A', 1024)];
        re_signed[0].ca = Some(SmolStr::new("fixed:sha256-x"));
        let re_signed = manifest(
            vec![store_path(BUSYBOX)],
            re_signed,
            base.path_prepend().to_vec(),
            ArtifactPrivacy::Public,
            policy(),
        )
        .unwrap();
        assert_eq!(digest, re_signed.closure_digest(), "ca is not bytes");

        let truncated = manifest(
            vec![store_path(BUSYBOX)],
            vec![entry(BUSYBOX, 'A', 1023)],
            base.path_prepend().to_vec(),
            ArtifactPrivacy::Public,
            policy(),
        )
        .unwrap();
        assert_ne!(
            digest,
            truncated.closure_digest(),
            "a shorter NAR is different bytes"
        );
    }

    #[test]
    fn a_policy_label_and_provenance_change_never_moves_the_closure_digest() {
        let base = busybox_manifest();
        let mut tightened = policy();
        tightened.verify = NarVerification::NarHashAndSignatures;
        tightened.sigs_needed = 2;
        let other = NixEnvironmentManifest::new(
            "renamed",
            PlatformRef::new("x86_64-linux", ContentHash::new([0x99; 32])),
            Provenance::ImportedTree {
                source_artifact: ArtifactId(crate::primitives::FixedBytes([0x44; 32])),
            },
            vec![store_path(BUSYBOX)],
            vec![entry(BUSYBOX, 'A', 1024)],
            Vec::new(),
            tightened,
            ArtifactPrivacy::Public,
            RetentionIntent {
                class: RetentionClass::Cache,
            },
            "nix copy",
        )
        .unwrap();
        assert_eq!(base.closure_digest(), other.closure_digest());
    }

    #[test]
    fn a_closure_digest_is_order_independent_and_the_environment_ref_carries_it() {
        let forward = manifest(
            vec![store_path(BASH)],
            vec![entry(BASH, 'B', 2), entry(COREUTILS, 'C', 3)],
            Vec::new(),
            ArtifactPrivacy::Public,
            policy(),
        )
        .unwrap();
        let reversed = manifest(
            vec![store_path(BASH)],
            vec![entry(COREUTILS, 'C', 3), entry(BASH, 'B', 2)],
            Vec::new(),
            ArtifactPrivacy::Public,
            policy(),
        )
        .unwrap();
        assert_eq!(forward, reversed);
        let manifest_id = ArtifactId(crate::primitives::FixedBytes([0x21; 32]));
        let reference = forward.environment_ref(manifest_id);
        assert_eq!(reference.manifest(), manifest_id);
        assert_eq!(reference.closure_digest(), forward.closure_digest());
        assert_eq!(
            reference,
            EnvironmentRef::new(manifest_id, forward.closure_digest())
        );
    }

    #[test]
    fn a_manifest_round_trips_and_carries_no_host_path() {
        let built = busybox_manifest();
        let bytes = built.manifest_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains("/home/"), "{text}");
        assert_eq!(bytes, serde_json::to_vec(&built).unwrap());
        json_roundtrip(built);
    }

    /// Deserialization goes through `new`, so a manifest forged in JSON — the
    /// only place these invariants can be violated, since the fields are
    /// private — is refused.
    #[test]
    fn a_forged_manifest_is_refused_on_deserialize() {
        let document = serde_json::to_value(busybox_manifest()).unwrap();

        let mut foreign = document.clone();
        foreign["schema_version"] = serde_json::json!(NIX_ENVIRONMENT_MANIFEST_SCHEMA_VERSION + 1);
        let error = serde_json::from_value::<NixEnvironmentManifest>(foreign)
            .expect_err("a foreign schema_version must be refused")
            .to_string();
        assert!(error.contains("schema_version"), "{error}");

        let mut private = document.clone();
        private["privacy"] = serde_json::json!("private");
        assert!(serde_json::from_value::<NixEnvironmentManifest>(private).is_err());

        let mut dangling = document.clone();
        dangling["closure"][0]["references"] = serde_json::json!([7]);
        assert!(serde_json::from_value::<NixEnvironmentManifest>(dangling).is_err());

        let mut rootless = document.clone();
        rootless["roots"] = serde_json::json!([BASH]);
        assert!(serde_json::from_value::<NixEnvironmentManifest>(rootless).is_err());

        let mut escaped = document.clone();
        escaped["path_prepend"] = serde_json::json!(["/work/bin"]);
        assert!(serde_json::from_value::<NixEnvironmentManifest>(escaped).is_err());

        let mut unsigned = document.clone();
        unsigned["integrity_policy"]["verify"] = serde_json::json!("nar_hash_and_signatures");
        assert!(serde_json::from_value::<NixEnvironmentManifest>(unsigned).is_err());

        // A policy key the type does not declare is a requirement nothing enforces —
        // refused, not dropped. kata's own writer has emitted exactly the five declared
        // keys since schema 1, so no manifest kata wrote carries one.
        let mut undeclared = document.clone();
        undeclared["integrity_policy"]["require_signatures_from"] =
            serde_json::json!(["cache.example"]);
        let error = serde_json::from_value::<NixEnvironmentManifest>(undeclared)
            .expect_err("an undeclared integrity-policy key must be refused")
            .to_string();
        assert!(error.contains("require_signatures_from"), "{error}");

        serde_json::from_value::<NixEnvironmentManifest>(document)
            .expect("the untouched document is the positive twin");
    }

    /// Plant `key` in the object `at` selects inside the busybox manifest's JSON and
    /// decode it: the refusal must name the key. Every nested level is closed, so a
    /// key at ANY of them is a forgery or another writer's shape, never kata's.
    fn undeclared_key_refusal(
        key: &str,
        at: impl FnOnce(&mut serde_json::Value) -> &mut serde_json::Value,
    ) -> String {
        let mut document = serde_json::to_value(busybox_manifest()).unwrap();
        at(&mut document)
            .as_object_mut()
            .expect("the planted level is a JSON object")
            .insert(key.to_owned(), serde_json::json!(true));
        let error = serde_json::from_value::<NixEnvironmentManifest>(document)
            .expect_err("an undeclared key must be refused")
            .to_string();
        assert!(error.contains(key), "the refusal names `{key}`: {error}");
        error
    }

    #[test]
    fn a_manifest_refuses_an_undeclared_top_level_key() {
        undeclared_key_refusal("realised_at", |document| document);
    }

    /// `deriver` is the shape kata's own writer emitted before operational schema 22
    /// moved it, with `signatures`, out of the entry and into `ClosureEvidence`.
    #[test]
    fn a_closure_entry_refuses_an_undeclared_key() {
        undeclared_key_refusal("deriver", |document| &mut document["closure"][0]);
    }

    /// Every variant of the internally tagged enum, not only the one the busybox
    /// manifest carries: `kind` is consumed as the tag, so it is not itself refused.
    #[test]
    fn a_provenance_of_every_variant_refuses_an_undeclared_key() {
        for provenance in [
            Provenance::StorePaths {
                nixpkgs_attribute: SmolStr::new("pkgsStatic.busybox"),
            },
            Provenance::Flake {
                flake_ref: SmolStr::new("github:NixOS/nixpkgs"),
                locked_rev: SmolStr::new("0123456789abcdef"),
                locked_nar_hash: sri('C'),
                attribute: SmolStr::new("busybox"),
            },
            Provenance::ImportedTree {
                source_artifact: ArtifactId(crate::primitives::FixedBytes([0x44; 32])),
            },
        ] {
            let tag = provenance.as_tag();
            let encoded = serde_json::to_value(&provenance).unwrap();
            serde_json::from_value::<Provenance>(encoded.clone())
                .unwrap_or_else(|error| panic!("the {tag} positive twin decodes: {error}"));
            undeclared_key_refusal("pinned_by", move |document| {
                document["provenance"] = encoded;
                &mut document["provenance"]
            });
        }
    }

    #[test]
    fn a_retention_intent_refuses_an_undeclared_key() {
        undeclared_key_refusal("ttl_secs", |document| &mut document["retention"]);
    }

    #[test]
    fn a_platform_refuses_an_undeclared_key() {
        undeclared_key_refusal("libc", |document| &mut document["platform"]);
    }
}
