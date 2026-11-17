//! Cache key, result, and policy types.

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::primitives::{ContentHash, FixedBytes, ObjectId};

/// The accounting convention every adapter normalizes its vendor's wire to:
/// **`input` EXCLUDES `cache_read` and `cache_write`; `output` INCLUDES
/// reasoning.**
///
/// Vendors disagree on both axes — OpenAI/codex and grok report an input
/// count that contains the cached prefix (codex its cache writes too) and an
/// output count that already holds the reasoning tokens (their `total` is
/// `input + output`), while Anthropic, pi and opencode report all four as
/// disjoint counters — so an adapter that copies its wire's `input`
/// unmodified prices the cached prefix twice under API-key rates
/// (`input_cost + cache_read_cost` in
/// `kata_worker::pricing::lookup_cost_usd`). The measured identity each
/// adapter normalized from is stated on its own map function.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Non-cached prompt tokens — see the struct doc.
    pub input: u64,
    /// Completion tokens, reasoning included — see the struct doc.
    pub output: u64,
    /// Tokens served from the provider's prompt cache. Anthropic
    /// reports these as `cache_read_input_tokens` (separate from
    /// `input_tokens`); OpenAI as `prompt_tokens_details.cached_tokens`
    /// (a SUBSET of its `input_tokens` — the adapter subtracts it).
    /// `#[serde(default)]` keeps a persisted entry without the field
    /// decodable.
    #[serde(default)]
    pub cache_read: u64,
    /// Tokens written into the provider's prompt cache. Anthropic
    /// reports these as `cache_creation_input_tokens` (separate from
    /// `input_tokens`); codex as `cacheWriteInputTokens`, off the Responses
    /// API's `input_tokens_details.cache_write_tokens` (a SUBSET of its
    /// `inputTokens` — the adapter subtracts it). A kind whose wire states
    /// no cache-write class leaves this at 0.
    #[serde(default)]
    pub cache_write: u64,
}

impl TokenUsage {
    /// `true` when every counter is zero — i.e. the backend surfaced NO usage
    /// at all.
    ///
    /// Metering reads this as "there is nothing here to price". For a backend
    /// with a billable provider that is an absence of information, not a
    /// measurement of zero: every backend's `Default` is this value, so a usage
    /// event that was never parsed into counters looks exactly like it. Pricing
    /// all-zero usage would yield
    /// `$0.00`, a silent `0` in every running total and every cost bound —
    /// indistinguishable from a genuinely free stage.
    ///
    /// See `kata_worker::pricing::meter_call`, which turns this into
    /// [`MeteredCost::Unavailable`](crate::metering::MeteredCost::Unavailable)
    /// rather than a zero charge.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.input == 0 && self.output == 0 && self.cache_read == 0 && self.cache_write == 0
    }
}

/// Length-prefix each segment into `h` so concatenation can't accidentally
/// collide across fields (e.g., splitting a 32-byte hash across adjacent
/// fields). Shared by every identity in `crate::execution_contract`, which must
/// hash field-wise rather than over a serde encoding.
///
/// `pub` rather than `pub(crate)` because a SECOND crate mints an identity that has to live in the
/// same framing: `kata_workflow::capsule_assembly::sandbox_permissions_hash`, whose output is
/// folded into `PreparedAction::id` alongside hashes taken through this very function. A private
/// copy over there would be the same framing spelled twice, and the day one spelling changed the
/// two would disagree about an identity they jointly produce.
pub fn hash_field(h: &mut blake3::Hasher, name: &str, value: &[u8]) {
    h.update(&(name.len() as u64).to_le_bytes());
    h.update(name.as_bytes());
    h.update(&(value.len() as u64).to_le_bytes());
    h.update(value);
}

/// The digest function — and so the whole ADDRESS SCHEME — a CAS object is
/// addressed under.
///
/// # Invariant
///
/// A CAS address NAMES ITS OWN FUNCTION, in both halves. [`Self::code`] is
/// folded into the digest PREIMAGE, so two generations can never produce the
/// same 32-byte value over the same bytes; [`Self::label`] is rendered into the
/// address SPELLING, so a blob on disk or a member inside a backup artifact
/// says which function verifies it. The 32-byte half alone is what every
/// downstream row keys on (`cas_objects.object_id`),
/// and that half cannot carry a label — which is exactly why the code goes in
/// the preimage rather than only in the rendering.
///
/// # Failure mode this closes
///
/// `kata.cas.object` was the ONE domain tag in this module with no versioning
/// mechanism of any kind. Every sibling carries a `.vN`; this tag had no
/// successor and no way to express a second generation, so a change to the
/// digest scheme silently
/// REUSED the same 64-hex namespace: old and new addresses were drawn from one
/// space, and nothing holding a 32-byte id could say which scheme produced it.
///
/// The fix is structural rather than a tag bump — REAPI's lesson, where
/// identity is the pair `(digest_function, digest)`, which is what let Bazel
/// move SHA-256 → BLAKE3 with no flag day. A tag bump answers the question once
/// and leaves the next generation asking it again.
///
/// Unlike REAPI this does NOT carry `size_bytes` beside the hash: the canonical
/// byte length is already folded into the preimage by
/// [`ObjectIdHasher::for_canonical_len`], so an address and a length cannot
/// disagree the way a `Digest{hash, size_bytes}` pair can.
///
/// # What a new variant is FOR
///
/// The function denotes the WHOLE address scheme, not merely the hash
/// algorithm: a change to the FRAMING — the domain tag, the length prefix, the
/// field order — is as much a new function as a change away from blake3, and
/// MUST take a new variant. A variant's [`Self::code`] and [`Self::label`] are
/// durable and may never be reused for different semantics.
///
/// # Enforcement point
///
/// [`ObjectIdHasher::for_canonical_len`] is the single place the preimage is
/// spelled and [`CasAddress`] the single place the rendering is, so there is no
/// second spelling of either to drift from. The streaming and in-memory paths
/// both go through the hasher (see [`cas_address_for_canonical_bytes`]).
///
/// # Proof
///
/// `a_cas_address_names_its_own_digest_function` (this crate's `cache_tests`)
/// pins the preimage byte-for-byte against a hand-spelled blake3 and asserts
/// a preimage without the function code — tag ‖ len ‖ bytes — lands somewhere
/// ELSE, which is the generation separation stated as a value.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum CasDigestFunction {
    /// blake3 over `b"kata.cas.object\0" ‖ [code] ‖ len_le(u64) ‖ canonical`.
    Blake3,
}

impl CasDigestFunction {
    /// Every function this binary can address under.
    ///
    /// Exists so a second variant cannot be added silently: the CAS store
    /// asserts this list's LENGTH at compile time where it reconstructs an
    /// address from a row that stores the hash half only.
    pub const ALL: &'static [Self] = &[Self::Blake3];

    /// The durable numeric code folded into the digest preimage.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Blake3 => 1,
        }
    }

    /// The durable textual label rendered into the address spelling.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
        }
    }

    /// The function a label names, or `None` for a label this binary cannot
    /// address under — including a FUTURE generation's, which is the honest
    /// answer: a binary that cannot verify an address must not pretend to.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "blake3" => Some(Self::Blake3),
            _ => None,
        }
    }
}

/// A CAS content address: the PAIR of a digest function and its 32-byte digest.
///
/// Rendered as `<64 lowercase hex>.<label>` — the digest first so the on-disk
/// 256-way shard (`<hex[0..2]>/`) stays derivable from the address's own
/// spelling with no knowledge of the function, and the label last so an object
/// file, a backup manifest member and an error message all say which function
/// verifies the bytes.
///
/// # Refusal set vs. the claim
///
/// [`FromStr`](std::str::FromStr) accepts EXACTLY what [`Display`](std::fmt::Display)
/// emits and nothing else: 64 lowercase hex characters, one `.`, a known label.
/// It refuses uppercase hex deliberately — hex case is not addressing
/// information, and admitting both spellings would give one object two
/// addresses and therefore two blob paths, which is the drift class this type
/// exists to remove. It refuses an unknown label, which includes every FUTURE
/// generation; that refusal is a capability statement, not a validity one.
///
/// It does NOT prove the named object exists, that the bytes at any path hash
/// to it, or that the function is one the caller wants — those are the store's
/// and the backup preflight's checks, not the parser's.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct CasAddress {
    function: CasDigestFunction,
    hash: ObjectId,
}

impl CasAddress {
    /// Pair a digest with the function that produced it.
    #[must_use]
    pub const fn new(function: CasDigestFunction, hash: ObjectId) -> Self {
        Self { function, hash }
    }

    /// The address of `hash` under [`CasDigestFunction::Blake3`].
    ///
    /// The reconstruction direction: a store row keys on the 32-byte half and
    /// must re-derive the full address to find the object's blob. Sound only
    /// while `Blake3` is the sole variant, which
    /// `crate::store::cas`'s compile-time assert on
    /// [`CasDigestFunction::ALL`] holds — in `kata-core`, because that is where
    /// the row lives.
    #[must_use]
    pub const fn blake3(hash: ObjectId) -> Self {
        Self::new(CasDigestFunction::Blake3, hash)
    }

    /// The function half.
    #[must_use]
    pub const fn function(&self) -> CasDigestFunction {
        self.function
    }

    /// The digest half — what durable rows key on.
    #[must_use]
    pub const fn hash(&self) -> ObjectId {
        self.hash
    }
}

impl std::fmt::Display for CasAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.hash, self.function.label())
    }
}

/// Why a string is not a CAS address this binary can use.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CasAddressParseError {
    /// No `.` separator, so the string carries no function at all — a bare
    /// digest.
    #[error("cas address {0:?} carries no `.<function>` suffix")]
    NoFunction(String),
    /// A well-formed suffix naming a function this binary cannot address under.
    #[error(
        "cas address {address:?} names digest function {label:?}, which this binary cannot address under"
    )]
    UnknownFunction {
        /// The offending address, verbatim.
        address: String,
        /// The label that was not recognised.
        label: String,
    },
    /// The digest half is not 64 lowercase hex characters.
    #[error("cas address {0:?} does not carry a 64-character lowercase hex digest")]
    MalformedDigest(String),
}

impl std::str::FromStr for CasAddress {
    type Err = CasAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (digest, label) = s
            .rsplit_once('.')
            .ok_or_else(|| CasAddressParseError::NoFunction(s.to_string()))?;
        let function = CasDigestFunction::from_label(label).ok_or_else(|| {
            CasAddressParseError::UnknownFunction {
                address: s.to_string(),
                label: label.to_string(),
            }
        })?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(CasAddressParseError::MalformedDigest(s.to_string()));
        }
        let hash: ObjectId = digest
            .parse()
            .map_err(|_| CasAddressParseError::MalformedDigest(s.to_string()))?;
        Ok(Self::new(function, hash))
    }
}

/// Content-address the already-canonicalised byte encoding of a value.
///
/// This is the single definition of the CAS address so that the byte-level
/// store (`CasStore::put`, which sees canonical bytes) and a caller that
/// canonicalises with [`crate::idempotency::canonicalize_args`] first can never
/// disagree on
/// where an object lands. It delegates to [`ObjectIdHasher`], which the
/// STREAMING callers also use, so there is one spelling of the scheme and not
/// three.
///
/// The domain tag (`b"kata.cas.object\0"`) namespaces this digest so it can
/// never collide with another length-prefixed blake3 usage in the crate, even
/// over identical bytes; the function code makes it impossible for a future
/// address scheme to collide with THIS one (see [`CasDigestFunction`]); the
/// length prefix keeps the framing and the payload from bleeding into one
/// another.
///
/// Callers must pass bytes produced by
/// [`crate::idempotency::canonicalize_args`]; passing non-canonical bytes
/// defeats dedup (equal-but-reordered values would hash apart).
#[must_use]
pub fn cas_address_for_canonical_bytes(canonical: &[u8]) -> CasAddress {
    let mut hasher = ObjectIdHasher::for_canonical_len(canonical.len() as u64);
    hasher.update(canonical);
    hasher
        .finish()
        .expect("the slice's own length was declared, so the fed count cannot differ from it")
}

/// The DIGEST HALF of [`cas_address_for_canonical_bytes`].
///
/// Kept as its own spelling because that half is what durable rows key on —
/// `cas_objects.object_id` and `operational.db`'s `cas_roots` — and neither
/// column can carry a function label. It is
/// the same address; it is not a second scheme.
#[must_use]
pub fn object_id_for_canonical_bytes(canonical: &[u8]) -> ObjectId {
    cas_address_for_canonical_bytes(canonical).hash()
}

/// [`cas_address_for_canonical_bytes`], computed over a STREAM.
///
/// # Why the length has to be declared first
///
/// The preimage is `domain ‖ function_code ‖ len_le ‖ canonical`, so the byte
/// length is hashed BEFORE the payload. A one-pass streaming caller — the backup
/// capture and the restore preflight, which address multi-hundred-megabyte blob
/// files they must not read into memory — therefore has to state the length up
/// front, from a stat of the handle it is about to read.
///
/// [`Self::finish`] returns `None` when the fed byte count is not the declared
/// length, and that refusal is the reason this type exists rather than a bare
/// `blake3::Hasher`. Without it a file that changed size under the read would
/// produce a confident address over a length that was never true of the bytes,
/// and the caller would compare it to a path and get a mismatch it would blame
/// on the wrong thing.
///
/// This is the ONE spelling of the domain tag, the function code and the length
/// prefix; [`cas_address_for_canonical_bytes`] delegates to it so a streaming
/// address and an in-memory one cannot drift apart.
pub struct ObjectIdHasher {
    hasher: blake3::Hasher,
    function: CasDigestFunction,
    declared: u64,
    seen: u64,
}

impl std::fmt::Debug for ObjectIdHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectIdHasher")
            .field("function", &self.function)
            .field("declared", &self.declared)
            .field("seen", &self.seen)
            .finish_non_exhaustive()
    }
}

impl ObjectIdHasher {
    /// Begin addressing canonical bytes whose length is known to be
    /// `canonical_len`.
    ///
    /// There is no function parameter and there should not be one until a
    /// second [`CasDigestFunction`] exists: this binary WRITES under exactly one
    /// function, and offering a choice it cannot honour is how a caller comes to
    /// believe an address was produced under a scheme that was never available.
    /// The mechanism that survives a second variant is the address itself, which
    /// already carries the function; the parameter is degenerate today on
    /// purpose.
    #[must_use]
    pub fn for_canonical_len(canonical_len: u64) -> Self {
        let function = CasDigestFunction::Blake3;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kata.cas.object\0");
        hasher.update(&[function.code()]);
        hasher.update(&canonical_len.to_le_bytes());
        Self {
            hasher,
            function,
            declared: canonical_len,
            seen: 0,
        }
    }

    /// Feed the next chunk of the payload.
    pub fn update(&mut self, chunk: &[u8]) {
        self.seen = self.seen.saturating_add(chunk.len() as u64);
        self.hasher.update(chunk);
    }

    /// The content address, or `None` if the fed byte count is not the length
    /// declared to [`Self::for_canonical_len`].
    #[must_use]
    pub fn finish(self) -> Option<CasAddress> {
        (self.seen == self.declared).then(|| {
            CasAddress::new(
                self.function,
                FixedBytes(*self.hasher.finalize().as_bytes()),
            )
        })
    }
}

/// The INPUT-SET digest an [`ActionManifest`] folds: the digest of the EMPTY
/// resolved input set. No stage resolves its read closure to per-path digests,
/// so every action's input set is empty, and this is the one value it can take.
/// It is spelled exactly as the per-path set it replaced hashed an empty set —
/// the domain, then a zero `file_count` — so every prepared-action id is
/// byte-identical to the one an earlier build minted
/// (`prepared_action_id_vector_is_pinned`).
fn empty_input_set_digest() -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, "kata.action.input_set.v1", &[]);
    hash_field(&mut hasher, "file_count", &0u64.to_le_bytes());
    FixedBytes(*hasher.finalize().as_bytes())
}

/// The identity of ONE Bazel-style ACTION: the fine-grained cache/effect
/// unit. An action = **(command identity, INPUT file set, OUTPUT file set)**,
/// which is the move from keying on the whole STAGE (whole-workspace content
/// hash + whole-worktree captured tree) to keying on exactly the files the
/// action reads and writes.
///
/// - `command` — the prompt/contract hash that pins WHAT the action does,
///   independent of the files it touches.
/// - the INPUT set — always empty: no stage resolves its read closure to
///   per-path digests, so the identity folds the empty set's digest
///   (`empty_input_set_digest`) and the manifest carries no field for it.
/// - `declared_outputs` — the DECLARED output file set (`produces_files` globs).
///   SKELETON scope: the declared globs are recorded; resolving them to
///   post-execution digests and materializing ONLY the output set (path-scoped
///   restore) are not built, and nothing here half-builds them.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ActionManifest {
    pub command: ContentHash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_outputs: Vec<SmolStr>,
}

impl ActionManifest {
    /// Build a manifest, sorting `declared_outputs` so the content hash is
    /// independent of author-declared glob order.
    #[must_use]
    pub fn new(command: ContentHash, mut declared_outputs: Vec<SmolStr>) -> Self {
        declared_outputs.sort_unstable();
        declared_outputs.dedup();
        Self {
            command,
            declared_outputs,
        }
    }

    /// A stable blake3 over the whole action identity — command + the empty
    /// input set's digest + declared outputs — length-prefixed via
    /// [`hash_field`] so no field bleeds into the next. Two manifests with equal
    /// fields hash equal; changing the command or ANY declared output rotates
    /// the digest.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, "kata.action.manifest.v1", &[]);
        hash_field(&mut hasher, "command", self.command.as_bytes());
        hash_field(
            &mut hasher,
            "input_set",
            empty_input_set_digest().as_bytes(),
        );
        hash_field(
            &mut hasher,
            "declared_output_count",
            &(self.declared_outputs.len() as u64).to_le_bytes(),
        );
        for output in &self.declared_outputs {
            hash_field(&mut hasher, "declared_output", output.as_bytes());
        }
        FixedBytes(*hasher.finalize().as_bytes())
    }
}

/// How a stage's result may be reused. The two reuse variants are named for the
/// semantics they enforce, not the mechanism, and are split at runtime:
///
/// - [`Self::ModelReuse`] — optional cross-run reuse of a
///   stage's recorded RESULT (envelope + any captured file-tree). Sound only for
///   a read-only verdict stage: a workspace-mutating or effect-adapter-issuing
///   stage is refused at load (determinism boundary, clause 4 — see
///   [`crate::effect`]) because its
///   nondeterministic mutation/issue cannot be soundly re-served from a stale
///   recorded run. Under `oci` this is served only for a stage that lowers to
///   `CapsuleProcess::Agent`, whose reuse key folds the rendered prompt,
///   adapter, model and credential reference beside the shared inputs.
/// - [`Self::ContentCache`] — the content-addressed cache keyed on
///   the capsule's declared inputs. Sound only for a
///   [content-cache-eligible](crate::execution_class::CheckedExecutionClass::is_content_cache_eligible)
///   stage (deterministic + hermetic).
///
/// The serving surface is `capsule_reuse_v1`, a HINT table: a hit names the
/// accepted occurrence whose result the operational plane re-verifies and
/// adopts, so a stale or fabricated row can only cause a miss.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    /// The author wrote no `cache_policy=` kwarg at all — the (a) state of
    /// [`AuthoredCachePolicy`], DURABLE.
    ///
    /// This is `#[default]` and not [`Self::Disabled`] because
    /// [`AuthoredCachePolicy::default`] is `Omitted` and `Default::default()`
    /// has exactly one production caller — `kata_workflow`'s
    /// `StageFlatFields::join_default`, which exists to make a synthetic join
    /// lower *"byte-identically to a minimal authored shell stage"*. A minimal
    /// authored shell stage decodes `""` through
    /// [`AuthoredCachePolicy::from_spelling`] and lands HERE, so a default of
    /// `Disabled` would break that byte-identity claim and make a
    /// join the one stage in the tree whose silence reads as an EXEMPTION.
    /// `AuthoredCachePolicy::default().collapse() == CachePolicy::default()`
    /// holds as a result, and is pinned.
    #[default]
    Omitted,
    Disabled,
    ModelReuse,
    ContentCache,
}

impl CachePolicy {
    /// The closed set of AUTHORABLE policy variants, in a stable order — the
    /// source of truth for the DSL catalog's `cache_policy` domain.
    ///
    /// # What it is NOT the source of truth for
    ///
    /// * The WIRE spelling set. `serde` also emits `"omitted"` for
    ///   [`Self::Omitted`], so the wire spelling set has FOUR members while this
    ///   list deliberately carries THREE: `"omitted"` is a
    ///   [RESERVED](AuthoredCachePolicy::RESERVED_SPELLINGS) spelling that
    ///   [`AuthoredCachePolicy::from_spelling`] REFUSES, and the catalog domain is
    ///   built from this list, so advertising it would publish a spelling the
    ///   evaluator rejects — the exact drift
    ///   `catalog_enum_spellings_round_trip_through_decoders` exists to catch.
    ///   The invariant is an INCLUSION, not an equality: every entry here is a
    ///   wire spelling, and not every wire spelling is here. Pinned by
    ///   `variants_are_a_strict_subset_of_the_wire_spellings`.
    /// * The decoder's accepted spellings.
    ///   [`AuthoredCachePolicy::from_spelling`] is, and it accepts a spelling
    ///   this list does not carry (`"no_cache"`, the Bazel-shaped exemption) and
    ///   REFUSES one it would otherwise admit
    ///   ([`AuthoredCachePolicy::RESERVED_SPELLINGS`]). The REFUSED set and the
    ///   CLAIMED set are stated on that function.
    /// * Every spelling table. `format_cache_policy` in
    ///   `bin/kata/src/cli/workflows/render.rs` is a second, exhaustive,
    ///   hand-maintained one that duplicates [`Self::as_tag`] and is the only
    ///   thing in the workspace that a new variant breaks.
    #[must_use]
    pub const fn variants() -> &'static [Self] {
        // DELIBERATELY EXCLUDES `Self::Omitted` — see the doc above. This list
        // feeds the DSL catalog's `cache_policy` domain, and `"omitted"` is
        // unauthorable by construction.
        &[Self::Disabled, Self::ModelReuse, Self::ContentCache]
    }

    /// The canonical `snake_case` wire spelling — the SAME token serde emits, so
    /// it round-trips through the typed decoder (proven by the DSL decode-roundtrip
    /// drift guard).
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::Omitted => "omitted",
            Self::Disabled => "disabled",
            Self::ModelReuse => "model_reuse",
            Self::ContentCache => "content_cache",
        }
    }
}

// ---------------------------------------------------------------------------
// The FUSED cache-admission gate
// ---------------------------------------------------------------------------

/// The reuse regime an author may ASK FOR BY NAME — the (c) state of
/// [`AuthoredCachePolicy`].
///
/// # Why the payload is not just a [`CachePolicy`]
///
/// [`CachePolicy::Disabled`] is not a regime anyone can *request*; it is the
/// EXEMPTION, which [`AuthoredCachePolicy::Exempted`] already spells. Carrying a
/// whole `CachePolicy` in the request would leave `Requested(Disabled)`
/// constructible — a second, redundant spelling of the exemption that every
/// match on the authored state would have to remember to fold back onto the
/// first. Narrowing the payload to the two REQUESTABLE regimes makes that state
/// unrepresentable rather than merely discouraged: the defect is unreachable at
/// the type level instead of forbidden by a rule someone has to recall at the
/// next call site.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RequestedCacheRegime {
    /// [`CachePolicy::ModelReuse`] — the rendered-prompt reuse namespace.
    ModelReuse,
    /// [`CachePolicy::ContentCache`] — the content-addressed namespace.
    ContentCache,
}

impl RequestedCacheRegime {
    /// The [`CachePolicy`] this request lowers to.
    #[must_use]
    pub const fn as_policy(self) -> CachePolicy {
        match self {
            Self::ModelReuse => CachePolicy::ModelReuse,
            Self::ContentCache => CachePolicy::ContentCache,
        }
    }
}

/// The THREE states of an author's cache decision — the states [`CachePolicy`]
/// can spell in only TWO.
///
/// # Why three states
///
/// With [`CachePolicy`] alone, cacheability needs two INDEPENDENT opt-ins that
/// both have to be set: the seven-axis class has to derive
/// [`is_content_cache_eligible`](crate::execution_class::CheckedExecutionClass::is_content_cache_eligible)
/// (sound, derived, documented "never authored"), AND the author has to
/// separately write `cache_policy = "content_cache"`. A stage could be provably
/// pure and get nothing for it, and no product surface would tell the author
/// the second opt-in existed.
///
/// Bazel's shape is the target: a BUILD author never writes a cache directive.
/// Cacheability is the DEFAULT CONSEQUENCE of being an action with declared
/// inputs and outputs; `tags = ["no-cache"]` is the opt-OUT. That reading needs
/// three states where `CachePolicy` has two:
///
/// * [`Self::Omitted`] — the author said NOTHING. Under the fused gate this is
///   a request to do the right thing, so an ELIGIBLE stage caches.
/// * [`Self::Exempted`] — the author explicitly opted OUT. Never cached, and
///   the exemption is a visible decision rather than an absence.
/// * [`Self::Requested`] — the author asked for a regime by name.
///
/// # The three states are ALL durable
///
/// [`CachePolicy::Omitted`] exists, so [`Self::collapse`] and
/// [`Self::from_collapsed`] are a TOTAL, LOSSLESS bijection and the (a) row of
/// [`Self::content_cache_admission`] is reachable from a durable program. The
/// authored state is not computed-then-discarded: `kata_workflow`'s
/// `decode_cache_policy` builds it from the kwarg spelling and the checked
/// program CARRIES it.
///
/// A variant is read in more places than exhaustive matches: SILENT equality
/// sites no compiler flags (`compile.rs`'s two determinism-boundary clauses,
/// `WorkflowRunner::capsule_reuse_admission`) and one STRUCT-LITERAL
/// CONSTRUCTION —
/// `compile_agent_run_execution_program`'s synthetic stage in
/// `crates/program/src/execution_program/compile.rs`, the ONE production site
/// that WRITES a variant rather than reading one. It writes `Omitted`, because
/// that stage is unauthored by construction (`AgentRunRequest` carries no
/// `cache_policy`).
///
/// # The durable decode is TOTAL
///
/// A checked program carries a `schema_version` and
/// `kata_workflow::execution_program_store` refuses every non-current program
/// BY NAME (`LegacySchema` / `FutureSchema` / `MissingSchemaVersion` /
/// `UndecodableCurrentSchema`), never by silent coercion. Within one schema,
/// `"disabled"` decodes as `Exempted` — the conservative reading, which refuses
/// the cache and can never serve a wrong hit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum AuthoredCachePolicy {
    /// (a) The author said nothing.
    #[default]
    Omitted,
    /// (b) The author explicitly exempted this stage.
    Exempted,
    /// (c) The author asked for a regime by name.
    Requested(RequestedCacheRegime),
}

impl AuthoredCachePolicy {
    /// The Bazel-shaped spelling of the EXEMPTION: `cache_policy = "no_cache"`.
    ///
    /// `"disabled"` reads as configuration; `"no_cache"` reads as a decision,
    /// which is what an opt-out of a default-on behaviour has to read as. Both
    /// are accepted (see [`Self::from_spelling`]); only `"disabled"` is a WIRE
    /// spelling, because `serde` still emits [`CachePolicy::as_tag`] and this
    /// alias exists on the AUTHORING surface alone.
    pub const EXEMPTION_TAG: &'static str = "no_cache";

    /// Spellings that are RESERVED and deliberately UNAUTHORABLE.
    ///
    /// `"omitted"` IS the wire tag the (a) state takes — [`CachePolicy::Omitted`]
    /// serializes to exactly this string. It stays UNAUTHORABLE: omission is
    /// spelled by omitting the kwarg, and an author who types the word gets a
    /// message saying so rather than a second spelling of a state that already
    /// has one. This is why [`CachePolicy::variants`] excludes `Omitted` — the
    /// catalog domain is built from that list and must advertise only spellings
    /// [`Self::from_spelling`] accepts.
    pub const RESERVED_SPELLINGS: &'static [&'static str] = &["omitted"];

    /// Parse the `cache_policy=` kwarg spelling into the AUTHORED state.
    ///
    /// # REFUSED vs CLAIMED
    ///
    /// * ACCEPTS exactly: `""` (the kwarg omitted) → [`Self::Omitted`];
    ///   `"disabled"` and `"no_cache"` → [`Self::Exempted`]; `"model_reuse"` and
    ///   `"content_cache"` → [`Self::Requested`].
    /// * REFUSES everything else, including every entry of
    ///   [`Self::RESERVED_SPELLINGS`].
    /// * The DSL catalog's `cache_policy` domain
    ///   (`kata_program::dsl::catalog`) is built from
    ///   [`CachePolicy::variants`] and therefore CLAIMS three spellings, while
    ///   this function accepts four. The gap is `"no_cache"`: it is accepted and
    ///   not advertised. It is not exploitable — the extra spelling is a synonym
    ///   for a value already in the domain, so nothing decodable through it is
    ///   undecodable through `"disabled"` — but a completion surface built on the
    ///   catalog will not offer it. Closing it is a one-line addition to the
    ///   catalog domain.
    #[must_use]
    pub fn from_spelling(spelling: &str) -> Option<Self> {
        match spelling {
            "" => Some(Self::Omitted),
            "disabled" | Self::EXEMPTION_TAG => Some(Self::Exempted),
            "model_reuse" => Some(Self::Requested(RequestedCacheRegime::ModelReuse)),
            "content_cache" => Some(Self::Requested(RequestedCacheRegime::ContentCache)),
            _ => None,
        }
    }

    /// `true` when `spelling` is a RESERVED tag an author may not write.
    #[must_use]
    pub fn is_reserved_spelling(spelling: &str) -> bool {
        Self::RESERVED_SPELLINGS.contains(&spelling)
    }

    /// The authoring spellings, in the order an error message should list them.
    #[must_use]
    pub const fn authorable_spellings() -> &'static [&'static str] {
        &[
            "disabled",
            Self::EXEMPTION_TAG,
            "model_reuse",
            "content_cache",
        ]
    }

    /// Project the authored state onto the durable [`CachePolicy`] the checked
    /// program carries.
    ///
    /// TOTAL and LOSSLESS: each of the three authored
    /// states has its own durable value, and [`Self::from_collapsed`] is the
    /// exact inverse. The name "collapse" is kept because the projection still
    /// forgets which of `"disabled"` / `"no_cache"` an exemption was SPELLED
    /// with — an authoring synonym, never a state.
    #[must_use]
    pub const fn collapse(self) -> CachePolicy {
        match self {
            Self::Omitted => CachePolicy::Omitted,
            Self::Exempted => CachePolicy::Disabled,
            Self::Requested(regime) => regime.as_policy(),
        }
    }

    /// Recover the authored state from the durable [`CachePolicy`] — the exact
    /// inverse of [`Self::collapse`]. [`CachePolicy::Disabled`] reads back as
    /// [`Self::Exempted`] — the conservative reading, which REFUSES the cache
    /// (`CC1`) and can never serve a wrong hit.
    #[must_use]
    pub const fn from_collapsed(policy: CachePolicy) -> Self {
        match policy {
            CachePolicy::Omitted => Self::Omitted,
            CachePolicy::Disabled => Self::Exempted,
            CachePolicy::ModelReuse => Self::Requested(RequestedCacheRegime::ModelReuse),
            CachePolicy::ContentCache => Self::Requested(RequestedCacheRegime::ContentCache),
        }
    }

    /// **THE FUSED GATE**, pure half: may this authored state consult the
    /// content-addressed cache, given what is known about the DERIVED execution
    /// class?
    ///
    /// # The full table
    ///
    /// | authored | `Eligible` | `Unproven` | `Ineligible` |
    /// |---|---|---|---|
    /// | `Omitted` | ADMIT | refuse `CC4` | refuse `CC3` |
    /// | `Exempted` | refuse `CC1` | refuse `CC1` | refuse `CC1` |
    /// | `Requested(ContentCache)` | ADMIT | ADMIT | refuse `CC3` |
    /// | `Requested(ModelReuse)` | refuse `CC2` | refuse `CC2` | refuse `CC2` |
    ///
    /// # REFUSED vs CLAIMED
    ///
    /// This predicate REFUSES on the AUTHORED state and the DERIVED eligibility
    /// and on NOTHING else. It CLAIMS nothing about the toolchain, the git
    /// history, the workspace, or the sandbox — those are facts the capsule's
    /// identity either binds or cannot express
    /// (`kata_workflow::runner::dispatch::capsule_reuse` applies this admission
    /// inside its operational accept transaction), and a caller that used this
    /// alone would be admitting a stage whose executed bytes reach no component
    /// of the identity. The gap is not exploitable in-tree because the only
    /// caller is that runner gate, which is the reason it is `pub`: an
    /// out-of-tree caller must be able to read what it does not cover.
    ///
    /// # Why `Requested(ContentCache)` + `Unproven` still ADMITS
    ///
    /// It preserves the shipped verdict exactly, and it is not an unchecked
    /// admission: `kata_workflow`'s `compile_execution_program` REFUSES a program
    /// at LOAD when a stage authors `content_cache` on a class that is not
    /// content-cache eligible, so by the time an authored `content_cache` reaches
    /// dispatch its eligibility has already been PROVEN — by an earlier gate, on
    /// the same predicate. `Unproven` here means *this call site was not given
    /// the class*, not *the class was never checked*.
    ///
    /// The `Omitted` row cannot lean on that, which is why it fails closed on
    /// `Unproven`: there is no load-time gate refusing an ineligible stage that
    /// authored nothing, because authoring nothing is not an error. A default-on
    /// cache must be earned by a PROOF of eligibility, never by the absence of a
    /// disproof.
    #[must_use]
    pub const fn content_cache_admission(
        self,
        eligibility: ContentCacheEligibility,
    ) -> CacheAdmission {
        match self {
            Self::Exempted => CacheAdmission::Refuse(CacheAdmissionRefusal::CONTENT_EXEMPTED),
            Self::Requested(RequestedCacheRegime::ModelReuse) => {
                CacheAdmission::Refuse(CacheAdmissionRefusal::CONTENT_OTHER_REGIME)
            }
            Self::Omitted | Self::Requested(RequestedCacheRegime::ContentCache) => {
                match eligibility {
                    ContentCacheEligibility::Ineligible => {
                        CacheAdmission::Refuse(CacheAdmissionRefusal::CONTENT_CLASS_INELIGIBLE)
                    }
                    ContentCacheEligibility::Eligible => CacheAdmission::Admit,
                    ContentCacheEligibility::Unproven => match self {
                        Self::Omitted => CacheAdmission::Refuse(
                            CacheAdmissionRefusal::CONTENT_ELIGIBILITY_UNPROVEN,
                        ),
                        _ => CacheAdmission::Admit,
                    },
                }
            }
        }
    }
}

/// What the caller knows about a stage's DERIVED content-cache eligibility
/// ([`CheckedExecutionClass::is_content_cache_eligible`](crate::execution_class::CheckedExecutionClass::is_content_cache_eligible)).
///
/// Three-valued on purpose. A `bool` would force a call site that does not have
/// the checked stage to invent an answer, and the invented answer would be
/// `false` — which reads as *this class was checked and found ineligible* when
/// the truth is *nobody looked*. Those two facts call for different messages and
/// different fixes: one is "this stage is not pure", the other is "wire the class
/// through". [`Self::Unproven`] is the second one, said out loud.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ContentCacheEligibility {
    /// The derived seven-axis class IS content-cache eligible.
    Eligible,
    /// The derived seven-axis class is NOT content-cache eligible.
    Ineligible,
    /// The class was not available at this call site. Never a measurement.
    Unproven,
}

impl ContentCacheEligibility {
    /// Lift the derived predicate's `bool` into the two MEASURED states. There
    /// is deliberately no way to reach [`Self::Unproven`] from a `bool`.
    #[must_use]
    pub const fn from_derived(eligible: bool) -> Self {
        if eligible {
            Self::Eligible
        } else {
            Self::Ineligible
        }
    }

    /// Stable metric/log label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Ineligible => "ineligible",
            Self::Unproven => "unproven",
        }
    }
}

/// WHICH input a cache-admission refusal is about — the axis half of the
/// [`ClassRefusal`](crate::execution_class::ClassRefusal) shape this type
/// mirrors.
///
/// Two refusals with one label would send an operator to the wrong surface, so
/// the subject names WHICH decision — authored or derived — refused.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CacheRefusalSubject {
    /// What the AUTHOR wrote (or exempted).
    AuthoredPolicy,
    /// The DERIVED seven-axis execution class.
    ExecutionClass,
}

impl CacheRefusalSubject {
    /// Stable metric/log label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AuthoredPolicy => "authored_policy",
            Self::ExecutionClass => "execution_class",
        }
    }
}

/// WHY a stage was refused a cache regime — a stable code, the SUBJECT
/// responsible, and a sentence naming the property that refused.
///
/// # Why a reason and not a `bool`
///
/// A bare `bool` would make *"why did this stage re-run?"* unanswerable on every
/// surface: the four independent conditions that can refuse a stage would
/// collapse into one `false` before any caller saw them, and a refusal visible
/// only as a `warn!` inside the fence that fired cannot be attributed by a
/// caller at all. This is the cheapest half of Bazel's `--explain`.
///
/// Deliberately shaped like
/// [`ClassRefusal`](crate::execution_class::ClassRefusal) — `code` + subject +
/// `detail`, all `&'static str` — so the two refusal vocabularies read the same
/// on a surface that renders both, and so a refusal is `Copy` and free to carry.
///
/// Codes are stable diagnostic anchors: `CC1`..`CC4` are the AUTHORED/DERIVED
/// admission rows of [`AuthoredCachePolicy::content_cache_admission`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CacheAdmissionRefusal {
    /// Stable refusal code, e.g. `"CC3"`.
    pub code: &'static str,
    /// The input responsible.
    pub subject: CacheRefusalSubject,
    /// Human-readable statement of the refusing property.
    pub detail: &'static str,
    /// The metric `reason` label. For the three directive fences this is the
    /// EXACT string those fences ship — renaming one silently resets every
    /// dashboard built on it, so each is frozen.
    pub label: &'static str,
}

impl CacheAdmissionRefusal {
    const fn new(
        code: &'static str,
        subject: CacheRefusalSubject,
        label: &'static str,
        detail: &'static str,
    ) -> Self {
        Self {
            code,
            subject,
            detail,
            label,
        }
    }

    /// `CC1` — the author explicitly exempted this stage from reuse.
    pub const CONTENT_EXEMPTED: Self = Self::new(
        "CC1",
        CacheRefusalSubject::AuthoredPolicy,
        "authored_exemption",
        "the author exempted this stage from the content cache (cache_policy=\"no_cache\")",
    );
    /// `CC2` — the author asked for the OTHER reuse regime.
    pub const CONTENT_OTHER_REGIME: Self = Self::new(
        "CC2",
        CacheRefusalSubject::AuthoredPolicy,
        "other_regime_authored",
        "the stage authored cache_policy=\"model_reuse\", a different namespace",
    );
    /// `CC3` — the derived seven-axis class is not content-cache eligible.
    pub const CONTENT_CLASS_INELIGIBLE: Self = Self::new(
        "CC3",
        CacheRefusalSubject::ExecutionClass,
        "class_ineligible",
        "the derived execution class is not content-cache eligible (not deterministic + hermetic)",
    );
    /// `CC4` — nobody established eligibility at this call site.
    pub const CONTENT_ELIGIBILITY_UNPROVEN: Self = Self::new(
        "CC4",
        CacheRefusalSubject::ExecutionClass,
        "class_eligibility_unproven",
        "the stage authored no cache policy and this call site was not given the derived \
         execution class, so default-on cacheability has no proof to stand on",
    );
}

impl std::fmt::Display for CacheAdmissionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] cache refused: {} (subject={})",
            self.code,
            self.detail,
            self.subject.label()
        )
    }
}

impl std::error::Error for CacheAdmissionRefusal {}

/// The verdict of a cache-admission gate: consult the regime, or don't — and
/// when not, WHY.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CacheAdmission {
    /// Consult the regime for this stage.
    Admit,
    /// Do not consult it, for this reason.
    Refuse(CacheAdmissionRefusal),
}

impl CacheAdmission {
    /// The refusal, when refused.
    #[must_use]
    pub const fn refusal(self) -> Option<CacheAdmissionRefusal> {
        match self {
            Self::Admit => None,
            Self::Refuse(refusal) => Some(refusal),
        }
    }
}

#[cfg(test)]
mod fused_cache_admission_tests {
    use super::{
        AuthoredCachePolicy, CacheAdmission, CacheAdmissionRefusal, CachePolicy,
        CacheRefusalSubject, ContentCacheEligibility, RequestedCacheRegime,
    };

    const ELIGIBILITIES: [ContentCacheEligibility; 3] = [
        ContentCacheEligibility::Eligible,
        ContentCacheEligibility::Unproven,
        ContentCacheEligibility::Ineligible,
    ];

    const AUTHORED: [AuthoredCachePolicy; 4] = [
        AuthoredCachePolicy::Omitted,
        AuthoredCachePolicy::Exempted,
        AuthoredCachePolicy::Requested(RequestedCacheRegime::ContentCache),
        AuthoredCachePolicy::Requested(RequestedCacheRegime::ModelReuse),
    ];

    /// The whole 4x3 table, cell by cell. Written as data rather than as four
    /// separate assertions because the defect it guards against is a MISSING
    /// cell (`Omitted` + eligible), and a table is the only shape in which a
    /// missing cell is visible.
    #[test]
    fn the_fused_table_is_pinned_cell_by_cell() {
        use AuthoredCachePolicy as A;
        use ContentCacheEligibility as E;
        let expected: [(A, E, Option<&'static str>); 12] = [
            // (a) the author said nothing — eligibility DECIDES.
            (A::Omitted, E::Eligible, None),
            (A::Omitted, E::Unproven, Some("CC4")),
            (A::Omitted, E::Ineligible, Some("CC3")),
            // (b) the exemption is categorical and never consults the class.
            (A::Exempted, E::Eligible, Some("CC1")),
            (A::Exempted, E::Unproven, Some("CC1")),
            (A::Exempted, E::Ineligible, Some("CC1")),
            // (c) authored content_cache — admitted, and still refused on a
            // MEASURED ineligible class (defence in depth behind the load gate).
            (
                A::Requested(RequestedCacheRegime::ContentCache),
                E::Eligible,
                None,
            ),
            (
                A::Requested(RequestedCacheRegime::ContentCache),
                E::Unproven,
                None,
            ),
            (
                A::Requested(RequestedCacheRegime::ContentCache),
                E::Ineligible,
                Some("CC3"),
            ),
            // (c) the other regime never touches this namespace.
            (
                A::Requested(RequestedCacheRegime::ModelReuse),
                E::Eligible,
                Some("CC2"),
            ),
            (
                A::Requested(RequestedCacheRegime::ModelReuse),
                E::Unproven,
                Some("CC2"),
            ),
            (
                A::Requested(RequestedCacheRegime::ModelReuse),
                E::Ineligible,
                Some("CC2"),
            ),
        ];
        assert_eq!(
            expected.len(),
            AUTHORED.len() * ELIGIBILITIES.len(),
            "the table must cover every (authored, eligibility) pair — an uncovered pair is \
             exactly the hole this table exists to close"
        );
        for (authored, eligibility, code) in expected {
            let admission = authored.content_cache_admission(eligibility);
            assert_eq!(
                admission.refusal().map(|r| r.code),
                code,
                "authored={authored:?} eligibility={} must be {}",
                eligibility.label(),
                code.map_or("ADMITTED", |c| c)
            );
        }
    }

    /// THE headline row: a stage that authored NOTHING and derives ELIGIBLE is
    /// cached. This cell is the whole point of the fusion.
    ///
    /// **Would red if:** the `Omitted` arm went back to refusing, or the fused
    /// gate went back to consulting only the authored policy.
    #[test]
    fn an_eligible_stage_that_authored_nothing_is_cached() {
        assert_eq!(
            AuthoredCachePolicy::Omitted.content_cache_admission(ContentCacheEligibility::Eligible),
            CacheAdmission::Admit
        );
    }

    /// And the counterweight: an eligible stage whose author OPTED OUT is never
    /// cached, and the exemption is visible as a named decision rather than as
    /// an absence.
    #[test]
    fn an_exemption_beats_eligibility_and_says_so() {
        let admission = AuthoredCachePolicy::Exempted
            .content_cache_admission(ContentCacheEligibility::Eligible);
        let refusal = admission.refusal().expect("an exemption refuses");
        assert_eq!(refusal.code, "CC1");
        assert_eq!(refusal.subject, CacheRefusalSubject::AuthoredPolicy);
        assert!(
            refusal.detail.contains("exempted"),
            "the refusal must name the exemption, not merely deny the cache"
        );
    }

    /// Fail-closed: default-on cacheability needs a PROOF, not the absence of a
    /// disproof — and it says which of the two it is missing.
    #[test]
    fn unproven_eligibility_is_not_ineligibility() {
        let unproven = AuthoredCachePolicy::Omitted
            .content_cache_admission(ContentCacheEligibility::Unproven)
            .refusal()
            .expect("unproven fails closed");
        let ineligible = AuthoredCachePolicy::Omitted
            .content_cache_admission(ContentCacheEligibility::Ineligible)
            .refusal()
            .expect("ineligible refuses");
        assert_ne!(
            unproven.code, ineligible.code,
            "\"nobody looked\" and \"this class is not pure\" call for different fixes; one code \
             for both would send an operator to make a stage hermetic that already is"
        );
        assert_ne!(unproven.label, ineligible.label);
    }

    /// Every refusal code and metric label in the vocabulary is distinct — the
    /// property that makes a `reason=` label worth grepping.
    #[test]
    fn every_refusal_code_and_label_is_unique() {
        let all = [
            CacheAdmissionRefusal::CONTENT_EXEMPTED,
            CacheAdmissionRefusal::CONTENT_OTHER_REGIME,
            CacheAdmissionRefusal::CONTENT_CLASS_INELIGIBLE,
            CacheAdmissionRefusal::CONTENT_ELIGIBILITY_UNPROVEN,
        ];
        let mut codes: Vec<&str> = all.iter().map(|r| r.code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len(), "refusal codes must be unique");
        let mut labels: Vec<&str> = all.iter().map(|r| r.label).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(before, labels.len(), "metric reason labels must be unique");
        for refusal in all {
            assert!(!refusal.detail.is_empty());
            assert!(
                refusal.to_string().contains(refusal.code),
                "Display must lead with the stable code, like ClassRefusal does"
            );
        }
    }

    /// The authoring surface: what is accepted, what is refused, and the one
    /// spelling that is RESERVED so an author cannot claim the wire tag.
    #[test]
    fn the_authored_spelling_domain_is_exactly_what_it_claims() {
        assert_eq!(
            AuthoredCachePolicy::from_spelling(""),
            Some(AuthoredCachePolicy::Omitted)
        );
        assert_eq!(
            AuthoredCachePolicy::from_spelling("disabled"),
            Some(AuthoredCachePolicy::Exempted)
        );
        assert_eq!(
            AuthoredCachePolicy::from_spelling("no_cache"),
            Some(AuthoredCachePolicy::Exempted),
            "the Bazel-shaped exemption reads as a decision; `disabled` reads as configuration"
        );
        assert_eq!(
            AuthoredCachePolicy::from_spelling("content_cache"),
            Some(AuthoredCachePolicy::Requested(
                RequestedCacheRegime::ContentCache
            ))
        );
        assert_eq!(
            AuthoredCachePolicy::from_spelling("model_reuse"),
            Some(AuthoredCachePolicy::Requested(
                RequestedCacheRegime::ModelReuse
            ))
        );
        assert_eq!(
            AuthoredCachePolicy::from_spelling("omitted"),
            None,
            "omission is spelled by OMITTING the kwarg; reserving the word keeps an author from \
             claiming the tag the (a) state will take on the wire"
        );
        assert!(AuthoredCachePolicy::is_reserved_spelling("omitted"));
        assert!(!AuthoredCachePolicy::is_reserved_spelling("no_cache"));
        assert_eq!(AuthoredCachePolicy::from_spelling("replay_safe"), None);
        assert_eq!(AuthoredCachePolicy::from_spelling("stage"), None);
        // Every authorable spelling this type advertises must actually parse.
        for spelling in AuthoredCachePolicy::authorable_spellings() {
            assert!(
                AuthoredCachePolicy::from_spelling(spelling).is_some(),
                "advertised spelling {spelling:?} must parse — a message that names a spelling \
                 the decoder refuses is exactly a CLAIMED-vs-REFUSED gap"
            );
        }
    }

    /// The (a) and (b) states are DISTINCT durable values, and `from_collapsed`
    /// tells them apart.
    ///
    /// **Would red if:** either direction of the pairing were dropped — i.e. if
    /// an unauthored stage ever again became indistinguishable from an
    /// exempted one, which is the state in which `CC1` refuses a cache to an
    /// author who never opted out.
    #[test]
    fn omitted_and_exempted_are_now_distinct_durable_values() {
        assert_eq!(
            AuthoredCachePolicy::Omitted.collapse(),
            CachePolicy::Omitted
        );
        assert_eq!(
            AuthoredCachePolicy::Exempted.collapse(),
            CachePolicy::Disabled
        );
        assert_ne!(
            AuthoredCachePolicy::Omitted.collapse(),
            AuthoredCachePolicy::Exempted.collapse(),
            "the (a)/(b) distinction is DURABLE: an author who said nothing and an author \
             who said `no_cache` do not land on one value"
        );
        assert_eq!(
            AuthoredCachePolicy::from_collapsed(CachePolicy::Omitted),
            AuthoredCachePolicy::Omitted,
        );
        assert_eq!(
            AuthoredCachePolicy::from_collapsed(CachePolicy::Disabled),
            AuthoredCachePolicy::Exempted,
            "`\"disabled\"` reads back as the SOUND one — reading it as `Omitted` would hand \
             cache admission to an author who may really have opted out"
        );
        // The (c) states round-trip as they always did.
        for regime in [
            RequestedCacheRegime::ContentCache,
            RequestedCacheRegime::ModelReuse,
        ] {
            let authored = AuthoredCachePolicy::Requested(regime);
            assert_eq!(
                AuthoredCachePolicy::from_collapsed(authored.collapse()),
                authored
            );
        }
    }

    /// `collapse` and `from_collapsed` are a TOTAL BIJECTION over all four
    /// durable values — in BOTH directions, so neither can drop a state.
    ///
    /// `CachePolicy::variants()` is NOT the iteration source: it deliberately
    /// excludes [`CachePolicy::Omitted`] (it feeds the DSL catalog domain, which
    /// may advertise only authorable spellings), so iterating it would leave the
    /// `Omitted` untested. The list is written out, and
    /// `variants_are_a_strict_subset_of_the_wire_spellings` is what keeps the
    /// two lists' relationship honest.
    #[test]
    fn collapse_and_from_collapsed_are_a_total_bijection() {
        for policy in [
            CachePolicy::Omitted,
            CachePolicy::Disabled,
            CachePolicy::ModelReuse,
            CachePolicy::ContentCache,
        ] {
            assert_eq!(
                AuthoredCachePolicy::from_collapsed(policy).collapse(),
                policy,
                "durable -> authored -> durable must be the identity on {policy:?}"
            );
        }
        for authored in AUTHORED {
            assert_eq!(
                AuthoredCachePolicy::from_collapsed(authored.collapse()),
                authored,
                "authored -> durable -> authored must be the identity on {authored:?}"
            );
        }
        assert_eq!(
            AuthoredCachePolicy::default().collapse(),
            CachePolicy::default(),
            "the two types' defaults must be the SAME state: `CachePolicy::default()`'s one \
             production caller is `StageFlatFields::join_default`, which exists to make a \
             synthetic join lower byte-identically to a minimal AUTHORED stage — and a minimal \
             authored stage decodes `\"\"` to `AuthoredCachePolicy::default()`"
        );
    }

    /// [`CachePolicy::variants`] is a STRICT SUBSET of the wire spellings, and
    /// the doc on it says so.
    ///
    /// The retracted claim was an EQUALITY — *"the source of truth for … the
    /// WIRE spelling set (`serde` emits exactly `as_tag`)"*. That direction is
    /// what broke: `Omitted` is a wire spelling and is deliberately not a
    /// variant, because the DSL catalog's `cache_policy` domain is built from
    /// this list and `"omitted"` is
    /// [RESERVED](AuthoredCachePolicy::RESERVED_SPELLINGS) — advertising it
    /// would publish a spelling the evaluator REFUSES.
    ///
    /// **Would red if:** `Omitted` were added to `variants()` (which would ship
    /// a catalog that lies), or if a variant were ever added WITHOUT a serde
    /// spelling (which would make the surviving inclusion false too).
    #[test]
    fn variants_are_a_strict_subset_of_the_wire_spellings() {
        // Every advertised variant IS a wire spelling: serde emits exactly
        // `as_tag`, and the tag decodes back to the same variant.
        for policy in CachePolicy::variants() {
            assert_eq!(
                serde_json::to_value(policy).expect("serialize"),
                serde_json::json!(policy.as_tag()),
                "{policy:?} must serialize to its own tag"
            );
        }
        // And the converse FAILS, by exactly one spelling.
        assert_eq!(
            serde_json::to_value(CachePolicy::Omitted).expect("serialize"),
            serde_json::json!("omitted"),
            "`Omitted` IS a wire spelling"
        );
        assert!(
            !CachePolicy::variants().contains(&CachePolicy::Omitted),
            "…and it must NOT be advertised: the catalog domain is built from this list, and \
             `AuthoredCachePolicy::from_spelling` REFUSES \"omitted\" as reserved"
        );
        assert!(
            AuthoredCachePolicy::is_reserved_spelling(CachePolicy::Omitted.as_tag()),
            "the wire tag and the reserved spelling must be the SAME string — two spellings of \
             one state is how an author claims the omission tag by typing it"
        );
    }
}
