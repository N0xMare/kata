//! Identities used by one operator-owned main and its subordinate execution
//! workers. Public-key identity authenticates a concrete main; it does not
//! imply peer membership, tenancy, or delegated workflow authority.

use core::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::agent::BackendType;
use crate::primitives::FixedBytes;

/// Worker identifier scoped to the configured main.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerId(pub SmolStr);

/// Lifetime of one authoritative worker idempotency database. Reconnecting
/// does not change it; replacing that database creates a distinct lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerMembraneId(pub ulid::Ulid);

/// Main-scoped enrollment of a membrane, independent of connection labels and
/// of an individual attempt's lease epoch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEffectDomain {
    /// Persisted identity of the source main's data directory.
    pub source_main: String,
    /// Lifetime of the authoritative worker idempotency database.
    pub membrane: WorkerMembraneId,
    /// Stable main-scoped enrollment, retained across reconnects.
    pub enrollment: ulid::Ulid,
}

/// The one [`WorkerId`] value NO WORKER MAY HAVE.
///
/// It is the spelling of "no worker"; no worker may be named it. Completion
/// represents an unassigned worker directly, as absence.
///
/// # Invariant
///
/// THE NAME IS RESERVED, SO THE STRING HAS EXACTLY ONE MEANING: "no worker".
/// Downstream planes route on this value's equality — a row carrying it is
/// classified as unattributed rather than as work some worker performed — and that
/// LEXICAL question is only answerable if the name cannot also belong to a real
/// worker. Reserving it removes the ambiguity at the source instead of asking every
/// reader to infer which of the two things the string meant. Without the
/// reservation a genuinely worker-attributed row would be indistinguishable from
/// an unattributed one.
///
/// Enforced at the durable writer that would store it: `kata_core`'s single
/// `attempts.worker_id` normalization chokepoint refuses it, so no writer —
/// present or future — can place an attempt on it. That chokepoint screens the
/// STORED column the main-side advance writes back, not only CALLER-supplied
/// values: a value with two sources needs its gate at the point the value is
/// COMPUTED, not at one of its inputs.
pub const UNATTRIBUTED_WORKER: &str = "unknown";

/// Whether `name` is the RESERVED [`UNATTRIBUTED_WORKER`] name.
///
/// Compared after trimming, for the same reason the placement chokepoint trims
/// before it decides: `" unknown "` and `"unknown"` are the same declaration, and a
/// reservation a caller can evade with a space is not a reservation. ONE predicate
/// rather than scattered `==` comparisons, so every reader of the column comes to
/// the same answer about the same string.
#[must_use]
pub fn worker_name_is_reserved(name: &str) -> bool {
    name.trim() == UNATTRIBUTED_WORKER
}

/// Resource hint reported by a worker. This is scheduling input only; it never
/// certifies containment, provider capability, or workflow authority.
///
/// Decoding refuses a key it does not declare — beside `kind`/`data`, and inside a
/// struct variant's `data` — wherever a value is read: a worker file's
/// `capabilities`, the handshake. kata's own writer emits only
/// declared keys, so the refusal admits every value kata wrote.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WorkerResource {
    /// Worker can execute stages backed by the specified agent backend.
    AgentBackend(BackendType),
    /// Worker advertises at least `min_gb` GiB of local disk for
    /// temporary storage.
    Disk {
        /// Minimum free disk in gibibytes.
        min_gb: u32,
    },
    /// Worker has GPU with at least `min_vram_gb` GiB of VRAM.
    Gpu {
        /// Minimum VRAM in gibibytes.
        min_vram_gb: u32,
    },
    /// Worker has outbound network access.
    Network,
    /// Worker can execute sandboxed shell commands.
    Shell,
    /// Custom resource label — operator-defined.
    Custom(SmolStr),
}

/// Parse error for a capability spec passed on the command line.
///
/// Both `kata-worker provision --capability <spec>` and
/// `kata-worker provision --capability <spec>` route their arg parser
/// through [`WorkerResource::from_str`]; clap renders the `Display`
/// of this error to the user, so the messages have to be operator-
/// readable on their own.
//
// Every message ends with the same list of accepted forms so the
// operator doesn't have to grep the docs:
//   accepted forms: shell | network | agent_backend=<label> |
//   disk=<u32> | gpu=<u32> | custom=<string>
// Keep the `UnknownBackend` backend list in sync with `BackendType`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkerResourceParseError {
    /// The kind prefix (the part before `=`, or the whole spec for
    /// kindless variants like `shell`) is not one of the accepted
    /// kinds. Carries the unknown kind so the message is concrete.
    #[error(
        "unknown capability kind {0:?}; accepted forms: shell | network | \
         agent_backend=<label> | disk=<u32> | gpu=<u32> | custom=<string>"
    )]
    UnknownKind(String),
    /// `agent_backend=<label>` was given but `<label>` doesn't match
    /// any [`BackendType`] variant's [`BackendType::label`].
    #[error("unknown agent backend {0:?}; valid backends: harness")]
    UnknownBackend(String),
    /// A kind that requires a `=<value>` payload was given without
    /// one (e.g. `agent_backend` instead of `agent_backend=harness`).
    #[error(
        "capability kind {0:?} requires a `=<value>` payload; accepted forms: \
         shell | network | agent_backend=<label> | disk=<u32> | gpu=<u32> | \
         custom=<string>"
    )]
    MissingPayload(&'static str),
    /// A kind that does NOT take a `=<value>` payload was given one
    /// (e.g. `shell=foo` instead of `shell`).
    #[error(
        "capability kind {0:?} does not take a `=<value>` payload; accepted \
         forms: shell | network | agent_backend=<label> | disk=<u32> | \
         gpu=<u32> | custom=<string>"
    )]
    UnexpectedPayload(&'static str),
    /// `disk=<u32>` or `gpu=<u32>` had a non-integer payload.
    #[error(
        "capability {kind:?} expects a u32, got {value:?}; accepted forms: \
         shell | network | agent_backend=<label> | disk=<u32> | gpu=<u32> | \
         custom=<string>"
    )]
    InvalidNumber {
        /// Name of the kind whose number failed to parse.
        kind: &'static str,
        /// The raw payload that didn't parse as a `u32`.
        value: String,
    },
}

impl FromStr for WorkerResource {
    type Err = WorkerResourceParseError;

    /// Parse a capability spec from the form used on the command line by
    /// `kata-worker provision --capability <spec>` /
    /// `kata-worker provision --capability <spec>`.
    ///
    /// Accepted forms (the kind is matched case-insensitively; the
    /// payload after `=` is taken verbatim except where it is itself
    /// validated, e.g. against [`BackendType::label`]):
    ///
    /// - `shell` → [`WorkerResource::Shell`]
    /// - `network` → [`WorkerResource::Network`]
    /// - `agent_backend=<label>` → [`WorkerResource::AgentBackend`]
    ///   where `<label>` matches a [`BackendType`] variant's label.
    /// - `disk=<u32>` → [`WorkerResource::Disk`]
    /// - `gpu=<u32>` → [`WorkerResource::Gpu`]
    /// - `custom=<string>` → [`WorkerResource::Custom`]
    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let (kind_raw, payload) = match spec.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (spec, None),
        };
        let kind = kind_raw.to_ascii_lowercase();
        match kind.as_str() {
            "shell" => match payload {
                None => Ok(Self::Shell),
                Some(_) => Err(WorkerResourceParseError::UnexpectedPayload("shell")),
            },
            "network" => match payload {
                None => Ok(Self::Network),
                Some(_) => Err(WorkerResourceParseError::UnexpectedPayload("network")),
            },
            "agent_backend" => {
                let label =
                    payload.ok_or(WorkerResourceParseError::MissingPayload("agent_backend"))?;
                let backend = backend_from_label(label)
                    .ok_or_else(|| WorkerResourceParseError::UnknownBackend(label.to_owned()))?;
                Ok(Self::AgentBackend(backend))
            }
            "disk" => {
                let v = payload.ok_or(WorkerResourceParseError::MissingPayload("disk"))?;
                let min_gb =
                    v.parse::<u32>()
                        .map_err(|_| WorkerResourceParseError::InvalidNumber {
                            kind: "disk",
                            value: v.to_owned(),
                        })?;
                Ok(Self::Disk { min_gb })
            }
            "gpu" => {
                let v = payload.ok_or(WorkerResourceParseError::MissingPayload("gpu"))?;
                let min_vram_gb =
                    v.parse::<u32>()
                        .map_err(|_| WorkerResourceParseError::InvalidNumber {
                            kind: "gpu",
                            value: v.to_owned(),
                        })?;
                Ok(Self::Gpu { min_vram_gb })
            }
            "custom" => {
                let v = payload.ok_or(WorkerResourceParseError::MissingPayload("custom"))?;
                Ok(Self::Custom(SmolStr::new(v)))
            }
            _ => Err(WorkerResourceParseError::UnknownKind(kind_raw.to_owned())),
        }
    }
}

/// Look up a [`BackendType`] by its [`BackendType::label`].
///
/// Centralised here so [`WorkerResource::from_str`] can validate the
/// `agent_backend=<label>` payload without re-encoding the variant
/// list. Returns `None` for unknown labels.
fn backend_from_label(label: &str) -> Option<BackendType> {
    // Pinned to every BackendType variant. If a new backend lands in
    // crate::agent::BackendType, add it here AND extend
    // WorkerResourceParseError::Display's "valid backends" list.
    [BackendType::Harness]
        .into_iter()
        .find(|variant| variant.label() == label)
}

/// Append `field` to `buf` framed by its `u64` big-endian byte length.
/// Length-prefixing is what makes adjacent variable-length fields
/// non-spliceable: `("ab", "")` and `("a", "b")` encode to distinct
/// byte strings.
fn push_len_prefixed(buf: &mut Vec<u8>, field: &[u8]) {
    let len = u64::try_from(field.len()).unwrap_or(u64::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(field);
}

/// Authorization scope carried by a signed [`ApiToken`]. A **monotone ladder**:
/// `Admin ⊇ Approve ⊇ Operate`. A token minted at a given scope satisfies any
/// route whose required scope sits at or below it on the ladder ([`Self::permits`]).
///
/// The three tiers map to the API's route groups:
///
/// * [`ApiScope::Operate`] — reads plus workload-driving mutations an *agent*
///   may perform: submit/run, steer/external-input, watch/events. This is the
///   scope the `kata mcp` agent surface holds; it can drive work but can never
///   resolve a human gate.
/// * [`ApiScope::Approve`] — the human-gate mutations (approve / reject / cancel
///   / answer-human-request / promote / park). The whole point of scoped
///   tokens: the workload runs at `Operate`, so it cannot approve its own gates.
/// * [`ApiScope::Admin`] — the fail-closed default an *unclassified* protected
///   route is treated as, so a newly-added route is never silently reachable at
///   `Operate`. No route is classified `Admin` by name today.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiScope {
    /// Reads + workload-driving mutations (submit/run, steer, watch). The agent
    /// / MCP surface's scope.
    Operate,
    /// Human-gate mutations (approve/reject/cancel/answer/promote/park).
    Approve,
    /// The fail-closed default for a route nothing classifies.
    Admin,
}

impl ApiScope {
    /// Rank on the ladder — a strictly higher rank permits strictly more.
    /// `Operate < Approve < Admin`.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Operate => 0,
            Self::Approve => 1,
            Self::Admin => 2,
        }
    }

    /// Does a token minted at `self` satisfy a route that requires `required`?
    /// True iff `self` is at or above `required` on the ladder.
    #[must_use]
    pub const fn permits(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }

    /// 1-byte discriminant bound into [`ApiToken::signing_payload`]. Distinct,
    /// stable values so the signed scope is unambiguous. Bumping these is a
    /// wire break paired with the domain-version bump.
    #[must_use]
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::Operate => 0x01,
            Self::Approve => 0x02,
            Self::Admin => 0x03,
        }
    }
}

/// Domain separator binding a byte string to the **API-token** signing context,
/// so a signature minted over an API token can never validate as a signature
/// over any other kata message (cross-protocol / signature-confusion defense).
/// Bumping this string invalidates every previously-minted API token and MUST be
/// paired with a `vN` version bump.
pub const API_TOKEN_SIGNING_DOMAIN: &str = "kata.v1.api.token";

/// A scoped, ed25519-signed API bearer token. Minted by the main's
/// signing key and verified by the API against the main's verifying key;
/// the [`ApiToken::scope`] it carries is authenticated by the signature, so a
/// holder cannot escalate its own scope — unlike a single flat shared bearer
/// secret, under which any holder, including the workload, could authorize every
/// route.
///
/// Sign / verify / wire-encode live in `kata_crypto::api_token`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiToken {
    /// The authority this token grants. See [`ApiScope`].
    pub scope: ApiScope,
    /// Human-readable label naming who/what the token was issued for
    /// (`"operator-cli"`, `"mcp-agent"`). Bound into the signature so it cannot
    /// be relabeled after minting. It is recorded as the approver of an approval
    /// the token authenticates, and it decides authorization in one place: a stop
    /// discharge under this token is admitted only when its `operator` equals this
    /// label, both trimmed, and a blank label admits none.
    pub issued_for: SmolStr,
    /// Issuance timestamp. Bound into the signature; the verifier rejects a
    /// token presented before this instant.
    pub issued_at: DateTime<Utc>,
    /// Optional expiry. `None` ⇒ the token never expires (bound as an explicit
    /// "absent" marker so it cannot be spliced onto a token that *did* set one).
    /// When present, the verifier rejects the token after this instant.
    pub expires_at: Option<DateTime<Utc>>,
    /// ed25519 signature over [`ApiToken::signing_payload`].
    pub signature: FixedBytes<64>,
}

impl ApiToken {
    /// Canonical, unambiguous byte encoding of every field **except**
    /// [`ApiToken::signature`] — the exact message the main's ed25519 key
    /// signs at mint time and the API recomputes on verify (see
    /// `kata_crypto::api_token`).
    ///
    /// The encoding is domain-separated and length-prefixed so it is
    /// **injective** — the scope
    /// tag is a fixed discriminant byte, `issued_for` is length-prefixed, and the
    /// optional expiry carries a 1-byte present/absent marker so a token with no
    /// expiry can never collide with one whose expiry happens to encode to the
    /// same trailing bytes. Timestamps are bound at millisecond resolution so a
    /// token that round-tripped through JSON reproduces the identical payload.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        push_len_prefixed(&mut buf, API_TOKEN_SIGNING_DOMAIN.as_bytes());
        buf.push(self.scope.wire_tag());
        push_len_prefixed(&mut buf, self.issued_for.as_bytes());
        buf.extend_from_slice(&self.issued_at.timestamp_millis().to_be_bytes());
        match self.expires_at {
            Some(expires_at) => {
                buf.push(0x01);
                buf.extend_from_slice(&expires_at.timestamp_millis().to_be_bytes());
            }
            None => buf.push(0x00),
        }
        buf
    }
}

#[cfg(test)]
mod api_token_signing_tests {
    use super::*;
    use chrono::TimeZone as _;

    fn sample_token() -> ApiToken {
        ApiToken {
            scope: ApiScope::Operate,
            issued_for: SmolStr::new("mcp-agent"),
            issued_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            expires_at: Some(Utc.timestamp_opt(1_700_003_600, 0).unwrap()),
            signature: FixedBytes::zero(),
        }
    }

    #[test]
    fn scope_ladder_is_monotone() {
        // Admin ⊇ Approve ⊇ Operate. Each tier permits itself and everything
        // below it, and nothing above it.
        assert!(ApiScope::Admin.permits(ApiScope::Admin));
        assert!(ApiScope::Admin.permits(ApiScope::Approve));
        assert!(ApiScope::Admin.permits(ApiScope::Operate));
        assert!(ApiScope::Approve.permits(ApiScope::Operate));
        assert!(ApiScope::Approve.permits(ApiScope::Approve));
        assert!(!ApiScope::Approve.permits(ApiScope::Admin));
        assert!(!ApiScope::Operate.permits(ApiScope::Approve));
        assert!(!ApiScope::Operate.permits(ApiScope::Admin));
        assert!(ApiScope::Operate.permits(ApiScope::Operate));
    }

    #[test]
    fn scope_wire_tags_are_distinct() {
        // All three discriminants differ so the signed scope is unambiguous.
        let operate = ApiScope::Operate.wire_tag();
        let approve = ApiScope::Approve.wire_tag();
        let admin = ApiScope::Admin.wire_tag();
        assert_ne!(operate, approve);
        assert_ne!(operate, admin);
        assert_ne!(approve, admin);
    }

    #[test]
    fn signing_payload_excludes_signature_and_is_deterministic() {
        let mut a = sample_token();
        let before = a.signing_payload();
        a.signature = FixedBytes::new([0xAB; 64]);
        let after = a.signing_payload();
        assert_eq!(before, after, "signature must be excluded from the payload");
        assert_eq!(sample_token().signing_payload(), before);
    }

    #[test]
    fn signing_payload_is_domain_separated() {
        let payload = sample_token().signing_payload();
        let domain = API_TOKEN_SIGNING_DOMAIN.as_bytes();
        let len = u64::try_from(domain.len()).unwrap();
        assert_eq!(&payload[..8], &len.to_be_bytes());
        assert_eq!(&payload[8..8 + domain.len()], domain);
    }

    #[test]
    fn tampering_scope_changes_the_payload() {
        // The classic escalation attack: flip Operate → Approve on an otherwise
        // identical token. The scope is bound, so the payload — and thus the
        // signature — changes.
        let base = sample_token().signing_payload();
        let mut escalated = sample_token();
        escalated.scope = ApiScope::Approve;
        assert_ne!(escalated.signing_payload(), base, "scope is bound");
        let mut admin = sample_token();
        admin.scope = ApiScope::Admin;
        assert_ne!(admin.signing_payload(), base, "scope is bound");
    }

    #[test]
    fn tampering_any_other_bound_field_changes_the_payload() {
        let base = sample_token().signing_payload();

        let mut label = sample_token();
        label.issued_for = SmolStr::new("operator-cli");
        assert_ne!(label.signing_payload(), base, "issued_for is bound");

        let mut issued = sample_token();
        issued.issued_at = Utc.timestamp_opt(1_700_000_001, 0).unwrap();
        assert_ne!(issued.signing_payload(), base, "issued_at is bound");

        let mut expiry = sample_token();
        expiry.expires_at = Some(Utc.timestamp_opt(1_700_003_601, 0).unwrap());
        assert_ne!(expiry.signing_payload(), base, "expires_at is bound");
    }

    #[test]
    fn absent_expiry_is_bound_and_distinct_from_any_present_expiry() {
        // A token with no expiry must not encode-collide with one that sets an
        // expiry — the 1-byte present/absent marker guarantees it.
        let mut no_expiry = sample_token();
        no_expiry.expires_at = None;
        let with_expiry = sample_token();
        assert_ne!(no_expiry.signing_payload(), with_expiry.signing_payload());
    }
}
