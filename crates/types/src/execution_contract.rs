//! Portable, non-issuing execution contracts for the replacement runtime.
//!
//! These types describe checked semantics and immutable worker input. They do
//! not schedule work, authorize effects, or accept outcomes; the existing
//! operational authority remains the only component allowed to do that.
//!
//! # Identity discipline
//!
//! Every identity here is computed field-wise through [`hash_field`] under a
//! domain tag from [`domain`], never over a serialized encoding: a serde
//! representation is a presentation detail (field order, renames, number
//! formatting) and would silently rotate every id the moment it changed. Enum
//! discriminants enter the hash as `&'static str` tags, never as `as u8`, so
//! reordering a variant cannot alias one operation onto another's id.
//!
//! [`OperationPath`] carries no attempt ordinal and no worker placement
//! coordinate: retry and placement facts are runtime, not semantics, and must
//! never be able to rotate a logical identity. That the CHECKED LOWERER is the
//! only thing that mints one is a convention this module cannot enforce — the
//! constructor is public, and [`OperationPath::child`] is how a bounded expansion
//! addresses what it expands — so it is stated where it is kept
//! (`kata_program::execution_program::operation_lowering`), not claimed here.

use serde::{Deserialize, Deserializer, Serialize};
use smol_str::SmolStr;

use std::collections::{BTreeMap, BTreeSet};

use crate::agent::AdapterKind;
use crate::cache::{ActionManifest, hash_field};
use crate::effect::EffectKind;
use crate::execution_platform::ExecutorTerm;
use crate::primitives::{ContentHash, FixedBytes, ObjectId};
use crate::review_loop::ReviewLoop;
use crate::workflow::{BranchRoute, ExecutionId, MemorySnapshotSpec, StageId, WorkspaceEffectOp};
use crate::{KataError, KataResult};

/// Shape version of every contract in this module. It is part of every domain
/// tag, so a bump rotates every identity here by construction.
///
/// * v1 — the initial operation/occurrence/action/artifact/environment/platform/
///   capsule shapes.
/// * v2 — [`ActionExecutor::Effect`] gained its typed
///   [`WorkspaceEffectOp`]: `effect_kind` alone collapsed park / promote /
///   commit / forge-export onto one operation identity, which is a wider claim
///   than the mechanism (two effect stages with identical policies carry the
///   same `contract_hash`, so the executor is the only place the mutation is
///   named).
/// * v3 — [`RuntimeOperation::ExpandBounded`] gained its `policy_hash`
///   ([`loop_policy_selector`]): `template` and `maximum` alone collapsed every
///   loop POLICY onto one expansion identity, so two loops over the same body
///   and the same iteration ceiling that differ in their exhaustion action,
///   their walk-away bounds, their gate vocabulary, or their context-rollover
///   window wore the same id.
/// * v4 — [`CapsuleBudgets`] gained [`CapsuleBudgets::result_bytes`] and
///   [`CapsuleBudgets::result_entries`]: a capsule bounded what its process could
///   WRITE TO A STREAM (`output_bytes`) and said nothing about the RESULT TREE the
///   worker publishes out of `/out`, so the bound on the one artifact main adopts
///   lived in whatever main-side reader happened to check it rather than in the
///   promise the capsule id folds.
/// * v5 — [`Capsule`] gained [`Capsule::argv`]. A capsule named the action it
///   discharges by IDENTITY ([`PreparedActionId`], whose manifest `command` is the
///   checked stage contract HASH) and therefore committed to no argument vector at
///   all: the one consumer that needs one, `kata_worker::oci_bundle::spec_for`, took
///   it as a separate parameter, so the bytes a container actually `execve`s were a
///   value the worker's caller chose rather than one the authorization bound. Two
///   capsules with one id could run two different programs. The vector is now IN the
///   identity.
/// * v6 — two operation shapes changed for non-process waits and child
///   invocation. [`WaitOperation::Input`] is new: a blocking human request is a
///   wait, identified by [`input_request_selector`] over the request's authored
///   fields. [`RuntimeOperation::Invoke`] names its child by `program` — the
///   CHECKED child program's content hash, bound at the parent's CHECK — instead of
///   by `pack`, a NAME a library root resolves on whatever machine reads it: a name
///   is a machine fact and not a frozen program, so two invocations of one name
///   could run two different children under one operation identity.
/// * v7 — [`CapsuleBudgets`] gained [`CapsuleBudgets::work_delta_bytes`] and
///   [`CapsuleBudgets::work_delta_entries`] (the `/work` delta bound, CARRIED and
///   hashed; enforced at publish and at adoption) and
///   `output_bytes` is documented as the
///   COMBINED capture bound the provider enforces through `CaptureSpec` (provider
///   protocol v6): a capsule that bounded streams per-stream could not state the
///   bound the provider actually kills on.
/// * v8 — `Capsule.argv` becomes `Capsule.process`, a [`CapsuleProcess`] —
///   `Command` carries the shell argument vector unchanged and `Agent` names an
///   [`AgentTurnSpec`], a vendor process a worker-owned adapter speaks to — and
///   `Capsule.network` joins as a [`CapsuleNetwork`], `Offline` or a declared
///   `Egress` allowlist of [`EgressAuthority`] pairs. v8 is a contract SHAPE
///   only: no pack can author either non-default arm yet, so every capsule a
///   reader meets is `Command` + `Offline` and the worker refuses the two new
///   arms by name before a container starts.
/// * v9 — [`AgentTurnSpec`] gained `credential` (a [`TurnCredentialRef`]: WHERE
///   the worker reads the login, never the value) and `env` (the node's
///   declared non-secret environment, validated at [`Capsule::new`]).
/// * v10 — [`Capsule`] gained [`Capsule::git_view`], an
///   `Option<`[`CapsuleGitView`]`>` carrying the disposable-repository view an
///   agent capsule's `/work` presents: the history artifact, the base commit
///   and branch, and the inherited committer identity. Folded into the capsule
///   id like every field, because two capsules that show the agent different
///   repositories are different stages.
/// * v11 — [`Capsule`] gained [`Capsule::work_view`], an
///   `Option<`[`CapsuleWorkView`]`>` carrying the confined `/work` subset a
///   `reads=`-declaring stage runs against under `oci`: the worker
///   materializes only the members the view covers and the delta treats every
///   uncovered base member as unchanged. Folded into the capsule id like every
///   field, because two capsules that show the action different trees are
///   different stages. A v10 data directory is refused at open — the bump is
///   the fresh-data-dir kind, like every one before it.
/// * v12 — [`CapsuleGitView::branch`] becomes an `Option<`[`GitViewRef`]`>`: a
///   branch NAME with the commit it points at, both read off the execution's
///   frozen target, instead of a name the base commit was assumed to carry. A
///   pull-request target's view names the PR's base branch at the compare
///   base, a trunk target's names trunk at the head, and a view with no branch
///   is representable. Folded into the capsule id like every field. A v11 data
///   directory is refused at open — the bump is the fresh-data-dir kind, like
///   every one before it.
/// * v13 — [`AgentTurnSpec::adapter`] names one of the two nanocode kinds and
///   [`TurnCredentialRef::source`] is `kata_login` or `env:<VAR>`: the vendor
///   adapters (`codex_app_server`, `generic_acp`, `grok_acp`, `pi_rpc`) and the
///   host-login sources they lifted are gone, and so is the turn's `argv`, which
///   every remaining kind left empty (its capsule's init is `kata-toolhost`,
///   fixed by the kind): an agent turn no longer encodes a launch vector or
///   folds one into its capsule id. A v12 body naming a removed adapter or
///   login does not decode, and every v12 agent capsule's id moves, so a v12
///   data directory is refused at open (operational stamp 46) rather than
///   failing every read of such a capsule — the fresh-data-dir kind, like every
///   bump before it.
/// * v14 — an agent turn's declared `env` and its `env:<VAR>` credential source
///   may not name `http_proxy`, `https_proxy`, `ALL_PROXY`, `all_proxy`
///   ([`EGRESS_PLUMBING_ENV`] grew from four spellings to eight) or
///   `XDG_RUNTIME_DIR` ([`USER_MANAGER_ENV`]). [`Capsule`]'s `Deserialize`
///   re-runs [`Capsule::new`], so a v13 body declaring one of them would fail
///   every read of it; a v13 data directory is refused at open (operational
///   stamp 49) instead — the fresh-data-dir kind, like every bump before it.
pub const EXECUTION_CONTRACT_SCHEMA_VERSION: u32 = 14;

/// What an operator can do about a durable record at an earlier schema — a
/// checked program, an invocation envelope or an execution contract — in a data
/// directory this binary opens. No binary that opens the directory wrote it:
/// every bump of those three schemas moves the operational schema too (kata-
/// workflow's `every_*_schema_bump_moves_the_operational_stamp` guards pin the
/// pairing), and a directory at an earlier operational schema is refused at
/// open, so no earlier binary can finish the record here. One sentence for every
/// such refusal and the upgrade preview, so they say the same thing.
///
/// Appended where the main reads a record back from its own data directory, never
/// by a type's own decode: a worker decodes the same [`Capsule`] off its main's
/// frame, where a body at another schema says the two were built apart and a fresh
/// data directory is no answer.
pub const EARLIER_SCHEMA_RECOURSE: &str = "No Kata binary that opens this data directory \
     writes that schema (every checked-program, invocation-envelope and execution-contract \
     schema bump also moves the operational schema, and a directory at an earlier one is \
     refused at open), so nothing can dispatch it here: inspect it as read-only evidence and \
     run this binary against a fresh `[node] data_dir`";

/// Domain-separation tag for one identity family. The schema version is part of
/// the tag, so a version bump rotates every id in this module by construction
/// instead of by remembering to.
fn domain(name: &str) -> String {
    format!("kata.execution.{name}.v{EXECUTION_CONTRACT_SCHEMA_VERSION}")
}

/// Refuse any `schema_version` other than [`EXECUTION_CONTRACT_SCHEMA_VERSION`].
/// A tolerated foreign version would be a silent compatibility layer: the body
/// would be read under this build's field meanings.
fn current_schema_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != EXECUTION_CONTRACT_SCHEMA_VERSION {
        return Err(serde::de::Error::custom(format!(
            "execution contract schema_version {version} is not supported; \
             this build accepts only {EXECUTION_CONTRACT_SCHEMA_VERSION}"
        )));
    }
    Ok(version)
}

macro_rules! hash_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub ContentHash);
    };
}

hash_id!(OperationContractId);
hash_id!(OccurrenceId);
hash_id!(PreparedActionId);
hash_id!(
    /// An ARTIFACT-PLANE identity: [`ArtifactRef::new`] folds `(object, size, privacy)`.
    ///
    /// # Why this folds more than the object, and why an environment's does not
    ///
    /// The artifact plane CLASSIFIES bytes: one object may be declared `Public` (the
    /// canonical empty tree every capsule maps) or `Private` (a stage's `/out`), and the
    /// classification is a fact about the declaration rather than about the bytes, so it
    /// has to be inside the id or two declarations with different retention and
    /// redaction treatment would share one name. The length is folded beside it so an
    /// id names a byte count a reader can bound BEFORE it fetches anything.
    ///
    /// ONE field of this type is NOT such an id, and the exception is deliberate rather
    /// than accidental: [`EnvironmentRef`]'s `manifest` is the manifest bytes' RAW CAS ADDRESS
    /// ([`crate::nix_environment::environment_manifest_id`]). An environment manifest is
    /// `Public` by construction (`NixEnvironmentManifest::new` refuses anything else) and
    /// its length is already inside the CAS address's preimage, so folding either would
    /// add no information, and the manifest has no `artifacts` row to be the id OF — it
    /// is retained by a node-owned `cas_roots` row. Every reader resolving an
    /// environment must derive that field through the one function, never through
    /// `ArtifactRef::new`, which would compute a different id for it.
    ArtifactId
);
hash_id!(
    /// A Nix environment's identity: [`EnvironmentRef::new`] folds the manifest's RAW
    /// CAS address and the closure digest.
    ///
    /// # Why the manifest is folded by its raw address and not by an [`ArtifactId`]
    ///
    /// See [`ArtifactId`]: an environment manifest is always `Public` and its length is
    /// inside its address, so the artifact plane's `(object, size, privacy)` fold would
    /// carry nothing the address does not, and there is no artifact row for it to name.
    /// The address is minted by `kata_core::environment::declare_environment` and
    /// re-derived by the worker's plane index through the SAME function
    /// ([`crate::nix_environment::environment_manifest_id`]); the two agreeing is pinned
    /// by a cell, because two spellings of this derivation can disagree and refuse a
    /// correct row.
    EnvironmentId
);
hash_id!(PlatformId);
hash_id!(CapsuleId);
hash_id!(
    /// The CONTENT-CACHE identity of a capsule's work: [`Capsule::reuse_key`] folds every
    /// field a container can observe — the prepared action, the environment, the
    /// platform, the sorted mappings (so the walked `/work` tree), the argument vector
    /// and all six budgets — and NOT the occurrence, which [`CapsuleId`] folds and which
    /// names one execution's logical invocation — plus the node's executor term
    /// (a parameter rather than a field). Two capsules with equal reuse keys
    /// run the same program over the same bytes under the same bounds and the same
    /// kata fence, in different occurrences; that is the whole premise of adopting
    /// one's accepted result as the other's.
    CapsuleReuseKey
);

/// Stable position of one logical operation, including bounded expansion and
/// invocation coordinates. Attempt ordinals and worker placement never appear.
/// By convention only the checked lowerer mints one; see the module docs for why
/// that is a convention rather than a guarantee.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OperationPath(pub Vec<u32>);

impl OperationPath {
    /// Extend this path by one coordinate.
    ///
    /// # The expansion iteration rule
    ///
    /// The occurrence of template member `m` in iteration `N` of a
    /// [`RuntimeOperation::ExpandBounded`] at `expand_path` is
    /// `expand_path.child(N).child(m)` — for EVERY `N`, **including 0**.
    /// Iteration 0 is a child coordinate like any other and is deliberately not
    /// the bare expansion path, because a first iteration wearing the expansion's
    /// own coordinate would alias the occurrence of the thing expanded onto the
    /// occurrence of the expansion that owns it.
    ///
    /// Nothing in this module mints those coordinates; the rule is stated here
    /// because this is the operation that would have to be used to break it.
    #[must_use]
    pub fn child(&self, coordinate: u32) -> Self {
        let mut path = self.0.clone();
        path.push(coordinate);
        Self(path)
    }

    /// The path's canonical byte encoding: the `u64` little-endian coordinate
    /// COUNT followed by each coordinate as `u32` little-endian, in order.
    ///
    /// # Invariant
    ///
    /// ONE ENCODING, TWO CONSUMERS. These are byte-for-byte the VALUES
    /// [`hash_path`] folds into every identity in this module — the count field and
    /// then one field per coordinate — and they are also what
    /// `operational.db`'s `occurrences.operation_path` column stores and takes its
    /// `UNIQUE(execution_id, operation_contract_id, operation_path)` over. So SQL
    /// occurrence uniqueness and [`OccurrenceRef::id`] are derived from the SAME
    /// encoding rather than from two that agree today.
    ///
    /// A SECOND encoding for the column is what this method exists to prevent. Two
    /// paths that differ would hash to two `OccurrenceId`s while colliding on one
    /// row (or the reverse), and the durable uniqueness constraint would then be
    /// enforcing a different question from the one the content id answers.
    ///
    /// The count prefix is NOT redundant with the length of the returned vector: it
    /// is what makes the encoding injective under the field framing `hash_path`
    /// uses, and dropping it here would silently move the identity. Its presence is
    /// also why the byte length is always `8 + 4 * n` — divisible by four, which is
    /// the column's stored CHECK.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 4 * self.0.len());
        bytes.extend_from_slice(&(self.0.len() as u64).to_le_bytes());
        for coordinate in &self.0 {
            bytes.extend_from_slice(&coordinate.to_le_bytes());
        }
        bytes
    }

    /// The ONE inverse of [`Self::canonical_bytes`]: `Some(path)` for exactly the
    /// byte strings `canonical_bytes` produces — the count-prefixed `u32` LE
    /// sequence, each coordinate consumed whole, trailing bytes refused.
    #[must_use]
    pub fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        let (count, mut rest) = bytes.split_at_checked(8)?;
        let count = usize::try_from(u64::from_le_bytes(count.try_into().ok()?)).ok()?;
        if rest.len() != count.checked_mul(4)? {
            return None;
        }
        let mut coordinates = Vec::with_capacity(count);
        while let Some((coordinate, tail)) = rest.split_at_checked(4) {
            coordinates.push(u32::from_le_bytes(coordinate.try_into().ok()?));
            rest = tail;
        }
        Some(Self(coordinates))
    }

    /// The `attempts.stage_id` coordinate of an attempt at a PROGRAM-LEVEL operation
    /// (a branch route's `Select`), which has no stage of its own: `#op/<c0>.<c1>…`,
    /// each coordinate in canonical decimal.
    ///
    /// # Why not the condition stage's id
    ///
    /// A `Select`'s `source_stage` is its condition stage, but an attempt keyed on that
    /// id would share the condition's `(stage_id, attempt_ordinal)` key space and
    /// interleave its attempt ordinals. The program-operation coordinate is derived from the occurrence's OWN
    /// path, so the attempt's name cannot disagree with the occurrence it resolves;
    /// joinability to program identity is `occurrences.operation_path`.
    ///
    /// # Why it cannot collide with a stage
    ///
    /// `#` is reserved in an authored stage id: the Starlark frontend refuses one at
    /// registration (`stage_id_reserved_character`). [`Self::from_program_operation_stage_id`]
    /// is the ONE inverse; a reader recognizes a program operation through it and never
    /// by sniffing the prefix.
    #[must_use]
    pub fn program_operation_stage_id(&self) -> String {
        let coordinates: Vec<String> = self.0.iter().map(u32::to_string).collect();
        format!(
            "{PROGRAM_OPERATION_STAGE_ID_PREFIX}{}",
            coordinates.join(".")
        )
    }

    /// The ONE inverse of [`Self::program_operation_stage_id`]: `Some(path)` exactly when
    /// `stage_id` is the rendering of a non-empty path.
    ///
    /// Refused (`None`): no `#op/` prefix; an empty coordinate list; an empty coordinate
    /// (`#op/1..2`); a coordinate that is not a `u32`; and any NON-CANONICAL spelling
    /// (`#op/01`, `#op/+1`) — so the parse is injective and a name that renders
    /// differently from its path is never read as one.
    #[must_use]
    pub fn from_program_operation_stage_id(stage_id: &str) -> Option<Self> {
        let rendered = stage_id.strip_prefix(PROGRAM_OPERATION_STAGE_ID_PREFIX)?;
        if rendered.is_empty() {
            return None;
        }
        let path = Self(
            rendered
                .split('.')
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .ok()?,
        );
        (path.program_operation_stage_id() == stage_id).then_some(path)
    }
}

/// The prefix of [`OperationPath::program_operation_stage_id`]. Private: the prefix is
/// not a recognizer, [`OperationPath::from_program_operation_stage_id`] is.
const PROGRAM_OPERATION_STAGE_ID_PREFIX: &str = "#op/";

/// The `attempts.stage_id` coordinate prefix of a `/work` apply effect's
/// main-resolved attempt: `#apply/<stage>` for the stage whose accepted delta
/// it applies.
///
/// Deliberately NOT a [`OperationPath::program_operation_stage_id`]: the apply
/// is a derived occurrence over the STAGE's operation path (under
/// [`work_apply_operation_contract`]'s contract), not a program-level
/// operation — `#apply/` renders the stage's authored id so a reader names the
/// stage whose delta it applied, and the reserved `#` keeps it out of every
/// authored stage id.
pub const WORK_APPLY_STAGE_ID_PREFIX: &str = "#apply/";

/// The `#apply/<stage>` coordinate of `<stage>`'s `/work` apply attempt.
#[must_use]
pub fn work_apply_stage_id(stage: &str) -> String {
    format!("{WORK_APPLY_STAGE_ID_PREFIX}{stage}")
}

/// The ONE inverse of [`work_apply_stage_id`]: the stage an `#apply/`
/// coordinate applies, `None` for anything not spelled `#apply/<stage>`.
#[must_use]
pub fn work_apply_stage(stage_id: &str) -> Option<&str> {
    stage_id
        .strip_prefix(WORK_APPLY_STAGE_ID_PREFIX)
        .filter(|stage| !stage.is_empty() && !stage.contains('/'))
}

/// The separator inside a child-invocation stage id: `<base>#child-<role>` for
/// a static `topology` child, `<base>#child-<role>-<label>` for a dynamic
/// fanout one. Like `#apply/`, the `#` keeps the spelling out of every
/// authored stage id — it is the durable name a child's member contract
/// carries (`OperationContract::new` hashes `source_stage`), the name its
/// attempt's `stage_id` stamps, and the name the fan-in and the fold decode.
pub const CHILD_INVOCATION_MARKER: &str = "#child-";

/// The `<base>#child-<role>` coordinate of a static `topology` child.
#[must_use]
pub fn child_invocation_stage_name(base_stage: &str, role: &str) -> String {
    format!("{base_stage}{CHILD_INVOCATION_MARKER}{role}")
}

/// The ONE inverse of [`child_invocation_stage_name`]: `(base, role)` for a
/// name spelled `<base>#child-<role>` — a DYNAMIC child's
/// `<base>#child-<role>-<label>` decodes to `(base, "<role>-<label>")`.
/// `None` for a name with no marker, an
/// empty base, or an empty role.
#[must_use]
pub fn parse_child_invocation_stage_name(raw: &str) -> Option<(SmolStr, SmolStr)> {
    let (base, role) = raw.split_once(CHILD_INVOCATION_MARKER)?;
    if base.is_empty() || role.is_empty() {
        return None;
    }
    Some((SmolStr::new(base), SmolStr::new(role)))
}

/// The operation contract of a stage's `/work` apply occurrence: the stage's
/// own contract re-addressed under the apply's domain, so the apply mints an
/// occurrence of its OWN at the stage's operation path — distinct from the
/// worker-bound stage occurrence (`occurrences` is unique on
/// `(execution, operation_contract, path)`, and the stage's row is its
/// capsule's).
#[must_use]
pub fn work_apply_operation_contract(stage_contract: OperationContractId) -> OperationContractId {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, &domain("work_apply_contract"), &[]);
    hash_field(&mut hasher, "stage_contract", stage_contract.0.as_bytes());
    OperationContractId(FixedBytes(*hasher.finalize().as_bytes()))
}

fn hash_path(hasher: &mut blake3::Hasher, name: &str, path: &OperationPath) {
    hash_field(hasher, name, &(path.0.len() as u64).to_le_bytes());
    for coordinate in &path.0 {
        hash_field(hasher, "coordinate", &coordinate.to_le_bytes());
    }
}

fn hash_paths(hasher: &mut blake3::Hasher, name: &str, paths: &[OperationPath]) {
    hash_field(hasher, name, &(paths.len() as u64).to_le_bytes());
    for path in paths {
        hash_path(hasher, "path", path);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionExecutor {
    Command,
    /// Ordered fallback list: `drivers[0]` is preferred, later entries are tried
    /// in order. Order is semantic, so it is part of the identity.
    ///
    /// NON-EMPTY by contract of every producer: an operation that names no driver
    /// would be claiming that the authored program decided its own executor when
    /// it did not. WHICH member runs at attempt `i` is an ATTEMPT fact (the count
    /// of failed seats in the stage's durable retry chain picks it), so it never enters
    /// this operation's identity and never enters an [`OperationPath`].
    Agent {
        drivers: Vec<SmolStr>,
    },
    /// A recorded, replay-safe VCS/workspace mutation. `effect_kind` names the
    /// EFFECT FAMILY (its idempotency belt); `op` names WHICH mutation, because
    /// the family alone does not distinguish a park from a promote and the stage
    /// contract hash does not either.
    Effect {
        effect_kind: EffectKind,
        op: WorkspaceEffectOp,
    },
}

impl ActionExecutor {
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Agent { .. } => "agent",
            Self::Effect { .. } => "effect",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteOperation {
    pub executor: ActionExecutor,
    pub contract_hash: ContentHash,
}

/// A relative delay and an absolute deadline are different semantics, so they
/// are different variants rather than one field with a mode flag.
///
/// Internally tagged `mode`, not `kind`: [`RuntimeOperation`] flattens its
/// newtype payload under its own `kind` tag, and two `kind` tags in one object
/// is a duplicate field serde refuses on the way back in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum WaitOperation {
    For {
        delay_ms: u64,
    },
    Until {
        epoch_ms: u64,
    },
    /// A wait on one blocking human request's answer. `request` is
    /// [`input_request_selector`] over the request's authored fields.
    Input {
        request: ContentHash,
    },
}

impl WaitOperation {
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::For { .. } => "for",
            Self::Until { .. } => "until",
            Self::Input { .. } => "input",
        }
    }
}

/// The authored fields of one blocking human request, borrowed field by field.
///
/// Primitive rather than the checked request type because that type
/// (`kata_program::execution_program::ExecutionHumanRequest`) lives above this
/// crate. Every field here is one [`input_request_selector`] hashes.
#[derive(Clone, Copy, Debug)]
pub struct InputRequestFields<'a> {
    pub id: &'a str,
    pub stage: Option<&'a str>,
    pub question: &'a str,
    pub default_assumption: &'a str,
    pub timeout_ms: Option<u64>,
    pub priority: &'a str,
    pub context: Option<&'a str>,
}

/// Domain-separated identity of one blocking human request — the `request` a
/// [`WaitOperation::Input`] carries.
///
/// Field-wise under this module's own domain tag, never over a serde encoding,
/// over every field of [`InputRequestFields`]: the request id, its target stage,
/// the question, the default assumption, the self-heal timeout, the priority
/// label, and the context. Each optional field enters as a PRESENCE tag plus its
/// value, so an absent field and an empty one cannot collide.
///
/// Two fields of the checked request are deliberately NOT here: its `index` (its
/// position in the authored queue — the id, which CHECK refuses to repeat, is
/// what names it, so re-ordering the queue must not rotate a wait) and its
/// `blocking` flag (only a blocking request is a wait at all, so the flag is
/// constant for every request this identity can describe).
#[must_use]
pub fn input_request_selector(fields: InputRequestFields<'_>) -> ContentHash {
    fn optional(hasher: &mut blake3::Hasher, absent: &str, name: &str, value: Option<&[u8]>) {
        match value {
            None => hash_field(hasher, absent, &[]),
            Some(bytes) => hash_field(hasher, name, bytes),
        }
    }

    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, &domain("input_request"), &[]);
    hash_field(&mut hasher, "id", fields.id.as_bytes());
    optional(
        &mut hasher,
        "stage_absent",
        "stage",
        fields.stage.map(str::as_bytes),
    );
    hash_field(&mut hasher, "question", fields.question.as_bytes());
    hash_field(
        &mut hasher,
        "default_assumption",
        fields.default_assumption.as_bytes(),
    );
    let timeout = fields.timeout_ms.map(u64::to_le_bytes);
    optional(
        &mut hasher,
        "timeout_ms_absent",
        "timeout_ms",
        timeout.as_ref().map(<[u8; 8]>::as_slice),
    );
    hash_field(&mut hasher, "priority", fields.priority.as_bytes());
    optional(
        &mut hasher,
        "context_absent",
        "context",
        fields.context.map(str::as_bytes),
    );
    ContentHash::new(*hasher.finalize().as_bytes())
}

/// Domain-separated identity of one authored branch ROUTE's canonical content —
/// the `selector` a [`RuntimeOperation::Select`] carries.
///
/// Hashed field-wise under this module's own domain tag, never over a serde
/// encoding, over exactly what decides where the route sends control: the
/// condition stage, the verdict field read from its validated output, and the
/// arms in stored order with their tags and target stage ids. `branch_routes` is
/// held in canonical (condition-stage, then arm-tag) order by
/// [`canonical_order_branch_routes`](crate::workflow::canonical_order_branch_routes),
/// so authored order cannot rotate a selector while a re-targeted, re-tagged, or
/// added arm must.
///
/// It deliberately hashes the ROUTE and nothing else: the arm targets' own
/// contracts have their own identities, and folding them in here would make a
/// selector move when a target stage's body changed, which is not a routing fact.
#[must_use]
pub fn branch_route_selector(route: &BranchRoute) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, &domain("branch_selector"), &[]);
    hash_field(
        &mut hasher,
        "condition_stage",
        route.condition_stage.0.as_bytes(),
    );
    hash_field(&mut hasher, "verdict_field", route.verdict_field.as_bytes());
    hash_field(
        &mut hasher,
        "arms",
        &(route.arms.len() as u64).to_le_bytes(),
    );
    for arm in &route.arms {
        hash_field(&mut hasher, "tag", arm.tag.as_bytes());
        hash_field(
            &mut hasher,
            "targets",
            &(arm.targets.len() as u64).to_le_bytes(),
        );
        for target in &arm.targets {
            hash_field(&mut hasher, "target", target.0.as_bytes());
        }
    }
    ContentHash::new(*hasher.finalize().as_bytes())
}

/// Domain-separated identity of one authored [`ReviewLoop`]'s POLICY — the
/// `policy_hash` a [`RuntimeOperation::ExpandBounded`] carries.
///
/// # Why the expansion needs it
///
/// An expansion's `template` says WHAT iterates and its `maximum` says HOW MANY
/// TIMES. Everything else about a loop — how it resolves when the budget
/// exhausts, which walk-away bounds cut it short, which verdict tags mean
/// approve / refine / block, how often the carried context is distilled — decides
/// WHETHER a given iteration runs at all and what its outcome means. Without this
/// field two loops over the same body with the same ceiling and opposite
/// exhaustion actions wore one identity, which is a claim wider than the
/// mechanism.
///
/// # What is hashed
///
/// Field-wise under this module's own domain tag, never over a serde encoding,
/// over every semantic field of [`ReviewLoop`]:
///
/// * `worker_stage` and `reviewer_stage` — the pair the loop is between;
/// * `max_iterations` — also the expansion's `maximum`, hashed here too so the
///   policy hash is a complete statement about the policy on its own;
/// * `on_max` — as [`OnMaxAction::as_tag`](crate::review_loop::OnMaxAction::as_tag),
///   a `&'static str`, so reordering the enum cannot alias `accept` onto `fail`;
/// * `bounds` — the loop-scope walk-aways, in the CANONICAL order `ReviewLoop`
///   stores them in (`Time` before `Cost`, at most one per kind), so author order
///   cannot rotate the hash while an added or retuned bound must. Each entry
///   enters as its kind label plus its integer ceiling;
/// * the gate verdict vocabulary — the verdict FIELD plus the three tag-sets,
///   each SORTED AND DEDUPED, because a tag-set is a classification in which
///   neither order nor multiplicity decides anything (see the hash site);
/// * the effective body — the ordered body sub-DAG the runner re-dispatches;
/// * `rollover_after_iterations` — as a PRESENCE flag plus the set value.
///
/// # What is excluded, and why nothing else is
///
/// Nothing is excluded: every field of [`ReviewLoop`] is above. Two fields are
/// hashed through their NORMALIZING accessor rather than literally, and the
/// asymmetry between them is deliberate:
///
/// * [`ReviewLoop::effective_body_stages`] and
///   [`ReviewLoop::effective_gate_verdict`] resolve their empty / absent spelling
///   against a value that is itself an AUTHORED fact of the same loop (an empty
///   `body_stages` means "the body is `worker_stage`"; an absent `gate_verdict`
///   means the fixed default vocabulary this crate defines and the runtime reads
///   through the same accessor). Both spellings are the same policy, so they hash
///   the same.
/// * `rollover_after_iterations` is NOT resolved through
///   [`ReviewLoop::effective_rollover_after_iterations`], because that resolves
///   `None` against
///   [`DEFAULT_ROLLOVER_AFTER_ITERATIONS`](crate::review_loop::DEFAULT_ROLLOVER_AFTER_ITERATIONS)
///   — a BUILD constant, not an authored fact. Folding it in would make every
///   loop that declares no window rotate its policy hash the day that constant
///   moved, which is not a change to any author's loop. So `None` and
///   `Some(200)` are deliberately DISTINCT here: one is "whatever this build
///   defaults to", the other is "200, pinned by the author".
///
/// Runtime state — the live iteration counter, accumulated usage, the rollover
/// generation — is absent by construction: this is a function of the authored
/// loop and nothing else.
#[must_use]
pub fn loop_policy_selector(review_loop: &ReviewLoop) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, &domain("loop_policy"), &[]);
    hash_field(
        &mut hasher,
        "worker_stage",
        review_loop.worker_stage.as_bytes(),
    );
    hash_field(
        &mut hasher,
        "reviewer_stage",
        review_loop.reviewer_stage.as_bytes(),
    );
    hash_field(
        &mut hasher,
        "max_iterations",
        &review_loop.max_iterations.to_le_bytes(),
    );
    hash_field(
        &mut hasher,
        "on_max",
        review_loop.on_max.as_tag().as_bytes(),
    );

    hash_field(
        &mut hasher,
        "bounds",
        &(review_loop.bounds.len() as u64).to_le_bytes(),
    );
    for bound in &review_loop.bounds {
        hash_field(&mut hasher, "bound_kind", bound.kind().label().as_bytes());
        hash_field(&mut hasher, "bound_ceiling", &bound.limit().to_le_bytes());
    }

    let verdict = review_loop.effective_gate_verdict();
    hash_field(
        &mut hasher,
        "verdict_field",
        verdict.verdict_field.as_bytes(),
    );
    for (name, tags) in [
        ("approve", &verdict.approve),
        ("refine", &verdict.refine),
        ("block", &verdict.block),
    ] {
        // CANONICALIZED TO A SET, unlike a branch route's arms: a tag-set is a
        // CLASSIFICATION — `classify` asks only whether a tag is a MEMBER — so
        // neither its order nor its multiplicity decides anything. Two spellings
        // of one set must hash equal, or re-listing `["ship", "land"]` as
        // `["land", "ship"]`, or writing `["ship", "ship"]`, would rotate every
        // expansion identity in the pack for no change in behaviour. Hence sort
        // AND dedup. (A branch route's arms are hashed in STORED order instead,
        // and correctly: routes arrive already canonically ordered, and an arm
        // carries targets, which makes its position observable.)
        let mut tags = tags.clone();
        tags.sort_unstable();
        tags.dedup();
        hash_field(&mut hasher, name, &(tags.len() as u64).to_le_bytes());
        for tag in &tags {
            hash_field(&mut hasher, "tag", tag.as_bytes());
        }
    }

    let body = review_loop.effective_body_stages();
    hash_field(&mut hasher, "body", &(body.len() as u64).to_le_bytes());
    for stage in &body {
        hash_field(&mut hasher, "body_stage", stage.0.as_bytes());
    }

    match review_loop.rollover_after_iterations {
        None => hash_field(&mut hasher, "rollover_absent", &[]),
        Some(window) => hash_field(&mut hasher, "rollover_after", &window.to_le_bytes()),
    }

    ContentHash::new(*hasher.finalize().as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeOperation {
    Execute(ExecuteOperation),
    Wait(WaitOperation),
    /// Invoke one child program. `program` is the CHECKED child program's
    /// content hash, bound at the parent's CHECK, never a pack name; `params_hash`
    /// is the hash of the canonical parameters the parent passes it.
    Invoke {
        program: ContentHash,
        params_hash: ContentHash,
    },
    Select {
        selector: ContentHash,
    },
    Join {
        inputs: Vec<OperationPath>,
    },
    /// Bounded control flow over a `template` of already-lowered operations,
    /// repeated at most `maximum` times.
    ///
    /// `policy_hash` is [`loop_policy_selector`] over the authored loop: what
    /// decides whether an iteration runs and what its verdict means, none of which
    /// the template or the maximum can express. See
    /// [`OperationPath::child`] for the coordinate an iteration's member occupies.
    ExpandBounded {
        template: Vec<OperationPath>,
        maximum: u32,
        policy_hash: ContentHash,
    },
    /// A typed memory snapshot — the `memory_snapshot(kind=.., status=..)`
    /// builtin's operation. The runner resolves it MAIN-SIDE on every profile:
    /// kata reads the node's own memory store under `query` and accepts the
    /// stage with the snapshot as its output, so it has no executor, no capsule
    /// and no dispatch. `query` rides in full rather than a selector hash
    /// because it IS the authored operation — two fields, not a program to
    /// bind or a routing to commit.
    MemorySnapshot {
        /// The authored filter — `kind`/`status` narrow the read; `None` is
        /// unfiltered.
        query: MemorySnapshotSpec,
    },
}

impl RuntimeOperation {
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::Execute(_) => "execute",
            Self::Wait(_) => "wait",
            Self::Invoke { .. } => "invoke",
            Self::Select { .. } => "select",
            Self::Join { .. } => "join",
            Self::ExpandBounded { .. } => "expand_bounded",
            Self::MemorySnapshot { .. } => "memory_snapshot",
        }
    }

    fn hash_into(&self, hasher: &mut blake3::Hasher) {
        hash_field(hasher, "operation_tag", self.as_tag().as_bytes());
        match self {
            Self::Execute(execute) => {
                hash_field(hasher, "executor_tag", execute.executor.as_tag().as_bytes());
                match &execute.executor {
                    ActionExecutor::Command => {}
                    ActionExecutor::Agent { drivers } => {
                        hash_field(hasher, "drivers", &(drivers.len() as u64).to_le_bytes());
                        for driver in drivers {
                            hash_field(hasher, "driver", driver.as_bytes());
                        }
                    }
                    ActionExecutor::Effect { effect_kind, op } => {
                        hash_field(hasher, "effect_kind", effect_kind.as_str().as_bytes());
                        hash_field(hasher, "effect_op", op.as_str().as_bytes());
                    }
                }
                hash_field(hasher, "contract_hash", execute.contract_hash.as_bytes());
            }
            Self::Wait(wait) => {
                hash_field(hasher, "wait_tag", wait.as_tag().as_bytes());
                match wait {
                    WaitOperation::For { delay_ms } => {
                        hash_field(hasher, "delay_ms", &delay_ms.to_le_bytes());
                    }
                    WaitOperation::Until { epoch_ms } => {
                        hash_field(hasher, "epoch_ms", &epoch_ms.to_le_bytes());
                    }
                    WaitOperation::Input { request } => {
                        hash_field(hasher, "request", request.as_bytes());
                    }
                }
            }
            Self::Invoke {
                program,
                params_hash,
            } => {
                hash_field(hasher, "program", program.as_bytes());
                hash_field(hasher, "params_hash", params_hash.as_bytes());
            }
            Self::Select { selector } => hash_field(hasher, "selector", selector.as_bytes()),
            Self::Join { inputs } => hash_paths(hasher, "inputs", inputs),
            Self::ExpandBounded {
                template,
                maximum,
                policy_hash,
            } => {
                hash_paths(hasher, "template", template);
                hash_field(hasher, "maximum", &maximum.to_le_bytes());
                hash_field(hasher, "policy_hash", policy_hash.as_bytes());
            }
            Self::MemorySnapshot { query } => {
                // Each optional filter enters as a PRESENCE tag plus its
                // label, so an absent filter and an empty one cannot collide
                // and a widened filter is a different operation — the same
                // rule `input_request_selector` states.
                match query.kind {
                    None => hash_field(hasher, "filter_kind_absent", &[]),
                    Some(kind) => hash_field(hasher, "filter_kind", kind.label().as_bytes()),
                }
                match query.status {
                    None => hash_field(hasher, "filter_status_absent", &[]),
                    Some(status) => {
                        hash_field(hasher, "filter_status", status.label().as_bytes());
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationContract {
    /// Private: only [`Self::new`] may stamp it, and only
    /// [`EXECUTION_CONTRACT_SCHEMA_VERSION`] is stampable, so no caller can
    /// construct a value claiming a version this build does not implement.
    #[serde(deserialize_with = "current_schema_version")]
    schema_version: u32,
    pub source_stage: StageId,
    pub operation: RuntimeOperation,
}

impl OperationContract {
    #[must_use]
    pub fn new(source_stage: StageId, operation: RuntimeOperation) -> Self {
        Self {
            schema_version: EXECUTION_CONTRACT_SCHEMA_VERSION,
            source_stage,
            operation,
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub fn id(&self) -> OperationContractId {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("operation"), &[]);
        hash_field(&mut hasher, "source_stage", self.source_stage.0.as_bytes());
        self.operation.hash_into(&mut hasher);
        OperationContractId(FixedBytes(*hasher.finalize().as_bytes()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSourceMap {
    pub operation: OperationContractId,
    pub stage: StageId,
    pub source_hash: ContentHash,
    pub authored_label: SmolStr,
    /// The `pack.star:LINE:COL` call site that declared the authored construct
    /// this operation came from, so a reader can point at the line rather than at
    /// a minted stage id. `None` for a program whose stages carry no span.
    ///
    /// A source map is PROVENANCE and never contract material: nothing in this
    /// struct is hashed into [`OperationContractId`] — that identity is taken over
    /// the contract's own fields — so re-indenting a pack moves a span and rotates
    /// no operation id. The same discipline that keeps `authored_span` out of
    /// `contract_hash` in the checked IR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<crate::source::SourceSpan>,
}

/// Logical invocation of a checked operation. Retry, lease, worker, and attempt
/// facts are deliberately absent so they cannot rotate logical identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OccurrenceRef {
    /// Private; see [`OperationContract::schema_version`].
    #[serde(deserialize_with = "current_schema_version")]
    schema_version: u32,
    pub execution: ExecutionId,
    pub program: ContentHash,
    pub operation: OperationContractId,
    pub path: OperationPath,
}

impl OccurrenceRef {
    #[must_use]
    pub fn new(
        execution: ExecutionId,
        program: ContentHash,
        operation: OperationContractId,
        path: OperationPath,
    ) -> Self {
        Self {
            schema_version: EXECUTION_CONTRACT_SCHEMA_VERSION,
            execution,
            program,
            operation,
            path,
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub fn id(&self) -> OccurrenceId {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("occurrence"), &[]);
        hash_field(&mut hasher, "execution", &self.execution.0.to_bytes());
        hash_field(&mut hasher, "program", self.program.as_bytes());
        hash_field(&mut hasher, "operation", self.operation.0.as_bytes());
        hash_path(&mut hasher, "path", &self.path);
        OccurrenceId(FixedBytes(*hasher.finalize().as_bytes()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPrivacy {
    Public,
    Private,
}

impl ArtifactPrivacy {
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ArtifactRef {
    schema_version: u32,
    id: ArtifactId,
    object_id: ObjectId,
    size_bytes: u64,
    privacy: ArtifactPrivacy,
}

impl ArtifactRef {
    #[must_use]
    pub fn new(object_id: ObjectId, size_bytes: u64, privacy: ArtifactPrivacy) -> Self {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("artifact"), &[]);
        hash_field(&mut hasher, "object", object_id.as_bytes());
        hash_field(&mut hasher, "size", &size_bytes.to_le_bytes());
        hash_field(&mut hasher, "privacy", privacy.as_tag().as_bytes());
        Self {
            schema_version: EXECUTION_CONTRACT_SCHEMA_VERSION,
            id: ArtifactId(FixedBytes(*hasher.finalize().as_bytes())),
            object_id,
            size_bytes,
            privacy,
        }
    }

    #[must_use]
    pub const fn id(&self) -> ArtifactId {
        self.id
    }

    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub const fn privacy(&self) -> ArtifactPrivacy {
        self.privacy
    }
}

/// Raw mirror of [`ArtifactRef`]: deserialization recomputes the id from the
/// body and refuses a mismatch, so a serialized id can never disagree with what
/// it claims to identify.
#[derive(Deserialize)]
struct ArtifactRefRaw {
    /// Read only to refuse a foreign version: `current_schema_version` rejects
    /// anything but this build's, so the value itself is never needed.
    #[serde(rename = "schema_version", deserialize_with = "current_schema_version")]
    _schema_version: u32,
    id: ArtifactId,
    object_id: ObjectId,
    size_bytes: u64,
    privacy: ArtifactPrivacy,
}

impl<'de> Deserialize<'de> for ArtifactRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = ArtifactRefRaw::deserialize(deserializer)?;
        let recomputed = Self::new(raw.object_id, raw.size_bytes, raw.privacy);
        if recomputed.id != raw.id {
            return Err(serde::de::Error::custom(format!(
                "artifact id {} does not match its body (recomputed {})",
                raw.id.0, recomputed.id.0
            )));
        }
        Ok(recomputed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnvironmentRef {
    schema_version: u32,
    id: EnvironmentId,
    manifest: ArtifactId,
    closure_digest: ContentHash,
}

impl EnvironmentRef {
    #[must_use]
    pub fn new(manifest: ArtifactId, closure_digest: ContentHash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("environment"), &[]);
        hash_field(&mut hasher, "manifest", manifest.0.as_bytes());
        hash_field(&mut hasher, "closure", closure_digest.as_bytes());
        Self {
            schema_version: EXECUTION_CONTRACT_SCHEMA_VERSION,
            id: EnvironmentId(FixedBytes(*hasher.finalize().as_bytes())),
            manifest,
            closure_digest,
        }
    }

    #[must_use]
    pub const fn id(&self) -> EnvironmentId {
        self.id
    }

    #[must_use]
    pub const fn manifest(&self) -> ArtifactId {
        self.manifest
    }

    #[must_use]
    pub const fn closure_digest(&self) -> ContentHash {
        self.closure_digest
    }
}

/// Raw mirror of [`EnvironmentRef`]; see [`ArtifactRefRaw`].
#[derive(Deserialize)]
struct EnvironmentRefRaw {
    /// Read only to refuse a foreign version: `current_schema_version` rejects
    /// anything but this build's, so the value itself is never needed.
    #[serde(rename = "schema_version", deserialize_with = "current_schema_version")]
    _schema_version: u32,
    id: EnvironmentId,
    manifest: ArtifactId,
    closure_digest: ContentHash,
}

impl<'de> Deserialize<'de> for EnvironmentRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = EnvironmentRefRaw::deserialize(deserializer)?;
        let recomputed = Self::new(raw.manifest, raw.closure_digest);
        if recomputed.id != raw.id {
            return Err(serde::de::Error::custom(format!(
                "environment id {} does not match its body (recomputed {})",
                raw.id.0, recomputed.id.0
            )));
        }
        Ok(recomputed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlatformRef {
    schema_version: u32,
    id: PlatformId,
    target: SmolStr,
    profile: ContentHash,
}

impl PlatformRef {
    #[must_use]
    pub fn new(target: impl Into<SmolStr>, profile: ContentHash) -> Self {
        let target = target.into();
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("platform"), &[]);
        hash_field(&mut hasher, "target", target.as_bytes());
        hash_field(&mut hasher, "profile", profile.as_bytes());
        Self {
            schema_version: EXECUTION_CONTRACT_SCHEMA_VERSION,
            id: PlatformId(FixedBytes(*hasher.finalize().as_bytes())),
            target,
            profile,
        }
    }

    #[must_use]
    pub const fn id(&self) -> PlatformId {
        self.id
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub const fn profile(&self) -> ContentHash {
        self.profile
    }
}

/// Raw mirror of [`PlatformRef`]; see [`ArtifactRefRaw`]. Closed, so EVERY decode of a
/// [`PlatformRef`] refuses an undeclared key: [`PlatformRef`]'s writer has emitted
/// exactly these four keys since the type existed. Today the Nix environment manifest
/// is the only decoded type that embeds one (capsules and programs carry only its
/// [`PlatformId`]), and that manifest refuses an undeclared key at every level.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformRefRaw {
    /// Read only to refuse a foreign version: `current_schema_version` rejects
    /// anything but this build's, so the value itself is never needed.
    #[serde(rename = "schema_version", deserialize_with = "current_schema_version")]
    _schema_version: u32,
    id: PlatformId,
    target: SmolStr,
    profile: ContentHash,
}

impl<'de> Deserialize<'de> for PlatformRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = PlatformRefRaw::deserialize(deserializer)?;
        let recomputed = Self::new(raw.target, raw.profile);
        if recomputed.id != raw.id {
            return Err(serde::de::Error::custom(format!(
                "platform id {} does not match its body (recomputed {})",
                raw.id.0, recomputed.id.0
            )));
        }
        Ok(recomputed)
    }
}

/// An action identity excludes occurrence and placement so equal prepared work
/// can be recognized across logical occurrences without conflating outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedAction {
    /// Private; see [`OperationContract::schema_version`].
    #[serde(deserialize_with = "current_schema_version")]
    schema_version: u32,
    pub operation: OperationContractId,
    pub manifest: ActionManifest,
    pub environment: EnvironmentId,
    pub permissions: ContentHash,
    pub platform: PlatformId,
}

impl PreparedAction {
    #[must_use]
    pub fn new(
        operation: OperationContractId,
        manifest: ActionManifest,
        environment: EnvironmentId,
        permissions: ContentHash,
        platform: PlatformId,
    ) -> Self {
        Self {
            schema_version: EXECUTION_CONTRACT_SCHEMA_VERSION,
            operation,
            manifest,
            environment,
            permissions,
            platform,
        }
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    #[must_use]
    pub fn id(&self) -> PreparedActionId {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("prepared_action"), &[]);
        hash_field(&mut hasher, "operation", self.operation.0.as_bytes());
        hash_field(
            &mut hasher,
            "manifest",
            self.manifest.content_hash().as_bytes(),
        );
        hash_field(&mut hasher, "environment", self.environment.0.as_bytes());
        hash_field(&mut hasher, "permissions", self.permissions.as_bytes());
        hash_field(&mut hasher, "platform", self.platform.0.as_bytes());
        PreparedActionId(FixedBytes(*hasher.finalize().as_bytes()))
    }
}

/// Refuse an argument vector no runtime could exec.
///
/// # Failure — the refused set, stated exactly
///
/// Three things, and nothing else:
///
/// 1. an EMPTY vector. `process.args` is what a container's init execs, so an empty
///    argv is a capsule that cannot run; `kata_worker::oci_bundle::spec_for` refuses
///    one too, and refusing it HERE is what makes that arm unreachable from a
///    capsule rather than a second answer to the same question.
/// 2. an EMPTY `argv[0]`. A zero-length program name resolves to nothing, and a
///    runtime's own report of it is a `PATH` lookup failure inside the container
///    rather than a refusal naming the capsule.
/// 3. an argument containing a NUL byte. `execve` takes NUL-terminated strings, so a
///    NUL SILENTLY TRUNCATES the argument the stage receives — the one refusal here
///    that a downstream reader could not report at all, because by the time the
///    program sees its argv the missing bytes are gone.
///
/// Nothing else. In particular an argument carrying a newline, a space, a shell
/// metacharacter or a non-UTF-8-looking byte sequence is ACCEPTED: `argv` is a LIST,
/// so no element is ever re-split, and a capsule that refused a quote would refuse
/// `sh -c` scripts for a danger that only exists where a list is flattened to a
/// string.
fn refuse_unrunnable_argv(argv: &[SmolStr]) -> KataResult<()> {
    if argv.is_empty() {
        return Err(KataError::Validation(
            "capsule argv is empty. `process.args` is what the container's init execs, so a \
             capsule with no argument vector is one nothing can run"
                .to_owned(),
        ));
    }
    match unrunnable_argv_element(argv) {
        Some(reason) => Err(KataError::Validation(reason)),
        None => Ok(()),
    }
}

/// Items 2 and 3 of [`refuse_unrunnable_argv`]'s refused set — an empty
/// `argv[0]`, or an argument carrying a NUL byte — as the reason, or `None`
/// for any other vector (an empty one included: item 1 is the caller's own
/// door).
fn unrunnable_argv_element<S: AsRef<str>>(argv: &[S]) -> Option<String> {
    if argv
        .first()
        .is_some_and(|program| program.as_ref().is_empty())
    {
        return Some(
            "capsule argv[0] is empty. A zero-length program name resolves to nothing, and a \
             runtime reports that as a PATH lookup failure inside the container rather than as a \
             refusal naming the capsule"
                .to_owned(),
        );
    }
    argv.iter()
        .position(|argument| argument.as_ref().as_bytes().contains(&0))
        .map(|index| {
            format!(
                "capsule argv[{index}] contains a NUL byte. `execve` takes NUL-terminated \
                 strings, so the argument the stage receives would be SILENTLY TRUNCATED at that \
                 byte — the one malformed argv no consumer downstream can report, because the \
                 missing bytes are gone by the time the program reads its own argv"
            )
        })
}

/// Guest directories a mapping may live under. Nothing outside these roots is
/// addressable from a capsule, so a host path has no way in.
const GUEST_ROOTS: &[&str] = &["/work", "/nix/store", "/tmp", "/out"];

/// Absolute normalized path inside a guest. A main-host path has no type in a
/// capsule and therefore cannot be serialized accidentally.
///
/// # Refused set
///
/// [`GuestPath::new`] accepts a path if and only if ALL of the following hold:
/// it equals one of [`GUEST_ROOTS`] or begins with one of them followed by `/`;
/// every `/`-separated component after the leading `/` is non-empty and is
/// neither `.` nor `..`; it contains no NUL and no other ASCII control byte;
/// and it is at most 4096 bytes. Everything else is refused, including a
/// relative path, `/`, a path under an unlisted root (`/home/alice/x`), a root
/// prefix that is not a path boundary (`/workx`), a traversal (`/work/../x`),
/// and an embedded NUL (`"/work/a\0"`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GuestPath(SmolStr);

impl GuestPath {
    /// Maximum accepted byte length; matches Linux `PATH_MAX`, so a path this
    /// type accepts cannot be one the guest kernel would reject outright.
    const MAXIMUM_BYTES: usize = 4096;

    pub fn new(path: impl Into<SmolStr>) -> KataResult<Self> {
        let path = path.into();
        let refuse = |reason: &str| {
            Err(KataError::Validation(format!(
                "guest path {path:?} refused: {reason}"
            )))
        };
        if path.len() > Self::MAXIMUM_BYTES {
            return refuse("longer than 4096 bytes");
        }
        if path.bytes().any(|byte| byte.is_ascii_control()) {
            return refuse("contains a NUL or other ASCII control byte");
        }
        if !path.starts_with('/')
            || path == "/"
            || path
                .split('/')
                .skip(1)
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return refuse("not an absolute, non-root, normalized path");
        }
        if !GUEST_ROOTS
            .iter()
            .any(|root| path == *root || path.starts_with(&format!("{root}/")))
        {
            return refuse("not under a guest root");
        }
        Ok(Self(path))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for GuestPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path = SmolStr::deserialize(deserializer)?;
        Self::new(path).map_err(serde::de::Error::custom)
    }
}

/// The guest's right over a mapping's bytes.
///
/// `ReadWriteScratch` is distinct from `ReadWrite` — and not a flag on
/// `ReadWrite` — because the difference is a CONTRACT fact, not an access
/// level: it is the only spelling a `workspace = "scratch"` capsule mints at
/// `/work`, and it is what every main-side door keys on. A scratch `/work`'s
/// delta is RECORDED as evidence of what the stage did and never applied to
/// the execution's work-tree head — there is no head behind an ephemeral
/// scratch tree — while a `ReadWrite` `/work`'s delta is the workspace
/// mutation the apply sweep lands. One variant, not a boolean, so every
/// consumer answers the question by construction rather than by convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestAccess {
    ReadOnly,
    ReadWrite,
    /// A writable `/work` bound to NO durable head — a `workspace = "scratch"`
    /// stage's canonical empty tree. Its delta is recorded on the accepted
    /// outcome (`scratch_delta_*`), never scheduled for application.
    ReadWriteScratch,
}

impl GuestAccess {
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
            Self::ReadWriteScratch => "read_write_scratch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMapping {
    pub artifact: ArtifactId,
    pub guest_path: GuestPath,
    pub access: GuestAccess,
}

/// The captured-output ceiling a capsule budget carries.
///
/// 64 MiB. A `CapsuleId`-committed constant, not an env-overridable knob: an
/// environment variable must never be able to rotate a `CapsuleId`, so this
/// ceiling is one the capsule assembler and the worker both read out of this
/// crate rather than out of process state.
///
/// It is the default for a capsule's `output_bytes` budget (a stage's own
/// `output_bytes=` replaces it), and the budget is enforced COMBINED over stdout
/// and stderr: the worker hands it to the provider as
/// `kata_provider_protocol::CaptureSpec::limit_bytes`, and the provider kills a
/// capsule whose spooled capture exceeds it and reports `capture_exceeded`.
pub const CAPSULE_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// The RESULT-TREE byte ceiling a capsule budget carries.
///
/// 64 MiB, the same order as [`CAPSULE_OUTPUT_BYTES`] and a SEPARATE constant
/// because the two bound different things: `output_bytes` bounds the captured
/// STREAM (stdout/stderr), this bounds the total size of the `/out` tree the worker
/// publishes and main adopts as the occurrence's result. A stage that writes
/// nothing to its terminal and 4 GiB to `/out` is inside one bound and outside the
/// other.
pub const CAPSULE_RESULT_BYTES: u64 = 64 * 1024 * 1024;

/// The RESULT-TREE entry ceiling a capsule budget carries.
///
/// TWO result bounds and not one, which is a decision rather than an oversight: a
/// byte ceiling alone admits ten million empty files, and an entry ceiling alone
/// admits one file of any size. Each of those is a distinct cost on the adopting
/// side — the entry count is a per-member `get_verified` and a per-member
/// `artifacts` reachability walk, the byte count is one read — so neither bound
/// implies the other and a single field would have to be a claim wider than its
/// mechanism for one of them.
pub const CAPSULE_RESULT_ENTRIES: u32 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleBudgets {
    pub wall_time_ms: u64,
    /// The COMBINED capture bound — `stdout`+`stderr` TOGETHER. Enforced by the
    /// provider against its spool (provider protocol v6's
    /// [`kata_provider_protocol::CaptureSpec::limit_bytes`]): a stage whose two
    /// spool files pass it is KILLED and reported `capture_exceeded`. Folded
    /// into the capsule id, so a pack that promises a bigger capture runs a
    /// different capsule.
    pub output_bytes: u64,
    pub memory_bytes: u64,
    pub process_count: u32,
    /// Total bytes the published RESULT TREE may carry. See
    /// [`CAPSULE_RESULT_BYTES`].
    pub result_bytes: u64,
    /// Entries the published RESULT TREE may carry. See
    /// [`CAPSULE_RESULT_ENTRIES`].
    pub result_entries: u32,
    /// Total bytes the `/work` DELTA — what the stage changed, added or removed
    /// relative to its input tree — may carry. CARRIED since contract v7 and
    /// hashed; enforced at delta publish (worker) and again at adoption (main).
    /// See [`CAPSULE_WORK_DELTA_BYTES`].
    #[serde(default = "default_work_delta_bytes")]
    pub work_delta_bytes: u64,
    /// Entry count of the `/work` delta, carried, hashed and enforced the same
    /// way. See [`CAPSULE_WORK_DELTA_ENTRIES`].
    #[serde(default = "default_work_delta_entries")]
    pub work_delta_entries: u32,
}

/// The `/work`-delta byte ceiling a capsule budget carries — contract v7. 64
/// MiB, the same order as [`CAPSULE_RESULT_BYTES`]: a delta is output data and
/// scales like one.
pub const CAPSULE_WORK_DELTA_BYTES: u64 = 64 * 1024 * 1024;

/// The `/work`-delta ENTRY ceiling — contract v7. 10_000, the
/// [`CAPSULE_RESULT_ENTRIES`] order: entries are the per-member cost, not the
/// bytes.
pub const CAPSULE_WORK_DELTA_ENTRIES: u32 = 10_000;

/// The highest `output_bytes=` an author may give one stage on this node —
/// `[node] output_bytes_ceiling` in `kata.toml`, 1 GiB default. A stage is the
/// authoring grain; the ceiling is the operator's answer to it.
pub const NODE_OUTPUT_BYTES_CEILING: u64 = 1 << 30;

/// `[node] work_delta_bytes_ceiling` — 1 GiB.
pub const NODE_WORK_DELTA_BYTES_CEILING: u64 = 1 << 30;

/// `[node] work_delta_entries_ceiling` — 100_000.
pub const NODE_WORK_DELTA_ENTRIES_CEILING: u32 = 100_000;

// `[node] capsule_memory_bytes_ceiling` and
// `[node] capsule_process_count_ceiling` have NO constant of this kind: a
// node either declares the bound or it declares none, and kata never
// invents one — the `Option` fields in `NodeBudgetCeilings` carry that
// verbatim.

fn default_work_delta_bytes() -> u64 {
    CAPSULE_WORK_DELTA_BYTES
}

fn default_work_delta_entries() -> u32 {
    CAPSULE_WORK_DELTA_ENTRIES
}

/// WHAT a capsule's container runs — the v8 replacement for the bare `argv`
/// field.
///
/// The variants are the two process classes the contract can state: a
/// deterministic shell vector and an AGENT turn, whose process (the capsule's
/// init, `kata-toolhost`, fixed by the turn's kind) a worker-owned adapter
/// holds a conversation with. `process.args` reads only the `Command` arm; the
/// worker runs `Agent` through its worker-owned adapter
/// (`kata_worker::agent_turn`). The two arms fold under DIFFERENT tags, so a
/// `Command` and an `Agent` never share an id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapsuleProcess {
    /// The deterministic shell class — `["sh", "-c", <rendered command>]` for a
    /// `shell` stage. `argv[0]` is a PROGRAM NAME resolved on the bound
    /// environment's PATH (the `SHELL_PROGRAM` rule — never a store path).
    Command {
        /// The argument vector the container's init execs. Non-empty, no NUL —
        /// [`Capsule::new`] runs [`refuse_unrunnable_argv`] over it.
        argv: Vec<SmolStr>,
    },
    /// An agent turn: the container's init is `kata-toolhost`, which the
    /// harness in the worker drives over live stdio for one turn.
    Agent(AgentTurnSpec),
}

/// One agent turn inside a capsule — the `Agent` arm of [`CapsuleProcess`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTurnSpec {
    /// The harness and model provider the turn runs under.
    pub adapter: AdapterKind,
    /// The vendor's model selection, when the stage declared one. `Some("")`
    /// is refused at [`Capsule::new`] (`capsule_agent_model_empty`): the
    /// vendor's default is spelled `None`, so an empty string is a declared
    /// selection that names nothing — and `None` and `Some("")` hashing alike
    /// would let two capsules disagree about a declared field while sharing an
    /// id.
    pub model: Option<SmolStr>,
    /// The model's reasoning-effort selection, when the node's
    /// `[agents.<label>] reasoning_effort` declared one — an opaque
    /// pass-through spelling the embedded harness delivers as its reasoning
    /// setting.
    /// `None` sends nothing — the harness's own default applies. Folded into
    /// the capsule id ONLY when `Some` (unlike `model`, `None` writes no
    /// field at all), so a pre-effort capsule's id never rotates against a
    /// new spec that declares none. `Some("")` folds `reasoning_effort:""`
    /// — distinct from `None` by construction, so it needs no emptiness
    /// door of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<SmolStr>,
    /// The strict structured-output schema the vendor is sent for the turn's
    /// answer — [`crate::strict_output_schema::strict_output_schema`] of the
    /// stage's `produces=` contract, the same contract kata validates the
    /// answer against. `Some` only for a kind that
    /// [carries one](AdapterKind::carries_strict_output_schema) and a contract
    /// that renders strictly; `None` sends no schema and the turn keeps the
    /// prompt path. A schema on any other kind is refused at [`Capsule::new`]
    /// (`capsule_agent_output_schema_uncarried`): the capsule would claim a
    /// constraint the vendor never sees. Folded into the capsule id ONLY when
    /// `Some`, as its canonical JSON bytes, so a turn sent no schema hashes as
    /// though the field did not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// The rendered prompt, a durable CAS blob artifact (`Private`).
    pub prompt: ArtifactId,
    /// The credential the WORKER resolves at dispatch for this turn —
    /// the node config's `[agents.<label>] credential = { mode, source }` as a
    /// REFERENCE (mode + source kind), never a value. `None` declares no
    /// credential, which every nanocode door refuses `credential_undeclared`.
    /// Folded into the capsule id — two turns differing only in WHICH source
    /// they resolve are different stages.
    #[serde(default)]
    pub credential: Option<TurnCredentialRef>,
    /// The NON-SECRET environment the tool host and the tools it starts run
    /// under — `[agents.<label>] env = { … }`, identity-hashed and validated
    /// at [`Capsule::new`] (`capsule_agent_env_*`, the shared
    /// [`refuse_declared_agent_env`] door CHECK also runs): no name kata
    /// itself renders or reserves ([`kata_rendered_env`] — `PATH`, `HOME`, the
    /// egress plumbing's eight, `XDG_RUNTIME_DIR`; a name kata renders would
    /// shadow or be shadowed), no
    /// empty key, no `=` or NUL anywhere, and no credential-shaped names
    /// (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `AUTH_*`) — a secret
    /// declared here would bake into the capsule id, which is why the turn's
    /// credential travels in-process to the harness and never in identity.
    /// An empty map is the honest `no env` answer.
    #[serde(default)]
    pub env: std::collections::BTreeMap<SmolStr, SmolStr>,
}

/// The credential the worker lifts for an agent turn — WHERE it reads, never
/// WHAT. The value is loaded into the worker and carried to the harness
/// in-process; it never reaches the capsule or a durable record: the reference
/// is durable, the token is not. An `env:<VAR>` value is also in the worker's
/// own process environment, and the provider spawn does not clear that
/// environment, so `kata-provider-youki` and the pinned youki it runs hold it
/// too; the container init does not inherit it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnCredentialRef {
    /// `api_key` | `subscription` — which metering rule the turn's usage
    /// reports under (a subscription credential has no per-token price an
    /// estimate can bound — `MeteredCost::Unavailable`, never Estimated).
    pub mode: crate::metering::CredentialMode,
    /// Where the worker reads it: `kata_login` for kata's own login, or
    /// `env:<VAR>` for an API key the operator's environment supplies.
    pub source: CredentialSource,
}

/// The credential sources [`TurnCredentialRef::source`] admits — a closed
/// set. kata reads no other tool's login: its own login is the one credential
/// it holds itself, and an API key comes from the operator's environment.
/// Either is loaded into the worker and carried to the harness in-process,
/// never into the capsule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialSource {
    /// kata's OWN login for a kind's provider — a file kata writes on an
    /// explicit operator login, never another tool's. No path: the worker's
    /// credential source names the directory, and the kind names the provider.
    KataLogin,
    /// An API key the operator's environment supplies, named by variable —
    /// loaded into the worker, never mounted and never durable.
    EnvVar {
        /// The variable name — a machine fact the node declares, so it is
        /// identity (a different variable is a different credential source).
        var: SmolStr,
    },
}

/// The POSIX environment-variable name shape — `[A-Za-z_][A-Za-z0-9_]*`, the
/// charset a `KEY=value` env entry can carry unambiguously. `=` and NUL
/// cannot occur inside the charset, so a name passing this reaches the
/// container's `process.env` vector as exactly one entry for exactly the
/// variable declared.
#[must_use]
pub fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The env names kata's egress plumbing renders into `process.env` —
/// `EgressPlumbing::guest_env` in `kata_worker`, in this order — stated here
/// once so the declared-env refusal, the `env:<VAR>` reserved set and the
/// plumbing itself cannot drift apart on eight spellings.
///
/// Every proxy variable a common client reads, in both casings: curl reads
/// ONLY the lowercase `http_proxy` for an `http://` URL, either casing of
/// `https_proxy`, and `ALL_PROXY`/`all_proxy` for any scheme without its own
/// variable; undici and reqwest read the uppercase pair. A spelling kata left
/// unset would send that client direct, where the empty namespace fails it as
/// `ENETUNREACH` instead of the proxy's named refusal — and a spelling left
/// unreserved would let an authored `env` shadow kata's value.
pub const EGRESS_PLUMBING_ENV: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// The names an `env:<VAR>` credential source may NOT carry — every name
/// kata's own boundary plumbing renders into a capsule's `process.env`, and
/// the one more the worker keeps for its own clients:
///
/// * `PATH` — the bound environment's `path_prepend` owns it;
/// * the eight proxy names, `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` /
///   `NO_PROXY` in both casings — the egress plumbing's
///   ([`EGRESS_PLUMBING_ENV`], `EgressPlumbing::guest_env`);
/// * `HOME` — the toolhost init renders it;
/// * [`USER_MANAGER_ENV`] (`XDG_RUNTIME_DIR`) — the worker passes it, with
///   `PATH`, to the user-manager clients it starts (`systemd-run`, `systemctl`),
///   so a key under it would reach them.
///
/// Built from the egress constant, never spelled out again. The worker reads
/// an `env:<VAR>` source from its own process environment, where each of these
/// names holds a host plumbing value (the worker's own `PATH`, `HOME`, proxy
/// setting or runtime directory), never an API key: a source naming one would
/// hand that value to the harness as the key.
pub const CREDENTIAL_ENV_RESERVED: &[&str] = &[
    "PATH",
    EGRESS_PLUMBING_ENV[0],
    EGRESS_PLUMBING_ENV[1],
    EGRESS_PLUMBING_ENV[2],
    EGRESS_PLUMBING_ENV[3],
    EGRESS_PLUMBING_ENV[4],
    EGRESS_PLUMBING_ENV[5],
    EGRESS_PLUMBING_ENV[6],
    EGRESS_PLUMBING_ENV[7],
    "HOME",
    USER_MANAGER_ENV,
];

/// The variable the worker keeps, beside `PATH`, for the user-manager clients it
/// starts (`systemd-run`, `systemctl`; `kata_worker`'s `SYSTEMD_RUN_ENV`), which
/// cannot reach the user manager without it. Reserved in both env channels, so no
/// `env:` key and no declared env value is ever spelled under it.
pub const USER_MANAGER_ENV: &str = "XDG_RUNTIME_DIR";

/// Which of kata's own channels renders a name into a turn's `process.env` —
/// the owner [`refuse_declared_agent_env`] names when a declared `env` key
/// collides with it. Each arm is the channel that WRITES the name for the turn
/// under judgement, so the refusal points the operator at what actually owns
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KataEnvChannel {
    /// `PATH` — the bound environment's `path_prepend`.
    EnvironmentPath,
    /// `HOME`: the capsule bundle renders it for the tool host, whatever the
    /// credential.
    ToolhostInit(AdapterKind),
    /// The egress plumbing's eight ([`EGRESS_PLUMBING_ENV`]).
    EgressPlumbing,
    /// [`USER_MANAGER_ENV`]: not rendered into the capsule, but the worker's
    /// own, kept for its user-manager clients.
    UserManagerClients,
}

impl KataEnvChannel {
    /// The refusal's clause naming this channel as the name's owner.
    fn renders(self) -> String {
        match self {
            Self::EnvironmentPath => {
                "the bound environment's `path_prepend` renders `PATH`".to_owned()
            }
            Self::ToolhostInit(kind) => format!(
                "a `{}` turn's capsule init, `kata-toolhost`, renders `HOME` for the tool host",
                kind.as_label()
            ),
            Self::EgressPlumbing => "the egress plumbing renders the proxy names".to_owned(),
            Self::UserManagerClients => format!(
                "the worker keeps `{USER_MANAGER_ENV}` for its user-manager clients \
                 (`systemd-run`, `systemctl`)"
            ),
        }
    }
}

/// Every env name kata itself renders into this turn's `process.env`, each
/// with the [`KataEnvChannel`] that renders it: `PATH` (the bound
/// environment's `path_prepend`), `HOME` (the toolhost init), and the egress
/// plumbing's eight ([`EGRESS_PLUMBING_ENV`] — rendered only on an `Egress`
/// capsule but refused regardless: the names are kata's channel on every
/// network posture, and a declared `NO_PROXY` on an `Offline` capsule would
/// still be a claim sitting in identity) — and [`USER_MANAGER_ENV`], which kata
/// does not render but reserves in both env channels.
///
/// The declared `env` may name none of these: a name kata renders would either
/// shadow or be shadowed. `adapter` rather than the whole turn, so the
/// assembly door (`Capsule::new`) and CHECK judge the same set from the same
/// input — CHECK holds a node declaration, not a minted turn.
#[must_use]
pub fn kata_rendered_env(adapter: AdapterKind) -> BTreeMap<SmolStr, KataEnvChannel> {
    let mut names = BTreeMap::new();
    names.insert(SmolStr::new_static("PATH"), KataEnvChannel::EnvironmentPath);
    names.insert(
        SmolStr::new_static("HOME"),
        KataEnvChannel::ToolhostInit(adapter),
    );
    for name in EGRESS_PLUMBING_ENV {
        names.insert(SmolStr::new_static(name), KataEnvChannel::EgressPlumbing);
    }
    names.insert(
        SmolStr::new_static(USER_MANAGER_ENV),
        KataEnvChannel::UserManagerClients,
    );
    names
}

/// A [`Capsule::new`]-equal judgement on the declared env alone, run from
/// the turn's own `env` map at capsule assembly AND from CHECK against the
/// node's `[agents.<label>] env` — so a bad declaration is refused at
/// admission under the same names instead of at dispatch.
///
/// `rendered` is [`kata_rendered_env`] for the turn under judgement (or the
/// same set built from the node's adapter and credential declaration at
/// CHECK).
///
/// The refused set, in order: an empty / `=`- / NUL-key
/// (`capsule_agent_env_key_invalid`), a name kata renders — `PATH`, the
/// egress plumbing's, the toolhost init's `HOME` — or reserves
/// (`XDG_RUNTIME_DIR`) (`capsule_agent_env_channel_owned`, naming the
/// [`KataEnvChannel`] that renders it), a credential-shaped name
/// (`capsule_agent_env_secret_named`: `*_KEY`, `*_TOKEN`, `*_SECRET`,
/// `*_PASSWORD`, `AUTH_*`), and a NUL inside a value
/// (`capsule_agent_env_value_invalid`).
pub fn refuse_declared_agent_env(
    env: &std::collections::BTreeMap<SmolStr, SmolStr>,
    rendered: &BTreeMap<SmolStr, KataEnvChannel>,
) -> KataResult<()> {
    for (key, value) in env {
        if key.is_empty() || key.contains('=') || key.contains('\0') {
            return Err(KataError::Validation(format!(
                "capsule_agent_env_key_invalid: `env` key `{key}` is not a valid variable name — a `KEY=VALUE` spelled through the key would smuggle a second pair into identity"
            )));
        }
        if let Some(channel) = rendered.get(key) {
            let channel = channel.renders();
            return Err(KataError::Validation(format!(
                "capsule_agent_env_channel_owned: `env.{key}` names a channel kata owns — \
                 {channel}; the declared env is the node's channel and cannot name what kata \
                 renders for itself"
            )));
        }
        let upper = key.to_uppercase();
        if upper.ends_with("_KEY")
            || upper.ends_with("_TOKEN")
            || upper.ends_with("_SECRET")
            || upper.ends_with("_PASSWORD")
            || upper.starts_with("AUTH_")
        {
            return Err(KataError::Validation(format!(
                "capsule_agent_env_secret_named: `env.{key}` looks like a credential name — a secret declared on the turn would bake into the capsule id. Credentials ride `credential = {{ mode, source }}` and the worker's derived channel, never the declared env"
            )));
        }
        if value.contains('\0') {
            return Err(KataError::Validation(format!(
                "capsule_agent_env_value_invalid: `env.{key}` carries a NUL byte — the OCI spec's env list is NUL-terminated strings"
            )));
        }
    }
    Ok(())
}

/// Why `var` cannot name an `env:<VAR>` credential source — `None` means
/// admissible. One phrase for the refusal text; the caller prefixes the
/// refusal's name (`credential_undeclared`) because the refused set is the
/// caller's contract, not this function's.
#[must_use]
pub fn credential_env_refusal(var: &str) -> Option<String> {
    if !is_env_var_name(var) {
        return Some(format!(
            "`env:{var:.160}` is not a POSIX environment-variable name — the declared channel \
             accepts `[A-Za-z_][A-Za-z0-9_]*`, and anything else renders as a `process.env` entry \
             that is malformed, splits into two entries, or carries NUL"
        ));
    }
    if var == USER_MANAGER_ENV {
        return Some(format!(
            "`env:{var}` names the variable the worker keeps for its user-manager clients \
             (`systemd-run`, `systemctl`), which reach the user manager through it — a key \
             under it would reach those processes, and their value is no key"
        ));
    }
    if CREDENTIAL_ENV_RESERVED.contains(&var) {
        return Some(format!(
            "`env:{var}` names a channel kata's own boundary plumbing owns ({CREDENTIAL_ENV_RESERVED:?} \
             is the whole set) — the credential would either shadow the plumbing's value or be \
             shadowed by it, and both are misdelivery, not delivery"
        ));
    }
    None
}

/// The refusal of a credential mode the adapter kind cannot be served under in
/// this build ([`AdapterKind::serves_credential_mode`]): exactly
/// `nanocode_anthropic` under `subscription`, whatever the source. Refused at
/// CHECK (`refuse_agent_stage_under_capsule_profile`, the first credential door
/// after `credential_undeclared`) and at capsule assembly; `kata doctor`
/// names it.
///
/// [`AdapterKind::serves_credential_mode`]: crate::agent::AdapterKind::serves_credential_mode
pub const CREDENTIAL_MODE_UNSUPPORTED: &str = "credential_mode_unsupported";

/// The one rendering of [`CREDENTIAL_MODE_UNSUPPORTED`]. `subject` names what
/// declared the credential (`stage "x" selects agent `y`, whose`).
#[must_use]
pub fn credential_mode_unsupported(
    subject: &str,
    kind: crate::agent::AdapterKind,
    mode: crate::metering::CredentialMode,
) -> String {
    format!(
        "{CREDENTIAL_MODE_UNSUPPORTED}: {subject} `credential.mode = \"{mode}\"` cannot serve \
         adapter `{adapter}` — kata holds no Claude subscription login in this build. Run \
         `kata login anthropic --api-key` and declare `mode = \"api_key\"`",
        mode = mode.as_label(),
        adapter = kind.as_label(),
    )
}

/// The `credential_undeclared` refusal of an agent that declares NO
/// credential. A turn's model
/// calls are served by the credential its block declares and by nothing else
/// (its capsule holds no vendor login to fall back on), so the absence is
/// refused before any turn is issued: at CHECK
/// (`refuse_agent_stage_under_capsule_profile`), at capsule assembly and by the
/// worker's resolver before the container, and `kata doctor`'s
/// `agent_backends` row names it. The recourse names the kind's `kata login`.
/// `subject` names what declared the agent (`stage "x" selects agent `y`,
/// whose `[agents.y]``, or the capsule's turn on a worker).
#[must_use]
pub fn harness_credential_undeclared(subject: &str, kind: crate::agent::AdapterKind) -> String {
    use crate::agent::AdapterKind;
    let recourse = match kind {
        AdapterKind::NanocodeOpenai => {
            "Run `kata login openai` and declare `credential = { mode = \"subscription\", \
             source = \"kata_login\" }` (or `kata login openai --api-key` with `mode = \
             \"api_key\"`, or `mode = \"api_key\", source = \"env:OPENAI_API_KEY\"`)"
        }
        AdapterKind::NanocodeAnthropic => {
            "Run `kata login anthropic --api-key` and declare `credential = { mode = \
             \"api_key\", source = \"kata_login\" }` (or `source = \
             \"env:ANTHROPIC_API_KEY\"`)"
        }
    };
    format!(
        "credential_undeclared: {subject} declares no `credential`, and adapter `{adapter}`'s \
         harness runs in the worker on the credential the node declares and nothing else — \
         its capsule holds no vendor login. {recourse}",
        adapter = kind.as_label(),
    )
}

impl CredentialSource {
    /// The `source` spelling [`KataConfig`]'s `[agents.<label>] credential`
    /// declares: `kata_login` | `env:<VAR>`. `None` for anything else — the caller
    /// names the refusal;
    /// [`credential_env_refusal`] states why an `env:` name failed.
    #[must_use]
    pub fn from_declared(declared: &str) -> Option<Self> {
        match declared {
            "kata_login" => Some(Self::KataLogin),
            _ => declared
                .strip_prefix("env:")
                .filter(|var| credential_env_refusal(var).is_none())
                .map(|var| Self::EnvVar {
                    var: SmolStr::new(var),
                }),
        }
    }

    /// This source's spelling — the inverse of [`Self::from_declared`], so a
    /// refusal can echo exactly what the node declared.
    #[must_use]
    pub fn as_declared(&self) -> String {
        match self {
            Self::KataLogin => "kata_login".to_owned(),
            Self::EnvVar { var } => format!("env:{var}"),
        }
    }
}

/// The `user.name`/`user.email` pair a git view's scratch repository is
/// configured with — contract v10.
///
/// The IDENTITY kata INHERITS from the jj backend's git settings, carried so
/// the worker never resolves a host fact inside the capsule and the capsule id
/// folds which identity the agent's commits would record. Not the
/// [`crate::commit_identity`] sandbox-agent pair: that identity exists so an
/// agent-authored commit can be REFUSED at a publish point, while this one
/// exists because the view's commits are disposable evidence that never reach
/// the host repository — the operator's own answer, stated on the capsule, is
/// the honest config.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitIdentity {
    /// `user.name`.
    pub name: SmolStr,
    /// `user.email`.
    pub email: SmolStr,
}

/// A branch ref a git view writes: the SHORT name (`main`, never
/// `refs/heads/main`) and the commit it points at, in the backend's own hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitViewRef {
    /// The short branch name.
    pub name: SmolStr,
    /// The commit the branch points at.
    pub commit: SmolStr,
}

/// The disposable git repository view an agent capsule's `/work` presents —
/// contract v10's `Capsule::git_view` payload.
///
/// Everything the worker needs to build `/git` and `/work/.git` and nothing it
/// does not: the history artifact (reachable objects of the base commit, as
/// packs), the base commit the scratch branch and the base branch's short name
/// both point at, that branch's name, and the identity `git` in the guest
/// commits under. There is deliberately no path, no remote and no object id of
/// the host's — the view is CAS bytes and names, and the worker materializes
/// it without ever opening the host repository.
///
/// `Some` only on a capsule that maps `/work` — an agent's, or a shell stage's whose profile
/// `requires` `git`; [`Capsule::new`] refuses a view on a capsule with no `/work`
/// (`git_view_requires_work`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleGitView {
    /// The published history tree artifact (`objects/pack/pack-*.{pack,idx}`,
    /// `index`, `shallow` when depth-limited), materialized read-only at
    /// `/git-history` and reachable through `/git/objects/info/alternates`.
    /// The full ref — not the bare id — because the worker fetches it by
    /// object address and size, with no metadata lookup.
    pub history: ArtifactRef,
    /// The base commit the view is rooted at, in the backend's own hex
    /// spelling — the git object id `refs/heads/kata/<execution-id>` points to.
    pub base_commit: SmolStr,
    /// The view's second scratch ref, off the execution's frozen target — so
    /// `git diff main` and `git log main..` answer the way the operator's
    /// repository would: trunk's name at the base for a trunk target, a pull
    /// request's base branch at its compare base. `None` writes no second ref.
    pub branch: Option<GitViewRef>,
    /// The committer identity the scratch repository's config carries.
    pub identity: GitIdentity,
}

/// The confined `/work` subset a capsule's container is materialized with. `Some`
/// means the stage declared `reads=` and was
/// derived confinable (`should_confine_to_declared_inputs`): the worker writes
/// only the `/work` members [`Self::covers`] answers true for, and the
/// post-run delta treats every base member the view does not cover as
/// UNCHANGED — never a deletion — so confinement cannot read as the stage
/// erasing the rest of the tree.
///
/// `include` holds the closure's OWN spellings — the declared `reads=`
/// patterns, unioned with `produces_files=` when the workspace is writable —
/// sorted and deduplicated by [`Capsule::new`]. They are PATTERNS, not resolved
/// paths: the capsule is minted before any tree is read, so the member set a
/// pattern names is decided at materialization against the head's manifest —
/// which is also the moment the two semantics agree, because
/// `resolve_read_closure`'s `glob::glob` over the worktree and `covers`'s
/// `glob::Pattern` over the manifest both answer "the entries the pattern
/// names".
///
/// `Some` only on a capsule that maps `/work` — [`Capsule::new`] refuses the
/// pair `work_view_requires_work`, the same shape `git_view_requires_work`
/// takes and for the same reason: a view with no tree to view is a claim the
/// bundle cannot render.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleWorkView {
    /// The declared read/write closure, worktree-relative globs, sorted and
    /// deduplicated at mint. `capsule_assembly` writes the stage's `reads`
    /// (plus `produces_files` under a writable workspace); it is never edited
    /// after.
    pub include: Vec<SmolStr>,
}

/// The glob match options the view's pattern arm uses — `*` and `?` respect
/// `/` while `**` spans directories, the same semantics `resolve_read_closure`
/// gets for free by globbing the filesystem component-wise and the same
/// constant `output_closure`'s declared matcher compiled with.
const WORK_VIEW_GLOB_OPTIONS: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

impl CapsuleWorkView {
    /// Does the view cover the `/work` member at worktree-relative `path`?
    ///
    /// The rule is the shim's, restated against manifest paths rather than
    /// filesystem entries:
    ///
    /// * an entry naming no metacharacter is a SCOPE — it covers `path` when
    ///   `path` is it or lies beneath it, the parity of a Landlock rule landed
    ///   on the path itself (a matched directory grants its whole subtree);
    /// * an entry with `*`, `?` or `[` is a GLOB — it covers `path` when it
    ///   matches `path` or any ANCESTOR directory of `path` (the same dir-grant
    ///   parity: `*` covers `src/a.rs` because it matches `src`), or when its
    ///   trailing `/**` prefix scopes over `path`;
    /// * a pattern that is absolute, carries a `..` component, or normalizes to
    ///   nothing is dropped at match — `resolve_read_closure` drops the same
    ///   patterns from the Landlock grant — while a pattern that is only `.`
    ///   components names the tree root and covers everything.
    #[must_use]
    pub fn covers(&self, path: &str) -> bool {
        self.include
            .iter()
            .any(|pattern| view_pattern_covers(pattern.as_str(), path))
    }
}

/// The glob metacharacters that distinguish a glob `include` entry from a
/// scope — `pub` because the materializer splits a glob's literal prefix off
/// the same set the matcher compiles on.
pub const WORK_VIEW_GLOB_METACHARS: &[char] = &['*', '?', '['];

/// One `include` entry's normalized worktree-relative components — the ONE
/// normalization every consumer of the view reads: [`CapsuleWorkView::covers`]
/// matching members and the materializer's enclosing-directory pass alike.
///
/// `None` for a pattern that can never name a member — empty, absolute, or
/// escaping with `..`; the same set `normalize_stage_path_closure` refuses at
/// pack load and `resolve_read_closure` drops at resolve. An entry reduced to
/// no components (a `.` or `./` spelling) returns `Some(vec![])` — the tree
/// root, which covers everything and creates nothing.
#[must_use]
pub fn work_view_pattern_components(pattern: &str) -> Option<Vec<&str>> {
    let trimmed = pattern.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('/')
        || trimmed
            .split(['/', '\\'])
            .any(|component| component == "..")
    {
        return None;
    }
    Some(
        trimmed
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
            .collect(),
    )
}

/// One `include` entry against one manifest path — the per-pattern half of
/// [`CapsuleWorkView::covers`], which documents the rule.
fn view_pattern_covers(pattern: &str, path: &str) -> bool {
    let Some(components) = work_view_pattern_components(pattern) else {
        return false;
    };
    if components.is_empty() {
        // `.`/`./` names the tree root — the closure resolves to everything.
        return true;
    }
    let normalized = components.join("/");
    if !normalized.contains(WORK_VIEW_GLOB_METACHARS) {
        return path == normalized
            || path
                .strip_prefix(normalized.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
    }
    let Ok(compiled) = glob::Pattern::new(&normalized) else {
        // An uncompilable pattern covers nothing — the shim's glob-walk would
        // have skipped it the same way.
        return false;
    };
    // `dir/**` carries its literal prefix — the subtree is covered even where
    // the compiled pattern's own `**` edge cases would not reach it.
    let dir_prefix = normalized
        .strip_suffix("/**")
        .filter(|prefix| !prefix.contains(WORK_VIEW_GLOB_METACHARS));
    let mut candidate = path;
    loop {
        if compiled.matches_with(candidate, WORK_VIEW_GLOB_OPTIONS)
            || dir_prefix.is_some_and(|prefix| {
                candidate == prefix
                    || candidate
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/'))
            })
        {
            return true;
        }
        let Some((ancestor, _)) = candidate.rsplit_once('/') else {
            return false;
        };
        candidate = ancestor;
    }
}

/// WHAT the capsule's container may reach over the network — a DECLARED
/// posture, so a bundle planner can refuse rather than silently grant.
///
/// `Egress` runs under the worker-owned allowlisting `CONNECT` proxy: two
/// `createContainer` hooks raise the guest's `lo` and hand the guest-side
/// listener fd to the worker over `SCM_RIGHTS`, and the worker's
/// `EgressProxy` accepts on that inherited socket.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapsuleNetwork {
    /// The container gets its own empty network namespace — no interfaces but a
    /// loopback the runtime itself must bring up. The default.
    #[default]
    Offline,
    /// A declared egress allowlist: the exact `host:port` authorities the
    /// stage's traffic may reach through the worker's proxy. Refused EMPTY —
    /// `capsule_egress_allowlist_empty` — because `Offline` is the spelling for
    /// "no egress".
    Egress {
        /// Sorted; every entry already validated by [`EgressAuthority::new`].
        allowlist: BTreeSet<EgressAuthority>,
    },
}

/// What a capsule's network IS, in the words every operator face states it in:
/// `kata check`'s per-stage preflight, the execution record `kata run show` and
/// `GET /executions/{id}` serve, and the `check`/`observe` operation contract.
///
/// [`Self::of`] reads the capsule's OWN [`CapsuleNetwork`] — the allowlist the
/// worker's `CONNECT` proxy enforces. It never re-derives an allowlist, so a
/// posture cannot name an authority the capsule does not carry, nor omit one
/// it does. An agent capsule's network is exactly what its stage authored: the
/// harness's model calls leave from the process hosting the worker, so the
/// capsule opens no vendor endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "posture", rename_all = "snake_case", deny_unknown_fields)]
pub enum CapsuleNetworkPosture {
    /// No egress at all: the container's own empty network namespace.
    Offline,
    /// The stage authored `net = "host"`: the node's `egress_allow`.
    Egress {
        /// The exact `host:port` authorities, sorted as the capsule holds them.
        allowlist: Vec<String>,
    },
}

impl CapsuleNetworkPosture {
    /// Label `network` — a capsule's own declared network.
    #[must_use]
    pub fn of(network: &CapsuleNetwork) -> Self {
        let CapsuleNetwork::Egress { allowlist } = network else {
            return Self::Offline;
        };
        Self::Egress {
            allowlist: allowlist
                .iter()
                .map(|authority| format!("{}:{}", authority.host(), authority.port()))
                .collect(),
        }
    }

    /// The posture's wire label: `offline` or `egress`.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Egress { .. } => "egress",
        }
    }

    /// The exact authorities the capsule may reach — empty for [`Self::Offline`].
    #[must_use]
    pub fn allowlist(&self) -> &[String] {
        match self {
            Self::Offline => &[],
            Self::Egress { allowlist } => allowlist,
        }
    }

    /// One line for a text face: the label, then the authorities.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Offline => self.label().to_owned(),
            Self::Egress { allowlist } => format!("{} ({})", self.label(), allowlist.join(", ")),
        }
    }
}

/// One exact `host:port` authority an [`CapsuleNetwork::Egress`] allowlist may
/// name — the SAME rule `kata_worker::egress_proxy::EgressAllowlist::exact`
/// applies, moved here so the capsule field and the proxy's matching share ONE
/// rule rather than two spellings of it.
///
/// # What an entry is, and what it is not
///
/// An authority is an EXACT `host:port` pair — no wildcard, no scheme, no path.
/// It trusts the NAME as resolved at connect time, not an address: the
/// resolution caveat lives on `EgressAllowlist`'s docs where the resolve
/// actually happens.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EgressAuthority {
    host: SmolStr,
    port: u16,
}

impl EgressAuthority {
    /// Construct one exact authority, applying the allowlist rule.
    ///
    /// # Refused set
    ///
    /// An empty host; a host carrying `*` or `?` (a pattern, refused rather
    /// than matched literally); a host over 253 bytes; a host that is not a
    /// hostname or an IP literal — CHARSET-CHECKED: every label must be
    /// non-empty ASCII alphanumeric-or-`-`, must not begin or end with `-`, and
    /// the whole host must not begin or end with `.`; an IPv6 literal must be
    /// bracketed (`[::1]`), the only spelling a `CONNECT` target can carry; and
    /// port 0 — `pick one for me` to `bind`, unconnectable to `connect`.
    ///
    /// The charset check enumerates what is PERMITTED rather than screening
    /// what is forbidden, so a new smuggling character is refused by default.
    /// Hosts are stored lowercase: DNS names are case-insensitive, and an
    /// allowlist that compared case would refuse the same host a client
    /// spelled differently.
    ///
    /// # Errors
    /// [`KataError::Validation`] naming which clause refused.
    pub fn new(host: impl AsRef<str>, port: u16) -> KataResult<Self> {
        let host = host.as_ref();
        let refuse = |reason: String| {
            Err(KataError::Validation(format!(
                "egress authority refused: {reason}"
            )))
        };
        if host.is_empty() {
            return refuse("the host is EMPTY".to_owned());
        }
        if host.contains(['*', '?']) {
            return refuse(format!(
                "{host}:{port} looks like a PATTERN, and an authority is an exact host:port pair. Refusing rather than treating the metacharacter as a literal hostname character, which would silently allow nothing while reading as a wildcard"
            ));
        }
        if let Err(why) = check_egress_host_charset(host) {
            return refuse(format!(
                "{host}:{port} is not a hostname or an IP literal: {why}. The permitted charset is enumerated rather than a list of forbidden metacharacters, because a screen a new smuggling character is absent from admits it"
            ));
        }
        if port == 0 {
            return refuse(format!(
                "{host}:0 names port 0, which is `pick one for me` to `bind` and unconnectable to `connect`"
            ));
        }
        Ok(Self {
            host: SmolStr::new(host.to_ascii_lowercase()),
            port,
        })
    }

    /// Parse one `host:port` SPELLING into an authority — the rule the one
    /// declaration surface, `[node] egress_allow`, is read through at config
    /// load and at boot.
    ///
    /// The split is the LAST `:` (`rsplit_once`), so a bracketed IPv6 literal
    /// survives (`[::1]:443`), and an unbracketed one fails inside
    /// [`Self::new`]'s charset check rather than being host-split into
    /// something the proxy would match differently.
    ///
    /// # Errors
    /// [`KataError::Validation`] when the spelling has no `:` at all, when the
    /// port does not parse as a `u16`, or whatever [`Self::new`] refuses.
    pub fn from_authority_str(spelling: &str) -> KataResult<Self> {
        let (host, port) = spelling.rsplit_once(':').ok_or_else(|| {
            KataError::Validation(format!("`{spelling}` is not a `host:port` spelling"))
        })?;
        let port = port.parse::<u16>().map_err(|error| {
            KataError::Validation(format!("`{spelling}`: the port is not a u16: {error}"))
        })?;
        Self::new(host, port)
    }

    /// The normalized (lowercase) host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// The hostname/IP-literal charset for [`EgressAuthority::new`].
fn check_egress_host_charset(host: &str) -> Result<(), String> {
    /// RFC 1035's limit on a domain name's presentation form.
    const MAX_HOST_BYTES: usize = 253;

    if host.len() > MAX_HOST_BYTES {
        return Err(format!(
            "it is {} bytes, past the {MAX_HOST_BYTES}-byte limit on a domain name",
            host.len()
        ));
    }
    if let Some(inner) = host.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return Err("it opens a `[` it does not close".to_owned());
        };
        return inner
            .parse::<std::net::Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| "the bracketed form must hold an IPv6 literal".to_owned());
    }
    if host.contains(':') {
        return Err(
            "it carries a `:`. An IPv6 literal must be BRACKETED, because that is the only spelling a CONNECT target can carry — an unbracketed one would be split into host:port by the request parser, so the two surfaces would disagree about what was allowed"
                .to_owned(),
        );
    }
    if host.starts_with('.') || host.ends_with('.') {
        return Err("it begins or ends with `.`, so one of its labels is empty".to_owned());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("it carries an empty label (`..`)".to_owned());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("the label `{label}` begins or ends with `-`"));
        }
        if let Some(bad) = label
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && *c != '-')
        {
            return Err(format!(
                "the label `{label}` carries {bad:?}, which is not an ASCII alphanumeric or `-`"
            ));
        }
    }
    Ok(())
}

/// Raw mirror of [`EgressAuthority`], decoded so [`EgressAuthority::new`]'s
/// rule runs on deserialize too — a capsule's allowlist that skipped
/// construction would carry an entry the rule refuses.
#[derive(Deserialize)]
struct EgressAuthorityRaw {
    host: SmolStr,
    port: u16,
}

impl<'de> Deserialize<'de> for EgressAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = EgressAuthorityRaw::deserialize(deserializer)?;
        Self::new(raw.host.as_str(), raw.port).map_err(serde::de::Error::custom)
    }
}

/// The [`CapsuleProcess`] fold, shared by `Capsule::new` and
/// [`Capsule::reuse_key`] so the id and the cache key can never disagree about
/// the shape. The VARIANT TAG is folded first, domain-separating the arms: a
/// `Command`'s argument vector and an `Agent`'s turn fields never fold under
/// one tag.
fn hash_capsule_process(hasher: &mut blake3::Hasher, process: &CapsuleProcess) {
    match process {
        CapsuleProcess::Command { argv } => {
            hash_field(hasher, "process", b"command");
            hash_field(hasher, "argv", &(argv.len() as u64).to_le_bytes());
            for argument in argv {
                hash_field(hasher, "argument", argument.as_bytes());
            }
        }
        CapsuleProcess::Agent(turn) => {
            hash_field(hasher, "process", b"agent");
            hash_field(hasher, "adapter", turn.adapter.as_label().as_bytes());
            match &turn.model {
                Some(model) => hash_field(hasher, "model", model.as_bytes()),
                None => hash_field(hasher, "model", &[]),
            }
            // `reasoning_effort` folds ONLY when declared — no `None` field
            // at all, so a turn that declares no effort hashes as though the
            // field did not exist. It is part of the reuse key
            // by construction: two turns differing only in effort are
            // different capsules and never adopt each other's answer.
            if let Some(effort) = &turn.reasoning_effort {
                hash_field(hasher, "reasoning_effort", effort.as_bytes());
            }
            // The schema folds ONLY when sent, as `serde_json`'s canonical
            // bytes (object keys in sorted order): the same contract yields the
            // same bytes, and two turns differing only in the schema the vendor
            // holds the answer to are different capsules.
            if let Some(schema) = &turn.output_schema {
                hash_field(hasher, "output_schema", schema.to_string().as_bytes());
            }
            hash_field(hasher, "prompt", turn.prompt.0.as_bytes());
            // The credential REFERENCE folds — two turns differing only in
            // WHICH login or env var they resolve are different stages.
            // The value never does: it is the worker's secret, not the
            // contract's.
            match &turn.credential {
                Some(reference) => {
                    hash_field(hasher, "credential", b"declared");
                    hash_field(hasher, "mode", reference.mode.as_label().as_bytes());
                    hash_field(hasher, "source", reference.source.as_declared().as_bytes());
                }
                None => hash_field(hasher, "credential", b"none"),
            }
            // The declared env folds in BTreeMap order — two turns differing
            // only in a variable are different stages.
            hash_field(hasher, "env", &(turn.env.len() as u64).to_le_bytes());
            for (key, value) in &turn.env {
                hash_field(hasher, "var", key.as_bytes());
                hash_field(hasher, "value", value.as_bytes());
            }
        }
    }
}

/// The [`CapsuleNetwork`] fold — see [`hash_capsule_process`]. The `Egress`
/// arm's entries fold in the `BTreeSet`'s sorted order.
fn hash_capsule_network(hasher: &mut blake3::Hasher, network: &CapsuleNetwork) {
    match network {
        CapsuleNetwork::Offline => hash_field(hasher, "network", b"offline"),
        CapsuleNetwork::Egress { allowlist } => {
            hash_field(hasher, "network", b"egress");
            hash_field(hasher, "allowlist", &(allowlist.len() as u64).to_le_bytes());
            for authority in allowlist {
                hash_field(hasher, "host", authority.host.as_bytes());
                hash_field(hasher, "port", &authority.port.to_le_bytes());
            }
        }
    }
}

/// The [`CapsuleGitView`] fold — see [`hash_capsule_process`]. `None` and
/// `Some` fold under different bytes so an absent view never aliases a
/// declared one; the history folds by its [`ArtifactRef`]'s ID, which already
/// commits to object, size and privacy.
fn hash_capsule_git_view(hasher: &mut blake3::Hasher, git_view: Option<&CapsuleGitView>) {
    match git_view {
        None => hash_field(hasher, "git_view", b"none"),
        Some(view) => {
            hash_field(hasher, "git_view", b"declared");
            hash_field(hasher, "history", view.history.id().0.as_bytes());
            hash_field(hasher, "base_commit", view.base_commit.as_bytes());
            match &view.branch {
                None => hash_field(hasher, "branch", b"none"),
                Some(branch) => {
                    hash_field(hasher, "branch", b"declared");
                    hash_field(hasher, "branch_name", branch.name.as_bytes());
                    hash_field(hasher, "branch_commit", branch.commit.as_bytes());
                }
            }
            hash_field(hasher, "identity_name", view.identity.name.as_bytes());
            hash_field(hasher, "identity_email", view.identity.email.as_bytes());
        }
    }
}

/// The [`CapsuleWorkView`] fold — see [`hash_capsule_git_view`], whose
/// `none`/`declared` split this mirrors: an absent view never aliases a
/// declared one, and each include pattern folds in the sorted order
/// [`Capsule::new`] established.
fn hash_capsule_work_view(hasher: &mut blake3::Hasher, work_view: Option<&CapsuleWorkView>) {
    match work_view {
        None => hash_field(hasher, "work_view", b"none"),
        Some(view) => {
            hash_field(hasher, "work_view", b"declared");
            hash_field(
                hasher,
                "include",
                &(view.include.len() as u64).to_le_bytes(),
            );
            for pattern in &view.include {
                hash_field(hasher, "pattern", pattern.as_bytes());
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Capsule {
    schema_version: u32,
    id: CapsuleId,
    occurrence: OccurrenceId,
    action: PreparedActionId,
    environment: EnvironmentId,
    platform: PlatformId,
    inputs: Vec<GuestMapping>,
    process: CapsuleProcess,
    network: CapsuleNetwork,
    git_view: Option<CapsuleGitView>,
    work_view: Option<CapsuleWorkView>,
    budgets: CapsuleBudgets,
}

impl Capsule {
    /// The hard ceiling on a capsule object's encoded length, for every reader of one.
    ///
    /// A capsule cannot state its own size bound: the bound has to hold BEFORE the
    /// capsule is read, and a frame's `size_bytes` is a value the sender chose. So this
    /// is a reader's own refusal, and it is generous rather than tuned — a capsule is
    /// identities, guest paths and budgets, and the largest thing in it is its mapping
    /// list. A megabyte is thousands of mappings.
    ///
    /// ONE constant because a capsule has more than one reader: the worker's
    /// `capsule_frame::resolve` and the main's `capsule_result` both read the same object,
    /// and two readers that disagreed about whether it is readable would split one
    /// capsule into a runnable half and an unsettleable half.
    pub const MAXIMUM_ENCODED_BYTES: u64 = 1024 * 1024;

    /// Inputs are sorted by guest path so identity does not depend on the order
    /// a caller happened to collect them in. Two mappings for one guest path are
    /// refused rather than ordered: which one wins would be an invented answer.
    ///
    /// # Refused set
    ///
    /// Whatever [`refuse_unrunnable_argv`] refuses over `Command`'s `argv` —
    /// plus a `CapsuleNetwork::Egress` whose
    /// allowlist is EMPTY (`capsule_egress_allowlist_empty`: `Offline` is the
    /// spelling for "no egress", so an egress that names nothing is a declared
    /// posture that says nothing), and an `Agent` turn with `model =
    /// Some("")` (`capsule_agent_model_empty`: `None` is the spelling for the
    /// vendor's default), and an `Agent` turn carrying an `output_schema` whose
    /// kind does not [carry one](AdapterKind::carries_strict_output_schema)
    /// (`capsule_agent_output_schema_uncarried`), plus whatever
    /// [`refuse_declared_agent_env`] refuses
    /// on an `Agent` turn's declared `env` — the `capsule_agent_env_*` names,
    /// including any key kata itself renders (`capsule_agent_env_channel_owned`:
    /// `PATH`, the egress plumbing's eight, the toolhost's `HOME`, or the
    /// reserved `XDG_RUNTIME_DIR`) —
    /// plus the git-view rule: a `Some` `git_view` is refused unless `/work` is
    /// among the mappings (`git_view_requires_work` — the view is a look at the
    /// working tree's history, so a capsule with no `/work` for it to describe
    /// would be carrying a claim the bundle cannot render) — and its v11
    /// sibling: a `Some` `work_view` on the same ground
    /// (`work_view_requires_work` — the view confines the tree `/work` maps,
    /// and a capsule without one claims a confinement nothing enforces).
    pub fn new(
        occurrence: OccurrenceId,
        action: PreparedActionId,
        environment: EnvironmentId,
        platform: PlatformId,
        mut inputs: Vec<GuestMapping>,
        process: CapsuleProcess,
        network: CapsuleNetwork,
        git_view: Option<CapsuleGitView>,
        budgets: CapsuleBudgets,
        mut work_view: Option<CapsuleWorkView>,
    ) -> KataResult<Self> {
        if let CapsuleProcess::Command { argv } = &process {
            refuse_unrunnable_argv(argv)?;
        }
        if let CapsuleProcess::Agent(turn) = &process
            && turn.model.as_ref().is_some_and(SmolStr::is_empty)
        {
            return Err(KataError::Validation(
                "capsule_agent_model_empty: a `Some(\"\")` model is not a name — the vendor's default selection is spelled `None`, so an empty model is a declared selection that names nothing".to_owned(),
            ));
        }
        if let CapsuleProcess::Agent(turn) = &process
            && turn.output_schema.is_some()
            && !turn.adapter.carries_strict_output_schema()
        {
            return Err(KataError::Validation(format!(
                "capsule_agent_output_schema_uncarried: a `{}` turn carries an output schema, \
                 and that adapter's protocol has no channel for one — the capsule would claim a \
                 constraint the vendor never sees",
                turn.adapter.as_label()
            )));
        }
        if let CapsuleProcess::Agent(turn) = &process {
            // The declared-env refused set, stated on the field and shared
            // with CHECK: kata's own rendered names (`PATH`, the egress
            // plumbing's, the toolhost's `HOME`) are not the node's to set; a
            // credential-shaped name would bake a secret into identity.
            refuse_declared_agent_env(&turn.env, &kata_rendered_env(turn.adapter))?;
        }
        if let CapsuleNetwork::Egress { allowlist } = &network
            && allowlist.is_empty()
        {
            return Err(KataError::Validation(
                    "capsule_egress_allowlist_empty: a capsule declaring `Egress` must name at least one authority — `Offline` is the spelling for no egress, so an empty allowlist is a posture that claims a mechanism and grants nothing"
                        .to_owned(),
                ));
        }
        inputs.sort_by(|left, right| left.guest_path.cmp(&right.guest_path));
        if let Some(duplicate) = inputs
            .windows(2)
            .find(|pair| pair[0].guest_path == pair[1].guest_path)
        {
            return Err(KataError::Validation(format!(
                "capsule maps guest path {:?} more than once",
                duplicate[0].guest_path.as_str()
            )));
        }
        if git_view.is_some()
            && !inputs
                .iter()
                .any(|input| input.guest_path.as_str() == "/work")
        {
            return Err(KataError::Validation(
                "git_view_requires_work: a capsule's git view is a look at its own /work \
                 history — admitted only on a capsule that maps /work, and this one does not"
                    .to_owned(),
            ));
        }
        if work_view.is_some()
            && !inputs
                .iter()
                .any(|input| input.guest_path.as_str() == "/work")
        {
            return Err(KataError::Validation(
                "work_view_requires_work: a capsule's work view confines the tree its /work \
                 maps — admitted only on a capsule that maps /work, and this one does not"
                    .to_owned(),
            ));
        }
        // The include list is the capsule's byte shape AND its hash input, so
        // the canonical order is established here once — a caller that
        // gathered `reads` then `produces_files` and one that gathered them
        // the other way round mint the same capsule.
        if let Some(view) = work_view.as_mut() {
            view.include.sort();
            view.include.dedup();
        }
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("capsule"), &[]);
        hash_field(&mut hasher, "occurrence", occurrence.0.as_bytes());
        hash_field(&mut hasher, "action", action.0.as_bytes());
        hash_field(&mut hasher, "environment", environment.0.as_bytes());
        hash_field(&mut hasher, "platform", platform.0.as_bytes());
        hash_field(&mut hasher, "inputs", &(inputs.len() as u64).to_le_bytes());
        for input in &inputs {
            hash_field(&mut hasher, "artifact", input.artifact.0.as_bytes());
            hash_field(
                &mut hasher,
                "guest_path",
                input.guest_path.as_str().as_bytes(),
            );
            hash_field(&mut hasher, "access", input.access.as_tag().as_bytes());
        }
        hash_capsule_process(&mut hasher, &process);
        hash_capsule_network(&mut hasher, &network);
        hash_capsule_git_view(&mut hasher, git_view.as_ref());
        hash_capsule_work_view(&mut hasher, work_view.as_ref());
        hash_field(
            &mut hasher,
            "wall_time_ms",
            &budgets.wall_time_ms.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            "output_bytes",
            &budgets.output_bytes.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            "memory_bytes",
            &budgets.memory_bytes.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            "process_count",
            &budgets.process_count.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            "result_bytes",
            &budgets.result_bytes.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            "result_entries",
            &budgets.result_entries.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            "work_delta_bytes",
            &budgets.work_delta_bytes.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            "work_delta_entries",
            &budgets.work_delta_entries.to_le_bytes(),
        );
        Ok(Self {
            schema_version: EXECUTION_CONTRACT_SCHEMA_VERSION,
            id: CapsuleId(FixedBytes(*hasher.finalize().as_bytes())),
            occurrence,
            action,
            environment,
            platform,
            inputs,
            process,
            network,
            git_view,
            work_view,
            budgets,
        })
    }

    #[must_use]
    pub const fn id(&self) -> CapsuleId {
        self.id
    }

    #[must_use]
    pub const fn occurrence(&self) -> OccurrenceId {
        self.occurrence
    }

    #[must_use]
    pub const fn action(&self) -> PreparedActionId {
        self.action
    }

    #[must_use]
    pub const fn environment(&self) -> EnvironmentId {
        self.environment
    }

    #[must_use]
    pub const fn platform(&self) -> PlatformId {
        self.platform
    }

    /// Sorted by guest path, one mapping per path.
    #[must_use]
    pub fn inputs(&self) -> &[GuestMapping] {
        &self.inputs
    }

    /// WHAT the capsule's container runs — the v8 [`CapsuleProcess`].
    ///
    /// # Why the process is in the capsule and therefore in its id
    ///
    /// A capsule names its action by [`PreparedActionId`], whose
    /// [`ActionManifest`](crate::cache::ActionManifest) `command` is a CONTENT HASH of
    /// the checked stage contract. A hash proves that two actions are the same; it
    /// cannot be `execve`d. So before v5 the bytes a container actually ran were a
    /// separate parameter of `kata_worker::oci_bundle::spec_for`, chosen by whoever
    /// called the driver — which means two capsules sharing one id could run two
    /// different programs, and a capsule id could not answer *"what did this attempt
    /// run"*. Folding the vector into the id is what makes the answer the
    /// authorization's rather than the caller's; the same argument binds an agent
    /// turn's kind, model and prompt.
    ///
    /// A `Command`'s `argv[0]` is resolved by the runtime against the `PATH`
    /// the bound Nix environment's `path_prepend` renders, so a capsule carries a
    /// PROGRAM NAME and not a host path — the same reason a mapping carries a
    /// [`GuestPath`].
    #[must_use]
    pub const fn process(&self) -> &CapsuleProcess {
        &self.process
    }

    /// The capsule's DECLARED network posture — [`CapsuleNetwork`]. Folded into
    /// the id like every field: a capsule that may reach an authority is a
    /// different capsule from one that may not.
    #[must_use]
    pub const fn network(&self) -> &CapsuleNetwork {
        &self.network
    }

    /// The capsule's git view, when it declares one — contract v10's
    /// [`CapsuleGitView`]. `Some` only on a capsule that maps `/work` (the
    /// `git_view_requires_work` refusal in [`Capsule::new`]); the
    /// worker renders it as the attempt's `/git-history` mount, its `/git`
    /// scratch repository and the `/work/.git` gitfile.
    #[must_use]
    pub const fn git_view(&self) -> Option<&CapsuleGitView> {
        self.git_view.as_ref()
    }

    /// The capsule's confined `/work` view, when it declares one — contract
    /// v11's [`CapsuleWorkView`]. `Some` only on a capsule that maps `/work`
    /// (the `work_view_requires_work` refusal in [`Capsule::new`]); the worker
    /// materializes only the members it covers and the delta treats every
    /// member it does not as unchanged.
    #[must_use]
    pub const fn work_view(&self) -> Option<&CapsuleWorkView> {
        self.work_view.as_ref()
    }

    #[must_use]
    pub const fn budgets(&self) -> CapsuleBudgets {
        self.budgets
    }

    /// EVERY field of this capsule, handed out by ONE exhaustive destructure.
    ///
    /// The accessors above are projections each caller chooses; this is the whole
    /// value. It exists for the consumer that must react to every field rather
    /// than to a chosen few — `kata_worker::oci_bundle::spec_for`, whose
    /// `config.json` IS the capsule rendered for a container runtime. Without it
    /// a field added here would leave that renderer compiling and quietly
    /// producing a bundle that ignores what the capsule says, which is the
    /// boundary-drop the provider protocol's exhaustive destructures exist to make
    /// impossible on the wire.
    #[must_use]
    pub fn fields(&self) -> CapsuleFields<'_> {
        let Self {
            schema_version,
            id,
            occurrence,
            action,
            environment,
            platform,
            inputs,
            process,
            network,
            git_view,
            work_view,
            budgets,
        } = self;
        CapsuleFields {
            schema_version: *schema_version,
            id: *id,
            occurrence: *occurrence,
            action: *action,
            environment: *environment,
            platform: *platform,
            inputs,
            process,
            network,
            git_view: git_view.as_ref(),
            work_view: work_view.as_ref(),
            budgets: *budgets,
        }
    }

    /// This capsule's CONTENT-CACHE key — see [`CapsuleReuseKey`].
    ///
    /// # Every field but the occurrence, and decided per field
    ///
    /// Derived from [`Self::fields`]' EXHAUSTIVE destructure, so a field added to a
    /// capsule fails to compile here until someone decides whether it belongs in the
    /// key. Two fields are bound to `_`, each for a stated reason:
    ///
    /// * `id` folds the occurrence, so it differs across executions by construction —
    ///   keying on it would make every lookup a miss;
    /// * `occurrence` is the one thing two reusable capsules must NOT share: it names
    ///   one execution's logical invocation, and the key exists to recognise equal work
    ///   across occurrences (the `PreparedAction` doc states the same intent for the
    ///   action: "excludes occurrence and placement").
    ///
    /// `schema_version` is not hashed as a field because the DOMAIN TAG carries it
    /// (`kata.execution.capsule_reuse.v<N>`): a contract bump rotates every key by
    /// construction, and a capsule of another version does not decode at all.
    ///
    /// Each remaining field is folded under its own name in the order [`Capsule::new`]
    /// folds it, the mappings in their stored (guest-path-sorted) order.
    ///
    /// # And one term that is not a capsule field
    ///
    /// `executor` — the node's [`ExecutorTerm`] (the rendered seccomp rules, the pinned
    /// youki's content hash and the OCI bundle template, `kata_worker::executor_term`)
    /// — is folded right after the domain tag. Every field above is something a
    /// workflow declared; the term is what kata's own machinery does to it, so a kata
    /// whose term moved misses every result keyed under the old one. What the term
    /// does and does not cover is `kata_worker::executor_term`'s module doc. It is a
    /// PARAMETER and never a field: the capsule id, the occurrence and the platform do
    /// not move when it does (it moves the content-cache key, and nothing else).
    #[must_use]
    pub fn reuse_key(&self, executor: &ExecutorTerm) -> CapsuleReuseKey {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, &domain("capsule_reuse"), &[]);
        hash_field(&mut hasher, "executor", executor.digest().as_ref());
        self.fold_reuse_inputs(&mut hasher);
        CapsuleReuseKey(FixedBytes(*hasher.finalize().as_bytes()))
    }

    /// Whether `self` and `other` carry equal REUSE INPUTS — every field
    /// [`Self::reuse_key`] folds, under no executor term: equal exactly when the two
    /// capsules answer one reuse key under every term. The operational reuse door's
    /// re-check of a hint's source, which proves the CAPSULES equal; which executor
    /// the source ran under is the hint key's fact, not the capsules'.
    #[must_use]
    pub fn has_reuse_inputs_of(&self, other: &Self) -> bool {
        let digest = |capsule: &Self| {
            let mut hasher = blake3::Hasher::new();
            capsule.fold_reuse_inputs(&mut hasher);
            hasher.finalize()
        };
        digest(self) == digest(other)
    }

    /// The capsule half of [`Self::reuse_key`]: every field but the id and the
    /// occurrence, in [`Capsule::new`]'s order.
    fn fold_reuse_inputs(&self, hasher: &mut blake3::Hasher) {
        let CapsuleFields {
            schema_version: _,
            id: _,
            occurrence: _,
            action,
            environment,
            platform,
            inputs,
            process,
            network,
            git_view,
            work_view,
            budgets,
        } = self.fields();
        let CapsuleBudgets {
            wall_time_ms,
            output_bytes,
            memory_bytes,
            process_count,
            result_bytes,
            result_entries,
            work_delta_bytes,
            work_delta_entries,
        } = budgets;
        hash_field(hasher, "action", action.0.as_bytes());
        hash_field(hasher, "environment", environment.0.as_bytes());
        hash_field(hasher, "platform", platform.0.as_bytes());
        hash_field(hasher, "inputs", &(inputs.len() as u64).to_le_bytes());
        for GuestMapping {
            artifact,
            guest_path,
            access,
        } in inputs
        {
            hash_field(hasher, "artifact", artifact.0.as_bytes());
            hash_field(hasher, "guest_path", guest_path.as_str().as_bytes());
            hash_field(hasher, "access", access.as_tag().as_bytes());
        }
        hash_capsule_process(hasher, process);
        hash_capsule_network(hasher, network);
        hash_capsule_git_view(hasher, git_view);
        hash_capsule_work_view(hasher, work_view);
        hash_field(hasher, "wall_time_ms", &wall_time_ms.to_le_bytes());
        hash_field(hasher, "output_bytes", &output_bytes.to_le_bytes());
        hash_field(hasher, "memory_bytes", &memory_bytes.to_le_bytes());
        hash_field(hasher, "process_count", &process_count.to_le_bytes());
        hash_field(hasher, "result_bytes", &result_bytes.to_le_bytes());
        hash_field(hasher, "result_entries", &result_entries.to_le_bytes());
        hash_field(hasher, "work_delta_bytes", &work_delta_bytes.to_le_bytes());
        hash_field(
            hasher,
            "work_delta_entries",
            &work_delta_entries.to_le_bytes(),
        );
    }
}

/// [`Capsule`]'s complete field set — see [`Capsule::fields`].
#[derive(Clone, Copy, Debug)]
pub struct CapsuleFields<'a> {
    /// The contract schema version this capsule was minted at.
    pub schema_version: u32,
    /// Its content-addressed identity.
    pub id: CapsuleId,
    /// The occurrence it executes.
    pub occurrence: OccurrenceId,
    /// The prepared action it executes.
    pub action: PreparedActionId,
    /// The Nix environment it binds.
    pub environment: EnvironmentId,
    /// The execution platform it was prepared for.
    pub platform: PlatformId,
    /// Its guest mappings, sorted by guest path, one per path.
    pub inputs: &'a [GuestMapping],
    /// What its container runs; see [`Capsule::process`].
    pub process: &'a CapsuleProcess,
    /// Its declared network posture; see [`Capsule::network`].
    pub network: &'a CapsuleNetwork,
    /// Its git view, when it declares one; see [`Capsule::git_view`].
    pub git_view: Option<&'a CapsuleGitView>,
    /// Its `/work` confinement view, when it declares one; see
    /// [`Capsule::work_view`].
    pub work_view: Option<&'a CapsuleWorkView>,
    /// Its bounds.
    pub budgets: CapsuleBudgets,
}

/// Raw mirror of [`Capsule`]; see [`ArtifactRefRaw`].
#[derive(Deserialize)]
struct CapsuleRaw {
    /// Read only to refuse a foreign version: `current_schema_version` rejects
    /// anything but this build's, so the value itself is never needed.
    #[serde(rename = "schema_version", deserialize_with = "current_schema_version")]
    _schema_version: u32,
    id: CapsuleId,
    occurrence: OccurrenceId,
    action: PreparedActionId,
    environment: EnvironmentId,
    platform: PlatformId,
    inputs: Vec<GuestMapping>,
    process: CapsuleProcess,
    network: CapsuleNetwork,
    git_view: Option<CapsuleGitView>,
    work_view: Option<CapsuleWorkView>,
    budgets: CapsuleBudgets,
}

impl<'de> Deserialize<'de> for Capsule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = CapsuleRaw::deserialize(deserializer)?;
        let recomputed = Self::new(
            raw.occurrence,
            raw.action,
            raw.environment,
            raw.platform,
            raw.inputs,
            raw.process,
            raw.network,
            raw.git_view,
            raw.budgets,
            raw.work_view,
        )
        .map_err(serde::de::Error::custom)?;
        if recomputed.id != raw.id {
            return Err(serde::de::Error::custom(format!(
                "capsule id {} does not match its body (recomputed {})",
                raw.id.0, recomputed.id.0
            )));
        }
        Ok(recomputed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::json_roundtrip;
    use ulid::Ulid;

    fn hash(byte: u8) -> ContentHash {
        ContentHash::new([byte; 32])
    }

    /// One fixed executor term, for every cell whose subject is the capsule half of
    /// the reuse key.
    fn test_executor() -> ExecutorTerm {
        ExecutorTerm::derive(&[("test_executor", b"one")]).unwrap()
    }

    fn operation() -> OperationContractId {
        OperationContractId(hash(1))
    }

    fn occurrence() -> OccurrenceRef {
        OccurrenceRef::new(
            ExecutionId(Ulid::from_bytes([7; 16])),
            hash(2),
            operation(),
            OperationPath(vec![3, 5]),
        )
    }

    fn agent_contract(drivers: &[&str]) -> OperationContract {
        OperationContract::new(
            StageId(SmolStr::new("build")),
            RuntimeOperation::Execute(ExecuteOperation {
                executor: ActionExecutor::Agent {
                    drivers: drivers.iter().map(|d| SmolStr::new(*d)).collect(),
                },
                contract_hash: hash(11),
            }),
        )
    }

    fn budgets() -> CapsuleBudgets {
        CapsuleBudgets {
            wall_time_ms: 10,
            output_bytes: 20,
            memory_bytes: 30,
            process_count: 2,
            result_bytes: 40,
            result_entries: 5,
            work_delta_bytes: default_work_delta_bytes(),
            work_delta_entries: default_work_delta_entries(),
        }
    }

    fn mapping(byte: u8, path: &str) -> GuestMapping {
        GuestMapping {
            artifact: ArtifactId(hash(byte)),
            guest_path: GuestPath::new(path).unwrap(),
            access: GuestAccess::ReadOnly,
        }
    }

    fn capsule(inputs: Vec<GuestMapping>) -> KataResult<Capsule> {
        Capsule::new(
            OccurrenceId(hash(1)),
            PreparedActionId(hash(2)),
            EnvironmentId(hash(3)),
            PlatformId(hash(4)),
            inputs,
            CapsuleProcess::Command {
                argv: vec![SmolStr::new("sh"), SmolStr::new("-c"), SmolStr::new("true")],
            },
            CapsuleNetwork::Offline,
            None,
            budgets(),
            None,
        )
    }

    /// One deterministic v10 view — the payload an agent capsule that maps
    /// `/work` may carry. `history` is the published artifact's full ref; the
    /// identity is the operator's own pair, not the sandbox-agent refusal one.
    fn git_view() -> CapsuleGitView {
        CapsuleGitView {
            history: ArtifactRef::new(hash(0x66), 128, ArtifactPrivacy::Private),
            base_commit: SmolStr::new("f".repeat(40)),
            branch: Some(GitViewRef {
                name: SmolStr::new("main"),
                commit: SmolStr::new("e".repeat(40)),
            }),
            identity: GitIdentity {
                name: SmolStr::new("Operator"),
                email: SmolStr::new("operator@host.test"),
            },
        }
    }

    /// A Command capsule mapping `/work` and declaring `include` as its work
    /// view — the shape `work_view`'s cells share.
    fn viewed_capsule(include: &[&str]) -> Capsule {
        Capsule::new(
            OccurrenceId(hash(1)),
            PreparedActionId(hash(2)),
            EnvironmentId(hash(3)),
            PlatformId(hash(4)),
            vec![mapping(5, "/work")],
            CapsuleProcess::Command {
                argv: vec![SmolStr::new("sh")],
            },
            CapsuleNetwork::Offline,
            None,
            budgets(),
            Some(CapsuleWorkView {
                include: include.iter().map(|p| SmolStr::new(*p)).collect(),
            }),
        )
        .expect("a viewed capsule constructs")
    }

    /// An `Agent` process capsule over caller-chosen mappings, carrying
    /// caller-chosen git view — the shape `git_view_requires_work` rules on.
    fn agent_capsule(
        inputs: Vec<GuestMapping>,
        git_view: Option<CapsuleGitView>,
    ) -> KataResult<Capsule> {
        Capsule::new(
            OccurrenceId(hash(1)),
            PreparedActionId(hash(2)),
            EnvironmentId(hash(3)),
            PlatformId(hash(4)),
            inputs,
            CapsuleProcess::Agent(AgentTurnSpec {
                adapter: AdapterKind::NanocodeOpenai,
                model: None,
                reasoning_effort: None,
                output_schema: None,
                prompt: ArtifactId(hash(7)),
                credential: None,
                env: std::collections::BTreeMap::new(),
            }),
            CapsuleNetwork::Offline,
            git_view,
            budgets(),
            None,
        )
    }

    /// **The git-view gate refuses exactly the capsules the view cannot render.** Its refused set
    /// (`git_view_requires_work`) is a `Some` view with no `/work` mapping — the view describes the
    /// working tree's history, and without one the claim is empty. A COMMAND capsule may carry a
    /// view too (a shell stage whose profile `requires` `git`), so the process arm is no part of
    /// the gate. `None` stays admitted on every shape.
    ///
    /// **Would red if:** the gate still checked the process arm (the Command
    /// row would be refused), or dropped the mapping check (the no-`/work` row
    /// would construct).
    #[test]
    fn the_git_view_gate_requires_a_work_mapping_and_nothing_else() {
        let command = Capsule::new(
            OccurrenceId(hash(1)),
            PreparedActionId(hash(2)),
            EnvironmentId(hash(3)),
            PlatformId(hash(4)),
            vec![mapping(5, "/work")],
            CapsuleProcess::Command {
                argv: vec![SmolStr::new("sh")],
            },
            CapsuleNetwork::Offline,
            Some(git_view()),
            budgets(),
            None,
        )
        .expect("a Command capsule mapping /work carries a view");
        assert_eq!(command.git_view(), Some(&git_view()));
        json_roundtrip(command);

        let error = agent_capsule(
            vec![mapping(5, "/out"), mapping(6, "/work/src")],
            Some(git_view()),
        )
        .expect_err("a capsule without a /work mapping is refused")
        .to_string();
        assert!(
            error.contains("git_view_requires_work"),
            "no /work mapping: {error}"
        );

        capsule(vec![mapping(5, "/work")]).expect("a Command capsule with NO view is admitted");
        agent_capsule(vec![mapping(5, "/out")], None)
            .expect("an agent capsule with no /work and no view is admitted");

        let capsule = agent_capsule(vec![mapping(5, "/work")], Some(git_view()))
            .expect("an agent capsule that maps /work");
        assert_eq!(capsule.git_view(), Some(&git_view()));
        json_roundtrip(capsule);
    }

    /// The v11 sibling of the gate above: `work_view_requires_work` — a
    /// `/work` confinement view on a capsule mapping no `/work` is refused, on
    /// either process arm, because the view is a claim about the tree the
    /// mapping carries and a capsule with none cannot render it.
    ///
    /// **Would red if:** the gate read the wrong mapping set (the `Some`
    /// without-`/work` row would construct), or `Capsule::new` skipped the
    /// check (both rows would construct).
    #[test]
    fn the_work_view_gate_requires_a_work_mapping_and_nothing_else() {
        fn viewed(inputs: Vec<GuestMapping>) -> KataResult<Capsule> {
            Capsule::new(
                OccurrenceId(hash(1)),
                PreparedActionId(hash(2)),
                EnvironmentId(hash(3)),
                PlatformId(hash(4)),
                inputs,
                CapsuleProcess::Command {
                    argv: vec![SmolStr::new("sh")],
                },
                CapsuleNetwork::Offline,
                None,
                budgets(),
                Some(CapsuleWorkView {
                    include: vec![SmolStr::new("src")],
                }),
            )
        }
        let viewed_capsule =
            viewed(vec![mapping(5, "/work")]).expect("a capsule mapping /work carries the view");
        assert_eq!(
            viewed_capsule
                .work_view()
                .map(|view| view.include.as_slice()),
            Some(&[SmolStr::new("src")][..])
        );
        json_roundtrip(viewed_capsule);

        let error = viewed(vec![mapping(5, "/out"), mapping(6, "/work/src")])
            .expect_err("a capsule without a /work mapping is refused")
            .to_string();
        assert!(
            error.contains("work_view_requires_work"),
            "no /work mapping: {error}"
        );
        capsule(vec![mapping(5, "/work")]).expect("a Command capsule with NO view stays admitted");
    }

    /// **A v10 body is refused by the schema-version door, before the new
    /// field is even read.** v11 added `work_view` to the capsule; a
    /// v10-encoded capsule — which does not spell it — must not decode under
    /// v11's field meanings. (`current_schema_version` refuses by name; the
    /// field would otherwise default to `None` and the id recompute would read
    /// a v10 id against v11's fold.)
    ///
    /// **Would red if:** the schema bump were missed (the body decodes — a
    /// v10 fold would alias a v11 capsule), or the refusal lost the version
    /// number.
    #[test]
    fn a_v10_capsule_is_refused_by_its_schema_version_on_deserialize() {
        let mut document = serde_json::to_value(
            agent_capsule(vec![mapping(5, "/work")], None).expect("an agent capsule"),
        )
        .expect("the capsule encodes");
        document["schema_version"] = serde_json::json!(10);
        let error = serde_json::from_value::<Capsule>(document)
            .expect_err("a v10 capsule body must be refused")
            .to_string();
        assert!(
            error.contains("schema_version 10 is not supported"),
            "the refusal names the version: {error}"
        );
    }

    /// **A v11 body is refused.** v12 turned `git_view.branch` from a bare
    /// name into an optional name-and-commit ref off the execution's frozen
    /// target. A body stamped 11 is refused by the schema-version door, naming
    /// the version, even when every field already has v12's shape — so a v11
    /// id is never read against v12's fold. A body in the genuine v11 shape (a
    /// bare-string branch) does not decode either: serde reaches `git_view`
    /// before `schema_version` in that document, so it is refused by the
    /// branch's shape.
    ///
    /// **Would red if:** the schema bump were missed (the v12-shaped body
    /// stamped 11 decodes), or the refusal lost the version number.
    #[test]
    fn a_v11_capsule_is_refused_by_its_schema_version_on_deserialize() {
        let mut document = serde_json::to_value(
            agent_capsule(vec![mapping(5, "/work")], Some(git_view())).expect("an agent capsule"),
        )
        .expect("the capsule encodes");
        document["schema_version"] = serde_json::json!(11);
        let error = serde_json::from_value::<Capsule>(document.clone())
            .expect_err("a v11 capsule body must be refused")
            .to_string();
        assert!(
            error.contains("schema_version 11 is not supported"),
            "the refusal names the version: {error}"
        );

        document["git_view"]["branch"] = serde_json::json!("main");
        let error = serde_json::from_value::<Capsule>(document)
            .expect_err("a v11-shaped view does not decode")
            .to_string();
        assert!(
            error.contains("expected struct GitViewRef"),
            "refused by the branch's shape: {error}"
        );
    }

    /// **A v12 body is refused, even one whose every value v13 still admits.**
    /// v13 narrowed [`AdapterKind`] to the two nanocode kinds and
    /// [`CredentialSource`] to `kata_login` and `env:<VAR>`. A v12 body naming
    /// a nanocode kind is refused by the schema-version door, naming the
    /// version, so a v12 id is never read against v13's fold; a body naming a
    /// removed vendor adapter or a host login does not decode at all, whatever
    /// its stamp.
    ///
    /// **Would red if:** the bump were missed (the 12-stamped body decodes), or
    /// a removed adapter or host-login spelling decoded.
    #[test]
    fn a_v12_capsule_is_refused_by_its_schema_version_on_deserialize() {
        let document = serde_json::to_value(
            agent_capsule(vec![mapping(5, "/work")], Some(git_view())).expect("an agent capsule"),
        )
        .expect("the capsule encodes");
        assert_eq!(
            document["process"]["adapter"], "nanocode_openai",
            "{document}"
        );
        let mut stamped = document.clone();
        stamped["schema_version"] = serde_json::json!(12);
        let error = serde_json::from_value::<Capsule>(stamped)
            .expect_err("a v12 capsule body must be refused")
            .to_string();
        assert!(
            error.contains("schema_version 12 is not supported"),
            "the refusal names the version: {error}"
        );
        for removed in ["codex_app_server", "generic_acp", "grok_acp", "pi_rpc"] {
            let mut body = document.clone();
            body["process"]["adapter"] = serde_json::json!(removed);
            let error = serde_json::from_value::<Capsule>(body)
                .expect_err("a removed adapter does not decode")
                .to_string();
            assert!(
                error.contains(&format!("unknown variant `{removed}`")),
                "{removed}: {error}"
            );
        }
        for host_login in [
            "codex_login",
            "pi_login",
            "opencode_login",
            "grok_login",
            "claude_login",
        ] {
            let mut body = document.clone();
            body["process"]["credential"] =
                serde_json::json!({"mode": "subscription", "source": {"kind": host_login}});
            let error = serde_json::from_value::<Capsule>(body)
                .expect_err("a host login does not decode")
                .to_string();
            assert!(
                error.contains(&format!("unknown variant `{host_login}`")),
                "{host_login}: {error}"
            );
        }
    }

    /// **A v13 body is refused, even one whose every value v14 still admits.**
    /// v14 reserved `http_proxy`, `https_proxy`, `ALL_PROXY`, `all_proxy` and
    /// `XDG_RUNTIME_DIR` in an agent turn's declared env and as `env:<VAR>`
    /// sources. A v13 body declaring none of them is refused by the
    /// schema-version door, naming the version, so a v13 id is never read
    /// against v14's fold; a body declaring one is refused by
    /// `capsule_agent_env_channel_owned`, whatever its stamp.
    ///
    /// **Would red if:** the bump were missed (the 13-stamped body decodes), or
    /// a newly reserved name decoded.
    #[test]
    fn a_v13_capsule_is_refused_by_its_schema_version_on_deserialize() {
        let document = serde_json::to_value(
            agent_capsule(vec![mapping(5, "/work")], Some(git_view())).expect("an agent capsule"),
        )
        .expect("the capsule encodes");
        let mut stamped = document.clone();
        stamped["schema_version"] = serde_json::json!(13);
        let error = serde_json::from_value::<Capsule>(stamped)
            .expect_err("a v13 capsule body must be refused")
            .to_string();
        assert!(
            error.contains("schema_version 13 is not supported"),
            "the refusal names the version: {error}"
        );
        for reserved in [
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "XDG_RUNTIME_DIR",
        ] {
            let mut body = document.clone();
            body["process"]["env"][reserved] = serde_json::json!("x");
            let error = serde_json::from_value::<Capsule>(body)
                .expect_err("a newly reserved name does not decode")
                .to_string();
            assert!(
                error.contains("capsule_agent_env_channel_owned") && error.contains(reserved),
                "{reserved}: {error}"
            );
        }
    }

    /// **`CapsuleWorkView::covers`'s refused set and reach**, stated in the
    /// manifest terms the worker matches on: a scope covers itself and its
    /// subtree, a glob covers its match AND the subtree of any ancestor it
    /// names (a directory granted read carries its contents — the parity with
    /// the shim's Landlock `PathBeneath` rule), and an escaping pattern covers
    /// nothing. `.` alone is the root.
    ///
    /// **Would red if:** scope entries stopped covering their subtree (the
    /// `src/lib.rs` assert fails), globs stopped honoring ancestors (`*` no
    /// longer reaches `src/lib.rs`), or the escape drop turned into a match.
    #[test]
    fn a_work_view_covers_scopes_globs_and_nothing_past_them() {
        let view = |include: &[&str]| CapsuleWorkView {
            include: include.iter().map(|p| SmolStr::new(*p)).collect(),
        };
        // A directory scope covers its subtree, a file scope itself.
        let v = view(&["src", "kata/brief.md"]);
        assert!(v.covers("src/lib.rs") && v.covers("src") && v.covers("kata/brief.md"));
        assert!(!v.covers("docs/b") && !v.covers("srcx/lib.rs") && !v.covers("kata"));
        // A glob covers its match and any ancestor directory it names — `*`
        // reaching `src/lib.rs` because it names `src` is the Landlock
        // directory-grant parity.
        let v = view(&["*.md"]);
        assert!(v.covers("notes.md") && !v.covers("docs/notes.md"));
        let v = view(&["*"]);
        assert!(
            v.covers("src/lib.rs"),
            "* names the dir, the dir carries the file"
        );
        let v = view(&["src/**/fixtures/*.txt"]);
        assert!(v.covers("src/a/fixtures/x.txt"));
        assert!(!v.covers("src/a/b/x.txt") && !v.covers("docs/x.txt"));
        // `dir/**`'s literal prefix scopes the subtree even past glob edges —
        // the bare dir itself is covered through the literal prefix (the
        // compiled `**` does not reach a zero-component tail).
        let v = view(&["src/**"]);
        assert!(v.covers("src") && v.covers("src/deep/x.rs") && !v.covers("srcx/y.rs"));
        // A non-`**` glob matches one component only: the file it names, never
        // a deeper one and never a sibling the pattern does not spell.
        let v = view(&["src/*.rs"]);
        assert!(v.covers("src/a.rs"));
        assert!(
            !v.covers("src/sub/b.rs") && !v.covers("src/notes.md") && !v.covers("docs/x.rs"),
            "`src/*.rs` names `src`'s own .rs members, nothing past them"
        );
        // An escape-shaped pattern covers nothing; a `.`-only one names the
        // root and covers everything.
        let v = view(&["../outside", "/abs", "a/../b"]);
        assert!(!v.covers("a/b") && !v.covers("outside"));
        let v = view(&["."]);
        assert!(v.covers("anything/at/all.rs"));
        // Order and duplicates are presentation, not identity: the mint sorts
        // and dedups them.
        let text = serde_json::to_string(&view(&["b", "a", "a"])).unwrap();
        let _ = text;
    }

    /// The ONE view-pattern normalizer's refused set, each arm alone: empty,
    /// absolute, and `..`-escaping patterns drop to `None` (the covers check
    /// answers false for them), while `.`/`./` reduce to the tree root and a
    /// real pattern keeps its components.
    #[test]
    fn a_work_view_pattern_drops_the_refused_set() {
        for pattern in ["", "   ", "/abs", "/abs/x", "a/../b", "../x", "//"] {
            assert_eq!(
                work_view_pattern_components(pattern),
                None,
                "{pattern:?} is dropped"
            );
        }
        assert_eq!(work_view_pattern_components("."), Some(vec![]));
        assert_eq!(work_view_pattern_components("./"), Some(vec![]));
        assert_eq!(
            work_view_pattern_components(" a//b/./c "),
            Some(vec!["a", "b", "c"]),
            "trim, empty and `.` components drop out"
        );
    }

    /// A child-invocation stage name decodes only with BOTH sides non-empty —
    /// `#child-w` (no base) and `base#child-` (no role) are no coordinate.
    #[test]
    fn a_child_invocation_stage_name_needs_a_base_and_a_role() {
        assert_eq!(
            parse_child_invocation_stage_name("implement#child-reviewer"),
            Some(("implement".into(), "reviewer".into()))
        );
        for name in ["#child-w", "base#child-", "#child-", "plain", ""] {
            assert_eq!(
                parse_child_invocation_stage_name(name),
                None,
                "{name:?} decodes to no coordinate"
            );
        }
    }

    /// **`Capsule::new`'s work-view door on the DECODE path and the sorted
    /// mint:** a serialized capsule whose `work_view` is tampered with, or
    /// declared with an unsorted include list, must decode to the capsule the
    /// mint would have produced — so the body names one identity, never the
    /// writer's order.
    ///
    /// **Would red if:** the mint skipped the sort (the unsorted body would
    /// recompute to a different id and refuse — the wrong half red), or the
    /// decode skipped the recompute (the tampered body would decode).
    #[test]
    fn a_work_view_mints_sorted_and_a_tampered_view_is_refused_on_decode() {
        let ordered = viewed_capsule(&["b/x", "a/y", "a/y"]);
        let reordered = viewed_capsule(&["a/y", "b/x"]);
        assert_eq!(
            ordered.id(),
            reordered.id(),
            "include order and duplicates are not the capsule's identity"
        );
        let mut document = serde_json::to_value(&reordered).expect("the capsule encodes");
        document["work_view"]["include"] = serde_json::json!(["other/**"]);
        let error = serde_json::from_value::<Capsule>(document)
            .expect_err("a tampered include must not match the minted id")
            .to_string();
        assert!(
            error.contains("does not match its body"),
            "the recompute door: {error}"
        );

        // And the gate on decode: a view on a body that maps no `/work` is
        // refused before the id check is reached.
        let mut bare =
            serde_json::to_value(capsule(vec![mapping(5, "/out")]).expect("a no-/work capsule"))
                .expect("the capsule encodes");
        bare["work_view"] = serde_json::to_value(CapsuleWorkView {
            include: vec![SmolStr::new("src")],
        })
        .expect("the view encodes");
        let error = serde_json::from_value::<Capsule>(bare)
            .expect_err("a body with no /work carrying a view is refused on decode")
            .to_string();
        assert!(
            error.contains("work_view_requires_work"),
            "the gate runs on decode: {error}"
        );
    }

    /// **`Capsule::new`'s git-view door on the DECODE path:** a serialized
    /// capsule whose `git_view` is tampered with — or declared where the gate
    /// forbids it — is refused by the same `new` every reader funnels through,
    /// so a forged body never reaches the worker's renderer.
    ///
    /// **Would red if:** `Capsule`'s Deserialize skipped `new` (both bodies
    /// would decode), or the id recomputation dropped the view (the tampered
    /// `branch` would decode).
    #[test]
    fn a_tampered_or_out_of_shape_git_view_is_refused_on_deserialize() {
        let viewed = agent_capsule(vec![mapping(5, "/work")], Some(git_view()))
            .expect("the admitted shape constructs");
        let mut document = serde_json::to_value(&viewed).expect("the capsule encodes");
        document["git_view"]["branch"]["name"] = serde_json::json!("trunk");
        let error = serde_json::from_value::<Capsule>(document.clone())
            .expect_err("a tampered git_view body must not match the minted id")
            .to_string();
        assert!(
            error.contains("does not match its body"),
            "the recompute door: {error}"
        );

        // The gate on decode: hand a body that maps no `/work` the view — the
        // recompute in `new` refuses before the id check is even reached.
        let mut bare = serde_json::to_value(
            agent_capsule(vec![mapping(5, "/out")], None).expect("an agent capsule"),
        )
        .expect("the capsule encodes");
        bare["git_view"] = serde_json::to_value(git_view()).expect("the view encodes");
        let error = serde_json::from_value::<Capsule>(bare)
            .expect_err("a body with no /work carrying a view is refused on decode")
            .to_string();
        assert!(
            error.contains("git_view_requires_work"),
            "the gate runs on decode: {error}"
        );
    }

    /// **A v9 body is refused by the schema-version door, before the new field
    /// is even read.** v10 added `git_view` to the capsule; a v9-encoded
    /// capsule — which does not spell it — must not decode under v10's field
    /// meanings. (`current_schema_version` refuses by name; the field would
    /// otherwise default to `None` and the id recompute would read a v9 id
    /// against v10's fold.)
    ///
    /// **Would red if:** the schema bump were missed (the body decodes — v9's
    /// fold would alias a v10 capsule), or the refusal lost the version number.
    #[test]
    fn a_v9_capsule_is_refused_by_its_schema_version_on_deserialize() {
        let mut document = serde_json::to_value(
            agent_capsule(vec![mapping(5, "/work")], None).expect("an agent capsule"),
        )
        .expect("the capsule encodes");
        document["schema_version"] = serde_json::json!(9);
        let error = serde_json::from_value::<Capsule>(document)
            .expect_err("a v9 capsule body must be refused")
            .to_string();
        assert!(
            error.contains("schema_version 9 is not supported"),
            "the refusal names the version: {error}"
        );
    }

    #[test]
    fn occurrence_identity_changes_for_expansion_path_not_retry_facts() {
        let base = occurrence();
        assert_eq!(base.id(), base.clone().id());
        assert_ne!(
            base.id(),
            OccurrenceRef {
                path: base.path.child(8),
                ..base
            }
            .id()
        );
    }

    fn prepared() -> PreparedAction {
        PreparedAction::new(
            operation(),
            ActionManifest::new(hash(2), vec![SmolStr::new("out/**")]),
            EnvironmentId(hash(4)),
            hash(5),
            PlatformId(hash(6)),
        )
    }

    #[test]
    fn every_semantic_binding_rotates_prepared_action_identity() {
        let base = prepared();
        let id = base.id();
        let mut changed = base.clone();
        changed.operation = OperationContractId(hash(9));
        assert_ne!(id, changed.id());
        let mut changed = base.clone();
        changed.manifest.command = hash(9);
        assert_ne!(id, changed.id());
        let mut changed = base.clone();
        changed.manifest.declared_outputs = vec![SmolStr::new("other/**")];
        assert_ne!(id, changed.id());
        let mut changed = base.clone();
        changed.environment = EnvironmentId(hash(9));
        assert_ne!(id, changed.id());
        let mut changed = base.clone();
        changed.permissions = hash(9);
        assert_ne!(id, changed.id());
        let mut changed = base;
        changed.platform = PlatformId(hash(9));
        assert_ne!(id, changed.id());
    }

    #[test]
    fn capsule_is_portable_and_input_order_independent() {
        let one = capsule(vec![mapping(5, "/work/b"), mapping(6, "/work/a")]).unwrap();
        let two = capsule(vec![mapping(6, "/work/a"), mapping(5, "/work/b")]).unwrap();
        assert_eq!(one, two);
        assert!(!serde_json::to_string(&one).unwrap().contains("/home/"));
        assert!(GuestPath::new("/work/../host").is_err());
        assert!(serde_json::from_str::<GuestPath>("\"relative\"").is_err());
        json_roundtrip(one);
    }

    /// **THE EXECUTOR TERM MOVES THE REUSE KEY AND NOTHING IDENTITY-BEARING.**
    /// One capsule keyed under two executor terms — a kata upgrade that changed the
    /// fence — answers two keys, so the upgraded node misses; the capsule itself (its
    /// id, its occurrence, its platform and its encoded bytes) is the same value under
    /// both, because the term is a parameter of the key and never a capsule field.
    ///
    /// **Would red if:** `reuse_key` ignored its executor term (the upgraded node would
    /// adopt a result computed under the old fence), or the term were folded into a
    /// capsule field (the id and the encoded bytes would move with it).
    #[test]
    fn the_executor_term_moves_the_reuse_key_and_not_the_capsule() {
        let capsule = capsule(vec![mapping(5, "/work")]).unwrap();
        let before = ExecutorTerm::derive(&[("oci_seccomp_rules", b"deny ptrace")]).unwrap();
        let after = ExecutorTerm::derive(&[("oci_seccomp_rules", b"deny ptrace, bpf")]).unwrap();
        assert_ne!(
            capsule.reuse_key(&before),
            capsule.reuse_key(&after),
            "an executor change must miss"
        );
        assert_eq!(capsule.reuse_key(&before), capsule.reuse_key(&before));
        let encoded = serde_json::to_vec(&capsule).unwrap();
        let reread: Capsule = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(reread.reuse_key(&after), capsule.reuse_key(&after));
        assert_eq!(
            (reread.id(), reread.occurrence(), reread.platform()),
            (capsule.id(), capsule.occurrence(), capsule.platform()),
            "the term is no capsule field: identity is the same value under either term"
        );
    }

    /// **EQUAL REUSE INPUTS ARE EQUAL KEYS UNDER EVERY TERM** — the operational door's
    /// executor-free re-check agrees with the key: two capsules differing only in the
    /// occurrence have equal reuse inputs and one key per term; one changed mapping
    /// makes the inputs unequal and the keys unequal under any term.
    ///
    /// **Would red if:** `has_reuse_inputs_of` folded a field `reuse_key` does not (the
    /// occurrence: no hint would ever be adopted), or dropped one it does (the door
    /// would adopt a result computed over other bytes).
    #[test]
    fn equal_reuse_inputs_are_equal_keys_under_every_term() {
        let baseline = capsule(vec![mapping(5, "/work")]).unwrap();
        let fields = baseline.fields();
        let other_occurrence = Capsule::new(
            OccurrenceId(hash(9)),
            fields.action,
            fields.environment,
            fields.platform,
            fields.inputs.to_vec(),
            fields.process.clone(),
            fields.network.clone(),
            None,
            fields.budgets,
            None,
        )
        .unwrap();
        let changed = capsule(vec![mapping(6, "/work")]).unwrap();
        assert_ne!(other_occurrence.id(), baseline.id());
        assert!(other_occurrence.has_reuse_inputs_of(&baseline));
        assert!(!changed.has_reuse_inputs_of(&baseline));
        for term in [
            test_executor(),
            ExecutorTerm::derive(&[("oci_seccomp_rules", b"other")]).unwrap(),
        ] {
            assert_eq!(other_occurrence.reuse_key(&term), baseline.reuse_key(&term));
            assert_ne!(changed.reuse_key(&term), baseline.reuse_key(&term));
        }
    }

    /// **THE REUSE KEY IS EVERY CAPSULE FIELD BUT THE OCCURRENCE** — the rotation
    /// table. Each row changes exactly one field of one capsule; every row but the
    /// occurrence's must rotate the key, and the occurrence's must rotate the capsule id
    /// while leaving the key equal.
    ///
    /// **Would red if:** a field were dropped from `Capsule::reuse_key` (its row keeps
    /// the key equal), or the occurrence were folded into it (its row rotates the key,
    /// and no two executions could ever share a result).
    #[test]
    fn the_reuse_key_is_every_capsule_field_but_the_occurrence() {
        struct Body {
            occurrence: OccurrenceId,
            action: PreparedActionId,
            environment: EnvironmentId,
            platform: PlatformId,
            inputs: Vec<GuestMapping>,
            process: CapsuleProcess,
            network: CapsuleNetwork,
            git_view: Option<CapsuleGitView>,
            budgets: CapsuleBudgets,
            work_view: Option<CapsuleWorkView>,
        }
        fn base() -> Body {
            Body {
                occurrence: OccurrenceId(hash(1)),
                action: PreparedActionId(hash(2)),
                environment: EnvironmentId(hash(3)),
                platform: PlatformId(hash(4)),
                inputs: vec![mapping(5, "/work"), mapping(6, "/out")],
                process: CapsuleProcess::Command {
                    argv: vec![SmolStr::new("sh"), SmolStr::new("-c"), SmolStr::new("true")],
                },
                network: CapsuleNetwork::Offline,
                git_view: None,
                budgets: budgets(),
                work_view: None,
            }
        }
        fn build(body: Body) -> Capsule {
            Capsule::new(
                body.occurrence,
                body.action,
                body.environment,
                body.platform,
                body.inputs,
                body.process,
                body.network,
                body.git_view,
                body.budgets,
                body.work_view,
            )
            .unwrap()
        }
        let baseline = build(base());
        type Rotation = (&'static str, fn(&mut Body));
        let rotations: [Rotation; 16] = [
            ("action", |body| body.action = PreparedActionId(hash(9))),
            ("environment", |body| {
                body.environment = EnvironmentId(hash(9));
            }),
            ("platform", |body| body.platform = PlatformId(hash(9))),
            ("inputs.artifact (/work bytes)", |body| {
                body.inputs[0].artifact = ArtifactId(hash(9));
            }),
            ("inputs.guest_path", |body| {
                body.inputs[0].guest_path = GuestPath::new("/work/other").unwrap();
            }),
            ("inputs.access", |body| {
                body.inputs[0].access = GuestAccess::ReadWrite;
            }),
            ("inputs.count", |body| {
                body.inputs.push(mapping(7, "/tmp"));
            }),
            ("process.argv", |body| {
                let CapsuleProcess::Command { argv } = &mut body.process else {
                    unreachable!("the base capsule is a Command");
                };
                argv[2] = SmolStr::new("false");
            }),
            ("process.tag (Command becomes Agent)", |body| {
                body.process = CapsuleProcess::Agent(AgentTurnSpec {
                    adapter: AdapterKind::NanocodeOpenai,
                    model: None,
                    reasoning_effort: None,
                    output_schema: None,
                    prompt: ArtifactId(hash(7)),
                    credential: None,
                    env: std::collections::BTreeMap::new(),
                });
            }),
            ("network.tag (Offline becomes Egress)", |body| {
                body.network = CapsuleNetwork::Egress {
                    allowlist: BTreeSet::from([
                        EgressAuthority::new("api.vendor.test", 443).unwrap()
                    ]),
                };
            }),
            ("budgets.wall_time_ms", |body| {
                body.budgets.wall_time_ms += 1;
            }),
            ("budgets.output_bytes", |body| {
                body.budgets.output_bytes += 1;
            }),
            ("budgets.memory_bytes", |body| {
                body.budgets.memory_bytes += 1;
            }),
            ("budgets.process_count", |body| {
                body.budgets.process_count += 1;
            }),
            ("budgets.result_bytes", |body| {
                body.budgets.result_bytes += 1;
            }),
            ("budgets.result_entries", |body| {
                body.budgets.result_entries += 1;
            }),
        ];
        for (field, rotate) in rotations {
            let mut body = base();
            rotate(&mut body);
            let rotated = build(body);
            assert_ne!(
                rotated.reuse_key(&test_executor()),
                baseline.reuse_key(&test_executor()),
                "changing {field} must rotate the reuse key: a container observes it"
            );
        }
        // The AGENT arm's own fields, one flip each, Agent→Agent so the row
        // isolates the field rather than the tag.
        fn agent_body() -> Body {
            Body {
                process: CapsuleProcess::Agent(AgentTurnSpec {
                    adapter: AdapterKind::NanocodeOpenai,
                    model: Some(SmolStr::new("vendor/small")),
                    reasoning_effort: None,
                    output_schema: None,
                    prompt: ArtifactId(hash(7)),
                    credential: None,
                    env: std::collections::BTreeMap::new(),
                }),
                ..base()
            }
        }
        let agent_baseline = build(agent_body());
        type AgentRotation = (&'static str, fn(&mut AgentTurnSpec));
        let agent_rotations: [AgentRotation; 4] = [
            ("adapter", |turn| {
                turn.adapter = AdapterKind::NanocodeAnthropic;
            }),
            ("model", |turn| {
                turn.model = Some(SmolStr::new("vendor/big"));
            }),
            // The baseline's `reasoning_effort` is `None` — the same row pins
            // both halves: a declared effort ROTATES the reuse key (it is
            // part of the reuse key by construction), and `None` itself is
            // the baseline, so a capsule spec written before the field
            // existed hashes to the same id it always did.
            ("reasoning_effort", |turn| {
                turn.reasoning_effort = Some(SmolStr::new("low"));
            }),
            ("prompt", |turn| turn.prompt = ArtifactId(hash(8))),
        ];
        for (field, rotate) in agent_rotations {
            let mut body = agent_body();
            let CapsuleProcess::Agent(turn) = &mut body.process else {
                unreachable!("agent_body is the Agent arm");
            };
            rotate(turn);
            assert_ne!(
                build(body).reuse_key(&test_executor()),
                agent_baseline.reuse_key(&test_executor()),
                "changing the agent turn's {field} must rotate the reuse key"
            );
        }
        // `output_schema` rides only a kind that carries one, so its row is
        // its own: on a codex turn, a sent schema rotates the key against no
        // schema, and two different schemas rotate it against each other.
        fn codex_body(schema: Option<serde_json::Value>) -> Body {
            let mut body = agent_body();
            let CapsuleProcess::Agent(turn) = &mut body.process else {
                unreachable!("agent_body is the Agent arm");
            };
            turn.adapter = AdapterKind::NanocodeOpenai;
            turn.output_schema = schema;
            body
        }
        let unschema = build(codex_body(None)).reuse_key(&test_executor());
        let one = build(codex_body(Some(
            serde_json::json!({"type": "object", "a": 1}),
        )))
        .reuse_key(&test_executor());
        let other = build(codex_body(Some(
            serde_json::json!({"type": "object", "a": 2}),
        )))
        .reuse_key(&test_executor());
        assert_ne!(
            one, unschema,
            "a sent output schema must rotate the reuse key"
        );
        assert_ne!(
            one, other,
            "a different output schema must rotate the reuse key"
        );
        // The v10 VIEW's own fields, one flip each, over an agent capsule that
        // maps /work — the only shape `Capsule::new` lets carry `Some`.
        fn viewed_body() -> Body {
            Body {
                git_view: Some(git_view()),
                ..agent_body()
            }
        }
        let viewed_baseline = build(viewed_body());
        type ViewRotation = (&'static str, fn(&mut CapsuleGitView));
        let view_rotations: [ViewRotation; 7] = [
            ("history", |view| {
                view.history = ArtifactRef::new(hash(0x77), 64, ArtifactPrivacy::Private);
            }),
            ("base_commit", |view| {
                view.base_commit = SmolStr::new("0".repeat(40));
            }),
            ("branch.name", |view| {
                if let Some(branch) = &mut view.branch {
                    branch.name = SmolStr::new("trunk");
                }
            }),
            ("branch.commit", |view| {
                if let Some(branch) = &mut view.branch {
                    branch.commit = SmolStr::new("1".repeat(40));
                }
            }),
            ("branch absent", |view| view.branch = None),
            ("identity.name", |view| {
                view.identity.name = SmolStr::new("Other");
            }),
            ("identity.email", |view| {
                view.identity.email = SmolStr::new("other@host.test");
            }),
        ];
        for (field, rotate) in view_rotations {
            let mut body = viewed_body();
            let Some(view) = &mut body.git_view else {
                unreachable!("viewed_body declares a git view");
            };
            rotate(view);
            assert_ne!(
                build(body).reuse_key(&test_executor()),
                viewed_baseline.reuse_key(&test_executor()),
                "changing the git view's {field} must rotate the reuse key"
            );
        }
        let mut dropped = viewed_body();
        dropped.git_view = None;
        assert_ne!(
            build(dropped).reuse_key(&test_executor()),
            viewed_baseline.reuse_key(&test_executor()),
            "None and Some fold under different bytes: a capsule without the view \
             must not share an identity with one that has it"
        );

        // The v11 WORK VIEW, same rule: the confined `/work` subset is part of
        // what the capsule IS — two capsules differing only in the view show the
        // action different trees, so neither the id nor the reuse key may merge
        // them, and `None` never aliases a declared view.
        let mut confined = base();
        confined.work_view = Some(CapsuleWorkView {
            include: vec![SmolStr::new("src"), SmolStr::new("out/**")],
        });
        let confined = build(confined);
        assert_ne!(
            confined.reuse_key(&test_executor()),
            baseline.reuse_key(&test_executor()),
            "a declared work view must rotate the reuse key: the stage reads a \
             different tree"
        );
        let mut narrowed = base();
        narrowed.work_view = Some(CapsuleWorkView {
            include: vec![SmolStr::new("src")],
        });
        let narrowed = build(narrowed);
        assert_ne!(
            narrowed.reuse_key(&test_executor()),
            confined.reuse_key(&test_executor()),
            "two views differing in the include list must not share an identity"
        );
        let other_occurrence = build(Body {
            occurrence: OccurrenceId(hash(9)),
            ..base()
        });
        assert_ne!(
            other_occurrence.id(),
            baseline.id(),
            "the capsule id folds the occurrence"
        );
        assert_eq!(
            other_occurrence.reuse_key(&test_executor()),
            baseline.reuse_key(&test_executor()),
            "the reuse key must NOT fold the occurrence: it recognises equal work across \
             occurrences"
        );
    }

    /// **A turn whose init is `kata-toolhost` encodes no launch vector, and
    /// kata owns its `HOME`.** Both nanocode kinds mint a capsule whose encoded
    /// turn carries no `argv` — the kind fixes what the container execs — and
    /// which decodes back to itself. A declared `HOME` is refused as a name
    /// kata renders — naming the tool host's init, its owner, and the kind.
    ///
    /// **Would red if:** the Agent arm encoded a launch vector (a second answer
    /// to what the container execs), or `HOME` left
    /// `kata_rendered_env` for the nanocode kinds (a declared `HOME` would
    /// render twice), or the refusal named another channel as its owner
    /// (watched: the credential carrier's text, which a nanocode turn's
    /// in-process credential never renders).
    #[test]
    fn a_toolhost_kind_turn_encodes_no_launch_vector_and_kata_renders_its_home() {
        let build = |adapter: AdapterKind, env: std::collections::BTreeMap<SmolStr, SmolStr>| {
            Capsule::new(
                OccurrenceId(hash(1)),
                PreparedActionId(hash(2)),
                EnvironmentId(hash(3)),
                PlatformId(hash(4)),
                vec![mapping(5, "/work")],
                CapsuleProcess::Agent(AgentTurnSpec {
                    adapter,
                    model: None,
                    reasoning_effort: None,
                    output_schema: None,
                    prompt: ArtifactId(hash(7)),
                    credential: None,
                    env,
                }),
                CapsuleNetwork::Offline,
                None,
                budgets(),
                None,
            )
        };
        let home =
            || std::collections::BTreeMap::from([(SmolStr::new("HOME"), SmolStr::new("/tmp/h"))]);
        for kind in AdapterKind::ALL {
            let capsule = build(kind, std::collections::BTreeMap::new())
                .unwrap_or_else(|error| panic!("{kind:?}: the turn constructs: {error}"));
            let encoded = serde_json::to_value(&capsule).expect("the capsule encodes");
            assert_eq!(
                encoded["process"]["kind"], "agent",
                "{kind:?}: the Agent arm: {encoded}"
            );
            assert!(
                encoded["process"].get("argv").is_none(),
                "{kind:?}: the encoded turn carries no launch vector: {encoded}"
            );
            json_roundtrip(capsule);
            let error = build(kind, home())
                .expect_err("a declared HOME is kata's")
                .to_string();
            // The owner named is the tool host's init, for this kind — a
            // nanocode turn's credential is carried in-process and renders
            // no env at all, so "credential carrier" would name a channel
            // that writes nothing here.
            assert!(
                error.contains("capsule_agent_env_channel_owned")
                    && error.contains("`kata-toolhost`")
                    && error.contains(kind.as_label())
                    && !error.contains("credential carrier"),
                "{kind:?}: the refusal names the tool host's init as `HOME`'s owner: {error}"
            );
        }
    }

    /// **`Capsule::new`'s v8 refusal: an Egress with no authorities is refused
    /// by name**, beside the Agent arm's own: an empty declared model and an
    /// output schema on a kind with no channel for one. Each refusal is pinned
    /// rather than assumed: an empty egress allowlist would assert a posture
    /// that grants nothing.
    ///
    /// **Would red if:** the empty-allowlist guard were dropped (the capsule
    /// constructs).
    #[test]
    fn capsule_new_refuses_an_empty_egress_and_the_agent_arms_empty_declarations() {
        let build = |process: CapsuleProcess| {
            Capsule::new(
                OccurrenceId(hash(1)),
                PreparedActionId(hash(2)),
                EnvironmentId(hash(3)),
                PlatformId(hash(4)),
                vec![mapping(5, "/work")],
                process,
                CapsuleNetwork::Offline,
                None,
                budgets(),
                None,
            )
        };
        let turn = || {
            CapsuleProcess::Agent(AgentTurnSpec {
                adapter: AdapterKind::NanocodeOpenai,
                model: None,
                reasoning_effort: None,
                output_schema: None,
                prompt: ArtifactId(hash(7)),
                credential: None,
                env: std::collections::BTreeMap::new(),
            })
        };
        build(turn()).expect("an agent turn constructs");

        let error = Capsule::new(
            OccurrenceId(hash(1)),
            PreparedActionId(hash(2)),
            EnvironmentId(hash(3)),
            PlatformId(hash(4)),
            vec![mapping(5, "/work")],
            CapsuleProcess::Command {
                argv: vec![SmolStr::new("sh")],
            },
            CapsuleNetwork::Egress {
                allowlist: BTreeSet::new(),
            },
            None,
            budgets(),
            None,
        )
        .expect_err("an egress with no authorities is refused");
        assert!(
            error.to_string().contains("capsule_egress_allowlist_empty"),
            "the refusal is named: {error}"
        );

        // `model: Some("")` is refused too: it and `None` hash alike under
        // `hash_capsule_process`, so without this door two capsules could
        // disagree about a declared field while sharing an id.
        let error = build(CapsuleProcess::Agent(AgentTurnSpec {
            adapter: AdapterKind::NanocodeOpenai,
            model: Some(SmolStr::new("")),
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(hash(7)),
            credential: None,
            env: std::collections::BTreeMap::new(),
        }))
        .expect_err("an empty declared model is refused");
        assert!(
            error.to_string().contains("capsule_agent_model_empty"),
            "the refusal is named: {error}"
        );
        // and a DESERIALIZED `Some("")` meets the same door, because
        // `Capsule`'s Deserialize re-runs `new`.
        let spec = build(turn()).expect("the base capsule constructs");
        let mut body = serde_json::to_value(&spec).expect("the capsule encodes");
        body["process"]["model"] = serde_json::json!("");
        let error = serde_json::from_value::<Capsule>(body)
            .expect_err("a decoded empty-model capsule is refused too");
        assert!(
            error.to_string().contains("capsule_agent_model_empty"),
            "the refusal is named on decode: {error}"
        );

        // An output schema on a kind whose protocol has no channel for one is
        // refused, on every kind answering false; a kind that carries one
        // constructs; and a DECODED capsule meets the same door.
        let schema = serde_json::json!({"type": "object"});
        let with_schema = |adapter: AdapterKind| {
            CapsuleProcess::Agent(AgentTurnSpec {
                adapter,
                model: None,
                reasoning_effort: None,
                output_schema: Some(schema.clone()),
                prompt: ArtifactId(hash(7)),
                credential: None,
                env: std::collections::BTreeMap::new(),
            })
        };
        for adapter in AdapterKind::ALL {
            // The measured table, written here and NOT read from the switch
            // under test: an arm flipped in `carries_strict_output_schema`
            // reds this row instead of moving the expectation with it.
            let carries = match adapter {
                AdapterKind::NanocodeOpenai => true,
                AdapterKind::NanocodeAnthropic => false,
            };
            assert_eq!(
                adapter.carries_strict_output_schema(),
                carries,
                "{adapter:?}: the switch answers the measured table"
            );
            let constructed = build(with_schema(adapter));
            if carries {
                constructed.expect("a kind that carries a schema constructs with one");
            } else {
                let error = constructed.expect_err("a kind with no schema channel refuses one");
                assert!(
                    error
                        .to_string()
                        .contains("capsule_agent_output_schema_uncarried"),
                    "{adapter:?}: the refusal is named: {error}"
                );
            }
        }
        let mut unschemaed = with_schema(AdapterKind::NanocodeAnthropic);
        if let CapsuleProcess::Agent(turn) = &mut unschemaed {
            turn.output_schema = None;
        }
        let unschemaed =
            build(unschemaed).expect("a nanocode_anthropic turn with no schema constructs");
        let mut body = serde_json::to_value(&unschemaed).expect("the capsule encodes");
        body["process"]["output_schema"] = schema.clone();
        let error = serde_json::from_value::<Capsule>(body)
            .expect_err("a decoded nanocode_anthropic capsule with a schema is refused too");
        assert!(
            error
                .to_string()
                .contains("capsule_agent_output_schema_uncarried"),
            "the refusal is named on decode: {error}"
        );
    }

    /// **`EgressAuthority`'s refused set refuses, every clause.** The capsule field and
    /// `kata_worker::egress_proxy::EgressAllowlist`'s matched set are both built through
    /// [`EgressAuthority::new`], so they are one rule. Each row is the entry
    /// [`EgressAuthority::new`] must refuse and the clause's fingerprint in the refusal text.
    ///
    /// **Would red if:** any clause of `EgressAuthority::new` were dropped (its
    /// row constructs), or the normalisation were dropped (`API.Example.COM`
    /// would round-trip case-sensitively).
    #[test]
    fn egress_authority_refuses_its_whole_refused_set() {
        for (entry, clause) in [
            ("", "EMPTY"),
            ("*.example.com", "PATTERN"),
            ("example?.com", "PATTERN"),
            ("exa mple.com", "not an ASCII alphanumeric or `-`"),
            ("example.com\n", "not an ASCII alphanumeric or `-`"),
            ("example..com", "empty label"),
            ("-example.com", "begins or ends with `-`"),
            (".example.com", "begins or ends with `.`"),
            ("::1", "BRACKETED"),
            ("[example.com]", "an IPv6 literal"),
        ] {
            let error = EgressAuthority::new(entry, 443).unwrap_err().to_string();
            assert!(
                error.contains("egress authority refused"),
                "{entry:?}: {error}"
            );
            assert!(
                error.contains(clause),
                "{entry:?} must hit {clause}: {error}"
            );
        }
        let over = "a".repeat(254) + ".com";
        assert!(
            EgressAuthority::new(&over, 443)
                .unwrap_err()
                .to_string()
                .contains("253-byte"),
            "the 253-byte bound refuses"
        );
        assert!(
            EgressAuthority::new("example.com", 0)
                .unwrap_err()
                .to_string()
                .contains("port 0"),
            "port 0 refuses"
        );
        // The whole point of normalising: the same host spelled in caps is the
        // same authority.
        let authority = EgressAuthority::new("API.Example.COM", 443).expect("a valid pair");
        assert_eq!(authority.host(), "api.example.com");
        assert_eq!(authority.port(), 443);
        EgressAuthority::new("[::1]", 443).expect("a bracketed IPv6 literal");
        EgressAuthority::new("127.0.0.1", 443).expect("a dotted IPv4 literal");
        // A malformed entry INSIDE a serialized allowlist meets the same rule:
        // the raw-mirror decode re-runs `new`.
        let bad = serde_json::json!({"host": "*.example.com", "port": 443});
        serde_json::from_value::<EgressAuthority>(bad)
            .expect_err("a wildcard host must be refused on deserialize");
    }

    /// **The posture labels the capsule's OWN allowlist, never a re-derived one**,
    /// and its wire shape is the one every face serializes: an `Egress`
    /// capsule is `egress` over exactly its allowlist, sorted; an `Offline`
    /// capsule is `offline`.
    #[test]
    fn the_capsule_network_posture_labels_the_capsules_own_allowlist() {
        let egress = CapsuleNetwork::Egress {
            allowlist: BTreeSet::from([
                EgressAuthority::new("registry.example", 443).unwrap(),
                EgressAuthority::new("crates.example", 443).unwrap(),
            ]),
        };
        let posture = CapsuleNetworkPosture::of(&egress);
        assert_eq!(
            posture,
            CapsuleNetworkPosture::Egress {
                allowlist: vec![
                    "crates.example:443".to_owned(),
                    "registry.example:443".to_owned(),
                ],
            }
        );
        assert_eq!(
            serde_json::to_value(&posture).unwrap(),
            serde_json::json!({
                "posture": "egress",
                "allowlist": ["crates.example:443", "registry.example:443"],
            })
        );
        assert_eq!(
            posture.summary(),
            "egress (crates.example:443, registry.example:443)"
        );
        assert_eq!(
            serde_json::from_value::<CapsuleNetworkPosture>(
                serde_json::to_value(&posture).unwrap()
            )
            .unwrap(),
            posture
        );
        let offline = CapsuleNetworkPosture::of(&CapsuleNetwork::Offline);
        assert_eq!(offline, CapsuleNetworkPosture::Offline);
        assert!(offline.allowlist().is_empty());
        assert_eq!(
            serde_json::to_value(&offline).unwrap(),
            serde_json::json!({"posture": "offline"})
        );
    }

    /// **The v8 arms' serde shape is pinned: `kind` tags and the id
    /// separation.** `CapsuleProcess::Command` and `::Agent` are
    /// `kind`-tagged, `CapsuleNetwork::Offline`/`::Egress` are `kind`-tagged,
    /// and a Command and an Agent produce different capsule ids — the variant
    /// tag folds before any field does.
    ///
    /// **Would red if:** the tags' spellings drifted, or the fold dropped the
    /// tag (the two capsules would share an id).
    #[test]
    fn the_v8_process_and_network_arms_have_their_serde_shape_and_own_ids() {
        let command = CapsuleProcess::Command {
            argv: vec![SmolStr::new("vendor"), SmolStr::new("--stdio")],
        };
        assert_eq!(
            serde_json::to_value(&command).unwrap()["kind"],
            serde_json::json!("command")
        );
        let agent = CapsuleProcess::Agent(AgentTurnSpec {
            adapter: AdapterKind::NanocodeOpenai,
            model: Some(SmolStr::new("vendor/small")),
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(hash(7)),
            credential: None,
            env: std::collections::BTreeMap::new(),
        });
        let agent_json = serde_json::to_value(&agent).unwrap();
        assert_eq!(agent_json["kind"], serde_json::json!("agent"));
        assert_eq!(
            serde_json::from_value::<CapsuleProcess>(agent_json).unwrap(),
            agent
        );
        assert_eq!(
            serde_json::to_value(&CapsuleNetwork::Offline).unwrap()["kind"],
            serde_json::json!("offline")
        );
        let egress = CapsuleNetwork::Egress {
            allowlist: BTreeSet::from([EgressAuthority::new("api.vendor.test", 443).unwrap()]),
        };
        let egress_json = serde_json::to_value(&egress).unwrap();
        assert_eq!(egress_json["kind"], serde_json::json!("egress"));
        assert_eq!(
            serde_json::from_value::<CapsuleNetwork>(egress_json).unwrap(),
            egress
        );

        // The domain-separation the design names: different kinds, different
        // capsules — and different reuse keys.
        let build = |process| {
            Capsule::new(
                OccurrenceId(hash(1)),
                PreparedActionId(hash(2)),
                EnvironmentId(hash(3)),
                PlatformId(hash(4)),
                vec![mapping(5, "/work")],
                process,
                CapsuleNetwork::Offline,
                None,
                budgets(),
                None,
            )
            .unwrap()
        };
        let command_capsule = build(CapsuleProcess::Command {
            argv: vec![SmolStr::new("sh"), SmolStr::new("-c"), SmolStr::new("true")],
        });
        let agent_capsule = build(CapsuleProcess::Agent(AgentTurnSpec {
            adapter: AdapterKind::NanocodeOpenai,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(hash(7)),
            credential: None,
            env: std::collections::BTreeMap::new(),
        }));
        assert_ne!(command_capsule.id(), agent_capsule.id());
        assert_ne!(
            command_capsule.reuse_key(&test_executor()),
            agent_capsule.reuse_key(&test_executor())
        );
    }

    /// **A v7 capsule is refused cleanly by the decode every reader funnels
    /// through.** The v7 body spelled the process as a bare `argv` field and
    /// carried no `network`; `current_schema_version` refuses it by name before
    /// the missing fields are even considered. (`capsule_frame::resolve` wraps
    /// the same refusal — the worker-side cell pins the wrap.)
    ///
    /// **Would red if:** a v7-shaped body were silently upgraded (the decode
    /// would succeed), or the refusal lost the version number.
    #[test]
    fn a_v7_capsule_is_refused_by_its_schema_version_on_deserialize() {
        let mut document =
            serde_json::to_value(capsule(vec![mapping(5, "/work/a")]).unwrap()).unwrap();
        // Shape the body as v7 spelled it: `argv`, no `process`, no `network`.
        let CapsuleProcess::Command { argv } = capsule(vec![mapping(5, "/work/a")])
            .unwrap()
            .process()
            .clone()
        else {
            unreachable!();
        };
        let body = document.as_object_mut().unwrap();
        body.remove("process");
        body.remove("network");
        body.insert("argv".to_owned(), serde_json::to_value(&argv).unwrap());
        body["schema_version"] = serde_json::json!(7);
        let error = serde_json::from_value::<Capsule>(document)
            .expect_err("a v7 capsule body must be refused")
            .to_string();
        assert!(
            error.contains("schema_version 7 is not supported"),
            "the refusal names the version: {error}"
        );
    }

    #[test]
    fn capsule_refuses_a_duplicate_guest_path() {
        let error = capsule(vec![mapping(5, "/work/a"), mapping(6, "/work/a")])
            .expect_err("duplicate guest path must be refused");
        let message = error.to_string();
        assert!(message.contains("/work/a"), "{message}");
        assert!(message.contains("more than once"), "{message}");
    }

    #[test]
    fn guest_path_accepts_every_root_and_refuses_everything_else() {
        for root in GUEST_ROOTS {
            GuestPath::new(*root).unwrap_or_else(|error| panic!("{root} refused: {error}"));
            GuestPath::new(format!("{root}/child")).unwrap();
        }
        for refused in [
            "/home/alice/x",
            "/",
            "/work/../x",
            "/workx",
            "/work/a\u{0}",
            "relative",
            "/work/./a",
            "/work//a",
        ] {
            assert!(
                GuestPath::new(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
        // Exactly PATH_MAX is accepted; one byte more is refused. "/work/" is 6
        // bytes, so the accepted tail is 4090 bytes and the refused one 4091.
        let at_limit = format!("/work/{}", "a".repeat(4096 - "/work/".len()));
        assert_eq!(at_limit.len(), 4096);
        GuestPath::new(at_limit).expect("a 4096-byte guest path is accepted");
        let over_limit = format!("/work/{}", "a".repeat(4097 - "/work/".len()));
        assert_eq!(over_limit.len(), 4097);
        assert!(
            GuestPath::new(over_limit).is_err(),
            "a 4097-byte guest path must be refused"
        );
    }

    /// Every schema-version carrier in this module, not a sample of them: a
    /// carrier whose refusal was never wired would otherwise read a foreign body
    /// under this build's field meanings.
    #[test]
    fn a_foreign_schema_version_is_refused_on_deserialize() {
        fn refuses<T>(carrier: &str, value: &T)
        where
            T: Serialize + serde::de::DeserializeOwned + std::fmt::Debug,
        {
            let mut document = serde_json::to_value(value).expect("the carrier serializes");
            assert!(
                document.get("schema_version").is_some(),
                "{carrier} must serialize a schema_version to be version-checked"
            );
            // DERIVED from the current version, never a literal: a literal
            // becomes the CURRENT version at the next bump, and the test would
            // then assert that the live schema is refused.
            let foreign = EXECUTION_CONTRACT_SCHEMA_VERSION + 1;
            document["schema_version"] = serde_json::json!(foreign);
            let error = serde_json::from_value::<T>(document)
                .expect_err("a foreign schema_version must be refused")
                .to_string();
            assert!(
                error.contains(&format!("schema_version {foreign}")),
                "{carrier}: {error}"
            );
        }

        refuses("OperationContract", &agent_contract(&["claude"]));
        refuses("OccurrenceRef", &occurrence());
        refuses("PreparedAction", &prepared());
        refuses(
            "ArtifactRef",
            &ArtifactRef::new(hash(7), 99, ArtifactPrivacy::Private),
        );
        refuses(
            "EnvironmentRef",
            &EnvironmentRef::new(ArtifactId(hash(1)), hash(2)),
        );
        refuses("PlatformRef", &PlatformRef::new("x86_64-linux", hash(3)));
        refuses("Capsule", &capsule(vec![mapping(5, "/work/a")]).unwrap());
    }

    #[test]
    fn a_tampered_capsule_id_is_refused_on_deserialize() {
        let mut value =
            serde_json::to_value(capsule(vec![mapping(5, "/work/a")]).unwrap()).unwrap();
        value["id"] = serde_json::json!(ContentHash::new([0xab; 32]).to_string());
        let error = serde_json::from_value::<Capsule>(value).unwrap_err();
        assert!(
            error.to_string().contains("does not match its body"),
            "{error}"
        );
    }

    #[test]
    fn a_tampered_artifact_id_is_refused_on_deserialize() {
        json_roundtrip(ArtifactRef::new(hash(7), 99, ArtifactPrivacy::Private));
        json_roundtrip(EnvironmentRef::new(ArtifactId(hash(1)), hash(2)));
        json_roundtrip(PlatformRef::new("x86_64-linux", hash(3)));
        let mut value =
            serde_json::to_value(ArtifactRef::new(hash(7), 99, ArtifactPrivacy::Private)).unwrap();
        value["id"] = serde_json::json!(ContentHash::new([0xcd; 32]).to_string());
        assert!(serde_json::from_value::<ArtifactRef>(value).is_err());
    }

    #[test]
    fn wait_shape_and_driver_order_rotate_operation_identity() {
        let wait = |operation| OperationContract::new(StageId(SmolStr::new("pause")), operation);
        let delay = wait(RuntimeOperation::Wait(WaitOperation::For { delay_ms: 0 }));
        let deadline = wait(RuntimeOperation::Wait(WaitOperation::Until { epoch_ms: 0 }));
        assert_ne!(delay.id(), deadline.id());

        let forward = agent_contract(&["claude", "codex"]);
        let reversed = agent_contract(&["codex", "claude"]);
        assert_ne!(forward.id(), reversed.id());
        assert_eq!(forward.id(), agent_contract(&["claude", "codex"]).id());
        json_roundtrip(forward);
        json_roundtrip(delay);
    }

    /// ONE ENCODING for the durable column and for the content id — the property
    /// [`OperationPath::canonical_bytes`] exists to hold.
    ///
    /// It is asserted by REBUILDING the fold from the stored bytes alone, not by
    /// comparing `canonical_bytes` to a copy of itself: the 8-byte prefix is fed as
    /// the `path` field and each following 4-byte chunk as a `coordinate` field,
    /// which is exactly what a reader of `occurrences.operation_path` can do. If the
    /// two ever diverge, SQL occurrence uniqueness and `OccurrenceId` would be
    /// answering different questions and nothing else in the tree would notice.
    #[test]
    fn hash_path_folds_exactly_the_canonical_bytes_field_wise() {
        for path in [
            OperationPath(Vec::new()),
            OperationPath(vec![0]),
            OperationPath(vec![3, 5]),
            OperationPath(vec![u32::MAX, 0, 7]),
        ] {
            let mut folded = blake3::Hasher::new();
            hash_path(&mut folded, "path", &path);

            let bytes = path.canonical_bytes();
            assert_eq!(
                bytes.len() % 4,
                0,
                "the stored column CHECK is length(operation_path) % 4 = 0"
            );
            let (count, coordinates) = bytes.split_at(8);
            assert_eq!(
                usize::try_from(u64::from_le_bytes(
                    count.try_into().expect("eight-byte count prefix")
                ))
                .expect("coordinate count fits usize"),
                coordinates.len() / 4,
                "the count prefix must agree with the coordinates that follow it"
            );
            let mut rebuilt = blake3::Hasher::new();
            hash_field(&mut rebuilt, "path", count);
            for chunk in coordinates.chunks(4) {
                hash_field(&mut rebuilt, "coordinate", chunk);
            }
            assert_eq!(folded.finalize(), rebuilt.finalize(), "{path:?}");
        }
    }

    /// The pre-v6 carrier is refused, not read under v6 field meanings. A literal
    /// `5` on purpose: this is the version whose `Invoke` named a PACK, and no later
    /// bump may make it acceptable again.
    #[test]
    fn a_v5_contract_is_refused_by_the_schema_version_door() {
        assert_ne!(EXECUTION_CONTRACT_SCHEMA_VERSION, 5);
        let mut document = serde_json::to_value(OperationContract::new(
            StageId(SmolStr::new("child")),
            RuntimeOperation::Invoke {
                program: hash(4),
                params_hash: hash(5),
            },
        ))
        .expect("the contract serializes");
        document["schema_version"] = serde_json::json!(5);
        let error = serde_json::from_value::<OperationContract>(document)
            .expect_err("a v5 contract must be refused")
            .to_string();
        assert!(
            error.contains("schema_version 5 is not supported"),
            "{error}"
        );
    }

    fn request_fields() -> InputRequestFields<'static> {
        InputRequestFields {
            id: "confirm",
            stage: Some("deploy"),
            question: "Ship it?",
            default_assumption: "no",
            timeout_ms: Some(60_000),
            priority: "high",
            context: Some("release notes"),
        }
    }

    /// Every field [`input_request_selector`] claims to hash rotates it, and an
    /// absent optional field is distinct from an empty one.
    #[test]
    fn every_input_request_field_rotates_the_selector() {
        let base = input_request_selector(request_fields());
        assert_eq!(base, input_request_selector(request_fields()));
        let rotations: [(&str, InputRequestFields<'static>); 11] = [
            (
                "id",
                InputRequestFields {
                    id: "confirm2",
                    ..request_fields()
                },
            ),
            (
                "stage",
                InputRequestFields {
                    stage: Some("deploy2"),
                    ..request_fields()
                },
            ),
            (
                "stage absent",
                InputRequestFields {
                    stage: None,
                    ..request_fields()
                },
            ),
            (
                "question",
                InputRequestFields {
                    question: "Ship it now?",
                    ..request_fields()
                },
            ),
            (
                "default_assumption",
                InputRequestFields {
                    default_assumption: "yes",
                    ..request_fields()
                },
            ),
            (
                "timeout_ms",
                InputRequestFields {
                    timeout_ms: Some(60_001),
                    ..request_fields()
                },
            ),
            (
                "timeout absent",
                InputRequestFields {
                    timeout_ms: None,
                    ..request_fields()
                },
            ),
            (
                "priority",
                InputRequestFields {
                    priority: "low",
                    ..request_fields()
                },
            ),
            (
                "context",
                InputRequestFields {
                    context: Some("notes"),
                    ..request_fields()
                },
            ),
            (
                "context absent",
                InputRequestFields {
                    context: None,
                    ..request_fields()
                },
            ),
            (
                "context empty",
                InputRequestFields {
                    context: Some(""),
                    ..request_fields()
                },
            ),
        ];
        let mut seen = std::collections::HashSet::from([base]);
        for (field, fields) in rotations {
            assert!(
                seen.insert(input_request_selector(fields)),
                "rotating {field} must produce a selector no other rotation produced"
            );
        }
        // Absent and empty are distinct for every optional field, not only context.
        assert_ne!(
            input_request_selector(InputRequestFields {
                stage: None,
                ..request_fields()
            }),
            input_request_selector(InputRequestFields {
                stage: Some(""),
                ..request_fields()
            }),
        );
    }

    /// Both new operation shapes fold every field they carry into the operation
    /// identity, and the new wait mode is distinct from the other two.
    #[test]
    fn the_v6_operation_shapes_fold_every_field() {
        let contract = |operation| OperationContract::new(StageId(SmolStr::new("s")), operation);
        let invoke = |program, params_hash| {
            contract(RuntimeOperation::Invoke {
                program,
                params_hash,
            })
            .id()
        };
        assert_ne!(
            invoke(hash(1), hash(2)),
            invoke(hash(3), hash(2)),
            "program"
        );
        assert_ne!(
            invoke(hash(1), hash(2)),
            invoke(hash(1), hash(3)),
            "params_hash"
        );
        assert_ne!(
            invoke(hash(1), hash(2)),
            invoke(hash(2), hash(1)),
            "program and params_hash are distinct fields"
        );

        let input =
            |request| contract(RuntimeOperation::Wait(WaitOperation::Input { request })).id();
        assert_ne!(input(hash(1)), input(hash(2)), "request");
        let zero_wait = |wait| contract(RuntimeOperation::Wait(wait)).id();
        let ids = [
            zero_wait(WaitOperation::Input {
                request: ContentHash::new([0; 32]),
            }),
            zero_wait(WaitOperation::For { delay_ms: 0 }),
            zero_wait(WaitOperation::Until { epoch_ms: 0 }),
        ];
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[2]);

        json_roundtrip(contract(RuntimeOperation::Invoke {
            program: hash(1),
            params_hash: hash(2),
        }));
        json_roundtrip(contract(RuntimeOperation::Wait(WaitOperation::Input {
            request: hash(9),
        })));
    }

    /// The program-operation coordinate and its ONE inverse agree on every path, and the
    /// inverse refuses every spelling that does not render back to itself.
    #[test]
    fn the_program_operation_coordinate_round_trips() {
        for path in [
            OperationPath(vec![0]),
            OperationPath(vec![7]),
            OperationPath(vec![3, 0, 12]),
            OperationPath(vec![u32::MAX, 1]),
        ] {
            let rendered = path.program_operation_stage_id();
            assert_eq!(
                OperationPath::from_program_operation_stage_id(&rendered),
                Some(path.clone()),
                "{rendered}"
            );
        }
        assert_eq!(
            OperationPath(vec![3, 0, 12]).program_operation_stage_id(),
            "#op/3.0.12"
        );
        for refused in [
            "classify",
            "#op/",
            "#op",
            "op/1",
            "#op/1.",
            "#op/.1",
            "#op/1..2",
            "#op/01",
            "#op/+1",
            "#op/-1",
            "#op/4294967296",
            "#op/1 ",
            "x#op/1",
            "#branch-skip",
        ] {
            assert_eq!(
                OperationPath::from_program_operation_stage_id(refused),
                None,
                "{refused:?} is not a program-operation coordinate"
            );
        }
    }

    /// `env:<VAR>`'s refused set, stated: every name that is not the POSIX
    /// `[A-Za-z_][A-Za-z0-9_]*` shape, and every name kata's own boundary
    /// plumbing renders into a capsule's `process.env`, which in the worker's
    /// environment holds a plumbing value, not a key — the two ways a
    /// credential source arrives misdelivered.
    #[test]
    fn env_credential_source_refuses_malformed_and_plumbing_owned_names() {
        for declared in [
            // Not the POSIX shape: empty, a digit first, a `=` that would split
            // the rendered `KEY=value` entry into two variables, a NUL, a dash.
            "env:",
            "env:1KEY",
            "env:BAD-NAME",
            "env:TWO=ONE",
            "env:HAS\0NUL",
            // The plumbing-owned names — `CREDENTIAL_ENV_RESERVED` verbatim.
            "env:PATH",
            "env:HTTP_PROXY",
            "env:HTTPS_PROXY",
            "env:http_proxy",
            "env:https_proxy",
            "env:ALL_PROXY",
            "env:all_proxy",
            "env:NO_PROXY",
            "env:no_proxy",
            "env:HOME",
            "env:XDG_RUNTIME_DIR",
        ] {
            assert_eq!(
                CredentialSource::from_declared(declared),
                None,
                "{declared} must refuse"
            );
        }
        // The user-manager variable is refused naming its own owner, not as a
        // value the capsule's plumbing would shadow.
        let why = credential_env_refusal(USER_MANAGER_ENV).expect("XDG_RUNTIME_DIR refuses");
        assert!(
            why.contains("user-manager clients")
                && why.contains("`systemd-run`")
                && why.contains("`systemctl`")
                && !why.contains("shadow"),
            "{why}"
        );
        // And the whole set is named: a name added to the plumbing without a
        // matching reservation fails here rather than silently colliding.
        for name in CREDENTIAL_ENV_RESERVED {
            assert!(
                credential_env_refusal(name).is_some(),
                "{name} is plumbing-owned and must refuse"
            );
        }
        // The admitted side: a credential-shaped name is the point of this
        // channel — only the declared `env` map bans `*_KEY` spellings.
        for declared in ["env:KATA_API_KEY", "env:_PRIVATE", "env:VENDOR_TOKEN"] {
            let Some(CredentialSource::EnvVar { var }) = CredentialSource::from_declared(declared)
            else {
                panic!("{declared} is the shape the channel exists to carry");
            };
            assert_eq!(format!("env:{var}"), declared, "as_declared is the inverse");
        }
    }

    /// **A declared `env` name kata itself renders is refused — under the
    /// name of the channel that owns it.** [`kata_rendered_env`] is the one
    /// statement of what the worker writes into `process.env` beside the
    /// declared map: `PATH`, the egress plumbing's eight, and the toolhost
    /// init's `HOME`. Each row declares one of them and the refusal names both
    /// the refusal and the owning channel — a name kata renders would shadow
    /// or be shadowed.
    ///
    /// **Would red if:** a rendered name dropped out of the refused set (its
    /// row constructs), or `Deserialize` stopped re-running `Capsule::new` (the
    /// decode row admits a colliding key).
    #[test]
    fn a_declared_env_naming_a_channel_kata_renders_is_refused_under_its_owner() {
        let capsule_with_env = |key: &str| -> KataResult<Capsule> {
            Capsule::new(
                OccurrenceId(hash(1)),
                PreparedActionId(hash(2)),
                EnvironmentId(hash(3)),
                PlatformId(hash(4)),
                vec![mapping(5, "/work")],
                CapsuleProcess::Agent(AgentTurnSpec {
                    adapter: AdapterKind::NanocodeOpenai,
                    model: None,
                    reasoning_effort: None,
                    output_schema: None,
                    prompt: ArtifactId(hash(7)),
                    credential: None,
                    env: [(SmolStr::new(key), SmolStr::new("x"))]
                        .into_iter()
                        .collect(),
                }),
                CapsuleNetwork::Offline,
                None,
                budgets(),
                None,
            )
        };
        for (key, channel) in [
            ("PATH", "path_prepend"),
            ("HTTP_PROXY", "the egress plumbing"),
            ("HTTPS_PROXY", "the egress plumbing"),
            ("http_proxy", "the egress plumbing"),
            ("https_proxy", "the egress plumbing"),
            ("ALL_PROXY", "the egress plumbing"),
            ("all_proxy", "the egress plumbing"),
            ("NO_PROXY", "the egress plumbing"),
            ("no_proxy", "the egress plumbing"),
            ("HOME", "`kata-toolhost`"),
            ("XDG_RUNTIME_DIR", "user-manager clients"),
        ] {
            let error = capsule_with_env(key)
                .expect_err("a declared name kata renders is refused")
                .to_string();
            assert!(
                error.contains("capsule_agent_env_channel_owned"),
                "{key}: the refusal is BY NAME: {error}"
            );
            assert!(
                error.contains(key) && error.contains(channel),
                "{key}: the refusal must name the variable and its owning channel ({channel}): {error}"
            );
        }
        // THE DECODE DOOR — `Capsule`'s Deserialize re-runs `new`, so a
        // serialized capsule carrying a colliding key meets the same refusal.
        let spec = capsule_with_env("TERM").expect("a clean capsule constructs");
        let mut body = serde_json::to_value(&spec).expect("the capsule encodes");
        body["process"]["env"]["PATH"] = serde_json::json!("x");
        let error = serde_json::from_value::<Capsule>(body)
            .expect_err("a decoded collision is refused too")
            .to_string();
        assert!(
            error.contains("capsule_agent_env_channel_owned"),
            "the refusal is named on decode: {error}"
        );
        // The reserved set is still exactly the eleven names the toolhost init
        // and the plumbing render or the worker keeps for its user-manager
        // clients — a twelfth arrives only through the constants it is built
        // from.
        assert_eq!(
            CREDENTIAL_ENV_RESERVED.len(),
            11,
            "PATH + EGRESS_PLUMBING_ENV + HOME + XDG_RUNTIME_DIR"
        );
    }

    /// **`kata_login` parses, spells and serializes as itself** — the persisted
    /// `TurnCredentialRef` shape is `{"kind":"kata_login"}` — an `env:<VAR>`
    /// source parses and spells as itself, and a host login's spelling
    /// (`codex_login`) parses to no source.
    ///
    /// **Would red if:** either spelling drifted from its parse or its wire
    /// shape, or a host login parsed.
    #[test]
    fn the_credential_sources_parse_spell_and_persist_as_themselves() {
        let kata_login = CredentialSource::KataLogin;
        assert_eq!(
            CredentialSource::from_declared("kata_login"),
            Some(kata_login.clone())
        );
        assert_eq!(kata_login.as_declared(), "kata_login");
        let reference = TurnCredentialRef {
            mode: crate::metering::CredentialMode::Subscription,
            source: kata_login,
        };
        let json = serde_json::to_string(&reference).unwrap();
        assert_eq!(
            json,
            r#"{"mode":"subscription","source":{"kind":"kata_login"}}"#
        );
        assert_eq!(
            serde_json::from_str::<TurnCredentialRef>(&json).unwrap(),
            reference
        );
        let env = CredentialSource::EnvVar {
            var: SmolStr::new("OPENAI_API_KEY"),
        };
        assert_eq!(
            CredentialSource::from_declared("env:OPENAI_API_KEY"),
            Some(env.clone())
        );
        assert_eq!(env.as_declared(), "env:OPENAI_API_KEY");
        assert_eq!(CredentialSource::from_declared("codex_login"), None);
    }
}
