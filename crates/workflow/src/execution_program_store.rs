//! Checked execution-program persistence types and compatibility classification.
//!
//! Runtime recovery is anchored on the checked `ExecutionProgram`, not the
//! frontend `WorkflowDefinition`. The durable rows live in `operational.db`'s
//! `programs`, `invocations` and `execution_lifecycle` tables
//! (`kata_core::operational`), written through
//! [`ExecutionLifecycleFace`](crate::execution_lifecycle::ExecutionLifecycleFace);
//! this module owns the typed shapes those rows decode into and the
//! classification of program bytes this binary cannot dispatch. Program bytes are
//! read as opaque JSON first so an incompatible program is classified rather than
//! failing to decode, but production writes accept only the concrete checked
//! [`ExecutionProgram`](kata_program::execution_program::ExecutionProgram).
//!
//! The checked program, immutable normalized invocation, and initial
//! `admitting` lifecycle row are established in one `synchronous=FULL`
//! transaction. `Running` therefore means admission evidence and workspace
//! setup completed and dispatch is allowed. `Terminalizing` durably latches an
//! outcome before any destructive closeout. Assignment rows are never used to
//! infer top-level workflow terminality: a valid runner may be between stages
//! while every assignment materialized so far is terminal.

use std::path::Path;

use kata_types::execution::ExecutionExternalInputEvidence;
use kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE;
use kata_types::idempotency::canonicalize_args;
use kata_types::params::InvocationParam;
use kata_types::target::ExecutionTarget;
use kata_types::{KataError, KataResult};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use kata_program::execution_program::{
    CarriedStageRefusal, DURABLE_EXECUTION_CLASS_REFUSAL_RECOURSE, ExecutionProgram,
};

/// Schema understood by the production checked-program persistence boundary.
///
/// Its value is the checked program's own
/// [`EXECUTION_PROGRAM_SCHEMA_VERSION`](kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION):
/// a bump is made there, and owes everything below.
///
/// The store takes the concrete checked-program type (`kata-program`'s
/// `ExecutionProgram`), never a trait, so the production write boundary cannot
/// be forged through a downstream marker-trait implementation.
///
/// A schema bump is how a decode-breaking field change stays legible to the
/// operator who has to act on it: a program written at an earlier schema
/// classifies as [`ExecutionProgramIncompatibility::LegacySchema`], which is what
/// it IS, rather than as
/// [`ExecutionProgramIncompatibility::UndecodableCurrentSchema`] — *"bytes that do
/// not decode"*, whose message tells the operator the bytes are corrupt and offers
/// no recourse but the old binary. Every bump rotates every program hash, because
/// `schema_version` is hash material.
///
/// # Every bump of this constant bumps `OPERATIONAL_SCHEMA_VERSION`
///
/// `programs.program_json` is a blob of this shape inside
/// `operational.db`, so a bump here is a blob-shape change of that database and
/// moves its stamp too, with the fresh-data-directory disposition the stamp
/// carries. A directory this binary opens therefore holds programs of ONE schema,
/// its own: a program an earlier schema wrote lives only in a directory refused at
/// open whatever state its executions are in. That is what lets boot and
/// `kata upgrade` check only the programs of NON-terminal executions
/// ([`blocking_incompatible_programs`]) — a terminal execution's older program is
/// never in a directory either of them accepts.
/// `every_program_schema_bump_moves_the_operational_stamp` guards the pairing:
/// bumping either constant APPENDS a row to its table, and its doc states the one
/// edit it cannot refuse (an in-place rewrite of a later last row).
///
/// A program at this schema that this binary still cannot dispatch (undecodable
/// bytes, a carried class it cannot honour) blocks while its execution is not
/// terminal: `kata upgrade --dry-run` names every such row and its reason, and the
/// operator finishes it on the binary that wrote it or starts this binary against
/// a fresh `[node] data_dir` (`boot::blocking_programs_refusal` is the one sentence
/// on that).
pub const CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION: u32 =
    kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION;

/// Schema of the immutable invocation envelope stored beside a checked program.
///
/// * v2 — the envelope carries the frozen [`ExecutionTarget`] of every
///   `worktree_isolated` workflow invocation. A target is present on EVERY
///   isolated run, so the bump changes the bytes of every isolated invocation;
///   a v1 row decoded with no target would mean "no frozen base" and send
///   recovery back to resolving trunk live, so v1 is refused rather than
///   defaulted (the operational stamp moved with it).
/// * v3 — a pull-request target's frozen facts carry `title_truncated` and
///   `body_truncated`, whether resolution's cut of the title and body dropped
///   anything. The cut text cannot say so (an uncut text within three bytes
///   of its bound looks like a cut one), so a v2 row holding a pull-request
///   target cannot be read as v3 with the flags `false`: it would tell a
///   template that a cut title is whole. v2 is refused rather than defaulted
///   (operational stamp 42 moved with it).
pub const CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION: u32 = 3;

/// A single admission is deliberately bounded independently of request limits.
/// This prevents a forged typed caller from turning the recovery authority into
/// an unbounded SQLite blob.
pub const MAX_EXECUTION_INVOCATION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_INITIAL_EXTERNAL_INPUTS: usize = 1_024;
pub const MAX_TERMINAL_REASON_CODE_BYTES: usize = 128;
pub use kata_core::operational::MAX_TERMINAL_REASON_MESSAGE_BYTES;

/// Product behavior attached to an immutable checked-program invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionInvocationKind {
    Workflow,
    DirectAgent,
}

impl ExecutionInvocationKind {
    /// The stable on-disk label. Must equal `kata_core::operational::InvocationKind`'s
    /// spelling; `invocation_kind_spellings_match_the_operational_vocabulary` pins it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workflow => "workflow",
            Self::DirectAgent => "direct_agent",
        }
    }

    /// Parse a stable on-disk label.
    pub fn parse(raw: &str) -> KataResult<Self> {
        match raw {
            "workflow" => Ok(Self::Workflow),
            "direct_agent" => Ok(Self::DirectAgent),
            other => Err(KataError::Storage(format!(
                "execution_program_store invalid invocation kind {other:?}"
            ))),
        }
    }
}

/// Immutable normalized invocation data accepted with a checked program.
///
/// Initial external inputs retain their generated ids, projections, targets,
/// and timestamps. Recovery republishes these exact values; it never
/// re-normalizes the caller's request or invents replacement ids.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionInvocation {
    pub schema_version: u32,
    pub kind: ExecutionInvocationKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initial_external_inputs: Vec<ExecutionExternalInputEvidence>,
    /// The resolved, canonically-ordered typed invocation params
    /// (`name` + `value`), default-filled at the executor boundary. Rides INSIDE
    /// the immutable invocation, so the admission hash binds these inputs for
    /// free and the load-verify / immutability / recovery paths cover them
    /// unchanged. Empty for a param-less invocation, and skipped from JSON when
    /// empty so a param-less invocation carries no `params` member (the additive
    /// precedent `initial_external_inputs` set; params moved no schema version).
    /// Provenance and the secret marker are recorded
    /// beside the digest / derived from the program spec, never here, so
    /// identical inputs from two faces converge to one admission hash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<InvocationParam>,
    /// The frozen [`ExecutionTarget`]: `Some` for EVERY `worktree_isolated`
    /// workflow invocation — the default trunk target included — and `None` for
    /// every other one, and for a schedule's pinned template (its target is
    /// resolved at every fire). Resolved before acceptance, so the admission
    /// digest binds the fork base, and recovery re-creates the workspace from it
    /// rather than resolving trunk again. Serialized as the
    /// [`kata_types::target::INVOCATION_TARGET_MEMBER`] member, the name the
    /// operational plane splices a schedule fire's target in under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<ExecutionTarget>,
}

impl ExecutionInvocation {
    #[must_use]
    pub const fn workflow(initial_external_inputs: Vec<ExecutionExternalInputEvidence>) -> Self {
        Self {
            schema_version: CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION,
            kind: ExecutionInvocationKind::Workflow,
            initial_external_inputs,
            params: Vec::new(),
            target: None,
        }
    }

    /// A workflow invocation carrying resolved typed params alongside any
    /// initial external inputs. The params must already be resolved + validated
    /// (default-filled, canonical name order) against the program's declared
    /// specs; [`crate::admission::checked_admission`] re-checks that
    /// idempotently.
    #[must_use]
    pub fn workflow_with_params(
        initial_external_inputs: Vec<ExecutionExternalInputEvidence>,
        params: Vec<InvocationParam>,
    ) -> Self {
        Self {
            schema_version: CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION,
            kind: ExecutionInvocationKind::Workflow,
            initial_external_inputs,
            params,
            target: None,
        }
    }

    /// This invocation carrying `target` — the frozen target of an isolated
    /// workflow invocation, or `None`.
    #[must_use]
    pub fn with_target(mut self, target: Option<ExecutionTarget>) -> Self {
        self.target = target;
        self
    }

    #[must_use]
    pub const fn direct_agent() -> Self {
        Self {
            schema_version: CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION,
            kind: ExecutionInvocationKind::DirectAgent,
            initial_external_inputs: Vec::new(),
            params: Vec::new(),
            target: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionInvocationRecord {
    pub execution_id: Ulid,
    pub invocation: ExecutionInvocation,
    pub admission_hash: [u8; 32],
    pub created_at_ms: i64,
}

/// Durable reason attached to a terminalization decision. The stable code is
/// suitable for automation while the bounded message is operator-facing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTerminalReason {
    pub code: String,
    pub message: String,
}

impl ExecutionTerminalReason {
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

pub(crate) fn validated_terminal_reason_bytes(
    reason: &ExecutionTerminalReason,
) -> KataResult<Vec<u8>> {
    let code = reason.code.trim();
    if code.is_empty() || code.len() > MAX_TERMINAL_REASON_CODE_BYTES {
        return Err(KataError::Validation(format!(
            "terminal reason code must contain 1..={MAX_TERMINAL_REASON_CODE_BYTES} bytes"
        )));
    }
    if !code.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
    }) {
        return Err(KataError::Validation(
            "terminal reason code must use lowercase ASCII letters, digits, '.', '-', or '_'"
                .to_string(),
        ));
    }
    if reason.message.trim().is_empty() || reason.message.len() > MAX_TERMINAL_REASON_MESSAGE_BYTES
    {
        return Err(KataError::Validation(format!(
            "terminal reason message must contain 1..={MAX_TERMINAL_REASON_MESSAGE_BYTES} bytes"
        )));
    }
    let value = serde_json::to_value(reason).map_err(|error| {
        KataError::Serialization(format!("serialize execution terminal reason: {error}"))
    })?;
    Ok(canonicalize_args(&value))
}

/// Why an opaque durable program cannot be dispatched by this binary.
///
/// # Invariant
///
/// The first three variants are SCHEMA verdicts, readable from the header alone.
/// The last two are CURRENT-SCHEMA verdicts, and they exist because the schema
/// is not the only thing that can make a stored program unrunnable: a blob
/// written by an earlier binary at the same schema can carry a seven-axis tuple
/// this binary's closed-world matrix refuses, and the decode doors refuse exactly
/// that at fire and at dispatch. A membrane that answered on the schema alone
/// would preview such a program as COMPATIBLE and then lose the operator a
/// scheduled fire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionProgramIncompatibility {
    MissingSchemaVersion,
    LegacySchema {
        version: u64,
    },
    FutureSchema {
        version: u64,
    },
    /// Current schema, but the bytes do not decode into a typed
    /// [`ExecutionProgram`] — so every runtime path that needs one refuses them,
    /// because every runtime path decodes them exactly the way this did.
    UndecodableCurrentSchema {
        detail: String,
    },
    /// Current schema, decodes, binds nothing else wrong — and carries a stage
    /// class the closed-world matrix refuses. This is the verdict
    /// `ExecutionProgram::validate_carried_stage_execution_classes` returns, in
    /// full, because it is the same value the decode doors will refuse with.
    UnhonourableExecutionClass {
        invalid: CarriedStageRefusal,
    },
}

impl ExecutionProgramIncompatibility {
    /// Whether this is one of the three SCHEMA verdicts: the header names no schema,
    /// or one other than this binary's. Every checked-program schema bump moves the
    /// operational stamp (see [`CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION`]), so in a
    /// directory this binary opens such bytes were written by no binary that opens it,
    /// and there is no writing binary to finish the execution on. The two
    /// current-schema verdicts were written by a binary of this schema, which can.
    #[must_use]
    pub fn is_schema_verdict(&self) -> bool {
        match self {
            Self::MissingSchemaVersion | Self::LegacySchema { .. } | Self::FutureSchema { .. } => {
                true
            }
            Self::UndecodableCurrentSchema { .. } | Self::UnhonourableExecutionClass { .. } => {
                false
            }
        }
    }

    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::MissingSchemaVersion => format!(
                "missing integer schema_version; current schema {CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION} is required"
            ),
            Self::LegacySchema { version } => format!(
                "unsupported checked-program schema {version}; current schema {CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION} is required. {EARLIER_SCHEMA_RECOURSE}"
            ),
            Self::FutureSchema { version } => format!(
                "future checked-program schema {version}; this binary supports schema {CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION}"
            ),
            Self::UndecodableCurrentSchema { detail } => format!(
                "checked-program schema {CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION} bytes that do not decode into a checked program: {detail}. Every runtime path decodes them the same way and will refuse them — inspect them as read-only evidence or finish/cancel the execution with the binary that wrote them"
            ),
            // Verbatim the decode doors' own wording: the preview an operator
            // reads at `kata upgrade` and the refusal they meet at fire/dispatch
            // must be the SAME sentence about the SAME tuple, or the preview is
            // a second opinion rather than a preview.
            Self::UnhonourableExecutionClass { invalid } => {
                format!("{invalid} {DURABLE_EXECUTION_CLASS_REFUSAL_RECOURSE}")
            }
        }
    }
}

/// A durable checked program that cannot be dispatched by the current runtime.
/// The raw bytes remain authoritative evidence; callers must never rewrite
/// them into a different boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompatibleExecutionProgram {
    pub execution_id: Ulid,
    pub schema_version: Option<u64>,
    pub incompatibility: ExecutionProgramIncompatibility,
}

/// Minimal, version-independent projection of an opaque checked program.
/// This is deliberately safe to expose for an incompatible program without pretending
/// that an old program can be dispatched by the current runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionProgramMetadata {
    pub schema_version: Option<u64>,
    pub workflow_name: Option<String>,
}

/// Durable, top-level authority for one workflow execution.
///
/// Assignment rows are deliberately not used to infer this state: a valid
/// runner can be between stages with every extant assignment terminal while
/// the workflow itself is still running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionLifecycleState {
    Admitting,
    Running,
    Terminalizing,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl ExecutionLifecycleState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }

    /// The stable on-disk label. Must equal
    /// `kata_core::operational::LifecycleState`'s spelling;
    /// `lifecycle_state_spellings_match_the_operational_vocabulary` pins it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitting => "admitting",
            Self::Running => "running",
            Self::Terminalizing => "terminalizing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }

    /// Parse a stable on-disk label.
    pub fn parse(raw: &str) -> KataResult<Self> {
        match raw {
            "admitting" => Ok(Self::Admitting),
            "running" => Ok(Self::Running),
            "terminalizing" => Ok(Self::Terminalizing),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "timed_out" => Ok(Self::TimedOut),
            other => Err(KataError::Storage(format!(
                "execution_program_store invalid lifecycle state {other:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionLifecycleRecord {
    pub execution_id: Ulid,
    pub state: ExecutionLifecycleState,
    pub created_at_ms: i64,
    pub terminal_outcome: Option<ExecutionLifecycleState>,
    pub terminal_reason: Option<ExecutionTerminalReason>,
    pub terminal_started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
}

/// Inspect the stable header fields — `schema_version` and `workflow_name` — and
/// nothing else, so a program of any schema can be named without being decoded.
pub fn execution_program_metadata(
    json: &[u8],
    execution_id: Option<Ulid>,
) -> KataResult<ExecutionProgramMetadata> {
    let value: serde_json::Value = serde_json::from_slice(json).map_err(|e| {
        KataError::Serialization(format!(
            "execution_program_store: invalid program JSON{}: {e}",
            execution_id.map_or_else(String::new, |id| format!(" for {id}"))
        ))
    })?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64);
    let workflow_name = value
        .get("workflow_name")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    Ok(ExecutionProgramMetadata {
        schema_version,
        workflow_name,
    })
}

/// Classify one opaque durable program against what this binary can dispatch.
///
/// `Ok(None)` means the program is CURRENT and dispatchable — schema, decodability,
/// and the closed-world validity of every carried stage class, which is the whole of what
/// the decode doors check that is a property of the BYTES alone. Anything else is
/// readable evidence that must never be rewritten or dispatched by this binary —
/// the compatibility membrane boot consults before any current deserialization.
///
/// Deliberately NOT covered: the per-execution checks the executor's door adds around
/// this one (its `program_hash` re-derivation, its ledger-identity comparison). Those
/// are properties of a program IN a durable context, not of the program, and the
/// membrane has neither context to hand.
pub fn classify_incompatible_program(
    execution_id: Ulid,
    program_json: &[u8],
) -> KataResult<Option<IncompatibleExecutionProgram>> {
    let (metadata, incompatibility) = classify_program_bytes(program_json, Some(execution_id))?;
    Ok(
        incompatibility.map(|incompatibility| IncompatibleExecutionProgram {
            execution_id,
            schema_version: metadata.schema_version,
            incompatibility,
        }),
    )
}

/// [`classify_incompatible_program`] for an opaque program that has NO execution id.
///
/// # Invariant
///
/// The classification is a property of the BYTES, and the execution id only ever
/// decorated an error message. Checked programs have a SECOND durable home —
/// `schedules.program_json`, the pin a schedule fires — and nothing keyed by
/// execution id can reach it. A probe that iterated the `programs` table only would
/// let a program/invocation schema bump make `checked_admission` refuse the pinned
/// bytes, `revalidated_pin` error, and the schedule fire NOTHING forever behind one
/// WARN per 30s — while the equivalent condition for an execution is a loud
/// fail-closed boot refusal.
pub fn classify_program_bytes(
    program_json: &[u8],
    subject: Option<Ulid>,
) -> KataResult<(
    ExecutionProgramMetadata,
    Option<ExecutionProgramIncompatibility>,
)> {
    let metadata = execution_program_metadata(program_json, subject)?;
    let incompatibility = match metadata.schema_version {
        Some(version) if version == u64::from(CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION) => {
            current_schema_incompatibility(program_json)
        }
        Some(version) if version < u64::from(CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION) => {
            Some(ExecutionProgramIncompatibility::LegacySchema { version })
        }
        Some(version) => Some(ExecutionProgramIncompatibility::FutureSchema { version }),
        None => Some(ExecutionProgramIncompatibility::MissingSchemaVersion),
    };
    Ok((metadata, incompatibility))
}

/// Why this binary cannot dispatch a program whose SCHEMA is already current.
///
/// # Invariant
///
/// The PREVIEW side of "invalid combinations fail before a run is created". A
/// membrane answering on the schema header alone would be complete only if the
/// schema were the only thing that could make a stored program unrunnable; it is
/// not: a blob carrying a self-consistent tuple an earlier binary at the same
/// schema wrote is refused at BOTH decode doors
/// ([`crate::schedule::ScheduleFace::revalidated_pin`] and the executor's
/// `execution_program_from_json`) by
/// [`ExecutionProgram::validate_carried_stage_execution_classes`]. Reading only the
/// header, the membrane would call such a program CURRENT and dispatchable, so
/// `kata upgrade` would preview it clean and the operator would meet the refusal at a
/// 3am fire.
///
/// # Enforcement
///
/// This calls that gate — the same method, not a paraphrase of it. Two predicates
/// answering "is this usable?" drift — a guard keyed on an agent LABEL that
/// approximates the derived CLASS disagrees with it for authorable
/// configurations. The gate is a pure
/// function of the decoded program, so there is nothing to reimplement: decode, ask,
/// report. Deliberately NOT a carried-vs-derived AGREEMENT warning — the derivation
/// can change within one schema (containment keyed on the `exec` brand is such a
/// change), so disagreement is a valid state and the doors do not refuse it either.
///
/// # Failure mode
///
/// Bytes that do not decode are reported too, rather than silently passing as
/// "current and dispatchable". Every runtime path turns these bytes into a program
/// with the same `serde_json::from_slice`, so a decode failure here is a decode
/// failure there; calling it compatible would reintroduce the exact gap this
/// function closes.
fn current_schema_incompatibility(program_json: &[u8]) -> Option<ExecutionProgramIncompatibility> {
    // DECODE DOOR — the PREVIEW one. It reports rather than refuses, but it runs the
    // same gate the refusing doors run, and `durable_program_decode_doors_all_validate`
    // holds it to that.
    let program: ExecutionProgram = match serde_json::from_slice(program_json) {
        Ok(program) => program,
        Err(error) => {
            return Some(ExecutionProgramIncompatibility::UndecodableCurrentSchema {
                detail: error.to_string(),
            });
        }
    };
    program
        .validate_carried_stage_execution_classes()
        .err()
        .map(|invalid| ExecutionProgramIncompatibility::UnhonourableExecutionClass { invalid })
}

/// THE set of retained checked programs that keep this binary off a data directory:
/// every incompatible program among `active` — the rows
/// [`kata_core::operational::active_program_rows`] selects, the programs of
/// executions whose top-level lifecycle is not terminal — in execution-id order.
///
/// # Invariant
///
/// Boot's membrane ([`crate::execution_lifecycle::ExecutionLifecycleFace::incompatible_programs`])
/// and `kata upgrade`'s preview ([`inspect_blocking_incompatible_programs_immutable`])
/// both compute their set here, from rows of that one query, so the two cannot
/// disagree. A terminal execution's program is retained evidence and blocks
/// nothing; finishing or cancelling an execution with the binary that wrote it is
/// what clears its row.
///
/// Every checked-program schema bump also bumps the operational stamp (see
/// [`CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION`]), so a directory this binary opens
/// holds no program an older schema wrote: what this set can name is bytes at this
/// binary's schema that do not decode or carry a class it cannot honour, or a
/// forged schema header — a schema verdict
/// ([`ExecutionProgramIncompatibility::is_schema_verdict`]) that no binary able to
/// open the directory wrote, so it has no writer to finish it on.
pub fn blocking_incompatible_programs(
    active: Vec<(Ulid, Vec<u8>)>,
) -> KataResult<Vec<IncompatibleExecutionProgram>> {
    let mut blocking = Vec::new();
    for (execution_id, program_json) in active {
        if let Some(found) = classify_incompatible_program(execution_id, &program_json)? {
            blocking.push(found);
        }
    }
    blocking.sort_by_key(|program| program.execution_id);
    Ok(blocking)
}

/// [`blocking_incompatible_programs`] over the AUTHORITATIVE `operational.db`,
/// without creating SQLite sidecars, taking locks, or recovering ambient journal
/// state — the read `kata upgrade` makes before it holds any authority.
///
/// A missing database, or one with no execution nucleus yet, blocks nothing.
pub fn inspect_blocking_incompatible_programs_immutable(
    path: impl AsRef<Path>,
) -> KataResult<Vec<IncompatibleExecutionProgram>> {
    let path = path.as_ref().to_path_buf();
    // Apply the SAME forward-version gate the production open path applies,
    // BEFORE reading a row. `kata upgrade` runs its preflight with the NEW binary
    // against a data dir that may have been written by a NEWER one; without this
    // the preflight reports green on a nucleus boot then refuses before SQLite is
    // even opened, and the operator is told to proceed into a node that will not
    // start. The gate is plain file I/O — no handle, no sidecar, no page rewrite —
    // so the probe stays byte-identically immutable.
    kata_core::refuse_newer_operational_schema(&path)?;
    kata_core::inspect_optional_immutable_sqlite(&path, "operational nucleus", |connection| {
        let nucleus_exists: bool = connection
            .query_row(
                "SELECT COUNT(*) = 2 FROM sqlite_schema
                  WHERE type = 'table' AND name IN ('programs', 'execution_lifecycle')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                KataError::Storage(format!("operational nucleus validate programs: {error}"))
            })?;
        if !nucleus_exists {
            return Ok(Vec::new());
        }
        blocking_incompatible_programs(kata_core::operational::active_program_rows(connection)?)
    })
    .map(Option::unwrap_or_default)
}

#[cfg(test)]
mod tests {
    use kata_types::execution::{
        EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION, EXTERNAL_INPUT_TEXT_MAX_CHARS,
    };
    use kata_types::params::resolve_and_validate_params;

    use super::*;
    use crate::execution_lifecycle::ExecutionLifecycleFace;

    fn face() -> ExecutionLifecycleFace {
        ExecutionLifecycleFace::in_memory().expect("open the operational nucleus")
    }

    fn current_program(name: &str) -> kata_program::execution_program::ExecutionProgram {
        kata_program::execution_program::compile_starlark_execution_program(
            &format!(
                "one = stage(id = \"one\", prompt = \"ok\", agent = \"shell\")\nworkflow(\"{name}\", root = one)\n"
            ),
            "lifecycle.star",
            &[],
        )
        .unwrap()
    }

    fn input_program(name: &str) -> kata_program::execution_program::ExecutionProgram {
        kata_program::execution_program::compile_starlark_execution_program(
            &format!(
                r#"
plan = stage(id = "plan", prompt = "use input", agent = "shell")
workflow(
    "{name}",
    root = plan,
    max_external_input_channels = 1,
    external_input_channels = [
        channel(
            "operator_steering",
            stage = "plan",
            expose_as = "steering",
            kind = "advisory",
            schema = "text",
            max_items = 3,
        ),
    ],
)
"#
            ),
            "invocation.star",
            &[],
        )
        .unwrap()
    }

    fn params_program(name: &str) -> kata_program::execution_program::ExecutionProgram {
        kata_program::execution_program::compile_starlark_execution_program(
            &format!(
                "one = stage(id = \"one\", prompt = \"ok\", agent = \"shell\")\n\
                 workflow(\"{name}\", root = one, params = {{\n\
                    \"target\": field(\"string\"),\n\
                    \"count\": field(integer(min = 1, max = 9), default = 3),\n\
                 }})\n"
            ),
            "params.star",
            &[],
        )
        .unwrap()
    }

    fn supplied(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    fn normalized_input(id: &str) -> ExecutionExternalInputEvidence {
        ExecutionExternalInputEvidence {
            schema_version: EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION,
            id: id.to_string(),
            channel: "operator_steering".to_string(),
            source: Some("operator".to_string()),
            target_stage: Some("plan".to_string()),
            text: "Proceed conservatively.".to_string(),
            payload: Some(serde_json::json!({"z": 1, "a": {"y": 2, "b": 3}})),
            projection: "Proceed conservatively.".to_string(),
            appended_at_ms: 42,
        }
    }

    /// Classify a set of opaque program blobs the way the boot membrane does.
    ///
    /// The compatibility scan is a PURE FUNCTION over bytes: there is no writer
    /// that can persist a non-current program (the admission chokepoint refuses
    /// one), so the matrix is exercised directly
    /// instead of through a store that would refuse the input.
    fn classify(rows: &[(Ulid, &[u8])]) -> Vec<IncompatibleExecutionProgram> {
        let mut out = Vec::new();
        for (id, json) in rows {
            if let Some(found) = classify_incompatible_program(*id, json).unwrap() {
                out.push(found);
            }
        }
        out.sort_by_key(|program| program.execution_id);
        out
    }

    /// `(operational stamp, the ONE checked-program schema a directory at that stamp
    /// holds)`, one row per stamp since the pairing took effect. APPEND a row for every
    /// bump of EITHER constant; never edit one — a row is a fact about directories
    /// already on disk.
    const PROGRAM_SCHEMA_BY_OPERATIONAL_STAMP: &[(i64, u32)] = &[
        (35, 8),
        (36, 8),
        (37, 9),
        (38, 9),
        (39, 9),
        (40, 9),
        (41, 10),
        (42, 10),
        (43, 11),
        (44, 11),
        (45, 11),
        (46, 11),
        (47, 11),
        (48, 11),
        (49, 11),
    ];

    /// The pair the table starts at: stamp 35 was first written by binaries already
    /// at program schema 8. Stated apart from the table, so an in-place rewrite of
    /// that row fails here too.
    const TABLE_ORIGIN: (i64, u32) = (35, 8);

    /// `(operational stamp, the ONE invocation-envelope schema a directory at that
    /// stamp holds)`, the same discipline as [`PROGRAM_SCHEMA_BY_OPERATIONAL_STAMP`].
    /// It starts where the pairing first held: invocation schema 2 landed with the
    /// stamp's move to 40 (48ae71c69), and 3 with its move to 42 (5d02b8b6c).
    const INVOCATION_SCHEMA_BY_OPERATIONAL_STAMP: &[(i64, u32)] = &[
        (40, 2),
        (41, 2),
        (42, 3),
        (43, 3),
        (44, 3),
        (45, 3),
        (46, 3),
        (47, 3),
        (48, 3),
        (49, 3),
    ];

    /// [`INVOCATION_SCHEMA_BY_OPERATIONAL_STAMP`]'s origin, stated apart from it.
    const INVOCATION_TABLE_ORIGIN: (i64, u32) = (40, 2);

    /// `(operational stamp, the ONE execution-contract schema a directory at that
    /// stamp holds)`, the same discipline again. It starts where the pairing first
    /// held: contract schema 12 landed with the stamp's move to 40 (48ae71c69),
    /// 13 with its move to 46, and 14 with its move to 49; 10 and 11 landed
    /// without one (stamps 31 and 33), which is why no row is older.
    const CONTRACT_SCHEMA_BY_OPERATIONAL_STAMP: &[(i64, u32)] = &[
        (40, 12),
        (41, 12),
        (42, 12),
        (43, 12),
        (44, 12),
        (45, 12),
        (46, 13),
        (47, 13),
        (48, 13),
        (49, 14),
    ];

    /// [`CONTRACT_SCHEMA_BY_OPERATIONAL_STAMP`]'s origin, stated apart from it.
    const CONTRACT_TABLE_ORIGIN: (i64, u32) = (40, 12);

    /// ONE STAMP, ONE SCHEMA, for `schema`'s table: `table` starts at `origin`, its
    /// last row is this build's `(OPERATIONAL_SCHEMA_VERSION, current)` pair, stamps
    /// strictly increase and the schema never goes back.
    ///
    /// What it refuses: a `schema` bump that leaves the table alone (the last row no
    /// longer matches this build's pair), a bump that APPENDS `(same stamp, new
    /// schema)` (stamps must strictly increase), and an in-place rewrite of the
    /// origin row. What it cannot refuse: an in-place rewrite of a LATER last row,
    /// which is a one-literal edit like any other; the tables' docs forbid it and
    /// review has to catch it. The guard is a convention made loud, not proof.
    fn assert_one_schema_per_stamp(
        schema: &str,
        table: &[(i64, u32)],
        origin: (i64, u32),
        current: u32,
    ) {
        assert_eq!(
            table.first(),
            Some(&origin),
            "the {schema} table starts at its origin pair; append rows, never rewrite one"
        );
        assert_eq!(
            table.last(),
            Some(&(kata_core::OPERATIONAL_SCHEMA_VERSION, current)),
            "the {schema} table's last row must be this build's (stamp, {schema} schema) \
             pair: append a row for the constant you bumped, and bump the operational \
             stamp with any {schema} schema bump"
        );
        for pair in table.windows(2) {
            assert!(
                pair[1].0 > pair[0].0,
                "one stamp, one {schema} schema — a {schema} schema bump without a stamp \
                 bump leaves directories of one stamp holding two schemas: {pair:?}"
            );
            assert!(
                pair[1].1 >= pair[0].1,
                "a {schema} schema never goes back: {pair:?}"
            );
        }
    }

    /// Every checked-program schema bump also bumps the operational stamp (see
    /// [`CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION`]).
    #[test]
    fn every_program_schema_bump_moves_the_operational_stamp() {
        assert_one_schema_per_stamp(
            "checked-program",
            PROGRAM_SCHEMA_BY_OPERATIONAL_STAMP,
            TABLE_ORIGIN,
            CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION,
        );
    }

    /// Every invocation-envelope schema bump also bumps the operational stamp (see
    /// [`CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION`]), so a directory this binary
    /// opens holds no envelope of an earlier schema and the refusal's
    /// [`EARLIER_SCHEMA_RECOURSE`] tells the truth.
    #[test]
    fn every_invocation_schema_bump_moves_the_operational_stamp() {
        assert_one_schema_per_stamp(
            "invocation-envelope",
            INVOCATION_SCHEMA_BY_OPERATIONAL_STAMP,
            INVOCATION_TABLE_ORIGIN,
            CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION,
        );
    }

    /// Every execution-contract schema bump also bumps the operational stamp (see
    /// [`kata_types::execution_contract::EXECUTION_CONTRACT_SCHEMA_VERSION`]), so a
    /// directory this binary opens holds no contract of an earlier schema and the
    /// refusal's [`EARLIER_SCHEMA_RECOURSE`] tells the truth.
    #[test]
    fn every_contract_schema_bump_moves_the_operational_stamp() {
        assert_one_schema_per_stamp(
            "execution-contract",
            CONTRACT_SCHEMA_BY_OPERATIONAL_STAMP,
            CONTRACT_TABLE_ORIGIN,
            kata_types::execution_contract::EXECUTION_CONTRACT_SCHEMA_VERSION,
        );
    }

    /// A `LegacySchema` program in a directory this binary opens was written by no
    /// binary that can open it: every program schema bump moved the operational stamp
    /// (`every_program_schema_bump_moves_the_operational_stamp`), and a directory at an
    /// earlier stamp is refused at open. So the reason may not send the operator to
    /// finish or cancel the execution on an earlier binary — that binary cannot open
    /// this directory — and names the move that exists: read-only evidence and a fresh
    /// data directory.
    #[test]
    fn a_legacy_schema_reason_offers_no_earlier_binary_as_recourse() {
        {
            let reason = ExecutionProgramIncompatibility::LegacySchema { version: 7 }.reason();
            // Vocabulary, not one phrasing: a recourse that sends the operator to
            // another binary in other words ("finish it with an earlier Kata binary")
            // is the same false move.
            let lowered = reason.to_lowercase();
            for offer in OFFERS_ANOTHER_BINARY {
                assert!(
                    !lowered.contains(offer),
                    "an earlier binary cannot open a directory this one admits, so the reason \
                     may not offer one ({offer:?}): {reason}"
                );
            }
            assert!(
                reason.contains("read-only evidence") && reason.contains("fresh `[node] data_dir`"),
                "the reason names the recourse that exists: {reason}"
            );
        }
    }

    /// Lower-case words a recourse uses when it sends the operator to finish an
    /// execution on some binary other than this one.
    const OFFERS_ANOTHER_BINARY: [&str; 8] = [
        "finish",
        "cancel",
        "drain",
        "binary that wrote",
        "previous",
        "prior",
        "older",
        "earlier kata",
    ];

    /// The schema verdicts are exactly the ones no binary that opens this directory
    /// wrote, so they are exactly the ones with no writing binary to finish them on.
    #[test]
    fn only_the_schema_verdicts_have_no_writing_binary() {
        let schema = [
            ExecutionProgramIncompatibility::MissingSchemaVersion,
            ExecutionProgramIncompatibility::LegacySchema { version: 7 },
            ExecutionProgramIncompatibility::FutureSchema { version: 9 },
        ];
        for incompatibility in schema {
            assert!(incompatibility.is_schema_verdict(), "{incompatibility:?}");
        }
        assert!(
            !ExecutionProgramIncompatibility::UndecodableCurrentSchema {
                detail: "eof".to_string(),
            }
            .is_schema_verdict()
        );
    }

    #[test]
    fn checked_program_and_store_share_one_schema_authority() {
        assert_eq!(
            kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION,
            CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
        );

        let program = current_program("schema-authority");
        assert_eq!(
            program.schema_version,
            CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
        );
        let json = serde_json::to_vec(&program).unwrap();
        assert_eq!(
            execution_program_metadata(&json, None)
                .unwrap()
                .schema_version,
            Some(u64::from(CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION))
        );
    }

    #[test]
    fn execution_program_json_round_trips() {
        let face = face();
        let id = Ulid::new();
        let program = current_program("round-trip");
        face.admit_current_execution(id, &program, &ExecutionInvocation::workflow(vec![]))
            .unwrap();
        assert_eq!(
            face.program_json(id).unwrap().unwrap(),
            serde_json::to_vec(&program).unwrap()
        );
    }

    #[test]
    fn incompatible_scan_is_complete_sandbox_scoped_and_non_mutating() {
        let first_id = Ulid::new();
        let second_id = Ulid::new();
        let future_id = Ulid::new();
        let missing_id = Ulid::new();
        let current_id = Ulid::new();
        // A REAL compiled program, not a stub with a `schema_version` field. The
        // membrane no longer answers on the header alone — it decodes and runs the
        // seven-axis gate — so a stub would now be flagged (as undecodable) and the
        // "current is not flagged" arm would be asserting the wrong thing about the
        // wrong input.
        let current_json = serde_json::to_vec(&current_program("current")).unwrap();
        let incompatible = classify(&[
            (
                first_id,
                br#"{"schema_version":1,"sandbox_profiles":{"old":{"exec":{"kind":"exec-alpha"},"fs":{"kind":"scratch"},"net":{"kind":"net-beta","data":{"profile":"p"}}}}}"#,
            ),
            (
                second_id,
                br#"{"schema_version":1,"sandbox_profiles":{"old":{"exec":{"kind":"exec-delta"},"fs":{"kind":"host"},"net":{"kind":"host"}}}}"#,
            ),
            (future_id, br#"{"schema_version":99}"#),
            (missing_id, br#"{"workflow_name":"missing"}"#),
            (current_id, current_json.as_slice()),
        ]);
        assert_eq!(incompatible.len(), 4);
        assert!(
            incompatible.iter().all(|p| p.execution_id != current_id),
            "a schema-3 program this binary compiled is current and must not be flagged"
        );
        for id in [first_id, second_id] {
            assert!(matches!(
                incompatible
                    .iter()
                    .find(|program| program.execution_id == id)
                    .unwrap()
                    .incompatibility,
                ExecutionProgramIncompatibility::LegacySchema { version: 1 }
            ));
        }
        assert!(matches!(
            incompatible
                .iter()
                .find(|program| program.execution_id == future_id)
                .unwrap()
                .incompatibility,
            ExecutionProgramIncompatibility::FutureSchema { version: 99 }
        ));
        assert!(matches!(
            incompatible
                .iter()
                .find(|program| program.execution_id == missing_id)
                .unwrap()
                .incompatibility,
            ExecutionProgramIncompatibility::MissingSchemaVersion
        ));
    }

    /// A program at an earlier checked-program schema is refused by its SCHEMA, and
    /// by nothing else: the reason names the version and the recourse, never a
    /// sandbox spelling that schema could carry. Every earlier schema is refused
    /// whatever its profiles say, so the reason carries the schema alone.
    #[test]
    fn a_legacy_program_is_refused_by_its_schema_naming_no_sandbox_kind() {
        let rows: [(Ulid, u64, &[u8]); 4] = [
            (
                Ulid::new(),
                1,
                br#"{"schema_version":1,"sandbox_profiles":{"old":{"exec":{"kind":"exec-alpha"},"fs":{"kind":"scratch"},"net":{"kind":"net-beta","data":{"profile":"p"}}}}}"#,
            ),
            (
                Ulid::new(),
                2,
                br#"{"schema_version":2,"sandbox_profiles":{"far":{"exec":{"kind":"exec-gamma","data":{"worker":"build-box"}},"fs":{"kind":"workspace_rw"},"net":{"kind":"host"}}}}"#,
            ),
            (
                Ulid::new(),
                7,
                br#"{"schema_version":7,"sandbox_profiles":{"safe":{"exec":{"kind":"exec-delta"},"fs":{"kind":"workspace_ro"},"net":{"kind":"offline"}}}}"#,
            ),
            (Ulid::new(), 7, br#"{"schema_version":7}"#),
        ];
        let incompatible = classify(&rows.map(|(id, _, json)| (id, json)));
        assert_eq!(
            incompatible.len(),
            rows.len(),
            "every earlier schema is refused"
        );
        for (id, version, _) in rows {
            let program = incompatible
                .iter()
                .find(|program| program.execution_id == id)
                .expect("each row is flagged");
            assert!(
                matches!(
                    program.incompatibility,
                    ExecutionProgramIncompatibility::LegacySchema { version: v, .. } if v == version
                ),
                "{:?}",
                program.incompatibility
            );
            let reason = program.incompatibility.reason();
            assert!(
                reason.contains(&format!("unsupported checked-program schema {version};")),
                "{reason}"
            );
            for spelling in [
                "exec-alpha",
                "net-beta",
                "exec-gamma",
                "exec-delta",
                "build-box",
                "retired",
            ] {
                assert!(!reason.contains(spelling), "names {spelling:?}: {reason}");
            }
        }
    }

    /// The schema-gate matrix: an earlier schema is `LegacySchema`, a program at the
    /// CURRENT schema is current, and a later schema is refused as `FutureSchema`.
    ///
    /// Every version in this matrix is DERIVED from
    /// [`CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION`] rather than written as a
    /// literal. A literal "current" and a literal "future" both rot into the wrong
    /// arm on the next bump — as they did at the 4 -> 5 bump this note was added
    /// for, where the "future" row started naming the current schema.
    #[test]
    fn the_schema_gate_derives_legacy_current_and_future_from_the_constant() {
        let legacy = Ulid::new();
        let current = Ulid::new();
        let future = Ulid::new();
        let legacy_version = u64::from(CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION) - 1;
        let legacy_json = format!("{{\"schema_version\":{legacy_version}}}");
        let future_version = u64::from(CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION) + 1;
        let future_json = format!("{{\"schema_version\":{future_version}}}");
        let current_json = serde_json::to_vec(&current_program("current")).unwrap();
        let incompatible = classify(&[
            (legacy, legacy_json.as_bytes()),
            (current, current_json.as_slice()),
            (future, future_json.as_bytes()),
        ]);
        assert!(
            incompatible.iter().all(|p| p.execution_id != current),
            "a program this binary compiled is current and must not be flagged"
        );
        let legacy = incompatible
            .iter()
            .find(|p| p.execution_id == legacy)
            .expect("the earlier schema is flagged");
        assert!(matches!(
            legacy.incompatibility,
            ExecutionProgramIncompatibility::LegacySchema { version } if version == legacy_version
        ));
        assert!(
            legacy
                .incompatibility
                .reason()
                .contains("read-only evidence"),
            "the recourse rides on the reason: {}",
            legacy.incompatibility.reason()
        );
        assert!(matches!(
            incompatible
                .iter()
                .find(|p| p.execution_id == future)
                .unwrap()
                .incompatibility,
            ExecutionProgramIncompatibility::FutureSchema { version } if version == future_version
        ));
    }

    /// The EMPTY-nucleus case: every read is `None`, none is an error, and nothing
    /// invents authority. The dangerous direction for a repointed reader.
    #[test]
    fn missing_returns_none() {
        let face = face();
        assert!(face.program_json(Ulid::new()).unwrap().is_none());
        assert!(face.lifecycle(Ulid::new()).unwrap().is_none());
        assert!(face.invocation(Ulid::new()).unwrap().is_none());
        assert!(face.metadata(Ulid::new()).unwrap().is_none());
        assert!(face.recoverable_execution_ids().unwrap().is_empty());
        assert!(face.lifecycle_execution_ids().unwrap().is_empty());
        assert!(face.incompatible_programs().unwrap().is_empty());
    }

    #[test]
    fn a_legacy_program_header_is_read_as_evidence_without_being_dispatchable() {
        let legacy = Ulid::new();
        let json = br#"{"schema_version":1,"workflow_name":"old-pack","sandbox_profiles":{"old":{"exec":{"kind":"exec-alpha"},"fs":{"kind":"host"},"net":{"kind":"host"}}}}"#;
        let metadata = execution_program_metadata(json, Some(legacy)).unwrap();
        assert_eq!(metadata.workflow_name.as_deref(), Some("old-pack"));
        assert_eq!(metadata.schema_version, Some(1));
        assert!(
            classify_incompatible_program(legacy, json)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn production_write_boundary_accepts_only_current_concrete_programs() {
        let face = face();
        let mut program = current_program("store-current");
        let current = Ulid::new();
        face.admit_current_execution(current, &program, &ExecutionInvocation::workflow(vec![]))
            .unwrap();
        assert!(face.program_json(current).unwrap().is_some());

        program.schema_version = 1;
        let error = face
            .admit_current_execution(
                Ulid::new(),
                &program,
                &ExecutionInvocation::workflow(vec![]),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing to persist"), "error={error}");
        assert!(error.contains("schema 1"), "error={error}");
    }

    #[test]
    fn checked_program_identity_is_insert_once_and_idempotent_equal() {
        let face = face();
        let id = Ulid::new();
        let first = current_program("identity");
        let invocation = ExecutionInvocation::workflow(vec![]);
        face.admit_current_execution(id, &first, &invocation)
            .unwrap();
        face.admit_current_execution(id, &first, &invocation)
            .expect("a byte-identical re-admission converges idempotently");

        let replacement = current_program("replacement");
        let error = face
            .admit_current_execution(id, &replacement, &invocation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("different"), "error={error}");
        assert!(error.contains("program hash"), "error={error}");
        assert_eq!(
            face.program_json(id).unwrap().unwrap(),
            serde_json::to_vec(&first).unwrap(),
            "the immutable checked program is never replaced"
        );
    }

    #[test]
    fn admission_atomically_retains_typed_canonical_invocation() {
        let face = face();
        let id = Ulid::new();
        let program = input_program("invocation-authority");
        let invocation = ExecutionInvocation::workflow(vec![normalized_input("input-1")]);

        face.admit_current_execution(id, &program, &invocation)
            .unwrap();

        let stored = face.invocation(id).unwrap().unwrap();
        assert_eq!(stored.invocation, invocation);
        let canonical = canonicalize_args(&serde_json::to_value(&invocation).unwrap());
        assert_eq!(stored.admission_hash, *blake3::hash(&canonical).as_bytes());
        assert_eq!(
            face.lifecycle(id).unwrap().unwrap().state,
            ExecutionLifecycleState::Admitting
        );
    }

    // ── typed invocation params ride the invocation + bind the digest ──────────

    #[test]
    fn param_less_invocation_admission_hash_is_byte_identical() {
        // A param-less program's invocation carries no params, so `params` is
        // skipped from its canonical JSON — the admission hash is byte-stable.
        let face = face();
        let id = Ulid::new();
        let program = current_program("no-params");
        let invocation = ExecutionInvocation::workflow(Vec::new());
        face.admit_current_execution(id, &program, &invocation)
            .unwrap();
        let stored = face.invocation(id).unwrap().unwrap();
        let json = serde_json::to_value(&stored.invocation).unwrap();
        assert!(
            json.get("params").is_none(),
            "empty params are skipped from the canonical invocation"
        );
        let canonical = canonicalize_args(&json);
        assert_eq!(stored.admission_hash, *blake3::hash(&canonical).as_bytes());
    }

    #[test]
    fn params_bind_admission_hash_and_converge_across_faces() {
        let program = params_program("p-bind");
        // Two faces supply the SAME params in DIFFERENT insertion order.
        let rows_a = resolve_and_validate_params(
            &program.params,
            &supplied(&[
                ("target", serde_json::json!("main")),
                ("count", serde_json::json!(5)),
            ]),
        )
        .unwrap();
        let rows_b = resolve_and_validate_params(
            &program.params,
            &supplied(&[
                ("count", serde_json::json!(5)),
                ("target", serde_json::json!("main")),
            ]),
        )
        .unwrap();
        assert_eq!(rows_a, rows_b, "the resolver canonicalizes across faces");

        let face = face();
        let admit = |rows: Vec<InvocationParam>| {
            let id = Ulid::new();
            let invocation = ExecutionInvocation::workflow_with_params(Vec::new(), rows);
            face.admit_current_execution(id, &program, &invocation)
                .unwrap();
            face.invocation(id).unwrap().unwrap().admission_hash
        };
        let hash_a = admit(rows_a);
        let hash_b = admit(rows_b);
        assert_eq!(
            hash_a, hash_b,
            "identical resolved inputs from two faces converge to one admission digest"
        );

        // A different value → a different digest.
        let rows_c = resolve_and_validate_params(
            &program.params,
            &supplied(&[("target", serde_json::json!("other"))]),
        )
        .unwrap();
        assert_ne!(hash_a, admit(rows_c), "different params → different digest");
    }

    #[test]
    fn admission_rejects_params_not_matching_the_contract() {
        let face = face();
        let program = params_program("p-drift");

        // Missing a required param (target) → refused by the idempotent re-check.
        let missing = ExecutionInvocation::workflow_with_params(Vec::new(), Vec::new());
        let err = face
            .admit_current_execution(Ulid::new(), &program, &missing)
            .unwrap_err()
            .to_string();
        assert!(err.contains("param.missing_required"), "err={err}");

        // An unknown param name → refused.
        let unknown = ExecutionInvocation::workflow_with_params(
            Vec::new(),
            vec![InvocationParam {
                name: smol_str::SmolStr::new("nope"),
                value: serde_json::json!("x"),
            }],
        );
        let err = face
            .admit_current_execution(Ulid::new(), &program, &unknown)
            .unwrap_err()
            .to_string();
        assert!(err.contains("param.unknown_key"), "err={err}");

        // Non-canonical rows (default not filled) → refused: the durable rows must
        // be exactly the resolver's canonical output.
        let non_canonical = ExecutionInvocation::workflow_with_params(
            Vec::new(),
            vec![InvocationParam {
                name: smol_str::SmolStr::new("target"),
                value: serde_json::json!("main"),
            }],
        );
        let err = face
            .admit_current_execution(Ulid::new(), &program, &non_canonical)
            .unwrap_err()
            .to_string();
        assert!(err.contains("canonical resolved set"), "err={err}");
    }

    #[test]
    fn admission_retry_rejects_invocation_replacement() {
        let face = face();
        let id = Ulid::new();
        let program = input_program("immutable-invocation");
        let first = ExecutionInvocation::workflow(vec![normalized_input("input-1")]);
        face.admit_current_execution(id, &program, &first).unwrap();

        let mut changed_input = normalized_input("input-1");
        changed_input.text = "Changed accepted input".to_string();
        changed_input.projection = "Changed accepted input".to_string();
        let changed = ExecutionInvocation::workflow(vec![changed_input]);
        let error = face
            .admit_current_execution(id, &program, &changed)
            .unwrap_err()
            .to_string();
        assert!(error.contains("admission digest"), "{error}");
        assert_eq!(face.invocation(id).unwrap().unwrap().invocation, first);
    }

    #[test]
    fn invocation_validation_rejects_non_normalized_or_unbounded_shapes() {
        let face = face();
        let program = input_program("invocation-bounds");
        let input = normalized_input("input-1");
        let error = face
            .admit_current_execution(
                Ulid::new(),
                &program,
                &ExecutionInvocation {
                    schema_version: CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION,
                    kind: ExecutionInvocationKind::DirectAgent,
                    initial_external_inputs: vec![input.clone()],
                    params: Vec::new(),
                    target: None,
                },
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("direct-agent"), "{error}");

        let error = face
            .admit_current_execution(
                Ulid::new(),
                &program,
                &ExecutionInvocation::workflow(vec![input.clone(), input]),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate"), "{error}");

        let mut oversized = normalized_input("oversized");
        oversized.text = "x".repeat(EXTERNAL_INPUT_TEXT_MAX_CHARS + 1);
        let error = face
            .admit_current_execution(
                Ulid::new(),
                &program,
                &ExecutionInvocation::workflow(vec![oversized]),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("character text bound"), "{error}");
    }

    #[test]
    fn admission_and_terminalization_state_machine_is_latched_and_idempotent() {
        let face = face();
        let id = Ulid::new();
        let program = current_program("lifecycle-latch");
        let invocation = ExecutionInvocation::workflow(vec![]);
        face.admit_current_execution(id, &program, &invocation)
            .unwrap();
        assert_eq!(
            face.lifecycle(id).unwrap().unwrap().state,
            ExecutionLifecycleState::Admitting
        );
        assert_eq!(face.recoverable_execution_ids().unwrap(), [id]);

        face.mark_running_after_admission(id).unwrap();
        face.mark_running_after_admission(id).unwrap();
        assert_eq!(
            face.lifecycle(id).unwrap().unwrap().state,
            ExecutionLifecycleState::Running
        );

        let reason = ExecutionTerminalReason::new("completed", "workflow completed");
        face.begin_terminalization(id, ExecutionLifecycleState::Completed, &reason)
            .unwrap();
        face.begin_terminalization(id, ExecutionLifecycleState::Completed, &reason)
            .unwrap();
        let terminalizing = face.lifecycle(id).unwrap().unwrap();
        assert_eq!(terminalizing.state, ExecutionLifecycleState::Terminalizing);
        assert_eq!(
            terminalizing.terminal_outcome,
            Some(ExecutionLifecycleState::Completed)
        );
        assert_eq!(terminalizing.terminal_reason.as_ref(), Some(&reason));
        assert!(terminalizing.finished_at_ms.is_none());

        face.complete_cleanup(id).unwrap();
        face.finish_terminalization(id).unwrap();
        face.finish_terminalization(id).unwrap();
        let terminal = face.lifecycle(id).unwrap().unwrap();
        assert_eq!(terminal.state, ExecutionLifecycleState::Completed);
        assert!(terminal.finished_at_ms.is_some());
        assert!(
            face.recoverable_execution_ids().unwrap().is_empty(),
            "a terminal execution leaves the recoverable set"
        );

        // Admission retries remain idempotent and cannot resurrect a terminal
        // lifecycle as Admitting.
        face.admit_current_execution(id, &program, &invocation)
            .unwrap();
        assert_eq!(
            face.lifecycle(id).unwrap().unwrap().state,
            ExecutionLifecycleState::Completed
        );
        face.begin_terminalization(id, ExecutionLifecycleState::Completed, &reason)
            .unwrap();
        assert!(
            face.begin_terminalization(
                id,
                ExecutionLifecycleState::Failed,
                &ExecutionTerminalReason::new("failed", "different outcome"),
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_intent_is_structured_bounded_and_required_before_finish() {
        let face = face();
        let id = Ulid::new();
        face.admit_current_execution(
            id,
            &current_program("terminal-intent-bounds"),
            &ExecutionInvocation::workflow(vec![]),
        )
        .unwrap();
        assert!(face.finish_terminalization(id).is_err());
        assert!(
            face.begin_terminalization(
                id,
                ExecutionLifecycleState::Failed,
                &ExecutionTerminalReason::new("Invalid Code", "failure"),
            )
            .is_err()
        );
        assert!(
            face.begin_terminalization(
                id,
                ExecutionLifecycleState::Failed,
                &ExecutionTerminalReason::new(
                    "failure",
                    "x".repeat(MAX_TERMINAL_REASON_MESSAGE_BYTES + 1),
                ),
            )
            .is_err()
        );
        assert_eq!(
            face.lifecycle(id).unwrap().unwrap().state,
            ExecutionLifecycleState::Admitting
        );
    }

    #[test]
    fn a_non_terminal_outcome_is_refused_as_terminal_intent() {
        let face = face();
        let id = Ulid::new();
        face.admit_current_execution(
            id,
            &current_program("non-terminal-intent"),
            &ExecutionInvocation::workflow(vec![]),
        )
        .unwrap();
        let error = face
            .begin_terminalization(
                id,
                ExecutionLifecycleState::Running,
                &ExecutionTerminalReason::new("failed", "not terminal"),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires a terminal outcome"), "{error}");
    }
}
