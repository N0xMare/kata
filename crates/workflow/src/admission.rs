//! The ONE admission-validation chokepoint, and the only producer of
//! the `(program_json, program_hash)` + `(invocation_json, admission_digest)`
//! pairs handed to [`OperationalDb::submit_execution`].
//!
//! # Invariant
//!
//! A durable admission is SELF-VERIFYING on BOTH halves. [`checked_admission`]
//! **re-derives the whole-program hash from the program body and refuses a body
//! that does not produce the hash it carries** (the header is a plain
//! `Deserialize` field, so on a decoded program it is a claim, not a
//! fact); pins the invocation-envelope schema version; cross-checks the declared
//! invocation kind against the checked program's source; **re-runs the one param
//! resolver over the params-as-supplied and refuses unless the result is
//! byte-identical**; checks the frozen execution target's structure
//! ([`check_invocation_target`]); bounds and normalizes the initial external
//! inputs; and
//! derives the admission digest over the canonical bytes it just proved. Nothing
//! downstream re-derives the digest or the program hash, so both can only ever
//! describe validated bytes.
//!
//! # Failure mode
//!
//! [`OperationalDb::submit_execution`] takes a prebuilt
//! [`InvocationRecord`] whose `admission_digest` is a CALLER-SUPPLIED field, and
//! `kata-core` cannot see the typed [`ExecutionProgram`] (it stores an opaque
//! `program_json` blob and does not depend on `kata-workflow`). So the operational
//! writer cannot re-derive or re-check the digest: if a face built an
//! `InvocationRecord` itself, the durable admission would degrade from
//! self-verifying to a caller assertion, and every existing test would still
//! pass. That is why this module exists and why
//! `admission_records_are_only_minted_by_the_checked_admission_seam`
//! (`crates/workflow/tests/admission_chokepoint.rs`) pins its call sites.
//!
//! # Enforcement
//!
//! [`CheckedAdmission`] is the only public constructor of an operational
//! `(ProgramRecord, InvocationRecord)` pair in the workspace, its fields are
//! private, and it can only be produced by [`checked_admission`]. The source
//! guard asserts no other non-test site names `InvocationRecord {`.

use kata_core::operational::{
    InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::execution::{
    EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION, EXTERNAL_INPUT_TEXT_MAX_CHARS,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::params::resolve_and_validate_params;
use kata_types::primitives::ContentHash;
use kata_types::target::{
    ExecutionTarget, TARGET_CHILDREN_UNSUPPORTED, TARGET_NOT_LANDABLE, TARGET_PRESENCE_INVALID,
    TARGET_REQUIRES_ISOLATED_WORKSPACE, TargetRefusal, TargetSpec,
};
use kata_types::workflow::{WorkflowSourceFormat, WorkspaceEffectOp};
use kata_types::{KataError, KataResult};
use ulid::Ulid;

use crate::execution_program_store::{
    CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION, CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION,
    ExecutionInvocation, ExecutionInvocationKind, MAX_EXECUTION_INVOCATION_BYTES,
    MAX_INITIAL_EXTERNAL_INPUTS,
};
use kata_program::execution_program::ExecutionProgram;

/// A validated admission: the checked program and the immutable normalized
/// invocation, in the exact shapes the operational writer persists.
///
/// The only way to obtain one is [`checked_admission`], so an
/// `InvocationRecord` reaching `operational.db` has provably passed the
/// chokepoint.
#[derive(Clone, Debug)]
pub struct CheckedAdmission {
    program: ProgramRecord,
    invocation: InvocationRecord,
}

impl CheckedAdmission {
    /// The checked program record to persist.
    #[must_use]
    pub fn program(&self) -> &ProgramRecord {
        &self.program
    }

    /// The validated immutable invocation record to persist.
    #[must_use]
    pub fn invocation(&self) -> &InvocationRecord {
        &self.invocation
    }

    /// The derived admission digest over the canonical invocation bytes.
    #[must_use]
    pub fn admission_digest(&self) -> AdmissionDigest {
        self.invocation.admission_digest
    }

    /// The canonical invocation bytes the digest binds.
    #[must_use]
    pub fn invocation_json(&self) -> &[u8] {
        &self.invocation.invocation_json
    }

    /// The serialized checked program bytes.
    #[must_use]
    pub fn program_json(&self) -> &[u8] {
        &self.program.program_json
    }

    /// Persist this validated admission through the operational writer: program +
    /// invocation + `admitting` lifecycle + the `submitted` transition +
    /// execution projection, in ONE `synchronous=FULL` transaction.
    ///
    /// A re-submission with byte-identical facts converges to
    /// [`SubmitOutcome::AlreadySubmitted`]; different bytes for the same
    /// execution id refuse.
    pub fn persist(&self, db: &OperationalDb, execution_id: Ulid) -> KataResult<SubmitOutcome> {
        db.submit_execution(execution_id, &self.program, &self.invocation)
    }
}

/// Mint deliberately opaque active authority for compatibility-refusal fixtures.
///
/// This is not an alternate production admission path: it is compiled only for
/// tests and test-support consumers, and exists so those fixtures can present
/// malformed or future-schema bytes that [`checked_admission`] must refuse.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn unchecked_active_fixture_admission(program_json: &[u8]) -> CheckedAdmission {
    let invocation_json = b"{\"schema_version\":1}".to_vec();
    CheckedAdmission {
        program: ProgramRecord {
            program_hash: ContentHash::new(*blake3::hash(program_json).as_bytes()),
            schema_version: serde_json::from_slice::<serde_json::Value>(program_json)
                .ok()
                .and_then(|value| value.get("schema_version")?.as_i64())
                .unwrap_or(0),
            program_json: program_json.to_vec(),
        },
        invocation: InvocationRecord {
            schema_version: 1,
            kind: InvocationKind::Workflow,
            admission_digest: AdmissionDigest(ContentHash::new(
                *blake3::hash(&invocation_json).as_bytes(),
            )),
            invocation_json,
        },
    }
}

/// Which rule a checked admission holds an invocation's frozen target to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetRule {
    /// An EXECUTION's admission: [`check_invocation_target`] — an isolated
    /// workflow invocation carries its frozen target, every other one none.
    Frozen,
    /// A schedule PIN: the invocation template every fire composes with the
    /// target resolved AT that fire, so it carries none, isolated or not.
    ResolvedPerFire,
}

/// Validate a checked program + invocation pair and derive its admission
/// identity. THE admission chokepoint.
///
/// # Failure
///
/// Refuses a non-current program schema, **a program body that does not re-derive
/// to the `program_hash` it carries**, a non-current invocation-envelope schema, a
/// direct-agent invocation carrying workflow params or external inputs, a params
/// set that is not a canonical resolved set of the program's declared contract, an
/// invocation kind that disagrees with the program source, a frozen target
/// [`check_invocation_target`] refuses, an out-of-bounds or
/// non-normalized initial external input, and an over-large canonical envelope.
pub fn checked_admission(
    program: &ExecutionProgram,
    invocation: &ExecutionInvocation,
) -> KataResult<CheckedAdmission> {
    checked(program, invocation, TargetRule::Frozen)
}

/// [`checked_admission`] for a schedule PIN — the invocation template a
/// schedule binds at install and re-validates at every fire. Every check is
/// the chokepoint's but the target's: a pin carries NO target, whether or not
/// its program forks an isolated workspace, because a schedule's target is
/// resolved at every fire ("review trunk nightly" reviews that night's trunk)
/// and the fire is admitted through [`checked_admission`] with it.
///
/// # Failure
///
/// [`checked_admission`]'s refused set with its target rule replaced: a pin that
/// carries a target is refused (`target_presence_invalid`), and an isolated
/// program's pin carrying none is not.
pub fn checked_schedule_pin(
    program: &ExecutionProgram,
    invocation: &ExecutionInvocation,
) -> KataResult<CheckedAdmission> {
    checked(program, invocation, TargetRule::ResolvedPerFire)
}

/// The body both chokepoints share.
fn checked(
    program: &ExecutionProgram,
    invocation: &ExecutionInvocation,
    target_rule: TargetRule,
) -> KataResult<CheckedAdmission> {
    let version = program.schema_version;
    if version != CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION {
        return Err(KataError::Validation(format!(
            "refusing to persist checked execution-program schema {version}; current schema is {CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION}"
        )));
    }
    // The PROGRAM half of "a durable admission is
    // self-verifying". `ExecutionProgram::program_hash` is a plain `Deserialize`
    // field, so on a program that came back off disk (the schedule pin's decoded
    // bytes) or off the wire the header is a CLAIM about the body, not a fact about
    // it. Re-derive the whole-program hash material from THIS program and refuse a
    // body that does not produce the hash it carries.
    //
    // Copying `program_hash` out of the decoded struct here instead would reduce
    // the schedule fire path's "derived hash equals bound_program_hash" assertion
    // to `header == column` — a check `pinned_admission` already performs — and a
    // `schedules.program_json` whose `prompt_template` was rewritten while its
    // `program_hash` string was left alone would pass every assertion and commit a
    // durable execution no compiler produced.
    let derived_program_hash = kata_program::execution_program::rederive_program_hash(program);
    if derived_program_hash != program.program_hash {
        return Err(KataError::Validation(format!(
            "checked execution program {} does not bind its own body: re-deriving the \
             whole-program hash over the program as presented yields {derived_program_hash}, \
             but it carries {}. Refusing to admit a program whose header describes \
             different bytes",
            program.workflow_name, program.program_hash
        )));
    }
    let program_json = serde_json::to_vec(program).map_err(|error| {
        KataError::Serialization(format!(
            "serialize current checked execution program: {error}"
        ))
    })?;
    let (invocation_json, admission_hash) =
        validated_invocation_bytes(program, invocation, target_rule)?;
    Ok(CheckedAdmission {
        program: ProgramRecord {
            // The DERIVED hash, never the header's copy — so a downstream assertion
            // against a durable `bound_program_hash` column compares a hash of the
            // body being submitted rather than restating the header.
            program_hash: derived_program_hash,
            schema_version: i64::from(version),
            program_json,
        },
        invocation: InvocationRecord {
            schema_version: i64::from(invocation.schema_version),
            kind: match invocation.kind {
                ExecutionInvocationKind::Workflow => InvocationKind::Workflow,
                ExecutionInvocationKind::DirectAgent => InvocationKind::DirectAgent,
            },
            admission_digest: AdmissionDigest(ContentHash::new(admission_hash)),
            invocation_json,
        },
    })
}

/// Refuse a caller's target spec for `program` BEFORE it is resolved — the
/// checks that need no repository: a target on a program that forks no
/// isolated workspace (`target_requires_isolated_workspace`), and a non-trunk
/// target on a program that can invoke an isolated child
/// (`target_children_unsupported`), which would otherwise fork trunk under a
/// non-trunk parent; and a pull-request target on a program that promotes or
/// exports its candidate (`target_not_landable`) — a `pr:<N>` target always
/// freezes no landable branch, so the refusal needs no forge read and no pin.
/// `None` (no spec named) is never refused here.
///
/// # Errors
///
/// Exactly those three refusals.
pub fn refuse_target_spec(
    program: &ExecutionProgram,
    spec: Option<&TargetSpec>,
) -> Result<(), TargetRefusal> {
    let Some(spec) = spec else {
        return Ok(());
    };
    if !program.summary.worktree_isolated {
        return Err(TargetRefusal::new(
            TARGET_REQUIRES_ISOLATED_WORKSPACE,
            format!(
                "workflow {} forks no isolated workspace (`worktree_isolated` is not set), so \
                 target `{spec}` has no base to aim",
                program.workflow_name
            ),
        ));
    }
    if *spec != TargetSpec::Trunk
        && program
            .bound_child_programs()
            .any(|child| child.summary.worktree_isolated)
    {
        return Err(TargetRefusal::new(
            TARGET_CHILDREN_UNSUPPORTED,
            format!(
                "workflow {} can invoke an isolated child, and a child resolves its own trunk \
                 target, so target `{spec}` would run that child against trunk; only `trunk` is \
                 admitted for such a workflow",
                program.workflow_name
            ),
        ));
    }
    if let TargetSpec::PullRequest { .. } = spec
        && lands_its_candidate(program)
    {
        return Err(TargetRefusal::new(
            TARGET_NOT_LANDABLE,
            format!(
                "workflow {} promotes or exports its candidate, and target `{spec}` is a pull \
                 request, which has no landable branch to land on or open a pull request into; \
                 run it against `trunk`",
                program.workflow_name
            ),
        ));
    }
    Ok(())
}

/// Whether `program` lands or exports its candidate — a `promote` or a
/// `forge_export` workspace effect — and so needs a landable branch.
fn lands_its_candidate(program: &ExecutionProgram) -> bool {
    program.stages.values().any(|stage| {
        matches!(
            stage.workspace_effect_op,
            Some(WorkspaceEffectOp::Promote | WorkspaceEffectOp::ForgeExport)
        )
    })
}

/// The structural target check — the target half of a self-verifying
/// admission. The submit path runs it before acceptance and every recovered or
/// child invocation is re-checked by it inside [`validated_invocation_bytes`].
///
/// Refuses exactly: a target present on a direct-agent or non-isolated
/// invocation, or absent on an isolated workflow invocation
/// (`target_presence_invalid`); [`ExecutionTarget::check_structure`]'s refused
/// set; [`refuse_target_spec`]'s refused set over the frozen spec; and a
/// landing program under a target with no landable branch
/// (`target_not_landable`).
///
/// # Errors
///
/// The first refusal found, under its code.
pub fn check_invocation_target(
    program: &ExecutionProgram,
    kind: ExecutionInvocationKind,
    target: Option<&ExecutionTarget>,
) -> Result<(), TargetRefusal> {
    let isolated = kind == ExecutionInvocationKind::Workflow && program.summary.worktree_isolated;
    let Some(target) = target else {
        if isolated {
            return Err(TargetRefusal::new(
                TARGET_PRESENCE_INVALID,
                format!(
                    "workflow {} forks an isolated workspace, and its invocation carries no \
                     frozen target to fork it from",
                    program.workflow_name
                ),
            ));
        }
        return Ok(());
    };
    if !isolated {
        return Err(TargetRefusal::new(
            TARGET_PRESENCE_INVALID,
            format!(
                "a {} invocation of {} forks no isolated workspace and carries no target, yet \
                 this one carries `{}`",
                kind.as_str(),
                program.workflow_name,
                target.spec
            ),
        ));
    }
    target.check_structure()?;
    refuse_target_spec(program, Some(&target.spec))?;
    if target.branch.is_none() && lands_its_candidate(program) {
        return Err(TargetRefusal::new(
            TARGET_NOT_LANDABLE,
            format!(
                "workflow {} promotes or exports its candidate, and target `{}` has no \
                 landable branch",
                program.workflow_name, target.spec
            ),
        ));
    }
    Ok(())
}

/// The five checks that make a durable admission self-verifying, plus the
/// admission-digest derivation. The re-resolution fixed point below is what
/// lets a stored admission be re-checked against the program it names.
fn validated_invocation_bytes(
    program: &ExecutionProgram,
    invocation: &ExecutionInvocation,
    target_rule: TargetRule,
) -> KataResult<(Vec<u8>, [u8; 32])> {
    if invocation.schema_version != CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION {
        return Err(KataError::Validation(format!(
            "refusing execution-invocation schema {}; current schema is {}. {}",
            invocation.schema_version,
            CURRENT_EXECUTION_INVOCATION_SCHEMA_VERSION,
            kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE,
        )));
    }
    if invocation.kind == ExecutionInvocationKind::DirectAgent
        && !invocation.initial_external_inputs.is_empty()
    {
        return Err(KataError::Validation(
            "direct-agent invocation cannot carry initial external inputs".to_string(),
        ));
    }
    if invocation.kind == ExecutionInvocationKind::DirectAgent && !invocation.params.is_empty() {
        return Err(KataError::Validation(
            "direct-agent invocation cannot carry workflow params".to_string(),
        ));
    }
    // Idempotently re-check the resolved params against the program's
    // declared specs. The executor boundary already resolved + default-filled
    // them; re-running the ONE resolver over the rows-as-supplied must reproduce
    // exactly the same canonical rows. This makes the durable admission (and the
    // admission hash computed below) self-verifying: a recovered invocation whose
    // params drift from a valid resolved set of the program's contract is
    // refused, and a mismatch between what a face claimed and what the program
    // declares cannot be admitted.
    let supplied: serde_json::Map<String, serde_json::Value> = invocation
        .params
        .iter()
        .map(|param| (param.name.to_string(), param.value.clone()))
        .collect();
    let reresolved = resolve_and_validate_params(&program.params, &supplied)
        .map_err(|error| KataError::Validation(error.to_string()))?;
    if reresolved != invocation.params {
        return Err(KataError::Validation(
            "execution invocation params are not a canonical resolved set of the program's \
             declared param contract"
                .to_string(),
        ));
    }
    match target_rule {
        TargetRule::Frozen => {
            check_invocation_target(program, invocation.kind, invocation.target.as_ref())?;
        }
        TargetRule::ResolvedPerFire => {
            if let Some(target) = &invocation.target {
                return Err(TargetRefusal::new(
                    TARGET_PRESENCE_INVALID,
                    format!(
                        "a schedule of {} pins an invocation carrying target `{}`; a schedule's \
                         target is resolved at every fire, never pinned",
                        program.workflow_name, target.spec
                    ),
                )
                .into());
            }
        }
    }
    let is_direct_agent_program = program.source.format == WorkflowSourceFormat::Api
        && program.workflow_name.as_str() == "api.agent_run"
        && program.source.compiler.compiler.as_str() == "kata-workflow"
        && program.source.compiler.evaluator.as_str() == "agent-run";
    if (invocation.kind == ExecutionInvocationKind::DirectAgent) != is_direct_agent_program {
        return Err(KataError::Validation(format!(
            "execution invocation kind {:?} does not match checked program source {}",
            invocation.kind, program.workflow_name
        )));
    }
    if invocation.initial_external_inputs.len() > MAX_INITIAL_EXTERNAL_INPUTS {
        return Err(KataError::Validation(format!(
            "execution invocation has {} initial external inputs; maximum is {MAX_INITIAL_EXTERNAL_INPUTS}",
            invocation.initial_external_inputs.len()
        )));
    }

    let mut keys = std::collections::BTreeSet::new();
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for input in &invocation.initial_external_inputs {
        if input.schema_version != EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION {
            return Err(KataError::Validation(format!(
                "initial external input {:?}/{:?} uses evidence schema {}; current schema is {EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION}",
                input.channel, input.id, input.schema_version
            )));
        }
        if input.id.trim().is_empty()
            || input.channel.trim().is_empty()
            || input.text.trim().is_empty()
            || input.projection.trim().is_empty()
        {
            return Err(KataError::Validation(
                "normalized initial external input requires non-empty id, channel, text, and projection"
                    .to_string(),
            ));
        }
        if input.text.chars().count() > EXTERNAL_INPUT_TEXT_MAX_CHARS {
            return Err(KataError::Validation(format!(
                "initial external input {:?}/{:?} exceeds the {EXTERNAL_INPUT_TEXT_MAX_CHARS}-character text bound",
                input.channel, input.id
            )));
        }
        if !keys.insert((input.channel.as_str(), input.id.as_str())) {
            return Err(KataError::Validation(format!(
                "duplicate initial external input key {:?}/{:?}",
                input.channel, input.id
            )));
        }
        let channel = program
            .external_input_channels
            .channels
            .iter()
            .find(|channel| channel.id.as_str() == input.channel)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "initial external input {:?}/{:?} names an undeclared channel",
                    input.channel, input.id
                ))
            })?;
        if let Some(declared_stage) = channel.stage.as_ref()
            && input.target_stage.as_deref() != Some(declared_stage.0.as_str())
        {
            return Err(KataError::Validation(format!(
                "initial external input {:?}/{:?} must target declared stage {:?}",
                input.channel, input.id, declared_stage.0
            )));
        }
        let count = counts.entry(input.channel.as_str()).or_default();
        *count += 1;
        if *count > channel.max_items as usize {
            return Err(KataError::Validation(format!(
                "initial external input channel {:?} has {} items; maximum is {}",
                input.channel, count, channel.max_items
            )));
        }
    }

    let value = serde_json::to_value(invocation).map_err(|error| {
        KataError::Serialization(format!("serialize typed execution invocation: {error}"))
    })?;
    let bytes = canonicalize_args(&value);
    if bytes.len() > MAX_EXECUTION_INVOCATION_BYTES {
        return Err(KataError::Validation(format!(
            "canonical execution invocation is {} bytes; maximum is {MAX_EXECUTION_INVOCATION_BYTES}",
            bytes.len()
        )));
    }
    let hash = *blake3::hash(&bytes).as_bytes();
    Ok((bytes, hash))
}
