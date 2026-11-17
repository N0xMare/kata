//! [`authorize_attempt`] — make one occurrence's authorization DURABLE and dispatch
//! it exactly once.

use kata_core::operational::{AttemptClaimSpec, CommandSpec, OccurrenceBinding, OperationalDb};
use kata_core::store::cas::CasStore;
use kata_core::{CapsuleDeclaration, EnvironmentRow};
use kata_transport::types::{CapsuleAssignment, CapsuleRef, DispatchFrame, TraceContext};
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{
    Capsule, CapsuleId, EnvironmentId, OccurrenceId, OccurrenceRef, PreparedAction,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::primitives::ContentHash;
use kata_types::workflow::ExecutionId;
use ulid::Ulid;

use crate::dispatcher::assignment_blob_for_the_chain;
use kata_program::execution_program::{ExecutionProgramStage, LoweredOperation};

/// The attempt-lifecycle state a claim enters at.
///
/// `pending` and not `dispatched`: a claim issues no dispatch command, and
/// `OperationalDb::claim_attempt` refuses a worker-attributed state outright. The
/// dispatch is step 5.
const CLAIM_STATE: &str = "pending";

/// Everything one authorization decision consists of.
///
/// # Why the coordinates ride beside the occurrence they fold
///
/// [`Self::occurrence`] already folds [`Self::execution`], [`Self::program_hash`] and
/// `lowered.contract.id()`. They are carried SEPARATELY on purpose, and the
/// redundancy is spent on a check rather than left as duplication:
/// [`authorize_attempt`] refuses a mismatch by field name before it writes anything.
/// A caller that derived the occurrence from one program and the claim's coordinates
/// from another would otherwise mint an occurrence under coordinates that do not
/// describe it — which is precisely the aliasing `occurrence_id` exists to prevent,
/// arriving through the one door the durable refusals cannot see (they compare a
/// binding against a STORED row, and the first claim has no stored row to disagree
/// with).
pub struct AuthorizeInput<'a> {
    /// The execution this occurrence belongs to.
    pub execution: ExecutionId,
    /// The checked program's hash.
    pub program_hash: ContentHash,
    /// The lowered operation, for its contract id and its canonical stage id.
    pub lowered: &'a LoweredOperation,
    /// The CHECKED stage the operation was lowered from — where the APPROVAL GATE is
    /// derived (`policies.approval_required`), inside this door and never from a
    /// caller's flag. See [`Authorization::Parked`].
    pub checked_stage: &'a ExecutionProgramStage,
    /// Checked-authority EXEMPTION from the derived gate, or `None`: a
    /// review-loop member re-dispatched at iteration ≥ 1 is checked-authority
    /// dispatched (the loop's own gate is the reviewer's, not a fresh human
    /// gate), so the derived `approval_required` is bypassed BY NAME rather
    /// than by absent policy. Refused when the checked stage is not
    /// `approval_required` (a bypass on an ungated stage is a caller mistake)
    /// or when the reason is blank (an unnamed bypass is not an authority).
    pub approval_bypass_reason: Option<String>,
    /// The logical invocation being authorized.
    pub occurrence: OccurrenceRef,
    /// The prepared action the capsule carries.
    pub prepared: PreparedAction,
    /// The capsule to publish, declare and dispatch.
    pub capsule: Capsule,
    /// The Nix environment the capsule binds.
    pub environment: EnvironmentId,
    /// Whether a path in the node's Nix store is an executable file — what the
    /// `capsule_program_not_in_environment` check asks of the environment's `PATH` dirs.
    /// Production passes [`HostProgramProbe`].
    pub programs: &'a dyn ProgramProbe,
    /// The execution's recorded `/work` head AT THIS STAGE'S coordinate —
    /// the `execution_work_tree_heads` row the submit path ensured for the
    /// stage's branch (or root). `Some` for a WORKSPACE-profiled stage, whose
    /// capsule's `/work` mapping must be exactly that artifact; the role check
    /// re-reads the durable row rather than trusting this copy. `None` for a
    /// `workspace = "scratch"` stage, whose capsule maps the canonical empty
    /// tree `ReadWriteScratch` and has no head to answer to — the role check's
    /// scratch arm asks the empty-tree question instead.
    pub work_head: Option<&'a kata_core::operational::ExecutionWorkTreeHead>,
    /// CHOOSES the worker this dispatch places the attempt on — called only when the
    /// authorization dispatches, and before any byte is published.
    ///
    /// A choice rather than a value because a GATED occurrence is parked, not placed:
    /// its placement is chosen when an operator approves it, so demanding a worker at
    /// park time would refuse a gate on a node whose worker is merely not registered
    /// yet. `dispatch_claimed_attempt` takes the placement as a REQUIRED `&str` —
    /// `dispatched` is a worker-attributed state with no shape for an absent placement —
    /// so the dispatching arm always names one. Production passes
    /// `Dispatcher::select_capsule_worker`.
    pub place: &'a dyn Fn() -> KataResult<smol_str::SmolStr>,
}

/// What one authorization made durable: a DISPATCHED attempt, or a GATED one PARKED
/// awaiting an operator's approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorization {
    /// The occurrence's attempt was claimed (or adopted) and dispatched.
    Dispatched(Authorized),
    /// The checked stage declares `approval = True` (the gate is on
    /// this capsule attempt), so its attempt is claimed PARKED `awaiting_approval`,
    /// bound to its capsule, and NOT dispatched — or, when a parked attempt already
    /// holds the occurrence, RE-PRESENTED unchanged. The only way on is
    /// `OperationalDb::decide_capsule_approval`.
    Parked(ParkedGate),
}

impl Authorization {
    /// The dispatch, when this authorization dispatched.
    #[must_use]
    pub const fn dispatched(self) -> Option<Authorized> {
        match self {
            Self::Dispatched(authorized) => Some(authorized),
            Self::Parked(_) => None,
        }
    }
}

/// A gated occurrence's attempt, parked awaiting approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParkedGate {
    /// The parked attempt.
    pub attempt_id: Ulid,
    /// Its occurrence.
    pub occurrence_id: OccurrenceId,
    /// The capsule an approval of it would dispatch.
    pub capsule_id: CapsuleId,
    /// `true` when the attempt was ALREADY parked at the occurrence (a runner resume
    /// re-presenting the stage); `false` when this call parked it.
    pub re_presented: bool,
}

/// What became durable when an authorization dispatched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorized {
    /// The attempt this authorization minted.
    pub attempt_id: Ulid,
    /// The occurrence the attempt is a generation of.
    pub occurrence_id: OccurrenceId,
    /// The capsule that was declared and dispatched.
    pub capsule_id: CapsuleId,
    /// The generation the dispatch was recorded at, READ BACK off the `attempts` row
    /// rather than predicted: `dispatch_claimed_attempt` allocates it, and a caller
    /// that computed "the claimed epoch plus one" would be restating a writer's rule.
    pub lease_epoch: i64,
}

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("authorization refused: {reason}"))
}

/// A failed [`authorize_attempt`], with the claim it had reached when it failed.
pub(crate) struct AuthorizationFailed {
    /// The authorization's own error.
    pub(crate) error: KataError,
    /// The attempt THIS call claimed or adopted before it failed — `None` for every
    /// failure before the claim point. A claim that existed before the call and that the
    /// call never reached is not named: it is an earlier submission's, left for the
    /// occurrence recovery to adopt or the abandoned-claim sweep to settle.
    pub(crate) claim: Option<Ulid>,
}

/// AUTHORIZE one occurrence: publish the capsule, declare it, claim the attempt that
/// binds it, and enqueue exactly one dispatch — or, for a stage declaring
/// `approval = True`, PARK the claim awaiting an operator's decision and dispatch nothing
/// ([`Authorization::Parked`]).
///
/// The order and the two crash windows it leaves are the module docs' subject; read
/// those first. This function's own contract is the refused set below and the
/// single-transaction claim.
///
/// # ONE TRANSACTION FOR THE CLAIM, AND IT IS `claim_attempt`'S OWN
///
/// The occurrence row, the attempt row and the `claimed` transition commit together
/// because `claim_attempt` writes all three inside one `in_writer_txn`. This function
/// opens no transaction of its own and must not: a second transaction around the
/// claim would either nest (which `OperationalDb` does not offer) or bracket it,
/// which would make "the occurrence and its attempt became durable together" a
/// property of two commits instead of one.
///
/// # Failure — the refused set, stated exactly
///
/// Refused BEFORE any byte is published, so the CAS is unchanged on every one:
///
/// * an ungated authorization whose `place` refuses (no eligible worker);
/// * an `environment` with no `nix_environments` row — not declared on this node;
/// * an `environment` whose row is RELEASED;
/// * an `environment` whose Nix gc root is UNPROMOTED (`root_promoted_at_ms IS
///   NULL`). This is the "promoted at AUTHORIZE" default: `declare_capsule`
///   deliberately does NOT check promotion (a capsule may be assembled during the
///   window the boot reconciler resolves), so the obligation lands here, at the one
///   door that authorizes work to actually run in that closure;
/// * a capsule whose `argv[0]` the environment does not provide
///   ([`CAPSULE_PROGRAM_NOT_IN_ENVIRONMENT`]);
/// * an `occurrence` that disagrees with `execution`, `program_hash` or
///   `lowered.contract.id()` — named per field;
/// * a `capsule` whose `occurrence()`, `action()` or `environment()` disagrees with
///   the occurrence, the prepared action or the environment being authorized.
///
/// Refused after the publish, by the plane that owns the question:
///
/// * `declare_capsule`'s own three (a mapping whose artifact has no `artifacts`
///   row, an environment that is undeclared or released, and a divergent
///   re-declaration), plus its tampered-bytes refusal;
/// * `claim_attempt`'s own — or, gated, `claim_attempt_parked_for_approval`'s, which
///   are the same (an attempt id that already exists, a divergent stored occurrence at
///   the same coordinates — `occurrence_id`, `program_hash` or `capsule_id`);
/// * `dispatch_claimed_attempt`'s own (an unknown attempt, an empty placement, a
///   terminal attempt).
///
/// # What is NOT refused here, and who owes it
///
/// STORE availability. The environment gate above reads `operational.db`, which
/// answers "did this node declare, promote and not release this closure?".
/// `kata_core::environment::reconcile::ReconcileReport::unavailable` answers a
/// different question — "does the store still HAVE the closure's paths?" — by asking
/// the Nix store, and it is produced only by `reconcile_environments`, which is
/// BOOT-PHASE ONLY by its own contract (it is not concurrency-safe against a live
/// declare) and returns a value no live door can re-derive without re-running it.
/// So this door cannot consult it, and does not pretend to: an environment whose
/// promoted root names a store path the collector has since taken passes this gate
/// and fails at materialization, by name, on the worker. The ISSUANCE GATE owes the
/// live check — either a durable `unavailable` column the reconciler stamps, or a
/// store probe at this door — and until it exists nothing here may be described as
/// proving an environment is BINDABLE, only that it is AUTHORIZED.
pub fn authorize_attempt(
    db: &OperationalDb,
    cas: &CasStore,
    input: AuthorizeInput<'_>,
) -> KataResult<Authorization> {
    authorize_attempt_reporting_claim(db, cas, input).map_err(|failed| failed.error)
}

/// [`authorize_attempt`], and on failure the attempt it had claimed or adopted
/// ([`AuthorizationFailed::claim`]) — what the submit path settles, and nothing else.
pub(crate) fn authorize_attempt_reporting_claim(
    db: &OperationalDb,
    cas: &CasStore,
    input: AuthorizeInput<'_>,
) -> Result<Authorization, AuthorizationFailed> {
    let AuthorizeInput {
        execution,
        program_hash,
        lowered,
        checked_stage,
        approval_bypass_reason,
        occurrence,
        prepared,
        capsule,
        environment,
        work_head,
        programs,
        place,
    } = input;
    let early = |error| AuthorizationFailed { error, claim: None };

    // THE GATE, derived from the checked stage and nowhere else. A gated occurrence
    // chooses no worker (its placement is chosen at approval); an ungated one chooses its
    // worker HERE, before a byte is published, so a node with no eligible worker refuses
    // with the CAS and the plane untouched. A checked-authority bypass EXEMPTS
    // the derived gate — refused on an ungated stage or with no reason named.
    let gate = match &approval_bypass_reason {
        Some(reason) if reason.trim().is_empty() => {
            return Err(early(KataError::Validation(format!(
                "authorization for stage {} carries a blank approval-bypass reason; \
                 a bypass is checked authority and must name it",
                checked_stage.stage_id.0
            ))));
        }
        Some(_) if !checked_stage.policies.approval_required => {
            return Err(early(KataError::Validation(format!(
                "authorization for stage {} carries an approval-bypass reason but the \
                 checked stage requires no approval; a bypass on an ungated stage is \
                 a caller mistake",
                checked_stage.stage_id.0
            ))));
        }
        Some(_) => None,
        None => approval_gate_reason(checked_stage),
    };
    let placement = match gate {
        Some(_) => None,
        None => Some(place().map_err(early)?),
    };

    let (durable, adopted) = declare_up_to_the_claim(
        db,
        cas,
        DeclareInput {
            execution,
            program_hash,
            lowered,
            occurrence: &occurrence,
            prepared: &prepared,
            capsule: &capsule,
            environment,
            work_head,
            programs,
            gated: gate.is_some(),
        },
    )
    .map_err(early)?;
    // THE CLAIM POINT. From here on every failure names the attempt this call claimed or
    // adopted, whether or not its claim committed: settling an attempt that does not
    // exist, or one a dispatch already reached, records nothing.
    let attempt_id = adopted.unwrap_or_else(Ulid::new);
    let claimed = |error| AuthorizationFailed {
        error,
        claim: Some(attempt_id),
    };
    // THE `/work` THE CLAIM BINDS: the capsule's own `/work` artifact — the
    // workspace head the door just proved for a workspace profile, or the
    // canonical empty tree for a scratch one. A capsule mapping no `/work`
    // binds the presented head, exactly as it always did.
    let work_binding = occurrence_work_binding(&capsule, work_head).map_err(early)?;
    let claim = ClaimInput {
        execution,
        lowered,
        occurrence: &occurrence,
        prepared: &prepared,
        capsule: &capsule,
        work_binding,
        durable: &durable,
        attempt_id,
        progress_visibility: checked_stage.policies.progress_visibility,
        adopted: adopted.is_some(),
    };
    match (gate, placement) {
        (Some(reason), _) => park_the_gate(db, claim, &reason).map_err(claimed),
        (None, Some(worker_id)) => {
            claim_and_dispatch(db, claim, worker_id.as_str()).map_err(claimed)
        }
        (None, None) => Err(claimed(KataError::Internal(
            "an ungated authorization reached its claim with no placement chosen".to_owned(),
        ))),
    }
}

/// The operator-visible reason a GATED stage parks under, or `None` for an ungated one.
///
/// The gate is `policies.approval_required` on the checked stage; the
/// gate is on this Execute's own capsule attempt. The reason is the authored
/// `approval_reason`, else a default naming the stage.
pub(crate) fn approval_gate_reason(stage: &ExecutionProgramStage) -> Option<String> {
    stage.policies.approval_required.then(|| {
        stage.policies.approval_reason.clone().unwrap_or_else(|| {
            format!(
                "stage {} requires operator approval before dispatch",
                stage.stage_id.0
            )
        })
    })
}

/// Step 4 for a GATED occurrence: claim its attempt PARKED `awaiting_approval` in ONE
/// transaction (`claim_attempt_parked_for_approval`), or RE-PRESENT the attempt already
/// parked there. Never a dispatch.
fn park_the_gate(
    db: &OperationalDb,
    input: ClaimInput<'_>,
    reason: &str,
) -> KataResult<Authorization> {
    let ClaimInput {
        execution,
        lowered,
        occurrence,
        prepared,
        capsule,
        work_binding,
        durable,
        attempt_id,
        progress_visibility,
        adopted,
    } = input;
    if !adopted {
        let frame = at_rest_frame(
            attempt_id,
            execution,
            occurrence,
            capsule,
            durable,
            progress_visibility,
        );
        let assignment_json = assignment_blob_for_the_chain(
            &DispatchFrame::Capsule(Box::new(frame)),
            "the capsule authorization",
        )?;
        db.claim_attempt_parked_for_approval(
            execution.0,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: lowered.contract.source_stage.0.to_string(),
                assignment_json,
                initial_state: kata_core::operational::AWAITING_APPROVAL_STATE.to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(prepared.id()),
                    Some(capsule.id()),
                )
                .with_work_tree(work_binding),
            },
            reason,
        )?;
    }
    Ok(Authorization::Parked(ParkedGate {
        attempt_id,
        occurrence_id: occurrence.id(),
        capsule_id: capsule.id(),
        re_presented: adopted,
    }))
}

/// [`authorize_attempt_reporting_claim`]'s inputs up to the claim point.
struct DeclareInput<'a> {
    execution: ExecutionId,
    program_hash: ContentHash,
    lowered: &'a LoweredOperation,
    occurrence: &'a OccurrenceRef,
    prepared: &'a PreparedAction,
    capsule: &'a Capsule,
    environment: EnvironmentId,
    work_head: Option<&'a kata_core::operational::ExecutionWorkTreeHead>,
    programs: &'a dyn ProgramProbe,
    /// Whether the occurrence is GATED: its recovery read is then the PARKED attempt,
    /// never an adoptable one.
    gated: bool,
}

/// Steps 1-3 and the occurrence recovery's read: every refusal, the capsule's bytes and
/// its declaration — and the undispatched attempt at the occurrence to ADOPT, if one is
/// there. Writes no attempt.
fn declare_up_to_the_claim(
    db: &OperationalDb,
    cas: &CasStore,
    input: DeclareInput<'_>,
) -> KataResult<(kata_core::store::cas::DurableObject, Option<Ulid>)> {
    let DeclareInput {
        execution,
        program_hash,
        lowered,
        occurrence,
        prepared,
        capsule,
        environment,
        work_head,
        programs,
        gated,
    } = input;
    refuse_incoherent_occurrence(occurrence, execution, program_hash, lowered)?;
    refuse_incoherent_capsule(capsule, occurrence, prepared, environment)?;
    require_promoted_active_environment(db, environment)?;
    refuse_a_program_not_in_the_environment(db, cas, environment, capsule, programs)?;
    refuse_a_work_tree_not_bound_by_role(db, execution, occurrence, capsule, work_head)?;
    refuse_a_divergent_capsule_at_a_stored_occurrence(db, occurrence, capsule)?;

    // STEP 2 — BYTES. The receipt this mints is the only proof of durability
    // `CapsuleDeclaration` accepts, and it exists only after the bytes are
    // fsync-durable. K8 fires at the end of this call: the bytes are durable and
    // nothing references them, which collection resolves.
    let bytes = canonical_capsule_bytes(capsule)?;
    let durable = cas.put_durable(&bytes)?;

    // STEP 3 — REFERENCES. `for_durable_object` checks the capsule, its bytes and the
    // receipt against each other all three ways before a row can name them.
    let declaration = CapsuleDeclaration::for_durable_object(capsule, &bytes, &durable)?;
    db.declare_capsule(&declaration)?;

    // STEP 4 — the occurrence, the attempt and the claiming transition, in ONE
    // transaction. The at-rest frame carries NO per-dispatch fact: epoch 0, no
    // command, no deadline, no effect domain. See `at_rest_frame`.
    //
    // # THE ADOPTION LEG COMES FIRST, and it does not claim
    //
    // `after_occurrence_authorized_before_dispatch` leaves an attempt that is bound,
    // durable and undispatched, and the obligation is "a durable occurrence acquires
    // exactly ONE dispatch". A restarted main dispatches that attempt at its runner's
    // boot (`Dispatcher::dispatch_claims_left_undispatched`), before anything can
    // present the occurrence here; this leg holds the obligation for a presentation
    // that finds such an attempt all the same: the door ADOPTS it instead of
    // minting a second generation for it. A second attempt would satisfy "the
    // occurrence got dispatched" while stranding the first one pending forever —
    // unreachable by any sweep that keys on the occurrence, which is the accumulating
    // orphan the boundary exists to prevent.
    //
    // The adopted attempt's stored blob is NOT rewritten. The frame reconstructed here
    // is a pure function of `(attempt_id, execution, occurrence, capsule, durable)`,
    // every one of which is the value the crashed claim already wrote, so the
    // reconstruction is the stored blob rather than a second opinion about it — which
    // `crates/workflow/tests/authorization.rs`'s crash cell asserts byte-for-byte
    // rather than reasoning about.
    //
    // # A GATED occurrence re-presents its park, and never adopts
    //
    // The adoption read excludes a parked attempt, so an ungated re-presentation can
    // never dispatch a gate. A gated one reads the park instead and returns it
    // unchanged (`park_the_gate`): re-presenting a gated occurrence — which is what a
    // runner resume does — NEVER dispatches it.
    let adopted = if gated {
        db.parked_capsule_attempt_at_occurrence(occurrence.id().0.0)?
    } else {
        db.undispatched_attempt_at_occurrence(occurrence.id().0.0)?
    };
    Ok((durable, adopted))
}

/// [`authorize_attempt_reporting_claim`]'s inputs from the claim point on.
struct ClaimInput<'a> {
    execution: ExecutionId,
    lowered: &'a LoweredOperation,
    occurrence: &'a OccurrenceRef,
    prepared: &'a PreparedAction,
    capsule: &'a Capsule,
    /// The artifact id the occurrence's `/work` binding names — the capsule's
    /// own `/work` mapping, checked against its role by the door already.
    work_binding: [u8; 32],
    durable: &'a kata_core::store::cas::DurableObject,
    attempt_id: Ulid,
    /// The checked stage's authored `progress_visibility`, stamped onto the
    /// at-rest frame with the rest of the authored facts — a per-stage fact,
    /// not a per-dispatch one, so it belongs in the durable blob and never in
    /// `frame_for_dispatch`'s stamp list.
    progress_visibility: kata_types::workflow::ProgressVisibility,
    /// Whether `attempt_id` is an ADOPTED (or, gated, re-presented) claim rather than a
    /// fresh one to claim.
    adopted: bool,
}

/// Step 4 (the claim, unless adopted) and step 5 (the dispatch).
fn claim_and_dispatch(
    db: &OperationalDb,
    input: ClaimInput<'_>,
    worker_id: &str,
) -> KataResult<Authorization> {
    let ClaimInput {
        execution,
        lowered,
        occurrence,
        prepared,
        capsule,
        work_binding,
        durable,
        attempt_id,
        progress_visibility,
        adopted,
    } = input;
    let frame = at_rest_frame(
        attempt_id,
        execution,
        occurrence,
        capsule,
        durable,
        progress_visibility,
    );
    if !adopted {
        let assignment_json = assignment_blob_for_the_chain(
            &DispatchFrame::Capsule(Box::new(frame.clone())),
            "the capsule authorization",
        )?;
        db.claim_attempt(
            execution.0,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: lowered.contract.source_stage.0.to_string(),
                assignment_json,
                initial_state: CLAIM_STATE.to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(prepared.id()),
                    Some(capsule.id()),
                )
                .with_work_tree(work_binding),
            },
        )?;
        // `after_occurrence_authorized_before_dispatch` has now fired, inside
        // `claim_attempt`, conditional on the binding this call carried. The adoption
        // leg does NOT pass through it, and must not: the window it names is already
        // behind this data directory.
    }

    // STEP 5 — the dispatch: transition and command in one transaction.
    let command_id = Ulid::new();
    db.dispatch_claimed_attempt(
        attempt_id,
        worker_id,
        command_id,
        &capsule_dispatch_command(&frame, worker_id)?,
    )?;

    let lease_epoch = db
        .attempt(attempt_id)?
        .ok_or_else(|| {
            KataError::Storage(format!(
                "operational.db has no attempt {attempt_id} immediately after dispatching it; the \
                 claim and the dispatch both committed, so an absent row means the plane is not \
                 the one they were written to"
            ))
        })?
        .lease_epoch;

    Ok(Authorization::Dispatched(Authorized {
        attempt_id,
        occurrence_id: occurrence.id(),
        capsule_id: capsule.id(),
        lease_epoch,
    }))
}

/// The refusal token for a capsule whose `argv[0]` does not resolve in its environment.
pub const CAPSULE_PROGRAM_NOT_IN_ENVIRONMENT: &str = "capsule_program_not_in_environment";

/// Whether `path` names an executable regular file in the node's Nix store.
pub trait ProgramProbe: Send + Sync {
    /// `true` when `path` is a regular file with an execute bit.
    fn executable(&self, path: &std::path::Path) -> bool;
}

/// The production [`ProgramProbe`]: the node's own `/nix/store`, which is the store the
/// capsule's closure binds read-only, so a file present here is present in the guest.
pub struct HostProgramProbe;

impl ProgramProbe for HostProgramProbe {
    fn executable(&self, path: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
}

/// Refuse a command capsule whose PROGRAM (`argv[0]`) is not in its environment.
///
/// # Refused set
///
/// [`CAPSULE_PROGRAM_NOT_IN_ENVIRONMENT`]: a bare `argv[0]` that is not an executable file
/// in any of the manifest's `path_prepend` directories (the guest `PATH` the bundle
/// renders), or an absolute `argv[0]` outside every closure store path or not executable.
/// Checked here, before any byte is published, because the alternative is a container
/// whose shell reports 127 and a stage that "fails" for a reason the environment, not the
/// stage, owns. Only `argv[0]` is checked — the commands inside a `sh -c` string are the
/// stage's own business and are not parsed here.
fn refuse_a_program_not_in_the_environment(
    db: &OperationalDb,
    cas: &CasStore,
    environment: EnvironmentId,
    capsule: &Capsule,
    programs: &dyn ProgramProbe,
) -> KataResult<()> {
    // An agent capsule's init is the provider entry's `kata-toolhost`, never a
    // program the environment provides; its argv is empty (`Capsule::new`).
    let kata_types::execution_contract::CapsuleProcess::Command { argv } = capsule.process() else {
        return Ok(());
    };
    let Some(program) = argv.first() else {
        return Ok(());
    };
    let row = db
        .environment(environment.0.0)?
        .ok_or_else(|| refused("the environment row vanished between two reads"))?;
    let bytes = cas.get_verified_bounded(
        &kata_types::primitives::FixedBytes(row.manifest_object_id),
        kata_types::nix_environment::NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES,
    )?;
    let manifest: kata_types::nix_environment::NixEnvironmentManifest =
        serde_json::from_slice(&bytes).map_err(|error| {
            refused(&format!(
                "Nix environment {}'s manifest does not decode: {error}",
                environment.0
            ))
        })?;
    let found = if program.contains('/') {
        let path = std::path::Path::new(program.as_str());
        manifest
            .closure()
            .iter()
            .any(|entry| path.starts_with(entry.store_path.as_str()))
            && programs.executable(path)
    } else {
        manifest.path_prepend().iter().any(|dir| {
            programs.executable(&std::path::Path::new(dir.as_str()).join(program.as_str()))
        })
    };
    if found {
        return Ok(());
    }
    Err(refused(&format!(
        "{CAPSULE_PROGRAM_NOT_IN_ENVIRONMENT}: capsule {} executes `{program}`, and the node \
         environment {} ({}) provides no such program on its PATH ({}). The container would \
         report 127 — a stage failing for a reason its environment owns. Add the program's \
         closure to `[node] environment`",
        capsule.id().0,
        environment.0,
        manifest.label(),
        manifest
            .path_prepend()
            .iter()
            .map(kata_types::execution_contract::GuestPath::as_str)
            .collect::<Vec<_>>()
            .join(":")
    )))
}

/// The refusal token for a stage whose `sandbox_profile(requires = [..])` names a
/// program its environment does not provide.
pub const CAPSULE_REQUIREMENT_NOT_IN_ENVIRONMENT: &str = "capsule_requirement_not_in_environment";

/// Refuse a stage whose authored `requires` names a program `environment` does not
/// provide on its guest `PATH` — the dispatch-time judge of the same list the `oci`
/// CHECK judges when the process bound an environment (`environment_requirement_unmet`),
/// asked the way `argv[0]` is (`programs` over the manifest's `path_prepend`
/// directories), before any byte is published.
///
/// # Errors
///
/// [`CAPSULE_REQUIREMENT_NOT_IN_ENVIRONMENT`] naming every missing program; a
/// vanished environment row or an undecodable manifest.
pub fn refuse_requirements_not_in_the_environment(
    db: &OperationalDb,
    cas: &CasStore,
    environment: EnvironmentId,
    stage: &str,
    requires: &[String],
    programs: &dyn ProgramProbe,
) -> KataResult<()> {
    if requires.is_empty() {
        return Ok(());
    }
    let row = db
        .environment(environment.0.0)?
        .ok_or_else(|| refused("the environment row vanished between two reads"))?;
    let bytes = cas.get_verified_bounded(
        &kata_types::primitives::FixedBytes(row.manifest_object_id),
        kata_types::nix_environment::NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES,
    )?;
    let manifest: kata_types::nix_environment::NixEnvironmentManifest =
        serde_json::from_slice(&bytes).map_err(|error| {
            refused(&format!(
                "Nix environment {}'s manifest does not decode: {error}",
                environment.0
            ))
        })?;
    let missing: Vec<&str> = requires
        .iter()
        .filter(|program| {
            !manifest.path_prepend().iter().any(|dir| {
                programs.executable(&std::path::Path::new(dir.as_str()).join(program.as_str()))
            })
        })
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(refused(&format!(
        "{CAPSULE_REQUIREMENT_NOT_IN_ENVIRONMENT}: stage \"{stage}\" requires {missing:?} on its \
         PATH, and the node environment {} ({}) provides no such program. Add the program's \
         closure to `[node] environment`, or drop the requirement",
        environment.0,
        manifest.label(),
    )))
}

/// The refusal token for a `/work` mapping that is not the durable head at this
/// stage's coordinate.
pub const WORK_TREE_NOT_ROLE_BOUND: &str = "work_tree_not_role_bound";

/// The artifact id an occurrence's `/work` binding names — the capsule's own
/// `/work` mapping when it carries one (the door has already checked that
/// mapping against its role), else the presented head's: a capsule mapping no
/// `/work` binds the head the same way it always did, and a scratch capsule's
/// mapping IS the canonical empty tree it binds.
///
/// # Errors
///
/// `Internal` for a capsule mapping no `/work` presented with no head — a
/// caller bug, unreachable from `submit_stage_as_capsule`, which either ensures
/// the head or assembles the scratch mapping.
fn occurrence_work_binding(
    capsule: &Capsule,
    head: Option<&kata_core::operational::ExecutionWorkTreeHead>,
) -> KataResult<[u8; 32]> {
    if let Some(mapped) = capsule
        .inputs()
        .iter()
        .find(|mapping| mapping.guest_path.as_str() == "/work")
    {
        return Ok(mapped.artifact.0.0);
    }
    head.map(|head| head.work_tree_artifact_id).ok_or_else(|| {
        KataError::Internal(format!(
            "capsule {} maps no /work and no /work head was presented — a binding has \
             nothing to name",
            capsule.id().0
        ))
    })
}

/// Refuse a capsule whose `/work` is not the artifact its ROLE binds —
/// decided by the `/work` mapping's access, which is the capsule's own claim:
///
/// * `ReadWrite` — an execution-WORKSPACE `/work`: the execution's recorded
///   head at the presented coordinate's branch, with the durable row re-read
///   as the authority over the caller's copy.
/// * `ReadWriteScratch` — a scratch `/work`: the canonical empty tree, which
///   is the only artifact that role may name. No head is consulted — a
///   scratch stage has none, which is exactly the point.
/// * `ReadOnly` — refused: a `/work` a capsule cannot write is no role this
///   plane binds, and the delta it could still report must never be taken for
///   a workspace delta.
///
/// # Refused set
///
/// * [`WORK_TREE_NOT_ROLE_BOUND`] — a workspace arm where the execution
///   records NO `/work` head at the presented coordinate's branch (a root
///   miss is `work_tree_head_unrecorded` upstream, at submit), the presented
///   head disagrees with the durable row (it is stale: an apply advanced it
///   between submit and this claim), or the capsule's `/work` artifact is not
///   the recorded head's — and a workspace arm presented with NO head at all,
///   a caller bug the door refuses rather than guesses past. Retention alone
///   is not the question: a previous stage's adopted `/out` is an
///   execution-retained tree too, and passed every check before this one.
///   A scratch arm whose `/work` artifact is not the canonical empty tree —
///   the one artifact the role may name. And a `/work` mapped `read_only`.
/// * `work_tree_divergent_redeclaration` — the occurrence's stored row already binds a
///   different tree (`kata_core::work_tree::refuse_divergent_work_tree`): a
///   re-presentation over different content.
///
/// All before the capsule's bytes are published.
fn refuse_a_work_tree_not_bound_by_role(
    db: &OperationalDb,
    execution: ExecutionId,
    occurrence: &OccurrenceRef,
    capsule: &Capsule,
    head: Option<&kata_core::operational::ExecutionWorkTreeHead>,
) -> KataResult<()> {
    let mapped = capsule
        .inputs()
        .iter()
        .find(|mapping| mapping.guest_path.as_str() == "/work");
    let access = mapped.map(|mapping| mapping.access);
    // The recorded tree a stored occurrence must not diverge from — the
    // workspace head for a workspace `/work`, the canonical empty tree for a
    // scratch one. Computed per arm below; the divergence check closes the
    // door either way.
    let recorded = match access {
        Some(kata_types::execution_contract::GuestAccess::ReadWriteScratch) => {
            let empty = crate::capsule_assembly::empty_tree_artifact()?.id().0.0;
            let mapped_artifact = mapped.map(|mapping| mapping.artifact.0.0);
            if mapped_artifact != Some(empty) {
                return Err(refused(&format!(
                    "{WORK_TREE_NOT_ROLE_BOUND}: capsule {} maps {} at /work read_write_scratch, \
                     and the canonical empty tree is {} — a scratch /work names exactly one \
                     artifact, and {} is not it",
                    capsule.id().0,
                    mapped.map_or_else(
                        || "nothing".to_owned(),
                        |mapping| mapping.artifact.0.to_string()
                    ),
                    kata_types::primitives::ContentHash::new(empty),
                    mapped_artifact.map_or_else(
                        || "nothing".to_owned(),
                        |artifact| kata_types::primitives::ContentHash::new(artifact).to_string()
                    ),
                )));
            }
            empty
        }
        Some(kata_types::execution_contract::GuestAccess::ReadWrite) => {
            let head = head.ok_or_else(|| {
                refused(&format!(
                    "{WORK_TREE_NOT_ROLE_BOUND}: capsule {} maps /work read_write but no /work \
                     head was presented — a workspace role answers to the durable row, and a \
                     caller that presents none has nothing to check it against",
                    capsule.id().0,
                ))
            })?;
            // THE DURABLE ROW IS THE AUTHORITY — read it again here rather than
            // trust the decoded copy the caller carried, so a presented head can
            // never name an artifact the admission did not record, and a stale copy
            // of one an apply has since advanced is refused rather than trusted.
            let stored = db
                .work_tree_head_at(execution.0, &head.branch)?
                .ok_or_else(|| {
                    refused(&format!(
                        "{WORK_TREE_NOT_ROLE_BOUND}: execution {} records no /work head at \
                         {:?} — the row submit's `ensure_work_tree_head` forked or read is the \
                         only authority a capsule may map",
                        execution.0, head.branch,
                    ))
                })?;
            if stored != *head {
                return Err(refused(&format!(
                    "{WORK_TREE_NOT_ROLE_BOUND}: the /work head presented for this attempt \
                     names artifact {} at {:?}, and execution {}'s recorded head there is {} — \
                     the durable row, not a caller's copy of it, is the authority the mapping \
                     answers to",
                    kata_types::primitives::ContentHash::new(head.work_tree_artifact_id),
                    head.branch,
                    execution.0,
                    kata_types::primitives::ContentHash::new(stored.work_tree_artifact_id),
                )));
            }
            let recorded = stored.work_tree_artifact_id;
            if mapped.map(|mapping| mapping.artifact.0.0) != Some(recorded) {
                return Err(refused(&format!(
                    "{WORK_TREE_NOT_ROLE_BOUND}: capsule {} maps {} at /work, and the recorded \
                     head execution {} holds at {:?} is {}. Only the recorded head may be the \
                     workspace a capsule edits; any other execution-retained tree — a previous \
                     stage's /out included — is not this role",
                    capsule.id().0,
                    mapped.map_or_else(
                        || "nothing".to_owned(),
                        |mapping| mapping.artifact.0.to_string()
                    ),
                    execution.0,
                    head.branch,
                    kata_types::primitives::ContentHash::new(recorded),
                )));
            }
            recorded
        }
        Some(kata_types::execution_contract::GuestAccess::ReadOnly) => {
            return Err(refused(&format!(
                "{WORK_TREE_NOT_ROLE_BOUND}: capsule {} maps /work read_only — a /work a \
                 capsule cannot write is no role this plane binds: it answers to no head, and \
                 a delta reported over it must never reach the workspace it is not",
                capsule.id().0,
            )));
        }
        None => {
            // A capsule mapping no `/work` binds the presented head — exactly
            // what `occurrence_work_binding` computes for the claim below —
            // and the stored-occurrence divergence check answers a
            // re-presentation over a different tree the same way. The
            // adoption's mapped-vs-reported check owns a delta such a capsule
            // still reports.
            return kata_core::work_tree::refuse_divergent_work_tree(
                db,
                occurrence.id().0.0,
                occurrence_work_binding(capsule, head)?,
            );
        }
    };
    kata_core::work_tree::refuse_divergent_work_tree(db, occurrence.id().0.0, recorded)
}

/// The AT-REST capsule frame: identities and a capsule reference, and not one
/// per-dispatch fact.
///
/// # Invariant
///
/// `lease_epoch = 0`, `command_id = None`, `start_deadline_ms = None`,
/// `effect_domain = None`, empty `placed_on`, empty trace. All six are stamped onto the OUTGOING clone
/// by `Dispatcher::frame_for_dispatch` from the durable row at delivery: this
/// blob is written at the claim, before the dispatch allocates the epoch and the
/// command, so a blob restating either would disagree with its own row.
/// `0` is the same "not stamped" value that field's `#[serde(default)]`
/// produces, and it is also the epoch a claim lands at — the authoritative
/// answer is `attempts.lease_epoch`, never this.
///
/// `progress_visibility` is the opposite kind of fact — authored, on the checked
/// stage, identical at every generation — so it is stamped HERE, in the durable
/// blob, and the dispatcher's stamp list does not touch it.
fn at_rest_frame(
    attempt_id: Ulid,
    execution: ExecutionId,
    occurrence: &OccurrenceRef,
    capsule: &Capsule,
    durable: &kata_core::store::cas::DurableObject,
    progress_visibility: kata_types::workflow::ProgressVisibility,
) -> CapsuleAssignment {
    CapsuleAssignment {
        attempt_id,
        execution_id: execution.0,
        occurrence_id: occurrence.id(),
        capsule: CapsuleRef {
            id: capsule.id(),
            object: durable.object_id(),
            size_bytes: durable.size(),
        },
        lease_epoch: 0,
        placed_on: smol_str::SmolStr::default(),
        command_id: None,
        effect_domain: None,
        start_deadline_ms: None,
        progress_visibility,
        trace: TraceContext::default(),
    }
}

/// The durable dispatch command for a capsule frame.
///
/// # What it records, and what it deliberately does not
///
/// Its shape: `kind`, the placement, and the authority this dispatch carries — here the FRAME
/// itself, because a capsule dispatch's authority IS the capsule reference and there is no second
/// row to join it from. It does NOT restate the lease epoch or the command id: the
/// `attempt_commands` row is filed under both and a payload copy could disagree with the row it is
/// filed under. The frame embedded here is therefore the AT-REST form, with epoch 0 and no command,
/// exactly as the `attempts.assignment_json` blob is — the delivery clone is stamped at delivery.
///
/// Canonical (recursively key-sorted) like every other command payload, so two
/// encodings of one dispatch are byte-equal.
pub(crate) fn capsule_dispatch_command(
    frame: &CapsuleAssignment,
    worker_id: &str,
) -> KataResult<CommandSpec> {
    let frame =
        serde_json::to_value(DispatchFrame::Capsule(Box::new(frame.clone()))).map_err(|error| {
            KataError::Internal(format!(
                "authorization: serialize the capsule dispatch frame for attempt {}: {error}",
                frame.attempt_id
            ))
        })?;
    Ok(CommandSpec {
        command_json: canonicalize_args(&serde_json::json!({
            "kind": "dispatch",
            "worker_id": worker_id,
            "frame": frame,
        })),
    })
}

/// The capsule's CANONICAL serialization — the bytes the CAS addresses and the
/// worker re-verifies.
///
/// # One encoder, and why the worker needs no matching one
///
/// Recursively key-sorted (`canonicalize_args`) so two encodings of one capsule are
/// byte-equal and the CAS address is a function of the capsule alone rather than of
/// serde's field order on the day it was published. The worker never re-encodes: it
/// re-derives the ADDRESS of the bytes it read and decodes them, and `Capsule`'s own
/// `Deserialize` recomputes the `CapsuleId` from the body. So the round trip is
/// closed by the identity rather than by two encoders agreeing.
fn canonical_capsule_bytes(capsule: &Capsule) -> KataResult<Vec<u8>> {
    let value = serde_json::to_value(capsule).map_err(|error| {
        KataError::Internal(format!(
            "authorization: serialize capsule {}: {error}",
            capsule.id().0
        ))
    })?;
    Ok(canonicalize_args(&value))
}

/// Refuse, BEFORE A BYTE IS PUBLISHED, a capsule that disagrees with the one the
/// STORED occurrence at these coordinates already names.
///
/// # Why this door exists when `claim_attempt` already refuses the same divergence
///
/// `mint_occurrence`'s `refuse_divergent_occurrence` catches it, and catches it too
/// late to be the only check: by then the divergent capsule's bytes are fsync-durable,
/// its `capsules` row is committed and its node-owned `cas_roots` row is RETAINING
/// those bytes for the node's lifetime (the capsule plane has no release verb). So the
/// claim's refusal left a permanent, unaccountable declaration behind for a capsule
/// this node then refused to authorize. Reading the stored occurrence first turns that
/// into a refusal that writes and publishes nothing.
///
/// # This is a check, not a lock
///
/// The read is outside any transaction, so a concurrent writer could mint the
/// occurrence between it and the claim. That is exactly why `mint_occurrence`'s
/// refusal STAYS: it is the authority, inside the claim's transaction, and this door is
/// the cheap early one that keeps the common failure from costing retained bytes. A
/// claim wider than that — "a divergent capsule can never be declared" — would be a
/// guarantee wider than its mechanism, so it is not made.
///
/// # Failure
///
/// One [`KataError::Validation`] naming both capsules, and only when the stored row
/// HAS a `capsule_id`. A stored occurrence with a NULL one is the shadow shape
/// (minting preceded preparation) and is not refused — it is the row the
/// authorization binds.
fn refuse_a_divergent_capsule_at_a_stored_occurrence(
    db: &OperationalDb,
    occurrence: &OccurrenceRef,
    capsule: &Capsule,
) -> KataResult<()> {
    let stored = db.occurrence_at(
        occurrence.execution.0,
        occurrence.operation.0.0,
        &occurrence.path.canonical_bytes(),
    )?;
    let Some(row) = stored else {
        return Ok(());
    };
    if let Some(bound) = row.capsule_id
        && bound != capsule.id().0.0
    {
        return Err(refused(&format!(
            "occurrence {} is already bound to capsule {} on this node, and this authorization \
             names capsule {}. Refusing BEFORE the publish, so a capsule this plane will not \
             authorize does not leave fsync-durable bytes and a node-owned cas_roots row behind \
             it — the capsules plane has no release verb, so that retention would be permanent",
            occurrence.id().0,
            ContentHash::new(bound),
            capsule.id().0
        )));
    }
    Ok(())
}

/// Refuse an occurrence that does not describe the coordinates presented with it.
/// See [`AuthorizeInput`] for why the redundancy exists at all.
fn refuse_incoherent_occurrence(
    occurrence: &OccurrenceRef,
    execution: ExecutionId,
    program_hash: ContentHash,
    lowered: &LoweredOperation,
) -> KataResult<()> {
    let divergent: Vec<&str> = [
        ("execution", occurrence.execution == execution),
        ("program_hash", occurrence.program == program_hash),
        ("operation", occurrence.operation == lowered.contract.id()),
        ("operation_path", occurrence.path == lowered.path),
    ]
    .into_iter()
    .filter_map(|(field, equal)| (!equal).then_some(field))
    .collect();
    if divergent.is_empty() {
        return Ok(());
    }
    Err(refused(&format!(
        "the occurrence {} does not describe the coordinates it was presented with: it disagrees \
         on {}. The occurrence id FOLDS all four, so authorizing this pair would mint a row whose \
         lookup key and whose content id describe different work",
        occurrence.id().0,
        divergent.join(", ")
    )))
}

/// Refuse a capsule that is not this authorization's capsule.
///
/// # The refused set, exactly
///
/// Three bindings, and no others: the capsule's occurrence, its prepared action, and
/// its environment. Each is a field the capsule id folds AND a field this
/// authorization independently names, so a disagreement means two different decisions
/// are being recorded as one. `platform` is deliberately NOT in the set: this door is
/// handed no platform to compare against — it is `prepared`'s own field, and
/// `Capsule::new` folds it from the same value the assembler passed — so a check here
/// would compare the capsule against itself.
fn refuse_incoherent_capsule(
    capsule: &Capsule,
    occurrence: &OccurrenceRef,
    prepared: &PreparedAction,
    environment: EnvironmentId,
) -> KataResult<()> {
    let divergent: Vec<&str> = [
        ("occurrence", capsule.occurrence() == occurrence.id()),
        ("action", capsule.action() == prepared.id()),
        ("environment", capsule.environment() == environment),
    ]
    .into_iter()
    .filter_map(|(field, equal)| (!equal).then_some(field))
    .collect();
    if divergent.is_empty() {
        return Ok(());
    }
    Err(refused(&format!(
        "capsule {} is not the capsule this authorization is for: it disagrees on {}. A capsule id \
         folds every one of those, so publishing it under this authorization would make the \
         occurrence's declared body a different body from the one that was prepared",
        capsule.id().0,
        divergent.join(", ")
    )))
}

/// The environment gate: DECLARED, not released, and PROMOTED.
///
/// See [`authorize_attempt`]'s refused set for the three refusals and for what this
/// gate cannot answer.
fn require_promoted_active_environment(
    db: &OperationalDb,
    environment: EnvironmentId,
) -> KataResult<()> {
    let id = environment.0.0;
    let Some(row): Option<EnvironmentRow> = db.environment(id)? else {
        return Err(refused(&format!(
            "Nix environment {} is not declared on this node, so there is no closure to authorize \
             work in. kata inherits the host's answer and refuses when there is none",
            environment.0
        )));
    };
    if let Some(released_at_ms) = row.released_at_ms {
        return Err(refused(&format!(
            "Nix environment {} ({}) was released at {released_at_ms}; authorizing work in a \
             closure this node has relinquished would record an authorization that was already \
             withdrawn",
            environment.0, row.label
        )));
    }
    if row.root_promoted_at_ms.is_none() {
        return Err(refused(&format!(
            "Nix environment {} ({}) has an UNPROMOTED gc root: its closure is still held only by \
             staging generation {}, so nothing stable retains it and a container started against \
             it could lose its store paths mid-run. `declare_capsule` deliberately does not check \
             promotion — a capsule may be assembled inside the window the boot reconciler \
             resolves — so the check is here, at the door that authorizes work to run",
            environment.0, row.label, row.root_stage_id
        )));
    }
    Ok(())
}
