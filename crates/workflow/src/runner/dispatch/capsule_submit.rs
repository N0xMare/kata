//! The PRODUCTION submit path for a shell stage on a
//! node.
//!
//! # What this module is
//!
//! The composition increments 1-3 each built one piece of, reached from the runner's own
//! dispatch path for the first time: the stage is RENDERED by the one renderer
//! (`WorkflowRunner::render_checked_prompt`, whose output arrives here as a
//! [`RenderedCommand`]), LOWERED to its typed operation, ASSEMBLED into a capsule over
//! the node's declared environment and the execution's own work tree, AUTHORIZED
//! (`kata_workflow::authorization::authorize_attempt` — publish, declare, claim, enqueue
//! one dispatch), and then DELIVERED as a `DispatchFrame::Capsule` across whichever
//! transport the placed worker is on.
//!
//! # The two node facts a capsule binds, and where each comes from
//!
//! A capsule names an ENVIRONMENT (an authorized Nix closure) and a WORK TREE (the
//! content-addressed head the action edits).
//!
//! * The environment is the one `[node] environment` declares, bound at BOOT
//!   (`kata_core::environment::bind_node_environment`) and carried on the dispatcher; it
//!   is re-read off its row here and refused by name if it is unbound
//!   ([`CAPSULE_ENVIRONMENT_UNBOUND`]), gone ([`CAPSULE_ENVIRONMENT_ABSENT`]) or
//!   unpromoted ([`CAPSULE_ENVIRONMENT_UNPROMOTED`]). A pack never names it.
//! * The work tree is the execution's RECORDED durable head AT THE STAGE'S OWN
//!   `parallel()` coordinate: `work_head_coordinate` derives
//!   which `execution_work_tree_heads` row the stage reads, `ensure_work_tree_head`
//!   forks the branch row off the frozen barrier base on first submission, and the
//!   capsule's `/work` maps the head's artifact. There is NO per-attempt scratch
//!   walk on this path: a branch's input is what the branch's applies recorded,
//!   never the bytes a scratch directory happens to hold.
//!
//! Neither has a fallback.
//!
//! # What it does NOT do, stated so nothing reads wider than the mechanism
//!
//! * It does not bind the worker MEMBRANE ENROLLMENT DURABLY.
//!   `authorize_attempt`'s `dispatch_claimed_attempt` writes no placement-time
//!   `(attempt, epoch)` binding — the capsule arm's `effect_domain` is stamped at the
//!   send from the CURRENT registration instead, so the instance-fenced send
//!   (`Dispatcher::deliver_capsule_frame` → `dispatch_to_current_instance`) compares the
//!   stamped value against the registration it may reach, not against a placement-time
//!   record.
//! * It does not RE-deliver. A capsule attempt whose first delivery failed — a frame the
//!   delivery door could not build or the transport refused — is SETTLED at that door,
//!   PROVEN NOT PERFORMED (`Dispatcher::settle_undelivered_capsule_attempt`), and a claim
//!   whose authorization failed after its own claim and before its dispatch committed is
//!   settled the same way here (`settle_claim_the_authorization_left`) — only the claim
//!   that authorization made or adopted, never an earlier one it did not reach. Neither is
//!   sent again; a re-submission of the stage authorizes a new attempt.
//! * It does not run a subworkflow, a durable sleep or a review loop: those are
//!   main-resolved or expansion-driven before this door (`dispatch::main_resolved`).
//!   The REUSE cache it does consult, for a stage that authored it
//!   (`dispatch::capsule_reuse`), between assembly and publication — `content_cache` on
//!   a shell capsule, and `model_reuse` on an AGENT capsule, keyed on the same
//!   `Capsule::reuse_key`, so a hit adopts the source's response AND its recorded
//!   `/work` delta rather than replaying a bare envelope.
//!
//! # An APPROVAL GATE parks here, and is not delivered
//!
//! A shell stage declaring `approval = True` is authorized like any other, and
//! `authorize_attempt` derives the gate from the checked stage: its capsule is published
//! and declared, and its attempt is claimed PARKED `awaiting_approval`, bound to that
//! capsule (`Authorization::Parked`). Nothing is delivered and no worker is chosen; the
//! approval door (`Dispatcher::approve_capsule_gate`) chooses the placement and delivers
//! the one dispatch an approval authorizes. Re-submitting a parked stage — a runner
//! resume — re-presents the park and never dispatches it.

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{EnvironmentId, OccurrenceRef, PlatformId};
use kata_types::sandbox::SandboxDirective;
use kata_types::workflow::{ExecutionId, StageId};
use smol_str::SmolStr;
use tracing::{info, warn};

use crate::capsule_assembly::{NodeBudgetDefaults, RenderedCommand, assemble_capsule};
use crate::runner::WorkflowRunner;
use kata_program::capsule_rules::CAPSULE_DEFAULT_MEMORY_BYTES;
use kata_program::capsule_rules::CAPSULE_PROCESS_COUNT;
use kata_program::execution_program::LoweredOperation;

/// This node's dispatcher carries no boot-bound environment.
pub const CAPSULE_ENVIRONMENT_UNBOUND: &str = "execution_profile_environment_unbound";
/// The boot-bound environment's row is gone or released.
pub const CAPSULE_ENVIRONMENT_ABSENT: &str = "execution_profile_environment_absent";
/// The boot-bound environment's gc root is not promoted.
pub const CAPSULE_ENVIRONMENT_UNPROMOTED: &str = "execution_profile_environment_unpromoted";
/// The node's content store is not attached, so no capsule can be published.
pub const CAPSULE_CONTENT_STORE_ABSENT: &str = "execution_profile_content_store_absent";

fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("capsule dispatch refused: {reason}"))
}

impl WorkflowRunner {
    /// SUBMIT one shell stage as a capsule: render → lower → assemble → authorize →
    /// deliver.
    ///
    /// `rendered` is the output of the ONE renderer, passed in rather than re-derived:
    /// `RenderedCommand`'s whole purpose is that the bytes folded into `CapsuleId` are
    /// the bytes a container will `execve`, and `submit_stage` has already rendered them
    /// for this dispatch. `lowered` is likewise the lowering the oci divert
    /// (`dispatch::main_resolved`) ROUTED this stage on, passed in rather than lowered
    /// again, so the operation that was judged a capsule command is the operation whose
    /// capsule is assembled.
    ///
    /// `approval_bypass_reason` rides [`AuthorizeInput::approval_bypass_reason`]
    /// unchanged: `None` for an ordinary stage's submission (the checked stage's
    /// gate derives on its own), `Some` ONLY for an expansion member the durable
    /// loop driver re-dispatches at iteration ≥ 1 — checked authority, named.
    ///
    /// # Errors
    ///
    /// The four absent/ambiguous node-fact refusals named in the module docs;
    /// [`assemble_capsule`]'s refused set (a host-path-bearing directive, a non-shell
    /// agent, an empty command, a zero wall clock); `authorize_attempt`'s refused set
    /// (an undeclared, released or unpromoted environment, an occurrence or capsule that
    /// disagrees with its own coordinates, a bypass named on an ungated stage or
    /// left blank); a placement failure from the scheduler; and the transport's own
    /// send failure. Every one of them leaves the stage
    /// UNSENT: there is no arm of this function that falls back to another
    /// dispatch route.
    pub(in crate::runner) async fn submit_stage_as_capsule(
        &self,
        stage_name: &SmolStr,
        lowered: &LoweredOperation,
        directive: Option<SandboxDirective>,
        rendered: &RenderedCommand,
        approval_bypass_reason: Option<String>,
    ) -> KataResult<()> {
        let stage_id = StageId(stage_name.clone());
        let checked_stage = kata_program::execution_program::preflight_stage_dispatch(
            &self.execution_program,
            &stage_id,
        )
        .map_err(|error| KataError::Validation(error.to_string()))?;
        // A stage at its OWN coordinate whose occurrence is already
        // ACCEPTED, yet whose stage is being submitted again, is a stage whose
        // accepted output failed its structured-output contract — its retry
        // chain (`[i].child(k)`, re-derived by the fold off the durable chain)
        // owns the next attempt. Re-submitting attempt 0 would mint a second
        // attempt at an accepted occurrence (a resume after a crash between the
        // invalid attempt's acceptance and its retry's dispatch did exactly
        // that), so this is a no-op, not a dispatch.
        if lowered.path.0.len() == 1 {
            let occurrence = kata_types::execution_contract::OccurrenceRef::new(
                kata_types::workflow::ExecutionId(self.execution_id),
                self.execution_program.program_hash,
                lowered.contract.id(),
                lowered.path.clone(),
            );
            let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
            if db
                .occurrence(occurrence.id().0.0)?
                .is_some_and(|row| row.accepted.is_some())
            {
                info!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    "capsule submit: attempt 0 is already accepted — its retry chain owns the stage"
                );
                return Ok(());
            }
        }
        self.submit_member_as_capsule(
            stage_name,
            &stage_id,
            checked_stage,
            lowered,
            directive,
            rendered,
            approval_bypass_reason,
        )
        .await
    }

    /// The capsule submit body over a CALLER-SUPPLIED checked stage — the
    /// member seam: an expansion member's durable stage spelling can
    /// be SYNTHETIC (`<base>#child-<role>` under a static `topology`), which
    /// `preflight_stage_dispatch` can never answer for, so the member dispatch
    /// supplies the checked stage it authorized with (the parent's for the
    /// root member, `preflight_derived_dispatch`'s for a declared child —
    /// with `op.agent_label` already narrowed to the member's effective one)
    /// and `stage_label` carries the durable spelling the reuse lookup and
    /// the logs read.
    ///
    /// `head_stage` is the AUTHORED stage whose coordinate the capsule maps its
    /// `/work` head at when `lowered.path` is no stage-expansion member — a
    /// synthetic spelling names no stage of the program, so it cannot feed
    /// `work_head_coordinate`. A `topology` member (its path's parent is the
    /// expansion) maps its own `/work` branch of the parent stage's head
    /// instead (`expansion_member_work_coordinate`).
    ///
    /// `lowered` still names the member's own contract and CHILD coordinate —
    /// the occurrence and the capsule identity change with the member, only
    /// the metadata door is shared.
    ///
    /// # Errors
    ///
    /// [`Self::submit_stage_as_capsule`]'s, minus the preflight's (which the
    /// caller ran its own arm of).
    pub(in crate::runner) async fn submit_member_as_capsule(
        &self,
        stage_label: &SmolStr,
        head_stage: &StageId,
        checked_stage: &kata_program::execution_program::ExecutionProgramStage,
        lowered: &LoweredOperation,
        directive: Option<SandboxDirective>,
        rendered: &RenderedCommand,
        approval_bypass_reason: Option<String>,
    ) -> KataResult<()> {
        let stage_name = stage_label;
        let directive = directive.ok_or_else(|| {
            refused(&format!(
                "stage {stage_name} resolved NO sandbox directive, and a capsule commits to a \
                 permissions hash computed over one. The directive is an \
                 input to the capsule's identity, so there is nothing to hash and nothing to \
                 promise"
            ))
        })?;

        let store = self.cache_store.as_ref().ok_or_else(|| {
            refused(&format!(
                "{CAPSULE_CONTENT_STORE_ABSENT}: this node has no content store attached, so a \
                 capsule's canonical bytes cannot be published and no artifact reference could \
                 resolve on the worker. The `oci` execution profile requires the node's `cas.db` \
                 / `cas/` authority"
            ))
        })?;
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());

        // THE /work SOURCE. A workspace profile maps the durable head at the stage's own
        // coordinate, whichever provenance seeded it:
        //
        // * ISOLATED (`worktree_isolated = true`): the root head is the committed
        //   base tree admission published (`publish_committed_base_head`), and an
        //   apply's jj leg advances it.
        // * NON-ISOLATED: the root head is the scratch workspace's ONE
        //   admission-time walk (`publish_scratch_tree_head`), and every apply
        //   advances CAS-only.
        // * A `parallel()` branch: the row `ensure_work_tree_head` forks here —
        //   lazily, at the branch's first submission — off the single frozen
        //   barrier base the sibling rows pin, so every branch of the join
        //   computes its delta against the same point.
        //
        // * A stage-EXPANSION member: the member's own branch of
        //   the parent stage's head, forked the same way — every member of one
        //   topology forks at one point, so no member's delta can go stale
        //   against a sibling's, and the expansion's settle merges them back.
        //
        // A stage at the ROOT coordinate whose row is absent is the admission
        // bug `ensure_work_tree_head` refuses by name (`work_tree_head_unrecorded`):
        // the root is recorded before the execution leaves `Admitting`, so a
        // dispatch-time miss can only mean admission did not run this binary.
        //
        // A `workspace = "scratch"` stage maps NO head: its `/work` is the
        // canonical empty tree `assemble_capsule` mints `ReadWriteScratch`,
        // its delta is recorded never applied, and no `work_head_coordinate`
        // question exists for it — so the coordinate/head read below is
        // skipped for it, never guessed.
        let scratch = matches!(directive.fs, kata_types::sandbox::FsPolicy::Scratch);
        let (head, work_tree) = if scratch {
            (None, crate::capsule_assembly::empty_tree_artifact()?.id())
        } else {
            // A topology member maps its own `/work` branch; every other
            // stage its stage's head.
            let coordinate =
                match kata_program::execution_program::expansion_member_work_coordinate(
                    &self.execution_program,
                    &lowered.path,
                    stage_label.as_str(),
                )? {
                    Some(branch) => branch,
                    None => kata_program::execution_program::work_head_coordinate(
                        &self.execution_program,
                        head_stage,
                    )?,
                };
            let head = db.ensure_work_tree_head(self.execution_id, &coordinate)?;
            let artifact = db.artifact(head.work_tree_artifact_id)?.ok_or_else(|| {
                KataError::Storage(format!(
                    "execution {}'s /work head at {:?} names artifact {}, and no `artifacts` \
                     row carries it — the head and the declaration are written together, so a \
                     missing row is plane corruption, not a refusal",
                    self.execution_id,
                    head.branch,
                    kata_types::primitives::ContentHash::new(head.work_tree_artifact_id),
                ))
            })?;
            let work_tree = kata_types::execution_contract::ArtifactRef::new(
                kata_types::primitives::FixedBytes(artifact.object_id),
                artifact.size_bytes,
                artifact.privacy,
            )
            .id();
            (Some(head), work_tree)
        };

        let (environment, platform) =
            bound_node_environment(self.dispatcher.node_environment(), &db)?;

        // THE PROMPT, for an agent stage: the rendered bytes become a durable
        // Private blob the capsule's `Agent` turn names by artifact id — the
        // prompt is what the vendor reads, so it is a content input like every
        // mapping's bytes, never a field the worker could render twice. The
        // declaration's owner is this execution, the same retention the
        // `artifacts` rows of the result it produces carry. A shell stage
        // publishes nothing — its command is the argv itself.
        let agent_prompt = if kata_program::capsule_rules::is_shell_class(checked_stage) {
            None
        } else {
            let bytes = rendered.as_str().as_bytes();
            let durable = store.cas().put_durable(bytes)?;
            let reference = kata_types::execution_contract::ArtifactRef::new(
                durable.object_id(),
                durable.size(),
                kata_types::execution_contract::ArtifactPrivacy::Private,
            );
            db.declare_artifact(
                &kata_core::operational::ArtifactDeclaration::for_durable_object(
                    &reference,
                    kata_core::operational::CasRootOwner::Execution(self.execution_id),
                    &durable,
                )?,
            )?;
            Some(reference.id())
        };

        // THE GIT VIEW, for an agent stage — or a stage whose profile
        // `requires` `git` (`carries_git_view`) — on a
        // worktree-isolated execution. The
        // `execution_git_views` row admission recorded becomes the capsule's
        // `git_view` payload (history artifact ref, base commit and branch,
        // inherited identity). Any other stage carries `None` and maps `/work`
        // with no repository behind it. A NON-isolated execution has no
        // repository to root a view at and records no row, so `None` there too.
        // An ISOLATED execution with such a stage and no row is the admission
        // record contradicting the stage set — Internal, never a silently bare
        // `/work`.
        let git_view = if !crate::capsule_assembly::carries_git_view(
            checked_stage,
            &self.execution_program.sandbox_profiles,
        ) || !self.execution_program.summary.worktree_isolated
        {
            None
        } else {
            let view = db.execution_git_view(self.execution_id)?.ok_or_else(|| {
                KataError::Internal(format!(
                    "execution {} dispatches agent stage {} but records no git view — \
                         admission owes the row to every isolated `oci` execution whose \
                         program contains one",
                    self.execution_id, checked_stage.stage_id.0,
                ))
            })?;
            let history = db.artifact(view.history_artifact_id)?.ok_or_else(|| {
                KataError::Storage(format!(
                    "execution {}'s git view names artifact {}, and no `artifacts` row \
                     carries it — the view and the declaration are written together, so a \
                     missing row is plane corruption, not a refusal",
                    self.execution_id,
                    kata_types::primitives::ContentHash::new(view.history_artifact_id),
                ))
            })?;
            Some(kata_types::execution_contract::CapsuleGitView {
                history: kata_types::execution_contract::ArtifactRef::new(
                    kata_types::primitives::FixedBytes(history.object_id),
                    history.size_bytes,
                    history.privacy,
                ),
                base_commit: SmolStr::from(view.base_commit.as_str()),
                branch: view.branch,
                identity: kata_types::execution_contract::GitIdentity {
                    name: SmolStr::from(view.identity_name.as_str()),
                    email: SmolStr::from(view.identity_email.as_str()),
                },
            })
        };

        let occurrence = OccurrenceRef::new(
            ExecutionId(self.execution_id),
            self.execution_program.program_hash,
            lowered.contract.id(),
            lowered.path.clone(),
        );
        let (prepared, capsule) = assemble_capsule(
            lowered,
            occurrence.id(),
            checked_stage,
            &directive,
            rendered,
            environment,
            platform,
            work_tree,
            NodeBudgetDefaults {
                memory_bytes: declared_memory_bytes(&directive),
                process_count: CAPSULE_PROCESS_COUNT,
            },
            agent_prompt,
            git_view,
        )?;

        // A DIVERGENT RE-DECLARATION is refused before anything is authorized:
        // the same occurrence re-presented over a different head artifact is a
        // different body of work under one occurrence.
        kata_core::work_tree::refuse_divergent_work_tree(&db, occurrence.id().0.0, work_tree.0.0)?;
        // THE CONTENT CACHE: an equal, already-accepted capsule's
        // result is ADOPTED here — before a worker is chosen and before anything is
        // authorized — so a hit runs no container and writes no capsule or command.
        // See `dispatch::capsule_reuse`.
        if self.consult_capsule_reuse(stage_name, checked_stage, &occurrence, &capsule)? {
            return Ok(());
        }
        // `declare_capsule` requires a live row for every mapping, so the canonical
        // empty tree `/out` and `/tmp` map still owes its declare — idempotent on
        // every re-drive.
        {
            let db2 = std::sync::Arc::clone(&db);
            let store2 = std::sync::Arc::clone(store);
            let execution = self.execution_id;
            tokio::task::spawn_blocking(move || {
                kata_core::work_tree::declare_empty_tree(&db2, store2.cas(), execution)
            })
            .await
            .map_err(|error| {
                KataError::Internal(format!("the empty-tree declare did not finish: {error}"))
            })??;
        }

        // THE ADMISSION CAP — `runtime.max_concurrent_dispatches` bounds how many
        // submissions run their authorize+deliver section at once: the section that
        // claims and dispatches the attempt (two durable transactions) and sends the
        // frame. The N+1th concurrent submission queues on the semaphore rather than
        // convoying on the ledger connection-mutex. `None` = unbounded (a dispatcher
        // built without `with_max_concurrent_dispatches`). The permit is held through
        // the delivery below — a gated stage that parks releases it on return, which
        // is correct: its submission section is over.
        let _permit = self.dispatcher.acquire_dispatch_permit().await;
        // THE PLACEMENT is chosen by the authorization itself, and only when it dispatches
        // (before any byte is published): a GATED stage is parked, and its placement is
        // chosen when an operator approves it. A capsule demands a certified container of
        // the worker it lands on — that is the whole of the `oci` profile — so the
        // containment filter is not `Unconstrained`.
        let place = || self.dispatcher.select_capsule_worker();
        // The stage's authored `requires`, judged against the bound
        // environment before anything is claimed or published.
        crate::authorization::refuse_requirements_not_in_the_environment(
            &db,
            store.cas(),
            environment,
            stage_label.as_str(),
            crate::capsule_assembly::stage_requirements(
                checked_stage,
                &self.execution_program.sandbox_profiles,
            ),
            self.dispatcher.program_probe(),
        )?;
        let authorization = match crate::authorization::authorize_attempt_reporting_claim(
            &db,
            store.cas(),
            crate::authorization::AuthorizeInput {
                execution: ExecutionId(self.execution_id),
                program_hash: self.execution_program.program_hash,
                lowered,
                checked_stage,
                approval_bypass_reason,
                occurrence,
                prepared,
                capsule,
                environment,
                work_head: head.as_ref(),
                programs: self.dispatcher.program_probe(),
                place: &place,
            },
        ) {
            Ok(authorization) => authorization,
            Err(failed) => {
                if let Some(claim) = failed.claim {
                    self.settle_claim_the_authorization_left(claim, &failed.error);
                }
                return Err(failed.error);
            }
        };
        let authorized = match authorization {
            crate::authorization::Authorization::Dispatched(authorized) => authorized,
            // A GATED stage: parked (or re-presented) awaiting an operator's approval, and
            // NOT delivered. Its `awaiting_approval` claim reaches the runner through the
            // delivery projector like any other lifecycle edge; the approval door
            // (`Dispatcher::approve_capsule_gate`) dispatches and delivers it.
            crate::authorization::Authorization::Parked(parked) => {
                info!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    attempt_id = %parked.attempt_id,
                    occurrence_id = %parked.occurrence_id.0,
                    capsule_id = %parked.capsule_id.0,
                    re_presented = parked.re_presented,
                    "runner: a gated capsule attempt is parked awaiting approval"
                );
                return Ok(());
            }
        };
        info!(
            execution_id = %self.execution_id,
            stage = %stage_name,
            attempt_id = %authorized.attempt_id,
            occurrence_id = %authorized.occurrence_id.0,
            capsule_id = %authorized.capsule_id.0,
            lease_epoch = authorized.lease_epoch,
            "runner: authorized a capsule attempt and is delivering its frame"
        );
        self.dispatcher
            .deliver_capsule_frame(authorized.attempt_id)
            .await
    }
}

impl WorkflowRunner {
    /// SETTLE `claimed` — the attempt a FAILED authorization had itself claimed or adopted
    /// (`AuthorizationFailed::claim`) — if it is still an unsent claim.
    ///
    /// `authorize_attempt` claims (one transaction) and then dispatches (another), so a
    /// dispatch that fails — a storage fault, a refusal of the placement — returns with
    /// the claim durable and undispatched. Nothing was sent: the frame leaves only through
    /// [`crate::dispatcher::Dispatcher::deliver_capsule_frame`], after `authorize_attempt`
    /// returns `Ok`. So the claim is recorded PROVEN NOT PERFORMED here rather than left
    /// for a re-submission that a failing stage's execution may never make. The
    /// `Undispatched` premise, re-read under the writer lock, makes this a no-op for an
    /// attempt whose claim never committed or whose dispatch did.
    ///
    /// ONLY this call's own claim. An authorization that failed BEFORE its claim point
    /// settles nothing — not even a claim found undispatched at the same occurrence: that
    /// one is the door's to adopt on a later presentation, or the abandoned-claim
    /// sweep's once the execution latches, and settling it here would turn a transient
    /// failure into a lost adoption. (A claim a CRASH left is dispatched by the resumed
    /// runner's boot, before this path runs at all.)
    ///
    /// A failure to settle is logged, not raised: the caller returns the authorization's
    /// own error, and a claim this misses is still reached by the abandoned-claim sweep
    /// once the execution latches its outcome.
    fn settle_claim_the_authorization_left(&self, claimed: ulid::Ulid, error: &KataError) {
        if let Err(settle_error) = self.dispatcher.settle_unsent_capsule_claim(
            claimed,
            &format!("the capsule attempt's authorization failed after its claim: {error}"),
        ) {
            warn!(attempt_id = %claimed, %settle_error, "capsule submit: settling the claim a failed authorization left failed");
        }
    }
}

/// The CAPSULE DIVERT's body, reachable from this crate's integration tests.
///
/// # Why a door and what it does NOT stand in for
///
/// `submit_stage` is `pub(in crate::runner)` and drives a whole graph through
/// `WorkflowRunner::run`, which waits for a terminal state — a stub worker never
/// produces one, so a cell that went in through `run` would assert about a timeout.
/// This door calls the divert's BODY, which is every step the divert takes
/// (render → lower → assemble → authorize → deliver) and the one place the two absent
/// node-fact refusals live.
///
/// It does NOT stand in for the divert's CONDITION
/// (the `submit_stage_as_capsule` call in `submit_stage`). That one line
/// is covered by `bin/kata/tests/oci_main_live.rs`, which runs the real pack
/// through the real submit path.
#[cfg(any(test, feature = "test-support"))]
impl WorkflowRunner {
    /// See the item docs above this `impl`.
    ///
    /// # Errors
    ///
    /// [`WorkflowRunner::submit_stage_as_capsule`]'s, verbatim.
    ///
    /// The stage is lowered here with the same `lower_stage_operation` the divert lowers
    /// with, and handed to the body as the divert hands it.
    #[doc(hidden)]
    pub async fn submit_stage_as_capsule_for_test(
        &self,
        stage_name: &SmolStr,
        directive: Option<SandboxDirective>,
        rendered: &RenderedCommand,
    ) -> KataResult<()> {
        let lowered = kata_program::execution_program::lower_stage_operation(
            &self.execution_program,
            &StageId(stage_name.clone()),
        )
        .map_err(|error| refused(&format!("stage {stage_name} does not lower: {error:?}")))?;
        self.submit_stage_as_capsule(stage_name, &lowered, directive, rendered, None)
            .await
    }
}

/// The memory ceiling this stage's capsule records: the AUTHORED `memory_mb` when the
/// directive declares one, else [`CAPSULE_DEFAULT_MEMORY_BYTES`].
///
/// Authored wins because it is hashed into the checked program: a capsule that recorded
/// a node default over a declared bound would promise a box the pack did not author,
/// and the disagreement would be invisible — both values are legal budgets.
fn declared_memory_bytes(directive: &SandboxDirective) -> u64 {
    directive
        .image
        .as_ref()
        .and_then(|image| image.memory_mb)
        .map_or(CAPSULE_DEFAULT_MEMORY_BYTES, |mb| {
            u64::from(mb).saturating_mul(1024 * 1024)
        })
}

/// The environment BOOT bound for this node, re-read off its row at selection.
///
/// # Why the boot-bound id and not a query
///
/// `[node] environment` is declared, promoted and bound at `BootRig::boot`
/// (`kata_core::environment::bind_node_environment`), which REFUSES a second live row
/// rather than leaving two to choose between — so there is exactly one answer and the
/// dispatcher carries it. Querying the plane for "the promoted one" here would be a second
/// answer to a question boot already settled, and the query is what could find two.
///
/// # Refused set
///
/// * [`CAPSULE_ENVIRONMENT_UNBOUND`] — this dispatcher carries no bound environment
///   (boot refuses an `oci` node without one, so this is a rig or a wiring defect);
/// * [`CAPSULE_ENVIRONMENT_ABSENT`] — the bound id's row is GONE or RELEASED. Defensive:
///   nothing in production releases a node environment while the node runs;
/// * [`CAPSULE_ENVIRONMENT_UNPROMOTED`] — the bound id's gc root is not promoted, so its
///   closure is collectable. Refused here, by name, before a capsule is assembled, rather
///   than left to `authorize_attempt`'s own promotion gate.
fn bound_node_environment(
    bound: Option<kata_core::environment::NodeEnvironment>,
    db: &kata_core::OperationalDb,
) -> KataResult<(EnvironmentId, PlatformId)> {
    let bound = bound.ok_or_else(|| {
        refused(&format!(
            "{CAPSULE_ENVIRONMENT_UNBOUND}: this node bound no Nix environment at boot, and a \
             capsule binds a closure by id. `[node] environment` is required under the `oci` \
             profile and boot refuses without it, so reaching this is a node assembled without \
             `BootRig::boot`'s binding"
        ))
    })?;
    let row = db
        .environment(bound.environment.0.0)?
        .filter(|row| row.released_at_ms.is_none())
        .ok_or_else(|| {
            refused(&format!(
                "{CAPSULE_ENVIRONMENT_ABSENT}: the environment this node bound at boot ({}) has \
                 no ACTIVE nix_environments row any more. kata will not substitute another \
                 closure; restart the node so boot declares its environment again",
                bound.environment.0
            ))
        })?;
    if row.root_promoted_at_ms.is_none() {
        return Err(refused(&format!(
            "{CAPSULE_ENVIRONMENT_UNPROMOTED}: the environment this node bound ({}) holds no \
             PROMOTED gc root, so its closure is collectable and a container bound to it could \
             find its store paths gone. The boot reconciler owes the promotion",
            bound.environment.0
        )));
    }
    Ok((bound.environment, bound.platform))
}
