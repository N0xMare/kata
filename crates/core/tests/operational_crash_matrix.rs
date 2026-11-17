//! The crash matrix over the operational transaction groups.
//!
//! The crash proof is "crash at every transaction/dispatch/CAS/jj boundary and
//! prove no unjustified state advances". The dimensions are therefore fixed, not
//! discretionary, and they are declared as TYPES below rather than as prose so a
//! reader can see the axes and a change can add a cell.
//!
//! There is one fixture direction: with no upgrade ladder, a behind-stamped fixture
//! is unconstructible. [`Fixture`] states what that gives up.
//!
//! # How a change adds a CELL
//!
//! A cell is `(fixture direction) x (transaction group) x (kill point)`.
//!
//! - A NEW TRANSACTION GROUP is one [`Group`] variant plus one arm in
//!   [`Group::drive`] (what the armed child runs) and one in
//!   [`Group::prepare`] (what the unarmed fixture process must set up first).
//!   Every existing kill point then applies to it automatically — the runner
//!   iterates `Group::iter()`, so nothing else is touched and nothing can be
//!   forgotten.
//! - A NEW WRITER TRANSACTION — anything that opens an `in_writer_txn`, whether or
//!   not it becomes a group — is one row in [`WRITER_TRANSACTIONS`] declaring
//!   either the [`Group`] whose cell drives it or the reason it needs none.
//!   [`every_writer_transaction_is_accounted_for_on_the_transaction_axis`] reads
//!   the callers out of `kata-core`'s own source and refuses any it cannot find a
//!   row for, so this is not optional and not a convention: a writer with no
//!   standing on this axis leaves the gate green while the crash proof is stated
//!   over EVERY transaction boundary.
//! - A NEW KILL POINT is one row in
//!   `kata_core::fault_inject::OPERATIONAL_CRASH_BOUNDARIES` (name **plus** the
//!   boundary FAMILY it crosses), one call site in production, one
//!   [`Kill`] variant (whose [`Kill::transaction_committed`] arm states which SIDE
//!   of the commit the seam fires on and whose [`Group::reaches`] arm states which
//!   groups arrive there), one entry in [`DRIVEN_HERE`], and one `#[test]` per
//!   fixture direction that calls [`run_matrix`]. Forgetting the last two is a
//!   test failure rather than a silent omission — see
//!   [`every_boundary_driven_here_has_a_test`].
//!
//! # The families
//!
//! The crash proof's obligation is stated over FAMILIES — transaction, dispatch,
//! CAS, jj — and the accounting test below enumerates the boundary REGISTRY.
//! Those are not the same thing: a family nobody registers is not in the registry,
//! so an accounting test alone can report a registered boundary with no cell and
//! cannot report an entire missing boundary class. So the registry carries a family
//! per row, `fault_inject.rs` asserts each of the four is non-empty, and
//! [`every_crash_proof_family_is_covered_by_cells`] asserts the stronger form — a family closed by
//! registering a name nothing drives would
//! be the same defect one level up.
//! - A NEW FIXTURE DIRECTION is one [`Fixture`] variant plus one arm in
//!   [`Fixture::build`].
//!
//! No cell is a new test FILE, and no cell duplicates a fixture: every direction runs
//! the IDENTICAL repository transaction API through the one [`Group::drive`].
//!
//! # What this file's cells prove, and what they CANNOT
//!
//! Every invariant below (I0-I11) is a property of the NUCLEUS: the projection is
//! a pure fold of the retained chain, the watermark is contiguous, the transaction
//! is all-or-nothing at its boundary, the retry converges. That is the crash
//! proof's obligation and this file discharges it.
//!
//! It is NOT a claim about what the system DECIDES after the crash. The deciding
//! reader, `WorkflowRunner::fold_to_head`, reads the authority chain and lives in
//! `kata-workflow`. `kata-core` cannot depend on that crate, so no cell here can
//! construct it, and a coherent nucleus is simply a different claim from a
//! correct verdict read off it. No cell HERE drives `fold_to_head` over the data
//! dir an abort at these boundaries leaves behind. For two of them the reader-level
//! half is proved where the reader ships: `crates/api/tests/boot_recovery_after_teardown.rs`
//! kills a main at `after_claim_commit` and at
//! `after_occurrence_authorized_before_dispatch` and boots the next one through the
//! executor's resume, which must dispatch the claim once. For
//! `before_claim_commit`, `before_txn_commit` and `after_txn_commit` no cell boots a
//! restarted main over what the abort left.
//!
//! K8's cells (`cas_root_liveness`) live outside this file for the same reason: a
//! cell belongs in the crate where the plane it observes is reachable.
//!
//! # The crash model, stated honestly
//!
//! Each cell re-execs THIS binary as a child that `std::process::abort()`s at a
//! named `operational.<boundary>` fault point. `abort` is uncatchable and skips
//! `Drop`, `atexit`, and stdio flushing, so what the parent finds is what the
//! child's committed transactions left, with no orderly close behind them — this
//! is a PROCESS-DEATH model, not a handle drop. It is not a power-cut model: the
//! kernel keeps a dead process's page cache, so the parent re-reads writes no
//! device need have received, and on the suite's tmpfs `TMPDIR` nothing reaches a
//! device at all. The parent then re-opens the same data dir and verifies.
//!
//! The fixture is built in a FIRST, UNARMED process and the armed child runs ONLY
//! the group's transaction. Two reasons: the generic `before_txn_commit` /
//! `after_txn_commit` boundaries sit at the single writer chokepoint (so an armed
//! process would otherwise die building its own preconditions), and a process that
//! crashes while constructing its preconditions is not the failure being modelled.
//!
//! # Regime
//!
//! Single operational plane. `transitions.seq` is reserved IN-TRANSACTION, so an
//! aborted transaction leaves NO hole and a lagging fold cursor is corruption. The
//! ledger's opposite rule (reserve-before-commit, permanent holes by design) is
//! correct on its own plane and wrong here.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use kata_core::fault_inject::{
    OPERATIONAL_CRASH_BOUNDARIES, OperationalBoundaryFamily, operational_boundary_family,
    operational_boundary_registered,
};
use kata_core::operational::OccurrenceBinding;
use kata_core::operational::{
    AttemptClaimSpec, AttemptLifecycle, MainAttemptSpec, MainOperation, MainResolution,
    MainResolvePremise, MainWait,
};
use kata_core::{
    CommandSpec, InvocationKind, InvocationRecord, LifecycleState, MissedFirePolicy, OperationalDb,
    ProgramRecord, ScheduleInstall,
};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use kata_types::wait::WaitDeadline;
// The transaction axis is ITERATED FROM THE ENUM, never from a list typed
// out beside it. See [`Group`].
use strum::IntoEnumIterator;
use ulid::Ulid;

// -- the axes ----------------------------------------------------------------

/// FIXTURE AXIS (1).
///
/// # Why this axis is one, and what that gives up
///
/// A second direction — a data dir stamped at an older `user_version` and walked
/// forward through an upgrade ladder — is UNCONSTRUCTIBLE: kata refuses any
/// non-current stamp and starts a fresh data directory, and there is no code in the
/// tree, product or test, that can produce a current-shaped database from a
/// behind-stamped one.
///
/// Stated plainly, because it is a real limit: a class of defect — a transaction that
/// behaves differently on a database whose shape arrived by a route other than
/// `create_fresh_current_schema` — is not covered here. It is not REACHABLE either, which
/// is why the limit is sound and not merely convenient: the refusal that replaced the
/// ladder is proved by
/// `a_stamp_one_version_behind_is_refused_with_the_new_data_directory_recourse`
/// (`operational_substrate.rs`), and a behind-stamped dir cannot enter this file's window
/// at all.
///
/// It stays a TYPE rather than collapsing into a string so that a future second
/// direction — a restored recovery generation is the obvious candidate — is one
/// variant plus one `build` arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fixture {
    /// A data dir this build created from nothing.
    NewEmpty,
}

impl Fixture {
    /// The declared directions. One element today; retained as a list because
    /// [`every_boundary_driven_here_has_a_test`] iterates it, so adding a direction
    /// re-arms that check for the new one without being touched.
    const ALL: &'static [Fixture] = &[Fixture::NewEmpty];

    fn as_str(self) -> &'static str {
        match self {
            Fixture::NewEmpty => "new-empty",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "new-empty" => Fixture::NewEmpty,
            other => panic!("unknown fixture direction {other}"),
        }
    }

    /// The Rust variant spelling, for the source-text check in
    /// [`every_boundary_driven_here_has_a_test`]. Kept as an exhaustive `match` so a
    /// new direction cannot be added without teaching that check to look for it.
    fn variant_name(self) -> &'static str {
        match self {
            Fixture::NewEmpty => "NewEmpty",
        }
    }

    /// Create the data dir this direction describes, at `path`.
    fn build(self, path: &Path) {
        match self {
            Fixture::NewEmpty => {
                drop(OperationalDb::open(path).expect("create a new-empty nucleus"));
            }
        }
    }
}

/// TRANSACTION AXIS — the operational transaction groups, all present in the repo
/// API, plus additional transactions that are DISTINCT writers rather than extra
/// groups: the attempt-claim group's advancing half (the placement writer), the
/// terminal publication, membrane enrollment and stage metadata append. Each
/// carries its own justification on its variant.
///
/// # The axis is DERIVED, and it is CHECKED AGAINST PRODUCTION
///
/// Two different defects, and each needs its own answer.
///
/// The first is a variant that exists and does not run. A hand-typed
/// `const ALL: &[Group]` beside the enum lets a new variant be forgotten in the
/// list, producing a group whose cells silently never run. So [`strum::EnumIter`]
/// derives the roster (as for `sandbox_posture::ContainmentLever`), and there is
/// only one of them. The `match` arms in [`Group::as_str`], [`Group::prepare`],
/// [`Group::drive`], [`Group::reaches`] and `group_committed` are already
/// exhaustive, so a new variant is a compile error until every axis is taught
/// about it.
///
/// The second is one derivation does NOT touch: a production WRITER TRANSACTION
/// that never becomes a variant at all (for example a stop-plane writer opening an
/// `in_writer_txn` that nothing here notices). That is what [`WRITER_TRANSACTIONS`]
/// and [`every_writer_transaction_is_accounted_for_on_the_transaction_axis`] close:
/// the axis is compared against the set of `in_writer_txn` callers read out of the
/// crate's own source, so a new writer must be given a standing before the gate
/// goes green.
#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::EnumIter)]
enum Group {
    SubmitExecution,
    InstallSchedule,
    FireSchedule,
    ClaimAttempt,
    DispatchAttempt,
    /// The dispatch-side placement writer. Not a separate group:
    /// it is the ADVANCING half of the attempt-claim group, and it earns its own
    /// cell because it is the only attempt transaction that MUTATES a row the
    /// crash could otherwise leave half-updated (`worker_id` +
    /// `dispatched_at_ms` + `source_seq` alongside the folding transition).
    DispatchClaimedAttempt,
    /// Stable receiver identity must survive a committed enrollment, not be
    /// silently reminted after the process dies before registry admission.
    EnrollWorkerDomain,
    /// Stage audit appends own authority sequence allocation even without an
    /// attempt; crash both sides of that transaction explicitly.
    RecordStageMetadata,
    AcceptIncomingEvent,
    /// The APPROVAL DOOR: the `approval_decided` record, the `dispatched` transition,
    /// and the command — three facts in one commit.
    DecideCapsuleApproval,
    DynamicChild,
    /// The terminal PUBLICATION: the `terminalized` transition, the lifecycle's
    /// published state and every in-transaction closeout of waits still parked on the
    /// execution, in one transaction.
    FinishTerminalization,
    /// The MAIN-RESOLVED claim: the occurrence, the
    /// `claimed` transition and the `executor = 'main'` row with its durable deadline, in
    /// one transaction. It reaches ONLY the generic K3/K4 pair — it has no seam of its
    /// own, and deliberately so: before its commit nothing of it exists, after it
    /// everything does, and the wait between claim and resolution is the durable state a
    /// restart reads back, not a crash window.
    ClaimMainAttempt,
    /// The main-resolved RESOLUTION: the accepting `completed` transition, the
    /// occurrence acceptance `record_transition` writes inside it, and the row's cleared
    /// deadline and finish instant.
    ResolveMainAttempt,
    /// The one-transaction CLAIM AND RESOLVE (a join): no durable instant exists at which
    /// the attempt is claimed and unresolved.
    ClaimAndResolveMainAttempt,
    /// The ANSWER door (`resolve_input_wait`), driven through its
    /// early-answer branch: an input attempt claimed and accepted in ONE transaction, so —
    /// like the join's claim and resolve — no durable instant holds it claimed and
    /// unresolved. Its parked branch is the same transaction resolving a row the fixture
    /// would have to claim unarmed first; the generic K3/K4 pair covers either.
    ResolveInputWait,
}

impl Group {
    fn as_str(self) -> &'static str {
        match self {
            Group::SubmitExecution => "submit_execution",
            Group::InstallSchedule => "install_schedule",
            Group::FireSchedule => "fire_schedule",
            Group::ClaimAttempt => "claim_attempt",
            Group::DispatchAttempt => "dispatch_attempt",
            Group::DispatchClaimedAttempt => "dispatch_claimed_attempt",
            Group::EnrollWorkerDomain => "enroll_worker_domain",
            Group::RecordStageMetadata => "record_stage_metadata",
            Group::AcceptIncomingEvent => "accept_incoming_event",
            Group::DecideCapsuleApproval => "decide_capsule_approval",
            Group::DynamicChild => "dynamic_child",
            Group::FinishTerminalization => "finish_terminalization",
            Group::ClaimMainAttempt => "claim_main_attempt",
            Group::ResolveMainAttempt => "resolve_main_attempt",
            Group::ClaimAndResolveMainAttempt => "claim_and_resolve_main_attempt",
            Group::ResolveInputWait => "resolve_input_wait",
        }
    }

    fn parse(value: &str) -> Self {
        Group::iter()
            .find(|group| group.as_str() == value)
            .unwrap_or_else(|| panic!("unknown transaction group {value}"))
    }

    /// Everything the group's transaction NEEDS, run UNARMED so the fault fires on
    /// the transaction under test rather than on its preconditions.
    ///
    fn prepare(self, db: &Arc<OperationalDb>) {
        match self {
            // Nothing precedes a submission, a schedule install, or an enrollment.
            Group::SubmitExecution | Group::InstallSchedule | Group::EnrollWorkerDomain => {}
            Group::RecordStageMetadata => {
                submit(db, fixed_execution());
                db.admit_undispatched_stage(
                    fixed_execution(),
                    fixed_attempt(),
                    "stage-a",
                    "stage-a",
                )
                .expect("admit stage before arming metadata transaction");
                let output = serde_json::json!({"content": "done"});
                db.record_undispatched_stage_transition(
                    fixed_attempt(),
                    &kata_core::operational::UndispatchedStageOutcome::from_status(
                        &kata_types::ledger::AssignmentStatus::Completed { worker_id: None },
                        Some(&output),
                    ),
                )
                .expect("complete the stage so its outcome can be amended");
            }
            // The publication PUBLISHES an already-latched terminal outcome, so its
            // precondition is the latched intent — and latched unarmed, because
            // `finish_terminalization` refuses an execution whose terminalization was
            // never begun and the cell would then prove a refusal rather than a crash
            // window.
            Group::FinishTerminalization => {
                submit(db, fixed_execution());
                db.begin_terminalization(
                    fixed_execution(),
                    LifecycleState::Completed,
                    b"{\"code\":\"closed\",\"message\":\"terminal cell\"}",
                )
                .expect("latch the terminal intent the publication publishes");
            }
            Group::FireSchedule => {
                install_schedule(db);
            }
            Group::DispatchAttempt
            | Group::DynamicChild
            | Group::ClaimMainAttempt
            | Group::ClaimAndResolveMainAttempt
            | Group::ResolveInputWait => {
                submit(db, fixed_execution());
            }
            // The resolution ADVANCES a main attempt, so its precondition is one claimed
            // WAITING, unarmed.
            Group::ResolveMainAttempt => {
                submit(db, fixed_execution());
                claim_main(db);
            }
            // The decision ADVANCES a gated capsule claim, so its precondition is one:
            // a declared capsule and an attempt claimed PARKED at its occurrence.
            Group::DecideCapsuleApproval => {
                submit(db, fixed_execution());
                park_capsule_gate(db);
            }
            // The bound claim additionally needs the lifecycle AUTHORIZED, because the
            // occurrence names work the execution has to be running to be doing.
            Group::ClaimAttempt => {
                submit(db, fixed_execution());
                db.mark_running(fixed_execution())
                    .expect("authorize dispatch before claiming at an occurrence");
            }
            // The placement writer ADVANCES an attempt, so its precondition is a
            // claimed one — and claimed at `pending`, because re-presenting a
            // placement the chain already holds is an idempotent no-op and would
            // make the cell vacuous.
            Group::DispatchClaimedAttempt => {
                submit(db, fixed_execution());
                claim_pending(db, fixed_execution(), fixed_attempt());
                assert_eq!(
                    db.attempt(fixed_attempt()).unwrap().unwrap().lease_epoch,
                    0,
                    "the armed first dispatch must allocate epoch 1"
                );
                db.enroll_worker_domain(
                    "crash-matrix-main",
                    kata_types::identity::WorkerMembraneId(fixed_command()),
                )
                .expect("enroll before arming placement transaction");
            }
            Group::AcceptIncomingEvent => {
                submit(db, fixed_execution());
                dispatch(db, fixed_execution(), fixed_attempt());
            }
        }
    }

    /// The ONE transaction the armed child runs. It must never return when the
    /// fault is armed at a boundary the transaction reaches.
    fn drive(self, db: &Arc<OperationalDb>) {
        match self {
            Group::SubmitExecution => {
                submit(db, fixed_execution());
            }
            Group::InstallSchedule => {
                install_schedule(db);
            }
            Group::FireSchedule => {
                db.fire_schedule(
                    SCHEDULE_ID,
                    FIRE_INSTANT,
                    fixed_execution(),
                    FIRE_INSTANT + 1,
                    None,
                )
                .expect("fire the installed schedule");
            }
            // CLAIMED AT AN OCCURRENCE — and this group is NOT
            // split in two for it, deliberately.
            //
            // `claim_attempt` is ONE writer transaction, and `WRITER_TRANSACTIONS`
            // requires a bijection between writers and cell-claiming groups: a second
            // variant for the bound shape would give one writer two claims, which is the
            // "two writers claim the same cell and only one of them is really driven"
            // failure that test names. So the cell drives the WIDER shape, which strictly
            // contains the narrower one — the bound claim writes the occurrence row, the
            // attempt row, the attempt's binding and the claiming transition, and K1/K2
            // then assert all four are all-or-nothing rather than only the last two.
            //
            // No cell here crashes an UNBOUND claim, and none can: `attempts.occurrence_id`
            // is NOT NULL, so every claim is the bound shape.
            Group::ClaimAttempt => {
                claim_at_occurrence(db, fixed_execution(), fixed_attempt());
            }
            Group::DispatchAttempt => {
                dispatch(db, fixed_execution(), fixed_attempt());
            }
            Group::DispatchClaimedAttempt => {
                let domain = db
                    .worker_effect_domains()
                    .unwrap()
                    .pop()
                    .expect("prepared domain");
                db.dispatch_claimed_attempt_in_domain(
                    fixed_attempt(),
                    "w-1",
                    Ulid::new(),
                    &dispatch_command(),
                    &domain,
                    &db.recovered_attempt(fixed_attempt())
                        .unwrap()
                        .unwrap()
                        .placement_expectation()
                        .unwrap(),
                )
                .expect("dispatch the claimed fixture attempt");
            }
            Group::EnrollWorkerDomain => {
                db.enroll_worker_domain(
                    "crash-matrix-main",
                    kata_types::identity::WorkerMembraneId(fixed_command()),
                )
                .expect("enroll receiver");
            }
            Group::RecordStageMetadata => {
                db.record_undispatched_stage_metadata(
                    fixed_attempt(),
                    kata_core::operational::UndispatchedStageRecord::OutcomeAmended(
                        serde_json::json!({"amended_by": "crash-matrix"}),
                    ),
                )
                .expect("append stage outcome amendment");
            }
            Group::AcceptIncomingEvent => {
                db.accept_incoming_event(
                    fixed_execution(),
                    fixed_attempt(),
                    STREAM_ID,
                    1,
                    ContentHash::new([0xE1; 32]),
                    "completed",
                    b"{}",
                )
                .expect("accept the incoming event");
            }
            Group::DecideCapsuleApproval => {
                let outcome = db
                    .decide_capsule_approval(
                        fixed_attempt(),
                        &kata_core::operational::CapsuleApprovalDecision {
                            principal:
                                &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                            capsule_id: db
                                .occurrence(occurrence_binding_ref().id().0.0)
                                .unwrap()
                                .and_then(|row| row.capsule_id)
                                .expect("the prepared occurrence binds the gate capsule"),
                            verdict: kata_core::operational::ApprovalVerdict::Approve(&|| {
                                Ok(kata_core::operational::ApprovedDispatch {
                                    worker_id: "w-1".to_owned(),
                                    command_id: fixed_command(),
                                    command: dispatch_command(),
                                })
                            }),
                        },
                    )
                    .expect("decide the parked gate");
                // I10 re-runs this after the crash: a committed decision answers
                // `AlreadyApproved`, an uncommitted one records afresh. Both converge.
                assert!(matches!(
                    outcome,
                    kata_core::operational::CapsuleApprovalOutcome::Approved { .. }
                        | kata_core::operational::CapsuleApprovalOutcome::AlreadyApproved
                ));
            }
            Group::DynamicChild => {
                db.dynamic_child(
                    fixed_execution(),
                    fixed_child(),
                    &program(),
                    &invocation(),
                    BOUND_KEY,
                )
                .expect("spawn the dynamic child");
            }
            Group::FinishTerminalization => {
                db.finish_terminalization(fixed_execution())
                    .expect("publish the terminal outcome");
            }
            Group::ClaimMainAttempt => claim_main(db),
            Group::ResolveMainAttempt => {
                db.resolve_main_attempt(
                    fixed_attempt(),
                    MainResolvePremise::ParkedIn(AttemptLifecycle::AwaitingTimer),
                    &MainResolution::Complete {
                        output: &serde_json::json!({"deadline_reached": true}),
                    },
                )
                .expect("resolve the waiting main attempt");
            }
            // Drives `claim_and_resolve_main_attempt_with` — the one writer transaction —
            // through its public wrapper, with the empty precondition.
            Group::ClaimAndResolveMainAttempt => {
                db.claim_and_resolve_main_attempt(
                    fixed_attempt(),
                    &main_spec(),
                    MainOperation::Join,
                    &MainResolution::Complete {
                        output: &serde_json::json!({"joined": []}),
                    },
                )
                .expect("claim and resolve the join");
            }
            Group::ResolveInputWait => {
                db.resolve_input_wait(
                    fixed_attempt(),
                    &main_spec(),
                    &serde_json::json!({"request": "q", "answer": "yes", "source": "operator"}),
                )
                .expect("answer the input wait");
            }
        }
    }

    /// Whether this group's transaction reaches `kill`'s boundary at all.
    ///
    /// A cell whose transaction never executes the armed fault point proves
    /// NOTHING — the child would exit through the "never reached" panic — so the
    /// runner must skip it deliberately and the receipt must name why. This is the
    /// one place that decision is made, so a new group cannot silently inherit a
    /// boundary it does not touch, and a new kill point must state its reach.
    fn reaches(self, kill: Kill) -> bool {
        match kill {
            // K3/K4 sit at `in_writer_txn`, the chokepoint EVERY typed method
            // funnels through, so every group reaches them by construction.
            Kill::BeforeTxnCommit | Kill::AfterTxnCommit => true,
            // K1/K2 are INSIDE `claim_attempt`. `dispatch_attempt` is the other
            // creating transaction for an attempt, not a caller of this one, and
            // `dispatch_claimed_attempt` only ADVANCES a row the fixture already
            // claimed unarmed — so `claim_attempt` is the sole group that arrives.
            //
            // The occurrence seam is reached by the same one group: every claim carries
            // an occurrence binding (`AttemptClaimSpec::occurrence` is required), so the
            // seam fires inside every `claim_attempt`. The arms are merged because
            // clippy refuses two identical bodies, and the merge is honest — the same
            // transaction reaches all three.
            Kill::BeforeClaimCommit
            | Kill::AfterClaimCommit
            | Kill::AfterOccurrenceAuthorizedBeforeDispatch => {
                matches!(self, Group::ClaimAttempt)
            }
        }
    }
}

/// KILL-POINT AXIS. Each variant is one registered `operational.<boundary>` and
/// the invariant subset that applies there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kill {
    /// K1 — the attempt CLAIM's rows are staged inside `claim_attempt`'s own
    /// transaction and it has NOT committed. Distinct from [`Kill::BeforeTxnCommit`]
    /// because the seam is INSIDE the method body, ahead of the generic chokepoint:
    /// it dies with the attempt row and its authorizing transition both written and
    /// neither durable.
    BeforeClaimCommit,
    /// K2 — the claim is fsync-durable and NOTHING has been dispatched for it. The
    /// window the dispatch/promotion/parking gates (which fail CLOSED on an absent
    /// row) and both workspace reapers (which fail SAFE) observe differently, so an
    /// unjustified advance here is the one that either wedges live work or deletes a
    /// live execution's workspace.
    AfterClaimCommit,
    /// The writer transaction is fully staged and has NOT committed.
    BeforeTxnCommit,
    /// The transaction is fsync-durable; nothing downstream of it has run.
    AfterTxnCommit,
    /// The OCCURRENCE-AUTHORIZED window, the crash proof's **dispatch**
    /// family: the occurrence and its attempt are fsync-durable and NO dispatch has
    /// been written for them.
    ///
    /// Distinct from [`Kill::AfterClaimCommit`], which sits one statement earlier and is a
    /// TRANSACTION-family claim ("the nucleus is coherent and nothing was dispatched").
    /// This one is a HANDOFF claim about a fact K2 cannot see: a durable OCCURRENCE with no
    /// dispatch is the state recovery must resolve to exactly one dispatch, never zero and
    /// never two.
    AfterOccurrenceAuthorizedBeforeDispatch,
}

impl Kill {
    fn boundary(self) -> &'static str {
        match self {
            Kill::BeforeClaimCommit => "before_claim_commit",
            Kill::AfterClaimCommit => "after_claim_commit",
            Kill::BeforeTxnCommit => "before_txn_commit",
            Kill::AfterTxnCommit => "after_txn_commit",
            Kill::AfterOccurrenceAuthorizedBeforeDispatch => {
                "after_occurrence_authorized_before_dispatch"
            }
        }
    }

    /// The Rust variant spelling, for the source-text check in
    /// `every_boundary_driven_here_has_a_test`. Exhaustive
    /// on purpose: a new kill point cannot be added without teaching that check to
    /// demand its two `#[test]`s.
    fn variant_name(self) -> &'static str {
        match self {
            Kill::BeforeClaimCommit => "BeforeClaimCommit",
            Kill::AfterClaimCommit => "AfterClaimCommit",
            Kill::BeforeTxnCommit => "BeforeTxnCommit",
            Kill::AfterTxnCommit => "AfterTxnCommit",
            Kill::AfterOccurrenceAuthorizedBeforeDispatch => {
                "AfterOccurrenceAuthorizedBeforeDispatch"
            }
        }
    }

    /// Did the transaction under test COMMIT before the process died?
    ///
    /// This is the axis's LOAD-BEARING claim, and a boundary NAME is not evidence
    /// for it — a fault seam placed one statement off lands on the other side of the
    /// commit and the cell then pins the inverse property while still passing. Every
    /// variant here is counterfactually verified: flipping this function must turn
    /// the corresponding cell RED with an I5 disagreement, which is what proves the
    /// seam really sits where its name says.
    fn transaction_committed(self) -> bool {
        match self {
            Kill::BeforeClaimCommit | Kill::BeforeTxnCommit => false,
            // The occurrence seam fires AFTER `claim_attempt`'s `in_writer_txn`
            // returns — one statement past K2 — so the claim transaction, occurrence row
            // included, is fsync-durable. Verified rather than named: flipping this arm
            // must red the cell with an I5 disagreement, because the recovered data dir
            // really does hold the occurrence.
            Kill::AfterClaimCommit
            | Kill::AfterTxnCommit
            | Kill::AfterOccurrenceAuthorizedBeforeDispatch => true,
        }
    }
}

// -- fixed identities so the parent can address the child's rows --------------

const FIXED_EXECUTION: &str = "01JZZZZZZZZZZZZZZZZZZZZZF1";
const FIXED_CHILD: &str = "01JZZZZZZZZZZZZZZZZZZZZZF2";
const FIXED_ATTEMPT: &str = "01JZZZZZZZZZZZZZZZZZZZZZF3";
const FIXED_COMMAND: &str = "01JZZZZZZZZZZZZZZZZZZZZZF4";
const SCHEDULE_ID: &str = "nightly";
const FIRE_INSTANT: i64 = 1_700_000_000_000;
const STREAM_ID: &[u8] = b"cm-stream-000000000000000";
const BOUND_KEY: &[u8] = b"cm-dynamic-bound";
fn fixed_execution() -> Ulid {
    Ulid::from_string(FIXED_EXECUTION).unwrap()
}
fn fixed_child() -> Ulid {
    Ulid::from_string(FIXED_CHILD).unwrap()
}
fn fixed_attempt() -> Ulid {
    Ulid::from_string(FIXED_ATTEMPT).unwrap()
}
fn fixed_command() -> Ulid {
    Ulid::from_string(FIXED_COMMAND).unwrap()
}

/// A COHERENT program fixture: the pinned bytes carry the `schema_version` /
/// `program_hash` header the schedule pin re-derives from them, so the pin binds
/// its own bytes rather than a caller assertion.
fn program() -> ProgramRecord {
    let program_hash = ContentHash::new([0xF8; 32]);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
            "program": 1,
        })),
    }
}

/// A COHERENT invocation fixture: the admission digest is `blake3` over the
/// canonical bytes it binds, and the bytes carry the `schema_version` / `kind`
/// header an envelope really has.
fn invocation() -> InvocationRecord {
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
        "inputs": [1],
    }));
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

fn submit(db: &OperationalDb, execution_id: Ulid) {
    // The variant is deliberately NOT asserted: I10 re-runs the group's
    // transaction after the crash, and a re-submission of an already-submitted
    // execution is a typed `AlreadySubmitted` — the correct answer, not a failure.
    // What must hold is that the call does not ERROR.
    db.submit_execution(execution_id, &program(), &invocation())
        .expect("submit the fixture execution");
    db.mark_running(execution_id).expect("authorize the run");
}

fn install_schedule(db: &OperationalDb) {
    db.install_schedule(
        &ScheduleInstall {
            schedule_id: SCHEDULE_ID.to_string(),
            submit_pack: "pack".to_string(),
            trigger: "{\"every_ms\":86400000}".to_string(),
            on_missed: MissedFirePolicy::Skip,
            cursor_ms: FIRE_INSTANT,
        },
        &program(),
        &invocation(),
    )
    .expect("install the fixture schedule");
}

/// The binding every occurrence-bearing cell claims at.
///
/// FIXED coordinates, like every other identity in this file, so the PARENT process can
/// address the row the armed CHILD wrote. The path is
/// `OperationPath::canonical_bytes()` by construction — the binding holds an
/// `OccurrenceRef` and derives all five durable coordinates off it — so a cell cannot
/// present an id that disagrees with the columns beside it.
fn occurrence_binding() -> kata_core::operational::OccurrenceBinding {
    kata_core::operational::OccurrenceBinding::new(occurrence_binding_ref(), None, None)
}

/// The occurrence every occurrence-bearing cell names — under the SUBMITTED program's
/// hash, not an arbitrary one: `occurrences` retains `program_hash` as the divergence
/// check the minting verb reads, so a binding that named a different program would be
/// describing work under a repointed execution.
fn occurrence_binding_ref() -> kata_types::execution_contract::OccurrenceRef {
    kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(fixed_execution()),
        ContentHash::new([0xF8; 32]),
        kata_types::execution_contract::OperationContractId(ContentHash::new([0x6C; 32])),
        kata_types::execution_contract::OperationPath(vec![0, 3]),
    )
}

/// The claim that MINTS an occurrence: `pending`, no placement, one binding.
fn claim_at_occurrence(db: &OperationalDb, execution_id: Ulid, attempt_id: Ulid) {
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: "build".to_string(),
            assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: occurrence_binding(),
        },
    )
    .expect("claim the fixture attempt at its occurrence");
}

/// The fixture main attempt's `(executor, wait_deadline_ms, finished_at_ms)`, and whether
/// the fixture occurrence is accepted BY the fixture attempt (`None`: no occurrence) — read
/// through a raw read-only handle, never through the plane under test.
#[allow(clippy::type_complexity)]
fn main_attempt_facts(
    path: &Path,
) -> Result<(Option<(String, Option<i64>, Option<i64>)>, Option<bool>), String> {
    use rusqlite::OptionalExtension as _;
    let raw = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("open raw reader: {error}"))?;
    let row = raw
        .query_row(
            "SELECT executor, wait_deadline_ms, finished_at_ms FROM attempts WHERE attempt_id = ?1",
            [fixed_attempt().to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| format!("read main attempt: {error}"))?;
    let accepted = raw
        .query_row(
            "SELECT accepted_attempt_id IS ?2 FROM occurrences WHERE occurrence_id = ?1",
            rusqlite::params![
                occurrence_binding().occurrence_id().as_slice(),
                fixed_attempt().to_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| format!("read occurrence: {error}"))?;
    Ok((row, accepted))
}

/// The MAIN-RESOLVED claim at the fixture occurrence — a timer wait whose deadline is
/// far enough out that nothing here ever resolves it by accident.
fn main_spec() -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: "build".to_string(),
        occurrence: occurrence_binding(),
    }
}

fn claim_main(db: &OperationalDb) {
    db.claim_main_attempt(
        fixed_attempt(),
        &main_spec(),
        MainWait::Timer(WaitDeadline::AfterClaim {
            delay_ms: 3_600_000,
        }),
    )
    .expect("claim the fixture main attempt");
}

/// The claim shape the DISPATCH side uses at admission: `pending`, no placement.
///
/// The precondition for `dispatch_claimed_attempt`'s cell. Claiming at `dispatched`
/// instead would make the placement an idempotent no-op and the cell vacuous.
fn claim_pending(db: &OperationalDb, execution_id: Ulid, attempt_id: Ulid) {
    db.claim_attempt(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: "build".to_string(),
            assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: OccurrenceBinding::for_test(execution_id, "build"),
        },
    )
    .expect("claim the fixture attempt at pending");
}

/// The capsule the approval cell's gate binds. Its body is arbitrary; only its id reaches
/// the plane (the `capsules` row and the occurrence's binding).
fn gate_capsule(
    work: kata_types::execution_contract::ArtifactId,
) -> kata_types::execution_contract::Capsule {
    use kata_types::execution_contract::{
        Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess, EnvironmentId, GuestAccess,
        GuestMapping, GuestPath, PlatformId, PreparedActionId,
    };
    Capsule::new(
        occurrence_binding_ref().id(),
        PreparedActionId(ContentHash::new([0x02; 32])),
        EnvironmentId(ContentHash::new(GATE_ENVIRONMENT)),
        PlatformId(ContentHash::new([0x04; 32])),
        vec![GuestMapping {
            artifact: work,
            guest_path: GuestPath::new("/work").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 1 << 20,
            result_entries: 16,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap()
}

const GATE_ENVIRONMENT: [u8; 32] = [0x5A; 32];
/// The gate capsule's `/work` bytes.
const GATE_WORK_TREE: &[u8] = b"crash-matrix-gate-work-tree";

/// The unarmed precondition of [`Group::DecideCapsuleApproval`]: the gate's environment
/// and capsule DECLARED (the occurrence's `capsule_id` is a foreign key into `capsules`),
/// then the attempt claimed PARKED at its occurrence on the capsule arm.
///
/// The declarations need `DurableObject` receipts, which only a `CasStore` mints, so a
/// store is opened beside the nucleus's own file. The cell's transaction reads no byte
/// of either object — it reads the `capsules` row through the occurrence's foreign key.
fn park_capsule_gate(db: &OperationalDb) {
    let dir = db
        .path()
        .and_then(Path::parent)
        .expect("the crash matrix's nucleus is file-backed");
    let cas = kata_core::store::cas::CasStore::open(dir.join("cas.db"), dir.join("cas")).unwrap();
    let manifest = cas.put_durable(b"crash-matrix-gate-environment").unwrap();
    db.declare_environment(
        &kata_core::operational::EnvironmentDeclaration::for_staged_root(
            GATE_ENVIRONMENT,
            &manifest,
            [0x5C; 32],
            "crash-matrix-gate",
            [0x04; 32],
            "01JZZZZZZZZZZZZZZZZZZZZZE1",
        )
        .unwrap(),
    )
    .unwrap();
    let work = cas.put_durable(GATE_WORK_TREE).unwrap();
    let work_ref = kata_types::execution_contract::ArtifactRef::new(
        work.object_id(),
        work.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    );
    db.declare_artifact(
        &kata_core::operational::ArtifactDeclaration::for_durable_object(
            &work_ref,
            kata_core::operational::CasRootOwner::Execution(fixed_execution()),
            &work,
        )
        .unwrap(),
    )
    .unwrap();
    let capsule = gate_capsule(work_ref.id());
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = cas.put_durable(&bytes).unwrap();
    db.declare_capsule(
        &kata_core::CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap(),
    )
    .unwrap();
    db.claim_attempt_parked_for_approval(
        fixed_execution(),
        fixed_attempt(),
        &AttemptClaimSpec {
            stage_id: "build".to_string(),
            assignment_json: GATE_FRAME.to_vec(),
            initial_state: "awaiting_approval".to_string(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: kata_core::operational::OccurrenceBinding::new(
                occurrence_binding_ref(),
                Some(capsule.action()),
                Some(capsule.id()),
            ),
        },
        "crash-matrix gate",
    )
    .expect("park the gated claim");
}

/// A capsule-arm at-rest frame, spelled by hand (`kata-core` cannot see `DispatchFrame`).
const GATE_FRAME: &[u8] = br#"{"capsule":{"attempt_id":"01JZZZZZZZZZZZZZZZZZZZZZF3",
    "occurrence_id":"0101010101010101010101010101010101010101010101010101010101010101",
    "capsule":{"id":"0202020202020202020202020202020202020202020202020202020202020202",
    "object":"0303030303030303030303030303030303030303030303030303030303030303",
    "size_bytes":512},"lease_epoch":0}}"#;

/// The dispatch command every cell below issues.
///
/// Opaque to the operational plane: the cells assert that the command and the
/// transition that authorizes it are one atomic unit, not what it says.
fn dispatch_command() -> CommandSpec {
    CommandSpec {
        command_json: b"{\"cmd\":1}".to_vec(),
    }
}

fn dispatch(db: &OperationalDb, execution_id: Ulid, attempt_id: Ulid) {
    db.dispatch_attempt(
        execution_id,
        attempt_id,
        fixed_command(),
        &AttemptClaimSpec {
            stage_id: "build".to_string(),
            initial_state: "pending".to_string(),
            assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(execution_id, "build"),
        },
        &dispatch_command(),
    )
    .expect("dispatch the fixture attempt");
}

// -- the invariant battery ----------------------------------------------------

/// Assert every invariant the crash proof lists that APPLIES at `kill`, on a
/// data dir re-opened after the child aborted.
///
/// Returns `Err(reason)` rather than panicking so the runner can report the whole
/// matrix in one failure instead of stopping at the first bad cell.
#[allow(clippy::too_many_lines)]
fn verify_cell(path: &Path, fixture: Fixture, group: Group, kill: Kill) -> Result<(), String> {
    let db = Arc::new(OperationalDb::open(path).map_err(|error| {
        format!("I0 the nucleus must re-open after an abort, but open failed: {error}")
    })?);

    // I0 — the re-opened dir carries THIS binary's stamp, because the product open
    // path is the only way a database can reach a current shape at all: an
    // assertion that the stamp is current is what turns "the open succeeded" into
    // "the open succeeded on the shape this file's cells were written against".
    let stamped = db
        .debug_user_version()
        .map_err(|error| format!("I0 read stamped version: {error}"))?;
    if stamped != kata_core::OPERATIONAL_SCHEMA_VERSION {
        return Err(format!(
            "I0 {fixture:?} must be at the current schema stamp after recovery, found {stamped}"
        ));
    }

    // I1 — NO UNJUSTIFIED STATE ADVANCE. Every projection row's authorizing
    // transition is present and its `source_seq` resolves. Both are structural
    // here: the projection is a pure fold of the retained chain and `source_seq`
    // is a foreign key into it, so an unjustified row cannot be committed. The
    // check re-derives the fold rather than trusting the stored row.
    //
    // I2 — the PROJECTION EQUALS A PURE FOLD of the retained chain, three ways
    // (lifecycle == projection == rebuild).
    //
    // I3 — a mismatch REFUSES rather than self-repairing: this is the same call
    // boot makes, and it returns `Err` rather than quietly reconciling.
    for execution_id in [fixed_execution(), fixed_child()] {
        db.verify_projection_integrity(execution_id)
            .map_err(|error| {
                format!("I1/I2/I3 projection is not a pure fold of the retained chain: {error}")
            })?;
        if let Some(found) = db
            .classify_nucleus_mismatch(execution_id)
            .map_err(|error| format!("I3 classify: {error}"))?
        {
            return Err(format!("I3 unexpected {:?} mismatch", found.class));
        }
    }

    // I4 — WATERMARK CONTIGUITY: `applied_through_seq == transition_sequence.value
    // == max(transitions.seq)`. The clause that distinguishes this plane from the
    // ledger — an aborted transaction reverts its reservation, so there is no
    // hole, and a surviving hole would be a dangling foreign key rather than a
    // tolerated gap.
    if !db
        .verify_global_watermark()
        .map_err(|error| format!("I4 watermark: {error}"))?
    {
        return Err("I4 the global watermark disagrees with the chain head".to_string());
    }

    // I5 — the transaction is ALL-OR-NOTHING at this boundary. Before the commit
    // point, none of its facts survive; after it, all of them do. Asserted per
    // group so "no unjustified advance" is a claim about THIS transaction's facts
    // rather than a global smell test.
    let committed = kill.transaction_committed();
    let observed = group_committed(&db, path, group).map_err(|error| format!("I5 {error}"))?;
    if observed != committed {
        return Err(format!(
            "I5 {group:?} at {kill:?}: expected the transaction's facts to be {} but found them \
             {}",
            if committed { "PRESENT" } else { "ABSENT" },
            if observed { "PRESENT" } else { "ABSENT" }
        ));
    }

    // I6 — BOTH-OR-NEITHER for the attempt-creating transactions.
    //
    // A global equality `attempts == commands` holds only when `dispatch_attempt` is
    // the sole creator of an attempt row, and it is not: `claim_attempt`'s own
    // contract is "No command". The global form would pin a legal, documented state
    // as a defect, so the teeth are kept per group below.
    let attempts = db
        .debug_count("attempts")
        .map_err(|error| format!("I6 count attempts: {error}"))?;
    let commands = db
        .debug_count("attempt_commands")
        .map_err(|error| format!("I6 count commands: {error}"))?;
    if commands > attempts {
        return Err(format!(
            "I6 a dispatch command outlived its attempt: {commands} commands over {attempts} \
             attempts. The foreign key makes this unrepresentable; seeing it means the FK is \
             not armed on the recovered file"
        ));
    }
    match group {
        Group::EnrollWorkerDomain | Group::RecordStageMetadata => {
            // Independent SQL observation of the crash child's committed bytes,
            // not merely the same API that emitted them reporting success.
            let raw = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
            let present: i64 = if group == Group::EnrollWorkerDomain {
                raw.query_row("SELECT count(*) FROM worker_effect_domains WHERE source_main = 'crash-matrix-main' AND membrane_id = ?1 AND length(enrollment_id) = 16", [fixed_command().to_bytes().as_slice()], |row| row.get(0)).map_err(|e| e.to_string())?
            } else {
                raw.query_row("SELECT count(*) FROM transitions WHERE kind = 'undispatched_stage_recorded' AND json_extract(CAST(payload_json AS TEXT), '$.assignment_id') = ?1 AND json_extract(CAST(payload_json AS TEXT), '$.record.kind') = 'outcome_amended' AND json_extract(CAST(payload_json AS TEXT), '$.record.value.output.amended_by') = 'crash-matrix'", [fixed_attempt().to_string()], |row| row.get(0)).map_err(|e| e.to_string())?
            };
            if present != i64::from(kill.transaction_committed()) {
                return Err(format!(
                    "I6 {group:?} raw committed payload count {present} disagrees with {kill:?}"
                ));
            }
        }
        Group::DispatchClaimedAttempt => {
            let raw = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
            let bindings: i64 = raw.query_row("SELECT count(*) FROM worker_dispatch_domains b JOIN worker_effect_domains d ON b.enrollment_id = d.enrollment_id WHERE d.source_main = 'crash-matrix-main' AND b.worker_label = 'w-1' AND b.attempt_id = ?1 AND d.membrane_id = ?2 AND b.lease_epoch = 1", rusqlite::params![fixed_attempt().to_bytes().as_slice(), fixed_command().to_bytes().as_slice()], |row| row.get(0)).map_err(|e| e.to_string())?;
            let expected = i64::from(kill.transaction_committed());
            if bindings != expected || commands != expected {
                return Err(format!(
                    "I6 receiver binding and dispatch command must each match commit boundary: expected {expected}, found {bindings} bindings, {commands} commands"
                ));
            }
        }
        // A MAIN-RESOLVED attempt never acquires a command or a lease epoch, at
        // EITHER side of any commit. Read raw.
        Group::ClaimMainAttempt
        | Group::ResolveMainAttempt
        | Group::ClaimAndResolveMainAttempt
        | Group::ResolveInputWait => {
            let raw = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
            let leased: i64 = raw
                .query_row(
                    "SELECT COUNT(*) FROM attempts WHERE lease_epoch != 0",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if commands != 0 || leased != 0 {
                return Err(format!(
                    "I6 {group:?} at {kill:?}: a main attempt acquired {commands} commands \
                     and {leased} leased rows"
                ));
            }
        }
        // The APPROVAL DOOR: the decision and the dispatch it authorizes are one commit,
        // so the decision record, the `dispatched` transition and the command are all
        // present or all absent — read through a second raw handle.
        Group::DecideCapsuleApproval => {
            let raw = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
            let count = |sql: &str| -> Result<i64, String> {
                raw.query_row(sql, [], |row| row.get(0))
                    .map_err(|e| e.to_string())
            };
            let decisions =
                count("SELECT count(*) FROM transitions WHERE kind = 'approval_decided'")?;
            let dispatched = count("SELECT count(*) FROM transitions WHERE kind = 'dispatched'")?;
            let expected = i64::from(kill.transaction_committed());
            if decisions != expected || dispatched != expected || commands != expected {
                return Err(format!(
                    "I6 an approval and the dispatch it authorizes are one commit: expected \
                     {expected} of each, found {decisions} decisions, {dispatched} dispatched \
                     transitions, {commands} commands"
                ));
            }
        }
        // The DISPATCH transaction writes the attempt and its command in one
        // commit — the I6 claim in its plain form.
        Group::DispatchAttempt if attempts != commands => {
            return Err(format!(
                "I6 dispatch must be both-or-neither: {attempts} attempts, {commands} commands"
            ));
        }
        // The CLAIM transaction's own both-or-neither: the attempt row and the
        // transition that AUTHORIZES it, with no command.
        Group::ClaimAttempt => {
            let authorized = db
                .debug_transition_kinds(fixed_execution())
                .map_err(|error| format!("I6 read chain: {error}"))?
                .iter()
                .any(|(_, kind)| kind == "claimed");
            if (attempts > 0) != authorized {
                return Err(format!(
                    "I6 claim must be both-or-neither: {attempts} attempt row(s) but the \
                     authorizing `claimed` transition is {}. An attempt with no authorizing \
                     transition is a lifecycle record no chain justifies",
                    if authorized { "PRESENT" } else { "ABSENT" }
                ));
            }
            if commands != 0 {
                return Err(format!(
                    "I6 a claim must write NO command (its own contract), found {commands} \
                     commands"
                ));
            }
        }
        _ => {}
    }

    // I9 — SCHEDULE: neither a LOST fire nor a DUPLICATE fire (no half-commit). The firing
    // claim and the cursor advance are one transaction, so after the kill they either both
    // happened or neither did.
    if matches!(group, Group::FireSchedule) {
        let firings = db
            .schedule_firings(SCHEDULE_ID)
            .map_err(|error| format!("I9 read firings: {error}"))?;
        let cursor = db
            .debug_schedule_cursor_ms(SCHEDULE_ID)
            .map_err(|error| format!("I9 read cursor: {error}"))?;
        let claimed = !firings.is_empty();
        let advanced = cursor.is_some_and(|value| value > FIRE_INSTANT);
        if claimed != advanced {
            return Err(format!(
                "I9 half-commit: firing claimed = {claimed}, cursor advanced = {advanced}. A \
                 claimed fire with an unmoved cursor DUPLICATES on the next sweep; an advanced \
                 cursor with no claim LOSES the fire"
            ));
        }
        if firings.len() > 1 {
            return Err(format!("I9 duplicate fire: {} claims", firings.len()));
        }
    }

    // I10 — RECOVERY IS CONVERGENT. Re-running the group's transaction after the
    // crash reaches a coherent nucleus exactly once: either it commits now (the
    // pre-commit kill) or it is an idempotent no-op / typed refusal (the
    // post-commit kill). Nothing is asserted about WHICH, because both are correct
    // at their own boundary; what must hold is that the nucleus stays coherent.
    // RecordStageMetadata has no caller-supplied idempotency key: another call
    // is another audit append, not a claim of retry deduplication. Its overlay
    // converges, and the retained history must not shrink.
    let before = db
        .debug_count_for_execution("transitions", fixed_execution())
        .map_err(|error| format!("I10 count chain: {error}"))?;
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| group.drive(&db)));
    let after = db
        .debug_count_for_execution("transitions", fixed_execution())
        .map_err(|error| format!("I10 recount chain: {error}"))?;
    if after < before {
        return Err(format!(
            "I10 the retry SHRANK the retained chain ({before} -> {after}); the accepted \
             transition chain is retained until the execution's declared history-deletion \
             boundary"
        ));
    }
    for execution_id in [fixed_execution(), fixed_child()] {
        db.verify_projection_integrity(execution_id)
            .map_err(|error| format!("I10 nucleus incoherent after the retry: {error}"))?;
    }
    if !db
        .verify_global_watermark()
        .map_err(|error| format!("I10 watermark: {error}"))?
    {
        return Err("I10 the watermark broke on the retry".to_string());
    }

    // I11 — FORWARD-VERSION REFUSAL BEFORE MUTATION, on the recovered file. The
    // refusal is read from the header by plain file I/O and must not open the
    // driver, so it holds on a database with a hot WAL — which is exactly what an
    // aborted process leaves behind.
    db.debug_stamp_user_version(kata_core::OPERATIONAL_SCHEMA_VERSION + 1)
        .map_err(|error| format!("I11 stamp forward: {error}"))?;
    drop(db);
    let refused = OperationalDb::open(path);
    if refused.is_ok() {
        return Err(
            "I11 a forward-stamped nucleus must be refused BEFORE any mutation, including on the \
             hot-WAL file an abort leaves behind"
                .to_string(),
        );
    }
    Ok(())
}

/// Whether the group's own facts are present.
fn group_committed(db: &OperationalDb, path: &Path, group: Group) -> Result<bool, String> {
    let count = |table: &str| {
        db.debug_count(table)
            .map_err(|error| format!("count {table}: {error}"))
    };
    Ok(match group {
        // The fixture already submitted for most groups, so submission presence is
        // read from the CHILD's execution rather than a global count.
        Group::SubmitExecution => db
            .execution_lifecycle(fixed_execution())
            .map_err(|error| format!("read lifecycle: {error}"))?
            .is_some(),
        Group::InstallSchedule => db
            .installed_schedule(SCHEDULE_ID)
            .map_err(|error| format!("read schedule: {error}"))?
            .is_some(),
        Group::FireSchedule => !db
            .schedule_firings(SCHEDULE_ID)
            .map_err(|error| format!("read firings: {error}"))?
            .is_empty(),
        Group::DispatchAttempt => count("attempts")? > 0,
        // BOTH HALVES, and the conjunction is the point: the claim writes the attempt row
        // and the occurrence row in one transaction, so a recovered data dir holding one
        // without the other is exactly the partial state K1/K2 exist to refuse, and a
        // predicate that read only `attempts` could not see it. The occurrence is read
        // through the production accessor, so this also proves the row is findable by the
        // coordinates a caller holds rather than only that a row exists.
        Group::ClaimAttempt => {
            count("attempts")? > 0
                && db
                    .occurrence(occurrence_binding().occurrence_id())
                    .map_err(|error| format!("read occurrence: {error}"))?
                    .is_some_and(|row| {
                        row.execution_id == fixed_execution()
                            && row.accepted.is_none()
                            && row.operation_path == occurrence_binding().operation_path()
                    })
        }
        // The attempt row already exists (the fixture claimed it at `pending`), so
        // the fact THIS transaction contributes is the folded `dispatched` state.
        Group::DispatchClaimedAttempt => db
            .attempt_projection_for(fixed_attempt())
            .map_err(|error| format!("read attempt projection: {error}"))?
            .is_some_and(|row| row.state == "dispatched"),
        Group::AcceptIncomingEvent => count("event_inbox")? > 0,
        Group::DecideCapsuleApproval => db
            .debug_transition_kinds(fixed_execution())
            .map_err(|error| format!("read chain: {error}"))?
            .iter()
            .any(|(_, kind)| kind == "approval_decided"),
        Group::DynamicChild => db
            .execution_lifecycle(fixed_child())
            .map_err(|error| format!("read child lifecycle: {error}"))?
            .is_some(),
        // The fixture already latched the terminal INTENT, so the fact THIS
        // transaction contributes is the PUBLISHED state.
        Group::FinishTerminalization => db
            .execution_lifecycle(fixed_execution())
            .map_err(|error| format!("read lifecycle: {error}"))?
            .is_some_and(|row| row.state.is_terminal()),
        Group::EnrollWorkerDomain => !db
            .worker_effect_domains()
            .map_err(|e| e.to_string())?
            .is_empty(),
        Group::RecordStageMetadata => !db
            .undispatched_stage_metadata(fixed_execution())
            .map_err(|e| e.to_string())?
            .is_empty(),
        // The CLAIM's facts: the main row with its deadline AND its unaccepted occurrence.
        // The main-resolved groups read their facts through a raw read-only handle rather
        // than the plane under test.
        Group::ClaimMainAttempt => {
            let (main_row, open_occurrence) = main_attempt_facts(path)?;
            main_row.is_some_and(|(executor, deadline, _)| executor == "main" && deadline.is_some())
                && open_occurrence == Some(false)
        }
        // The RESOLUTION's facts: the occurrence accepted by the fixture attempt, and the
        // deadline the resolution clears.
        Group::ResolveMainAttempt | Group::ClaimAndResolveMainAttempt | Group::ResolveInputWait => {
            let (main_row, accepted_by_fixture) = main_attempt_facts(path)?;
            let accepted = accepted_by_fixture == Some(true);
            let cleared = main_row
                .as_ref()
                .is_some_and(|(_, deadline, finished)| deadline.is_none() && finished.is_some());
            // The one-transaction CLAIM AND RESOLVE has no instant with the attempt claimed
            // and unresolved, so the row existing without the acceptance is a torn pair.
            let claimed = main_row.is_some();
            if matches!(
                group,
                Group::ClaimAndResolveMainAttempt | Group::ResolveInputWait
            ) && claimed != accepted
            {
                return Err(format!(
                    "{group:?}: the attempt row ({claimed}) and its acceptance ({accepted}) are \
                     one transaction's facts and disagree"
                ));
            }
            if accepted != cleared {
                return Err(format!(
                    "{group:?}: the acceptance ({accepted}) and the row's resolution ({cleared}) \
                     are one transaction's facts and disagree"
                ));
            }
            accepted
        }
    })
}

// -- the child role -----------------------------------------------------------

#[test]
fn bound_dispatch_crash_oracle_refuses_a_placement_with_both_companions_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    Fixture::NewEmpty.build(&path);
    let db = Arc::new(OperationalDb::open(&path).unwrap());
    Group::DispatchClaimedAttempt.prepare(&db);
    Group::DispatchClaimedAttempt.drive(&db);
    drop(db);
    // A deliberately counterfeit post-commit database: preserve the placement
    // and its transition, but remove BOTH companions so count equality is vacuous.
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("DELETE FROM worker_dispatch_domains; DELETE FROM attempt_commands;")
        .unwrap();
    drop(raw);
    assert!(
        verify_cell(
            &path,
            Fixture::NewEmpty,
            Group::DispatchClaimedAttempt,
            Kill::AfterTxnCommit
        )
        .is_err(),
        "a dispatched state with zero commands AND zero bindings is not a committed dispatch"
    );
}

const CHILD_MARKER: &str = "KATA_CRASH_MATRIX_CHILD";
const CHILD_DIR: &str = "KATA_CRASH_MATRIX_DIR";
const CHILD_GROUP: &str = "KATA_CRASH_MATRIX_GROUP";
const CHILD_FIXTURE: &str = "KATA_CRASH_MATRIX_FIXTURE";

/// If this process is an armed child, run the one transaction and never return.
fn run_as_child_if_marked() -> bool {
    if std::env::var(CHILD_MARKER).is_err() {
        return false;
    }
    let dir = PathBuf::from(std::env::var(CHILD_DIR).expect("the child must be told where"));
    let group = Group::parse(&std::env::var(CHILD_GROUP).expect("the child must be told which"));
    let fixture = Fixture::parse(
        &std::env::var(CHILD_FIXTURE).expect("the child must be told the direction"),
    );
    let db = Arc::new(
        OperationalDb::open(dir.join("operational.db")).expect("the child must adopt the fixture"),
    );

    group.drive(&db);
    panic!(
        "the armed fault point was never reached for {}/{} — the cell proves nothing",
        fixture.as_str(),
        group.as_str()
    );
}

// -- the runner ---------------------------------------------------------------

/// Run one row of the matrix: every group, in one fixture direction, killed at one
/// boundary. Reports EVERY failing cell rather than stopping at the first.
fn run_matrix(test_name: &str, fixture: Fixture, kill: Kill) {
    assert!(
        operational_boundary_registered(kill.boundary()),
        "kill point {kill:?} names an unregistered boundary {}; register it in \
         OPERATIONAL_CRASH_BOUNDARIES so the axis stays enumerable",
        kill.boundary()
    );

    let mut failures = String::new();
    let mut cells = 0_usize;
    for group in Group::iter() {
        if !group.reaches(kill) {
            // NOT silently truncated: the receipt must name a cell that does not
            // run, and this one does not run because the boundary is UNREACHABLE
            // for this group — see `Group::reaches` for the per-boundary reason —
            // not because it was skipped.
            continue;
        }
        cells += 1;
        if let Err(reason) = run_cell(test_name, fixture, group, kill) {
            let _ = writeln!(
                failures,
                "  [{}] {} @ {}: {reason}",
                fixture.as_str(),
                group.as_str(),
                kill.boundary()
            );
        }
    }
    assert!(cells > 0, "a matrix row with no cells proves nothing");
    assert!(
        failures.is_empty(),
        "{cells} cells run in the [{}] direction at {}; failures:\n{failures}",
        fixture.as_str(),
        kill.boundary()
    );
}

/// One cell: build the fixture unarmed, crash the armed child in it, verify.
fn run_cell(test_name: &str, fixture: Fixture, group: Group, kill: Kill) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|error| format!("tempdir: {error}"))?;
    let path = dir.path().join("operational.db");

    // Phase 1 — build the fixture UNARMED, in this process.
    fixture.build(&path);
    {
        let db = Arc::new(
            OperationalDb::open(&path)
                .map_err(|error| format!("open the fixture nucleus: {error}"))?,
        );
        group.prepare(&db);
    }

    // Phase 2 — the ARMED child runs only the group's transaction and aborts.
    let output = Command::new(std::env::current_exe().map_err(|error| format!("exe: {error}"))?)
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir.path())
        .env(CHILD_GROUP, group.as_str())
        .env(CHILD_FIXTURE, fixture.as_str())
        .env(
            "KATA_FAULT_INJECT",
            format!("operational.{}", kill.boundary()),
        )
        .output()
        .map_err(|error| format!("spawn the crash child: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if output.status.success() {
        return Err(format!(
            "the child exited CLEANLY; it must abort at the boundary.\nstdout:\n{}\nstderr:\n\
             {stderr}",
            String::from_utf8_lossy(&output.stdout)
        ));
    }
    let marker = format!("crash point reached: operational.{}", kill.boundary());
    if !stderr.contains(&marker) {
        return Err(format!(
            "the child must die AT the boundary, not incidentally.\nstderr:\n{stderr}"
        ));
    }

    // Phase 3 — recovery, from the file the abort left behind.
    verify_cell(&path, fixture, group, kill)
}

// -- the cells ----------------------------------------------------------------
//
// One `#[test]` per (fixture direction x kill point); each iterates every
// transaction group. Adding a GROUP touches only `Group`; adding a KILL POINT adds
// one `#[test]` here plus one production call site.

// K1/K2 — the attempt CLAIM's own transaction edges.
//
// These two boundaries were REGISTERED and called from production
// (`OperationalDb::claim_attempt`) with ZERO cells arming them in either fixture
// direction; the accounting test below stayed green only because its `elsewhere`
// list named `operational_inbox_composition / claim atomicity` as their home, and
// that file arms `before_accept_event` / `after_accept_event` and nothing else.
// A coverage claim that no cell backs is the same defect as a silently truncated
// matrix, so the claim is deleted and the cells are here.

#[test]
fn operational_crash_cell_new_empty_before_claim_commit() {
    if run_as_child_if_marked() {
        return;
    }
    run_matrix(
        "operational_crash_cell_new_empty_before_claim_commit",
        Fixture::NewEmpty,
        Kill::BeforeClaimCommit,
    );
}

#[test]
fn operational_crash_cell_new_empty_after_claim_commit() {
    if run_as_child_if_marked() {
        return;
    }
    run_matrix(
        "operational_crash_cell_new_empty_after_claim_commit",
        Fixture::NewEmpty,
        Kill::AfterClaimCommit,
    );
}

#[test]
fn operational_crash_cell_new_empty_before_txn_commit() {
    if run_as_child_if_marked() {
        return;
    }
    run_matrix(
        "operational_crash_cell_new_empty_before_txn_commit",
        Fixture::NewEmpty,
        Kill::BeforeTxnCommit,
    );
}

#[test]
fn operational_crash_cell_new_empty_after_txn_commit() {
    if run_as_child_if_marked() {
        return;
    }
    run_matrix(
        "operational_crash_cell_new_empty_after_txn_commit",
        Fixture::NewEmpty,
        Kill::AfterTxnCommit,
    );
}

// The OCCURRENCE-AUTHORIZED window.
//
// The occurrence is the first durable fact in this plane that names LOGICAL work
// rather than a generation of it, and the handoff between authorizing it and
// dispatching it is the window where "exactly one dispatch per occurrence" can be
// lost or doubled. Its cell drives `Group::ClaimAttempt`, which is the only
// transaction that reaches the seam at all.

#[test]
fn operational_crash_cell_new_empty_occurrence_authorized_before_dispatch() {
    if run_as_child_if_marked() {
        return;
    }
    run_matrix(
        "operational_crash_cell_new_empty_occurrence_authorized_before_dispatch",
        Fixture::NewEmpty,
        Kill::AfterOccurrenceAuthorizedBeforeDispatch,
    );
}

// -- the axes are ENUMERABLE, and the receipt must name what does not run ------

/// The set of boundaries this FILE drives with its own cells.
///
/// Derived from [`Kill`] rather than restated as literals, so the driven set and the
/// kill-point axis cannot disagree.
const DRIVEN_HERE: &[Kill] = &[
    Kill::AfterOccurrenceAuthorizedBeforeDispatch,
    Kill::BeforeClaimCommit,
    Kill::AfterClaimCommit,
    Kill::BeforeTxnCommit,
    Kill::AfterTxnCommit,
];

/// A boundary whose cells live in another file, the file that owns them, and **that
/// file's own source text**.
///
/// # There is no `directions` column
///
/// With the fixture axis at one direction (see [`Fixture`]), a `directions` set
/// compared against `Fixture::ALL` could only ever be satisfied, and a check that
/// refuses nothing while looking like it refuses something is worse than no check.
struct Elsewhere {
    boundary: &'static str,
    home: &'static str,
    /// The home file's SOURCE, included at compile time.
    ///
    /// This is the column that turns a coverage CLAIM into a coverage CHECK. The
    /// defect it closes: a boundary listed as covered by a file that arms other
    /// boundaries and nothing else. A prose `(boundary, home)` pair asserts only
    /// that someone typed a file name.
    ///
    /// Re-deriving from an INDEPENDENT source — the home's actual bytes — is what
    /// makes the claim falsifiable. It is a coarse check and that is stated rather
    /// than oversold: a mention is not a cell, and it cannot tell one from a
    /// comment. It CAN tell a home that arms the boundary from one that has never
    /// heard of it.
    source: &'static str,
}

/// Covered by cells in the files that own the machinery each boundary brackets.
/// Listing them here rather than re-running them keeps one home per property.
const ELSEWHERE: &[Elsewhere] = &[
    Elsewhere {
        boundary: "before_accept_event",
        home: "operational_inbox_composition K6",
        source: include_str!("operational_inbox_composition.rs"),
    },
    Elsewhere {
        boundary: "after_accept_event",
        home: "operational_inbox_composition K7",
        source: include_str!("operational_inbox_composition.rs"),
    },
    // K8 fires inside `CasStore::put_durable`, so its cell needs BOTH a `CasStore`
    // and an `OperationalDb` — the join `cas_root_liveness.rs` already owns.
    // Driving it from this file would mean widening `Group::drive`'s signature for
    // every arm to serve one boundary that is not an operational transaction group.
    Elsewhere {
        boundary: "after_cas_object_durable_before_root",
        home: "cas_root_liveness K8",
        source: include_str!("cas_root_liveness.rs"),
    },
    // K14/K15 bracket a DECLARED NIX ENVIRONMENT, and both cells need a `CasStore`
    // beside the nucleus for K8's reason, restated because it is the same one:
    // `EnvironmentDeclaration::for_staged_root` takes a `DurableObject`, which only
    // `CasStore::put_durable` mints, so the declaring transaction is unreachable from
    // `Group::drive`'s `&Arc<OperationalDb>` signature. Widening that signature for
    // every arm to serve two boundaries that are not operational transaction groups is
    // the trade this table exists to avoid.
    //
    // `cas_root_liveness.rs` is the home rather than a new file because K14's whole
    // subject is the CAS/operational join: the window it brackets is "manifest bytes
    // written, no root row", which is K8's window with an environment row added, and
    // the GC-does-not-reclaim assertion that pairs with it reads the CAS store
    // directly there already.
    Elsewhere {
        boundary: "after_nix_root_staged_before_manifest_durable",
        home: "cas_root_liveness K14",
        source: include_str!("cas_root_liveness.rs"),
    },
    Elsewhere {
        boundary: "after_environment_row_committed_before_root_promoted",
        home: "cas_root_liveness K15",
        source: include_str!("cas_root_liveness.rs"),
    },
    // K16 brackets an isolated execution's committed-base `/work` HEAD: the base
    // tree's members, manifest, `artifacts` row and owner `cas_roots` row are all
    // durable, and the `execution_work_tree_heads` row is not yet written. Its
    // producer `publish_base_tree_head` needs a `CasStore` beside the nucleus —
    // K8's reason verbatim — so the cell lives in `cas_root_liveness.rs`, which
    // already joins the two planes. Recovery is re-admission, which the cell
    // proves by re-driving the publish and asserting convergence.
    Elsewhere {
        boundary: "after_base_tree_published_before_head_recorded",
        home: "cas_root_liveness K16",
        source: include_str!("cas_root_liveness.rs"),
    },
    // The NON-ISOLATED twin of K16: the seeded scratch tree's members,
    // manifest and owner root are durable and the root (`branch = ''`) head
    // row is not yet written. `publish_scratch_tree_head` needs a `CasStore`
    // and a scratch directory — the same K8 reason — so the cell lives beside
    // K16's in `cas_root_liveness.rs`.
    Elsewhere {
        boundary: "after_scratch_seed_published_before_head_recorded",
        home: "cas_root_liveness K16b",
        source: include_str!("cas_root_liveness.rs"),
    },
    // K16's shape one table over: the git-history
    // artifact's members, manifest, `artifacts` row and owner `cas_roots` row
    // are durable, and the `execution_git_views` row is not yet written.
    // `publish_execution_git_view` needs a `CasStore` beside the nucleus —
    // K8's reason verbatim — so the cell lives beside K16's in
    // `cas_root_liveness.rs`. Recovery is the same re-admission: the producer
    // re-walks the same base commit, CAS dedup makes the republish
    // content-identical, and `record_execution_git_view` converges or refuses
    // a divergent restatement (`git_view_divergent`).
    Elsewhere {
        boundary: "after_git_view_published_before_recorded",
        home: "cas_root_liveness K17",
        source: include_str!("cas_root_liveness.rs"),
    },
    // The PRE-ACCEPTANCE edge of an isolated submission: its target is resolved
    // and pinned in the repository's git store (`refs/kata/targets/<id>/…`) and
    // nothing is accepted. Its residue is git refs, not operational rows, and
    // its producer is the executor's submit path over a real jj provider —
    // which `Group::drive`'s `&Arc<OperationalDb>` signature cannot reach — so
    // the armed-child cell lives beside the executor's other admission cells.
    // Recovery is the boot sweep, which the cell drives with the production
    // keep predicate.
    Elsewhere {
        boundary: "after_target_pinned_before_acceptance",
        home: "kata_api::oci_repository_census (armed submit child, boot-sweep recovery)",
        source: include_str!("../../api/tests/oci_repository_census.rs"),
    },
    // The RESULT-PUBLICATION edge, worker-side. It needs a
    // `CasStore` beside the nucleus for K8's reason restated — its whole subject is
    // "bytes exist and the store does not hold them" — which `Group::drive`'s
    // `&Arc<OperationalDb>` signature cannot reach. It has no main-side FAR edge: the
    // main declares a result in the transaction that accepts it, so there is no window
    // between the two.
    Elsewhere {
        boundary: "after_container_exited_before_result_published",
        home: "kata_worker::capsule_result_publication (worker-side publish)",
        source: include_str!("../../worker/tests/capsule_result_publication.rs"),
    },
    // The same worker-side handoff, one publish later: the
    // `/work` delta and its changed members are durable in the CAS and no
    // `CompletedCapsule` frame names them. It needs a `CasStore` for K8's
    // reason verbatim — the subject is store bytes, not an operational
    // transaction `Group::drive` can reach — so the cell lives beside the
    // publisher that owns the seam.
    Elsewhere {
        boundary: "after_work_delta_published_before_completion",
        home: "kata_worker::work_delta (worker-side /work delta publish)",
        source: include_str!("../../worker/tests/work_delta.rs"),
    },
    // The `Harness` family's one point, worker-side and a PROCESS edge, not a
    // durable one: it ends the process hosting the embedded harness at its first
    // completed model call. No operational transaction lies on it for
    // `Group::drive` to reach; its host-free cell arms a re-executed child beside
    // the sink that fires it, and its live cell
    // (`kata::code_mode_host_live`) proves which process that is.
    Elsewhere {
        boundary: "after_first_provider_event",
        home: "kata_worker::agent_turn (the harness's observation sink, armed child)",
        source: include_str!("../../worker/src/agent_turn.rs"),
    },
    // The `/work` apply's three windows. All three need a REAL
    // jj execution workspace (a git-colocated repo) beside the nucleus —
    // `Group::drive`'s `&Arc<OperationalDb>` signature cannot construct one —
    // plus the dispatcher's sweep choreography, which lives in kata-workflow.
    // The cells arm the boundaries through a re-executed child process and
    // recover through `drive_pending_work_applies`.
    Elsewhere {
        boundary: "after_work_apply_claimed_before_apply",
        home: "kata_workflow::work_apply (apply sweep, armed child)",
        source: include_str!("../../workflow/tests/work_apply.rs"),
    },
    Elsewhere {
        boundary: "after_work_apply_published_before_resolve",
        home: "kata_workflow::work_apply (apply sweep, armed child)",
        source: include_str!("../../workflow/tests/work_apply.rs"),
    },
    Elsewhere {
        boundary: "after_work_apply_acceptance_before_successor_release",
        home: "kata_workflow::work_apply (apply sweep, armed child)",
        source: include_str!("../../workflow/tests/work_apply.rs"),
    },
    // The capsule arm's dispatch boundary: the placement commit and the
    // transport send sit on different sides of a main-process death, and the
    // recovery is the dispatcher's restart settlement — neither is reachable
    // from this file's `&Arc<OperationalDb>` groups.
    Elsewhere {
        boundary: "after_capsule_dispatched_before_send",
        home: "kata_workflow::oci_check_and_dispatch (capsule dispatch boundary, restart settlement)",
        source: include_str!("../../workflow/tests/oci_check_and_dispatch.rs"),
    },
    // The `oci` `workspace_effect`'s claim and publish windows. Same shape
    // as the apply's: the verbs need a real jj execution workspace, so the
    // cells live in kata-workflow's armed-child harness.
    Elsewhere {
        boundary: "after_workspace_effect_claimed_before_jj_publish",
        home: "kata_workflow::workspace_effect (effect sweep, armed child)",
        source: include_str!("../../workflow/tests/workspace_effect.rs"),
    },
    Elsewhere {
        boundary: "after_workspace_effect_jj_publish_before_resolution",
        home: "kata_workflow::workspace_effect (effect sweep, armed child)",
        source: include_str!("../../workflow/tests/workspace_effect.rs"),
    },
    // A `forge_export`'s five intent windows: the remote read, the push's
    // intent and its push, the pull request's intent and its create. The
    // export's driver and the remote's and forge's observers live in
    // kata-workflow, and a cell needs a real bare remote and a fake forge.
    Elsewhere {
        boundary: "after_forge_read_before_push_intent",
        home: "kata_workflow::workspace_effect (forge intents, armed child)",
        source: include_str!("../../workflow/tests/workspace_effect.rs"),
    },
    Elsewhere {
        boundary: "after_forge_push_intent_before_push",
        home: "kata_workflow::workspace_effect (forge intents, armed child)",
        source: include_str!("../../workflow/tests/workspace_effect.rs"),
    },
    Elsewhere {
        boundary: "after_forge_push_before_pr",
        home: "kata_workflow::workspace_effect (forge intents, armed child)",
        source: include_str!("../../workflow/tests/workspace_effect.rs"),
    },
    Elsewhere {
        boundary: "after_forge_pr_intent_before_create",
        home: "kata_workflow::workspace_effect (forge intents, armed child)",
        source: include_str!("../../workflow/tests/workspace_effect.rs"),
    },
    Elsewhere {
        boundary: "after_forge_pr_create_before_receipt",
        home: "kata_workflow::workspace_effect (forge intents, armed child)",
        source: include_str!("../../workflow/tests/workspace_effect.rs"),
    },
];

/// Every registered boundary is either driven by a cell above or NAMED as
/// deliberately out of this file's scope, **every claim of coverage states the
/// **every claim is checked against the named home's own source**. Silent truncation
/// reads as full coverage.
///
/// # Two failure modes this shape closes
///
/// 1. An UNLISTED boundary.
/// 2. A claim whose home never mentions the boundary — a boundary listed as living
///    in a file that arms entirely different boundaries, so the guard written to
///    catch "silent truncation reads as full coverage" would itself be the
///    truncation. The claim is re-derived from the home's source text.
#[test]
fn operational_crash_matrix_accounts_for_every_registered_boundary() {
    let driven: Vec<&'static str> = DRIVEN_HERE.iter().map(|kill| kill.boundary()).collect();

    let mut unaccounted = Vec::new();
    for boundary in OPERATIONAL_CRASH_BOUNDARIES {
        let known = driven.contains(&boundary.name)
            || ELSEWHERE
                .iter()
                .any(|claim| claim.boundary == boundary.name);
        if !known {
            unaccounted.push(boundary.name);
        }
    }
    assert!(
        unaccounted.is_empty(),
        "every registered operational crash boundary must be driven by a cell or NAMED as living \
         elsewhere; unaccounted: {unaccounted:?}"
    );

    for claim in ELSEWHERE {
        // A name listed here that is no longer registered is a stale claim of
        // coverage, which is the same defect in the other direction.
        assert!(
            operational_boundary_registered(claim.boundary),
            "{} is claimed as covered by {} but is no longer a registered boundary",
            claim.boundary,
            claim.home
        );
        // The home must actually mention the boundary it is credited with.
        assert!(
            claim.source.contains(claim.boundary),
            "{} is claimed as covered by {}, but that file's SOURCE never mentions the boundary. \
             That is a coverage claim with no cell behind it, inside a \
             guard whose whole purpose is that silent truncation must not read as full coverage",
            claim.boundary,
            claim.home
        );
        // ... and must ARM a fault point at all.
        //
        // The name check above proves someone typed the boundary in the credited
        // file. It cannot tell a CELL from a comment, a doc table, or a prose
        // mention — the file's own `Elsewhere::source` doc says so and does not
        // oversell it. A home credited with a boundary while arming nothing is the
        // coverage-claim-with-no-cell defect one level down, so the claim
        // additionally requires the home to arm a crash at all.
        //
        // Keyed on `KATA_FAULT_INJECT` rather than on the literal
        // `operational.<boundary>`, deliberately: a home may spell the fault string
        // as a literal or as a `format!("operational.{boundary}")`, so a
        // literal-only check would fail a home that genuinely arms. This covers
        // both spellings without pinning either.
        assert!(
            claim.source.contains("KATA_FAULT_INJECT"),
            "{} is claimed as covered by {}, but that file's SOURCE never arms a fault point \
             (`KATA_FAULT_INJECT` appears nowhere in it). Naming the boundary is not driving it: \
             a home that arms nothing crashes nothing, and the claim is coverage that does not \
             exist",
            claim.boundary,
            claim.home
        );
    }
}

/// Every boundary this file's cells claim to drive really has a `#[test]`, in BOTH
/// fixture directions.
///
/// The sibling test checks the boundaries whose cells live ELSEWHERE against the
/// home's source. This applies the identical standard to the boundaries whose cells
/// live HERE — otherwise the stricter check would apply only to other people's
/// files — a partial guard.
///
/// It reads THIS file's own source, so a [`Kill`] variant that is registered,
/// reached by a group, and listed in [`DRIVEN_HERE`] but has no per-direction
/// `#[test]` fails rather than silently contributing zero cells.
#[test]
fn every_boundary_driven_here_has_a_test() {
    const OWN_SOURCE: &str = include_str!("operational_crash_matrix.rs");
    for kill in DRIVEN_HERE {
        assert!(
            operational_boundary_registered(kill.boundary()),
            "{kill:?} names an unregistered boundary {}",
            kill.boundary()
        );
        // Non-vacuity: a kill point no group reaches contributes no cells.
        assert!(
            Group::iter().any(|group| group.reaches(*kill)),
            "{kill:?} is driven here but NO group reaches it, so every cell would be skipped"
        );
        let variant = format!("Kill::{}", kill.variant_name());
        for fixture in Fixture::ALL {
            let direction = format!("Fixture::{}", fixture.variant_name());
            // The two appear together only inside a `run_matrix(..)` call, and only a
            // `#[test]` makes one.
            let paired = OWN_SOURCE.split("run_matrix(").skip(1).any(|call_site| {
                let head = &call_site[..call_site.len().min(240)];
                head.contains(&direction) && head.contains(&variant)
            });
            assert!(
                paired,
                "{} has no cell in the [{}] direction: no `run_matrix` call pairs {variant} with \
                 {direction}. Every boundary needs a cell in every fixture direction, including the \
                 ones this file drives itself",
                kill.boundary(),
                fixture.as_str()
            );
        }
    }
}

// -- the transaction axis, checked against PRODUCTION rather than typed out -----

/// How one production writer transaction stands on the transaction axis.
///
/// # What a CELL adds over the chokepoint — and therefore what a reason must cover
///
/// K3/K4 (`before_txn_commit` / `after_txn_commit`) sit INSIDE
/// `OperationalDb::in_writer_txn`, the single commit site every writer funnels
/// through. The all-or-nothing property OF THE CHOKEPOINT is therefore already
/// crashed at by every group on the axis — that is
/// not what a per-writer cell would add. What it would add is a crash against ONE
/// transaction's own COMPANION-WRITE shape: the particular set of rows it stages
/// together, checked absent-or-whole after the abort by `group_committed`.
///
/// So a [`Standing::NoCell`] reason has to be about the companion writes, and the
/// reasons below are of exactly two kinds. They are worth telling apart, because
/// only one of them is a proof:
///
/// 1. **There are none.** A single-statement transaction stages one row and
///    nothing else. "All of it or none of it" is then the chokepoint's own
///    property, already proved, and a dedicated cell would assert nothing this
///    file does not already assert across its existing groups. This is a COMPLETE answer.
///    The stop-plane writers are of this kind.
/// 2. **They are the shape a cell already crashes at**, on a transaction of the
///    same transaction group — typically one `record_transition` plus one `UPDATE` of
///    the row that transition authorizes. This is a REPRESENTATIVENESS judgement,
///    not a proof, and it is written down here rather than left implicit precisely
///    so a reader can disagree with it and add the cell.
///
/// Neither kind is a claim that the writer is uninteresting. It is a claim about
/// what THIS matrix owes, and several of these writers have their own dedicated
/// files (`operational_stop_ack`, `operational_attempt_mutators`,
/// `operational_undispatched_stage`, ...) proving
/// the non-crash half.
#[derive(Clone, Copy, Debug)]
enum Standing {
    /// A cell drives this transaction: it is what the named group's
    /// [`Group::drive`] arm opens.
    Cell(Group),
    /// No cell of its own, for the stated reason. Empty or perfunctory reasons are
    /// refused by the guard — `dev-loop-check`'s "every row states a why", applied
    /// to this table.
    NoCell(&'static str),
}

/// One `in_writer_txn` caller in `kata-core`, keyed exactly as
/// [`scan_writer_transactions`] reports it.
#[derive(Clone, Copy, Debug)]
struct WriterTxn {
    /// `<path under src/>::[<Type>::]<fn>`. The `<Type>` segment is the enclosing
    /// top-level `impl` target and is absent for a free function — it is present
    /// because callers can share a bare function name (two types' `enqueue`, say)
    /// and a key that collided would let one of a pair
    /// vanish from the accounting without failing anything.
    scope: &'static str,
    standing: Standing,
}

/// EVERY writer transaction in `kata-core`, and its standing on this axis.
///
/// Not a coverage table and not a wish list: it is the answer to "was this
/// transaction considered?", one row per `in_writer_txn` call site, checked against
/// the source by
/// [`every_writer_transaction_is_accounted_for_on_the_transaction_axis`]. A new
/// writer cannot land without a row, and a row cannot outlive its writer.
const WRITER_TRANSACTIONS: &[WriterTxn] = &[
    WriterTxn {
        scope: "operational/work_apply.rs::OperationalDb::claim_work_apply_attempt",
        standing: Standing::NoCell(
            "One transaction mints the apply occurrence's `pending` main attempt and, on a stale base, resolves it `failed` in the same commit — converge/terminal/ stale checks precede the insert so a refusal rolls back nothing. Its post-commit window is armed at `after_work_apply_claimed_before_apply` and recovered by the sweep, driven by the armed-child cells in kata_workflow::work_apply",
        ),
    },
    WriterTxn {
        scope: "operational/work_apply.rs::OperationalDb::resolve_work_apply_attempt",
        standing: Standing::NoCell(
            "The resolving transaction: apply attempt terminal AND `execution_work_tree_heads` advanced in one commit — the whole point of the seam. Its post-commit window is armed at `after_work_apply_acceptance_before_successor_release` (kata_workflow::work_apply) and the compare-and-swap refusal is the cell the_head_advance_is_checked_against_the_read",
        ),
    },
    WriterTxn {
        scope: "operational/workspace_effect.rs::OperationalDb::claim_workspace_effect_attempt",
        standing: Standing::NoCell(
            "One transaction mints the effect's `pending` (or `awaiting_approval`) main attempt at its own occurrence — converge/terminal-intent checks precede the insert so a refusal rolls back nothing; the parked arm's `main_parked` frame then takes `finalize_attempt_delivery`'s snapshot UPDATE on the same row, the companion every main-side writer carries (a gate park without it would store an undecodable frame). Its post-commit window is armed at `after_workspace_effect_claimed_before_jj_publish` and recovered by the sweep, driven by the armed-child cells in kata_workflow::workspace_effect",
        ),
    },
    WriterTxn {
        scope: "operational/expansion.rs::OperationalDb::claim_expansion_attempt",
        standing: Standing::NoCell(
            "One transaction mints the `ExpandBounded`'s `pending` main attempt at its own occurrence — the spec-coherence, converge and terminal-execution/stage checks precede the insert so a refusal rolls back nothing, and the companion writes (one claim transition + the attempt row + the occurrence mint) are the shape `Group::ClaimMainAttempt` already crashes at. The `pending` state it commits IS the recovery window: `pending_expansion_attempts` enumerates it and the re-drive convergence is pinned by the operational_expansion cells",
        ),
    },
    WriterTxn {
        scope: "operational/expansion.rs::OperationalDb::resolve_expansion_attempt",
        standing: Standing::NoCell(
            "One `resolve_main_attempt_in_tx` and nothing else — a resolution transition + the terminal attempt row + the occurrence acceptance, the shape `Group::ResolveMainAttempt` already crashes at. A lapsed `pending` premise answers None and writes nothing; pinned by the operational_expansion cells",
        ),
    },
    WriterTxn {
        scope: "operational/expansion.rs::OperationalDb::resolve_expansion_attempt_merging",
        standing: Standing::NoCell(
            "A topology settle: the projected-`pending` premise is read FIRST (a \
             lapsed one answers None having declared nothing), then `merge_fan_in_in_tx` — the \
             same fan-in `resolve_join` commits — declares the merged apply delta, and one \
             `resolve_main_attempt_in_tx` resolves the expansion `completed` (the record plus \
             `work_delta_artifact_id`) or `failed` on `work_fanin_conflict`. ONE commit: before \
             it the expansion is still `pending` and the drive re-derives and re-merges the \
             same branch heads; after it the delta's `#apply/<stage>` is ordinary apply-sweep \
             work. The shapes are `resolve_join`'s merge plus `Group::ResolveMainAttempt`'s \
             resolve; pinned by oci_expansion::every_writing_topology_member_lands_on_the_parent_head \
             and two_topology_members_writing_one_path_differently_fail_the_stage",
        ),
    },
    WriterTxn {
        scope: "operational/expansion.rs::OperationalDb::park_expansion_attempt",
        standing: Standing::NoCell(
            "The escalate park: the empty-reason, null-record, unknown-attempt and worker-executor refusals precede the transaction, the projected-`pending` premise and `require_placement_for_state` refuse inside it, then one `record_transition` with `TransitionEffect::Attempt { awaiting_approval }` plus `finalize_attempt_delivery`'s snapshot UPDATE on the same row — transition plus the attempt-row write `Group::DispatchClaimedAttempt` already crashes at, and the snapshot companion every main-side writer carries (a gate park without it stored an undecodable frame — the replay's durable-facts decode requires `delivery` of every projection-folding attempt frame; caught by the oci_expansion escalate e2e). The parked state, the leave-the-live-set semantics and every refused arm are pinned by a_parked_expansion_gate_leaves_the_live_set_and_refuses_non_pendings and park_expansion_attempt_refuses_by_name_what_it_cannot_hold",
        ),
    },
    WriterTxn {
        scope: "operational/expansion.rs::OperationalDb::decide_expansion_approval",
        standing: Standing::NoCell(
            "The write-once gate decision: `approval_decided` idempotency-keyed on the shared `approval_decision_key`, then `resolve_main_attempt_in_tx` resolves the parked attempt in place — `completed` adopting the park's own record (occurrence acceptance included) or `failed` on reject — the shape `Group::DecideCapsuleApproval` + `Group::ResolveMainAttempt` already crash at. The resolution bytes are prepared BEFORE the transaction (`prepare_main_resolution` may offload output to CAS) so no CAS write nests in the lock. The recorded-verdict convergence, the opposite-verdict refusal, the not-parked/not-running refusals and the adopted-record acceptance are pinned by an_approved_expansion_gate_resolves_completed_with_the_parked_record, a_rejected_expansion_gate_resolves_failed_with_the_operators_reason and decide_expansion_approval_refuses_what_is_not_a_parked_gate",
        ),
    },
    WriterTxn {
        scope: "operational/workspace_effect.rs::OperationalDb::resolve_workspace_effect_attempt",
        standing: Standing::NoCell(
            "The resolving transaction: the effect attempt terminal AND — for `commit` — `execution_work_tree_heads` compare-and-swapped onto the rewritten candidate in one commit. Its post-commit window is armed at `after_workspace_effect_jj_publish_before_resolution` (kata_workflow::workspace_effect); the CAS refusal is what `a_commit_effect_lands_once_and_advances_the_head` and the moved-candidate cell pin",
        ),
    },
    WriterTxn {
        scope: "operational/forge_intent.rs::OperationalDb::record_forge_intent",
        standing: Standing::NoCell(
            "One transaction re-checks the attempt is a `pending` `forge_export` of a running execution (a lapsed premise writes nothing and answers None), refuses an open intent or a second performed push, and inserts one `forge_intents` row — all or nothing at the commit, the shape every K3/K4 cell already crashes at. The export's windows around it — `after_forge_read_before_push_intent` before it, `after_forge_push_intent_before_push` and `after_forge_pr_intent_before_create` after it — are armed and recovered by the armed-child cells in kata_workflow::workspace_effect; the refused set is pinned by an_intent_is_recorded_only_for_a_pending_forge_export and one_intent_is_open_at_a_time_and_no_push_follows_a_performed_one (operational_forge_intent)",
        ),
    },
    WriterTxn {
        scope: "operational/forge_intent.rs::OperationalDb::settle_forge_intent",
        standing: Standing::NoCell(
            "single-statement: one write-once `UPDATE forge_intents SET verdict… WHERE verdict IS NULL`, then a primary-key read only to name a refusal — no companion write, so a crash before it leaves the intent open (the observer asks again) and after it leaves the verdict (the export acts on it). The push's receipt and the observer's PERFORMED and NOT PERFORMED arms that write it are driven by the armed-child cells in kata_workflow::workspace_effect, a main killed in the pull request's lookup after each PERFORMED among them; write-once and the receipt CHECK are pinned by a_verdict_is_written_once_and_a_receipt_only_says_performed (operational_forge_intent)",
        ),
    },
    WriterTxn {
        scope: "operational/forge_intent.rs::OperationalDb::record_forge_command_error",
        standing: Standing::NoCell(
            "single-statement: one write-once `UPDATE forge_intents SET command_error… WHERE verdict IS NULL AND command_error IS NULL`, then a primary-key read of the row it answers — no companion write. A crash before it leaves an intent no command answered, which recovery treats as a crash-left outcome (a NOT PERFORMED read issues the effect again, as after any crash); after it, the intent carries the error and a NOT PERFORMED read fails the export. The deferred-verdict path it feeds is driven by a_push_whose_remote_vanishes_stays_open_then_fails_not_performed_with_its_error (kata_workflow::workspace_effect); write-once and the empty refusal by an_open_intent_counts_unanswered_reads_and_keeps_its_command_error_once (operational_forge_intent)",
        ),
    },
    WriterTxn {
        scope: "operational/forge_intent.rs::OperationalDb::record_unanswered_forge_read",
        standing: Standing::NoCell(
            "single-statement: one `UPDATE forge_intents SET unanswered_reads = unanswered_reads + 1, … WHERE verdict IS NULL`, then a primary-key read of the count it answers — no companion write. A crash before it loses one unanswered read (the intent is asked again, still under the bound); a crash after the tenth and before the settlement leaves the count at the bound, which the next drive settles without asking — an_intent_at_the_bound_is_settled_without_another_ask (kata_workflow::workspace_effect). The settled-intent refusal is pinned by an_open_intent_counts_unanswered_reads_and_keeps_its_command_error_once (operational_forge_intent)",
        ),
    },
    WriterTxn {
        scope: "operational/forge_intent.rs::OperationalDb::resolve_forge_export_attempt",
        standing: Standing::NoCell(
            "The export's terminal: the optional write-once verdict, the no-open-intent refusal, and one `resolve_main_attempt_in_tx` — the shape `Group::ResolveMainAttempt` already crashes at, plus one `UPDATE forge_intents`, all or nothing at the commit. Its pre-commit window is armed at `after_forge_pr_create_before_receipt` (kata_workflow::workspace_effect); the refusal and the verdict-with-terminal commit are pinned by no_attempt_resolves_past_an_open_intent (operational_forge_intent)",
        ),
    },
    WriterTxn {
        scope: "operational/workspace_effect.rs::OperationalDb::decide_workspace_effect_approval",
        standing: Standing::NoCell(
            "The write-once decision: `approval_decided` idempotency-keyed, `approval_already_decided`/`approval_gate_not_parked` refuse in-transaction, and an approve un-parks to `pending` — pinned by the gate cells in kata_workflow::workspace_effect",
        ),
    },
    WriterTxn {
        scope: "operational/workspace_effect.rs::OperationalDb::resolve_workspace_effect_attempt_parked",
        standing: Standing::NoCell(
            "The cancel arm: one terminal resolve over the parked gate — `approval_gate_not_parked` otherwise; pinned by a_rejected_effect_gate_performs_nothing",
        ),
    },
    WriterTxn {
        scope: "operational/workspace_effect.rs::OperationalDb::workspace_effect_attempt_drivable",
        standing: Standing::NoCell(
            "The perform leg's drivability re-check: one transaction \
             reading the attempt's projection state and the execution's lifecycle inside the \
             perform lock — a READ under the writer mutex so it cannot interleave with the \
             drain's settle or a sibling resolve between the sweep's enumeration and the verb. \
             No companion write: a crash in or after it aborts nothing. The terminalizing fence \
             is pinned by \
             a_pending_effect_terminalized_before_perform_publishes_nothing and the single-\
             performer property by concurrent_drives_perform_the_effect_once (both in \
             kata_workflow::workspace_effect)",
        ),
    },
    WriterTxn {
        scope: "operational/work_apply.rs::OperationalDb::fail_work_apply_attempt",
        standing: Standing::NoCell(
            "One `failed` resolution and nothing else — the single-statement reason the stop writers carry, with the recorded refusal pinned by a_failed_resolve_is_recorded_and_the_head_stays and a_diverged_candidate_is_recorded_failed_and_never_retries",
        ),
    },
    WriterTxn {
        scope: "operational/work_tree_head.rs::OperationalDb::ensure_work_tree_head",
        standing: Standing::NoCell(
            "The lazy branch FORK: the parent head read, the first \
             sibling's frozen barrier base read, and ONE `execution_work_tree_heads` insert, \
             in a single transaction — every refusal (the unrecorded root, the absent parent \
             chain, a divergent restatement) precedes the insert, so a crash leaves either the \
             whole row or nothing of it. The refused sets and the convergence are pinned by \
             work_tree_head's own cells: an_unrecorded_root_is_refused_at_the_root_and_below_it, \
             a_branch_head_forks_lazily_off_the_parent_and_a_re_ensure_converges, \
             a_sibling_forks_at_the_first_siblings_frozen_base_not_the_moved_parent",
        ),
    },
    WriterTxn {
        scope: "operational/worker_completion.rs::OperationalDb::accept_worker_completion_with",
        standing: Standing::NoCell(
            "The capsule door's one transaction: the fence re-read, the result's declaration and \
             the accepting half. Its post-commit edge \
             is armed at `after_accept_event` and redelivered in operational_capsule_result's \
             a_capsule_completion_redelivered_after_a_crash_past_its_acceptance_is_accepted_once \
             (raw row, acceptance and transition counts); a declaration refused inside it rolls \
             the whole transaction back, which the bound and member cells read as no row. \
             worker_completion_precommit_fault_leaves_no_acceptance_and_a_redelivery_accepts_once \
             and worker_completion_stop_ack_is_atomic_with_acceptance inject a commit fault and \
             reopen raw SQLite: no inbox row, transition or stop acknowledgement survives it",
        ),
    },
    WriterTxn {
        scope: "operational/worker_failure.rs::OperationalDb::buffer_worker_failure",
        standing: Standing::NoCell(
            "Dedicated worker_failure_precommit_fault_reopens_with_raw_input_and_no_partial_resolution reads the reopened raw inbox after a commit fault; worker_failure_stop_ack_is_atomic_with_replayed_and_superseded_acceptance proves supersession acceptance and exact old stop acknowledgement atomicity without acknowledging the successor",
        ),
    },
    WriterTxn {
        scope: "operational/worker_failure.rs::OperationalDb::adjudicate_worker_failure",
        standing: Standing::NoCell(
            "Dedicated worker_failure_precommit_fault_reopens_with_raw_input_and_no_partial_resolution proves acceptance/retry rollback; worker_failure_stop_ack_is_atomic_with_replayed_and_superseded_acceptance independently reopens raw SQLite and proves stop acknowledgement cannot commit without input acceptance",
        ),
    },
    WriterTxn {
        scope: "operational/imports.rs::OperationalDb::quarantine_verified_import",
        standing: Standing::NoCell(
            "Dedicated import_quarantine_precommit_fault_rolls_back_gate_and_subjects cell injects the real writer commit fault, reopens, and independently counts both the global gate and populated execution subjects",
        ),
    },
    WriterTxn {
        scope: "operational/imports.rs::OperationalDb::apply_import_decisions",
        standing: Standing::NoCell(
            "Only subject-row UPDATEs; operational_substrate::import_operator_authorization_is_subject_bound_atomic_and_does_not_release_the_import independently proves a later invalid packet item rolls back all earlier decisions and that authorization alone does not release the import",
        ),
    },
    WriterTxn {
        scope: "operational/imports.rs::OperationalDb::release_reconciled_import",
        standing: Standing::NoCell(
            "Exactly one conditional UPDATE of recovery_imports.released_at_ms after immutable catalog, runtime target verifier and current obligation checks; no companion write or cross-file mutation occurs in this transaction",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::record_attempt_stalled",
        standing: Standing::NoCell(
            "Record-only attempt_stalled observation plus finalized delivery payload; no lifecycle or attempt-row mutation, the append/sequence/watermark transaction shape already covered by the record-only input cells",
        ),
    },
    // -- execution-level EVIDENCE --------------------------------------------
    WriterTxn {
        scope: "operational/evidence.rs::OperationalDb::append_execution_evidence",
        standing: Standing::NoCell(
            "single-statement: one `INSERT OR REPLACE INTO execution_evidence` with no \
             companion write and no sequence allocation. The row is keyed by a per-append \
             ULID, so a retry after an aborted commit writes the same row rather than a \
             second one, and there is no second fact a crash could separate it from",
        ),
    },
    WriterTxn {
        scope: "operational/evidence.rs::OperationalDb::append_execution_evidence_claimed",
        standing: Standing::NoCell(
            "TWO writes, and their atomicity is proved by the claim's own semantics rather \
             than by a cell: the `INSERT OR IGNORE` into `execution_evidence_claims` decides \
             the outcome and the evidence row follows in the same transaction, so a crash \
             between them rolls BOTH back and the next caller wins the claim again. \
             `ledger_store_roundtrip_tests::a_durable_execution_evidence_claim_survives_reopen` \
             independently reopens the plane and proves the committed pair is one fact; the \
             generic K3/K4 chokepoint covers the boundary itself, since this transaction \
             allocates no sequence and folds no projection",
        ),
    },
    // -- the projection REPAIR -------------------------------------------------
    WriterTxn {
        scope: "operational/projection.rs::OperationalDb::rebuild_projection",
        standing: Standing::NoCell(
            "The explicit projection-REBUILD path, not an authoritative transition: it \
             re-derives the projection from the retained chain and writes no transition at all. \
             The property it exists to restore is the one every cell here already asserts \
             (`verify_projection_integrity`, I1/I10) after the abort",
        ),
    },
    // -- the repository transactions ------------------------------------------
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::submit_execution",
        standing: Standing::Cell(Group::SubmitExecution),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::mark_running",
        standing: Standing::NoCell(
            "SUBMISSION group, second step: one transition plus the `execution_lifecycle` UPDATE \
             it authorizes — the two-write shape `Group::FinishTerminalization` crashes at, \
             one state earlier. Also driven UNARMED by `Group::prepare` for multiple \
             cells, so every one of those recoveries reads a nucleus this transaction wrote",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::begin_terminalization_with_cleanup",
        standing: Standing::NoCell(
            "EVIDENCE/terminal group, LATCH half: transition plus the `execution_lifecycle` \
             UPDATE and cleanup-obligation INSERT. `Group::FinishTerminalization` cells the \
             PUBLISH half and reaches this writer unarmed in `Group::prepare`; \
             operational_lifecycle::invalid_cleanup_disposition_rolls_back_terminal_intent \
             independently proves that a rejected obligation rolls back the transition and \
             lifecycle update together",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::complete_execution_cleanup",
        standing: Standing::NoCell(
            "single-statement: one conditional `UPDATE execution_cleanup_obligations` from \
             pending to completed, with no companion write; terminal publication is a separate \
             transaction that first refuses any still-pending row",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::defer_execution_cleanup",
        standing: Standing::NoCell(
            "single-statement: one conditional `UPDATE execution_cleanup_obligations` retaining \
             bounded failure evidence and the next retry instant, with no companion write",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::finish_terminalization",
        standing: Standing::Cell(Group::FinishTerminalization),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::debug_put_raw_program",
        standing: Standing::NoCell(
            "`#[cfg(any(test, feature = \"test-support\"))] #[doc(hidden)]` fixture door — it \
             does not exist in a production build, so it is not a boundary the crash proof is \
             stated over",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::debug_delete_execution",
        standing: Standing::NoCell(
            "`#[cfg(any(test, feature = \"test-support\"))] #[doc(hidden)]` fixture door; absent \
             from a production build",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::debug_claim_attempts_in_one_txn",
        standing: Standing::NoCell(
            "`#[cfg(any(test, feature = \"test-support\"))] #[doc(hidden)]` fixture door that \
             batches the claim transaction's own in-transaction writer; absent from a production \
             build, and the claim boundary it batches is `Group::ClaimAttempt`'s",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::install_schedule",
        standing: Standing::Cell(Group::InstallSchedule),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::rebind_schedule",
        standing: Standing::NoCell(
            "single-statement: one `UPDATE schedules`, no companion write, so all-or-nothing is \
             the chokepoint's own property",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::remove_schedule",
        standing: Standing::NoCell(
            "single-statement: one `DELETE FROM schedules`, no companion write",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::skip_schedule_to",
        standing: Standing::NoCell(
            "single-statement: a guard read, then one monotone cursor UPDATE \
             (`advance_cursor_monotonically`), no companion write",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::fire_schedule",
        standing: Standing::Cell(Group::FireSchedule),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::refuse_schedule_fire",
        standing: Standing::NoCell(
            "the shape the `fire_schedule` cell crashes at, minus its submit: the same \
             `claim_due_firing` firing-row INSERT and monotone cursor UPDATE (a refusal in place \
             of an execution id), with no execution rows staged",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::debug_force_schedule_cursor_ms",
        standing: Standing::NoCell(
            "`#[cfg(any(test, feature = \"test-support\"))]` fixture door; absent from a \
             production build",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::debug_forge_schedule_pin",
        standing: Standing::NoCell(
            "`#[cfg(any(test, feature = \"test-support\"))]` fixture door; absent from a \
             production build",
        ),
    },
    WriterTxn {
        // `claim_attempt` and `claim_attempt_parked_for_approval` are both
        // `claim_attempt_parking`, the one transaction, with and without a park reason.
        scope: "operational/repo.rs::OperationalDb::claim_attempt_parking",
        standing: Standing::Cell(Group::ClaimAttempt),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::advance_attempt_generation",
        standing: Standing::NoCell(
            "`#[cfg(any(test, feature = \"test-support\"))]` fixture door; absent from a \
             production build",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::record_main_side_transition_inner",
        standing: Standing::NoCell(
            "ATTEMPT group: transition plus one `UPDATE attempts`, the same companion-write shape \
             `Group::DispatchClaimedAttempt` crashes at; the `_if_live` door adds only a READ of \
             the projected state under the same lock, which writes nothing when it refuses",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::admit_undispatched_stage_with",
        standing: Standing::NoCell(
            "single-statement: an idempotency probe, then one `record_transition` with \
             `TransitionEffect::RecordOnly` and no row write at all",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::record_undispatched_stage_transition",
        standing: Standing::NoCell(
            "single-statement: one `record_transition`, `RecordOnly`, no companion write",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::record_attempt_append",
        standing: Standing::NoCell(
            "single-statement: one `record_transition`, `RecordOnly`, no companion write",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::record_attempt_safe_point",
        standing: Standing::NoCell(
            "single-statement: one clamped `UPDATE attempts SET last_checkpoint = MAX(..)` plus a \
             read-back of what the clamp settled on; no companion write",
        ),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::dispatch_claimed_attempt_inner",
        standing: Standing::Cell(Group::DispatchClaimedAttempt),
    },
    WriterTxn {
        scope: "operational/worker_domains.rs::OperationalDb::enroll_worker_domain",
        standing: Standing::Cell(Group::EnrollWorkerDomain),
    },
    WriterTxn {
        scope: "operational/stage_records.rs::OperationalDb::record_undispatched_stage_metadata",
        standing: Standing::Cell(Group::RecordStageMetadata),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::dispatch_attempt",
        standing: Standing::Cell(Group::DispatchAttempt),
    },
    // A `#[cfg(any(test, feature = "test-support"))]` fixture door, not a
    // production writer: its cell crashes at the fold it opens,
    // `accept_incoming_event_in_tx`, which production reaches only inside
    // `accept_worker_completion_with`'s transaction (row above).
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::accept_incoming_event",
        standing: Standing::Cell(Group::AcceptIncomingEvent),
    },
    WriterTxn {
        scope: "operational/capsule_approval.rs::OperationalDb::decide_capsule_approval",
        standing: Standing::Cell(Group::DecideCapsuleApproval),
    },
    WriterTxn {
        scope: "operational/repo.rs::OperationalDb::dynamic_child",
        standing: Standing::Cell(Group::DynamicChild),
    },
    WriterTxn {
        scope: "operational/main_attempt.rs::OperationalDb::claim_main_attempt",
        standing: Standing::Cell(Group::ClaimMainAttempt),
    },
    WriterTxn {
        scope: "operational/main_attempt.rs::OperationalDb::resolve_main_attempt",
        standing: Standing::Cell(Group::ResolveMainAttempt),
    },
    WriterTxn {
        scope: "operational/main_attempt.rs::OperationalDb::claim_and_resolve_main_attempt_with",
        standing: Standing::Cell(Group::ClaimAndResolveMainAttempt),
    },
    WriterTxn {
        scope: "operational/main_attempt.rs::OperationalDb::resolve_input_wait",
        standing: Standing::Cell(Group::ResolveInputWait),
    },
    WriterTxn {
        scope: "operational/main_attempt.rs::OperationalDb::resolve_join",
        standing: Standing::NoCell(
            "The join's claim + resolve + FAN-IN transaction: the input \
             acceptance precondition, the merged-delta declaration, the claim and its \
             accepting (or conflict-failed) resolution are ONE commit, so before it nothing of \
             the join exists and after it everything does — including the recorded \
             work_fanin_conflict verdict a re-presentation converges on. Its K3/K4 pair is \
             driven by the armed child in \
             oci_check_and_dispatch::a_join_crashed_at_its_commit_resolves_exactly_once_after_restart \
             (before_txn_commit / after_txn_commit over a second process's planes, every count \
             read raw); the conflict arm's nothing-moves guarantee is pinned by \
             work_tree_head::a_fanin_conflict_fails_the_join_naming_paths_and_branches_and_moves_nothing",
        ),
    },
    WriterTxn {
        scope: "operational/capsule_result.rs::OperationalDb::reuse_accepted_capsule_result",
        standing: Standing::NoCell(
            "The capsule REUSE door: the source re-read, the adopting \
             occurrence minted, the main attempt claimed, the adopter's artifact root and the \
             acceptance, in ONE transaction over a fixture that needs the content store bound \
             (`open_with_cas`), which this matrix's fixture does not open. Its K3/K4 pair is \
             driven by armed children in operational_capsule_reuse.rs \
             (a_crash_before_the_reuse_commit_leaves_nothing_and_a_retry_adopts_once, \
             a_crash_after_the_reuse_commit_leaves_it_whole_and_a_retry_writes_nothing), read \
             through a raw handle",
        ),
    },
    WriterTxn {
        scope: "operational/child_invocation.rs::OperationalDb::invoke_child_execution",
        standing: Standing::NoCell(
            "The INVOKE door: the parent's `Invoke` main attempt claimed and \
             parked on its child, the `dynamic_child_spawned` bound record on the parent, and the \
             child's program, invocation and `admitting` lifecycle, in ONE transaction - the \
             `ClaimMainAttempt` and `DynamicChild` shapes composed. Its K3/K4 pair is driven by \
             armed children with a restart in operational_child_invocation.rs \
             (one_child_per_invoke_across_k3_and_k4_on_the_combined_transaction: K3 leaves \
             neither half, K4 both, and the successor leaves exactly one attempt, one bound and \
             one child), read through a raw handle; the same file's \
             the_childs_terminal_resolves_its_parent_in_the_same_commit drives K3/K4 on the \
             child's publication, which now resolves the parent in its transaction",
        ),
    },
    WriterTxn {
        scope: "operational/child_invocation.rs::OperationalDb::latch_execution_cancel",
        standing: Standing::NoCell(
            "The CANCEL LATCH: `latch_terminal_intent_in_tx`, the same transition plus \
             `execution_lifecycle` UPDATE and cleanup-obligation INSERT as \
             `begin_terminalization_with_cleanup`'s LATCH half (whose standing covers the shape), \
             or nothing when the execution already latched. Its composition with an `Invoke`'s \
             end is the one with a crash window of its own, and is celled on \
             `settle_abandoned_child_waits` below",
        ),
    },
    WriterTxn {
        scope: "operational/child_invocation.rs::OperationalDb::begin_terminalization_adopting_cancel",
        standing: Standing::NoCell(
            "Either `begin_terminalization_with_cleanup`'s LATCH half on the caller's intent \
             (same shape, same standing) or NOTHING — the adopted cancel is read and answered, \
             never written — so it adds no durable state a crash could split",
        ),
    },
    WriterTxn {
        scope: "operational/child_invocation.rs::OperationalDb::settle_abandoned_child_waits",
        standing: Standing::NoCell(
            "The restart leg's settlement of a terminalizing parent's parked `Invoke`: the \
             child's cancel LATCHED and the `Invoke` resolved `cancelled`, in ONE transaction per \
             parent. Its K3/K4 pair is driven by armed children with a restart in \
             operational_child_invocation.rs \
             (an_abandoned_invoke_and_its_childs_latch_commit_together_across_k3_and_k4: K3 \
             leaves the wait parked and the child running, K4 both settled, and the successor's \
             pass leaves exactly the settled pair), read through a raw handle",
        ),
    },
    // -- the durable stop-ack writers ------------------------------------------
    //
    // Writers like these could land with no standing on this axis at all, and nothing
    // would fail. Their standing is kind 1 above, and
    // it is a complete answer rather than a deferral — each stages exactly one row
    // of `attempt_stop_requests` and nothing else, so there is no companion write
    // for a cell to catch half-done. What they DO need is the non-crash proof, and
    // that has its own file: `operational_stop_ack.rs`.
    WriterTxn {
        scope: "operational/stop_ack.rs::OperationalDb::record_stop_request",
        standing: Standing::NoCell(
            "single-statement: one `INSERT INTO attempt_stop_requests ... ON CONFLICT DO \
             NOTHING`, no companion write. The window this plane cannot close is between the \
             write and the transport send, which is a CROSS-RESOURCE ordering obligation \
             (the cross-resource rule) stated on `record_stop_request` itself — not a \
             transaction boundary, and not something a crash cell on this axis could observe",
        ),
    },
    WriterTxn {
        scope: "operational/stop_ack.rs::OperationalDb::mark_stop_delivered",
        standing: Standing::NoCell(
            "single-statement: one `UPDATE attempt_stop_requests SET delivered_at_ms`, no \
             companion write, and it is bookkeeping no safety decision reads — the parking \
             predicate reads `acknowledged_at_ms`",
        ),
    },
    WriterTxn {
        scope: "operational/stop_ack.rs::OperationalDb::acknowledge_stop",
        standing: Standing::NoCell(
            "single-statement: a primary-key probe, then one `UPDATE attempt_stop_requests SET \
             acknowledged_at_ms`, no companion write. This is the write parking depends on, and \
             a crash before it commits leaves the stop OUTSTANDING — which is the safe reading, \
             by the same argument `is_outstanding` states",
        ),
    },
    WriterTxn {
        scope: "operational/stop_ack.rs::OperationalDb::discharge_stop",
        standing: Standing::NoCell(
            "single-statement: a primary-key probe, then one `UPDATE attempt_stop_requests SET \
             acknowledged_at_ms, discharge_json`, no companion write. The operator discharge \
             — the fourth of these writers and the same kind-1 standing as the three above, for \
             the same reason. The two columns move in ONE statement, which is what keeps the \
             `discharge_json IS NULL OR acknowledged_at_ms IS NOT NULL` CHECK unobservable as a \
             torn pair rather than merely unlikely. A crash before it commits leaves the stop \
             OUTSTANDING and un-discharged, which is the safe reading: the operator re-issues \
             the assertion, and the idempotent path answers `AlreadyDischarged` if it did land",
        ),
    },
    WriterTxn {
        scope: "operational/environments.rs::OperationalDb::declare_environment",
        standing: Standing::NoCell(
            "TWO companion writes (the node-owned authoritative `cas_roots` manifest row and the \
             `nix_environments` row with `root_promoted_at_ms` NULL), and it IS crashed at — by \
             K14/K15 in `cas_root_liveness.rs`, which is its home because the declaration needs a \
             `DurableObject` receipt and therefore a `CasStore` this file's `Group::drive` signature \
             cannot reach. Those cells reopen a SECOND raw rusqlite handle and read `SELECT count(*) \
             FROM nix_environments` beside `SELECT count(*) FROM cas_roots WHERE \
             purpose='nix_environment_manifest'`: absent-or-both, never one of the two, and after \
             the K15 commit the row is present with a NULL promotion instant while the CAS blob is \
             still resolvable",
        ),
    },
    WriterTxn {
        scope: "operational/environments.rs::OperationalDb::record_environment_evidence",
        standing: Standing::NoCell(
            "single-statement: one `UPDATE nix_environments SET verification_evidence`, no \
             companion write, and the column is EVIDENCE rather than identity or state — nothing \
             decides on it. A crash before it commits leaves the previous verification's evidence, \
             which the next boot's re-verification overwrites",
        ),
    },
    WriterTxn {
        scope: "operational/environments.rs::OperationalDb::promote_environment_root",
        standing: Standing::NoCell(
            "single-statement: one row read for the state refusals, then one `UPDATE \
             nix_environments SET root_promoted_at_ms` guarded `WHERE root_promoted_at_ms IS NULL`, \
             no companion write. Kind-1 standing. A crash before it commits leaves the environment \
             UNPROMOTED, which is the safe reading and the exact state `unpromoted_environments` \
             returns — `operational_environments.rs` reopens the file and observes it through a \
             second raw handle",
        ),
    },
    WriterTxn {
        scope: "operational/environments.rs::OperationalDb::release_environment",
        standing: Standing::NoCell(
            "two `UPDATE`s (the environment row's `released_at_ms` and its manifest root's, through \
             `release_cas_root`) and no other write. The shape a cell would crash at is the same one \
             K14/K15 already crash at on the DECLARE side — the row and its root moving together — \
             and `operational_environments.rs` proves the release half with a second raw handle \
             reading both `released_at_ms` columns in one statement, so a torn release would be a \
             count mismatch rather than a missing assertion",
        ),
    },
    WriterTxn {
        scope: "operational/environments.rs::OperationalDb::delete_released_environment",
        standing: Standing::NoCell(
            "single-statement: one row read for the not-released refusal, then one `DELETE FROM \
             nix_environments`. Kind-1 standing, and the manifest root deliberately does NOT move \
             with it — release already stamped it and nothing deletes a root row — so \
             there is no companion write for a cell to catch torn. A crash before the commit leaves \
             the released row, which the next delete converges on",
        ),
    },
    // -- the portable artifact and capsule planes --------------------------------
    //
    // All three carry the SAME standing as `declare_environment`: a row plus its
    // `cas_roots` row in one transaction, with no NEW crash boundary, because the only
    // durability edge they open is K8 —
    // `operational.after_cas_object_durable_before_root` — which already fires at the end
    // of `CasStore::put_durable`, the sole producer of the `DurableObject` receipt each
    // declaration requires. There is deliberately no
    // `after_tree_members_durable_before_manifest_durable` boundary: that edge belongs to
    // the writer that PUBLISHES a tree's members, and no writer here does,
    // so a seam here would model a window no transaction in this build can be interrupted
    // in.
    WriterTxn {
        scope: "operational/artifacts.rs::OperationalDb::declare_artifact",
        standing: Standing::NoCell(
            "TWO companion writes (this owner's `cas_roots` object row and the `artifacts` row — inserted or left alone, because the row is a node-level content claim a second owner shares), and the window they bracket is K8's, already driven in `cas_root_liveness.rs`: the object is fsync-durable and NO operational root references it. That is where the cell lives because the declaration needs a `DurableObject` receipt and therefore a `CasStore` this file's `Group::drive` signature cannot reach. `operational_artifacts.rs` reads `SELECT count(*) FROM artifacts` beside `SELECT count(*) FROM cas_roots` in ONE statement through a second raw handle, so a torn declare is a value mismatch rather than a missing assertion",
        ),
    },
    WriterTxn {
        scope: "operational/capsules.rs::OperationalDb::declare_capsule",
        standing: Standing::NoCell(
            "TWO companion writes (the node-owned authoritative `cas_roots` capsule-object row and the `capsules` row), bracketing K8's window as `declare_artifact` does and for the same reason. The cross-plane refusals run INSIDE the same transaction as the insert, so there is no window in which an environment released concurrently could be bound by a committed capsule. A crash before the commit leaves no capsule and no root, which is the state `operational_artifacts.rs` asserts after every refused declaration",
        ),
    },
    // -- the execution /work head ---------------------------------------------
    WriterTxn {
        scope: "operational/work_tree_head.rs::OperationalDb::record_work_tree_head",
        standing: Standing::NoCell(
            "one `SELECT` of the stored row for the converge-or-refuse, then ONE `INSERT` — the single-statement kind-1 shape, all-or-nothing at the chokepoint K3/K4 own. Its crash window is NOT inside this writer but between it and the publish that precedes it: `after_base_tree_published_before_head_recorded`, claimed in `ELSEWHERE` with `cas_root_liveness` K16 as its home, which drives the armed child through `publish_base_tree_head` and proves the residue (artifact + owner root durable, no head row) and the re-admission convergence. The divergent half — a second record under one execution refusing `work_tree_head_divergent` — is proved in `work_tree_head.rs` against a raw handle",
        ),
    },
    // -- the execution git view ----------------------------------------------
    WriterTxn {
        scope: "operational/git_view.rs::OperationalDb::record_execution_git_view",
        standing: Standing::NoCell(
            "one `SELECT` of the stored row for the converge-or-refuse, then ONE `INSERT` — the same single-statement kind-1 shape `record_work_tree_head` carries, all-or-nothing at the chokepoint K3/K4 own. Its crash window is NOT inside this writer but between it and the member publication that precedes it: `after_git_view_published_before_recorded`, claimed in `ELSEWHERE` with `cas_root_liveness` K17 as its home, which drives the armed child through `publish_execution_git_view` and proves the residue (members + manifest + owner root durable, no view row) and the readmission re-pack convergence. The divergent half — a second record under one execution refusing `git_view_divergent` — is proved in `execution_git_view.rs::an_identical_restate_converges_and_a_divergent_one_is_refused_by_name`",
        ),
    },
];

/// Every family the crash proof names is covered by real CELLS — not merely registered.
///
/// The `fault_inject.rs` unit test asserts each crash-proof family has a BOUNDARY. That
/// is the weaker half, and on its own it would let a family be closed by
/// registering a name nothing drives — the coverage-claim-with-no-cell defect,
/// relocated one level up. This asserts the stronger half over the same
/// proof-derived family list.
#[test]
fn every_crash_proof_family_is_covered_by_cells() {
    let driven: Vec<&'static str> = DRIVEN_HERE.iter().map(|kill| kill.boundary()).collect();
    let mut uncovered = Vec::new();
    for family in OperationalBoundaryFamily::CRASH_PROOF_FAMILIES {
        let registered: Vec<&'static str> = OPERATIONAL_CRASH_BOUNDARIES
            .iter()
            .filter(|boundary| boundary.family == *family)
            .map(|boundary| boundary.name)
            .collect();
        let covered = registered.iter().any(|name| {
            driven.contains(name) || ELSEWHERE.iter().any(|claim| claim.boundary == *name)
        });
        if !covered {
            // The two ways to be uncovered are DIFFERENT repairs, so the diagnostic
            // distinguishes them. Found by counterfactual: unregistering the jj
            // rows made this fire with the right family and the WRONG reason
            // ("have a registered boundary but no cell"), which would have sent a
            // reader looking for a missing cell when the boundary itself was gone.
            // A diagnostic that names the wrong repair is its own defect.
            uncovered.push(if registered.is_empty() {
                format!("{} (NO registered boundary at all)", family.as_str())
            } else {
                format!(
                    "{} (registered {registered:?}, but no cell drives any of them)",
                    family.as_str()
                )
            });
        }
    }
    assert!(
        uncovered.is_empty(),
        "the crash proof requires a crash at every transaction/dispatch/CAS/jj boundary. \
         Uncovered: {uncovered:?}"
    );

    // Non-vacuity, and the reason it is here: an empty CRASH_PROOF_FAMILIES would
    // make the loop above pass trivially, which is how a guard silently stops guarding.
    assert_eq!(
        OperationalBoundaryFamily::CRASH_PROOF_FAMILIES.len(),
        4,
        "the crash proof names four boundary families (transaction/dispatch/CAS/jj); a change \
         to that count is a design change and must be made deliberately"
    );
    // Every registered boundary's family resolves — a `None` here would mean the
    // registry and its accessor disagree.
    for boundary in OPERATIONAL_CRASH_BOUNDARIES {
        assert_eq!(
            operational_boundary_family(boundary.name),
            Some(boundary.family),
            "{} is registered but its family lookup disagrees",
            boundary.name
        );
    }
}

// -- reading the writer transactions out of production -------------------------

/// `    pub(crate) async fn foo(..` -> `Some((4, "foo"))`.
///
/// Deliberately conservative: anything it does not recognise as a declaration it
/// reports as not-a-declaration, which attributes a following call site to the
/// PREVIOUS function and produces a key the roster does not contain. That fails
/// the guard LOUDLY rather than silently dropping a caller, which is the direction
/// a parser inside a guard has to fail in.
fn fn_declaration(line: &str) -> Option<(usize, &str)> {
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();
    let mut rest = trimmed;
    loop {
        rest = if let Some(tail) = rest.strip_prefix("pub(") {
            let close = tail.find(')')?;
            tail[close + 1..].trim_start()
        } else if let Some(tail) = rest
            .strip_prefix("pub ")
            .or_else(|| rest.strip_prefix("const "))
            .or_else(|| rest.strip_prefix("async "))
            .or_else(|| rest.strip_prefix("unsafe "))
        {
            tail.trim_start()
        } else {
            break;
        };
    }
    let name = rest.strip_prefix("fn ")?.trim_start();
    let end = name.find(|char: char| !char.is_alphanumeric() && char != '_')?;
    Some((indent, &name[..end]))
}

/// `impl Display for Name<'_> {` -> `"Name"`, given everything
/// after the literal `impl`.
fn impl_target(header: &str) -> &str {
    let mut rest = header.trim_start();
    if rest.starts_with('<') {
        let mut depth = 0_usize;
        let mut end = None;
        for (index, char) in rest.char_indices() {
            match char {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = end.map_or("", |end| rest[end..].trim_start());
    }
    let rest = rest.split('{').next().unwrap_or(rest);
    let rest = rest.rsplit_once(" for ").map_or(rest, |(_, target)| target);
    rest.trim()
        .split(['<', ' '])
        .next()
        .unwrap_or("")
        .trim_end_matches(';')
}

/// Every `.rs` file under `root`, deepest-first order made deterministic by
/// sorting, so a failure names the same file every run.
fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Every `in_writer_txn` CALL SITE in this crate's `src/`, keyed
/// `<path under src/>::[<Type>::]<fn>`, with the line it sits on.
///
/// # Why the source and not the types
///
/// There is no way to ask the compiler "who calls this?" from a test, and the fact
/// at issue is a fact about production source. `bin/kata-eval`'s gate guards and
/// this file's own `ELSEWHERE` check already re-derive claims from source text for
/// the same reason, and the `CARGO_MANIFEST_DIR` anchor is `gate_exclusion.rs`'s.
///
/// # What it does and does not see
///
/// It attributes a call site to the nearest preceding `fn` declaration, scoped by
/// the nearest preceding COLUMN-ZERO `impl` (reset by a column-zero `fn`, which
/// begins a free-function region). It skips comment lines, so the module docs that
/// discuss `in_writer_txn` are not callers. It does NOT understand `macro_rules!`
/// bodies or `include!`, and it would attribute a call inside a nested `mod` block
/// to the enclosing top-level `impl` — all three would produce a key absent from
/// [`WRITER_TRANSACTIONS`] and therefore a RED test, never a silent pass.
fn scan_writer_transactions() -> Vec<(String, usize)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(
        root.is_dir(),
        "{} must exist: this guard reads production source, and a guard that cannot find it must \
         fail rather than report an empty caller set",
        root.display()
    );

    let mut found = Vec::new();
    for file in rust_sources(&root) {
        let relative = file
            .strip_prefix(&root)
            .expect("walked from root")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
        let mut scope: Option<String> = None;
        let mut function: Option<String> = None;
        for (index, line) in text.lines().enumerate() {
            if let Some(header) = line.strip_prefix("impl")
                && header.starts_with([' ', '<'])
            {
                scope = Some(impl_target(header).to_string());
            }
            if let Some((indent, name)) = fn_declaration(line) {
                if indent == 0 {
                    scope = None;
                }
                function = Some(name.to_string());
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            if !line.contains("in_writer_txn(") || line.contains("fn in_writer_txn") {
                continue;
            }
            let function = function.as_deref().unwrap_or_else(|| {
                panic!(
                    "{relative}:{} calls in_writer_txn outside any function",
                    index + 1
                )
            });
            let key = match &scope {
                Some(scope) => format!("{relative}::{scope}::{function}"),
                None => format!("{relative}::{function}"),
            };
            found.push((key, index + 1));
        }
    }
    found
}

/// EVERY writer transaction in production has a standing on the transaction axis,
/// and every standing names a writer that still exists.
///
/// # The defect, stated as it happened
///
/// Writers such as `record_stop_request`, `mark_stop_delivered` and
/// `acknowledge_stop` each open an `in_writer_txn`. With a transaction axis typed out
/// by hand and compared against nothing, none would become a [`Group`], none would be
/// recorded as not needing to be, and the gate would be green. The crash proof is
/// stated over EVERY transaction boundary, so a change that widens the set of
/// boundaries silently widens the set the proof is CLAIMED over.
///
/// # What this asserts
///
/// 1. Every `in_writer_txn` caller the source scan finds has a row in
///    [`WRITER_TRANSACTIONS`]. This is the half that catches an unaccounted writer.
/// 2. Every row names a caller the scan still finds — a row that outlives its
///    writer is a stale claim, the same defect pointed the other way, and it is
///    how a roster silently stops describing anything.
/// 3. `Cell` and [`Group`] are a BIJECTION: every group is claimed by exactly one
///    row, and every `Cell` row names a group that exists. With `Group::iter()`
///    derived by `EnumIter`, this is what makes a variant that is never driven, or
///    a driven transaction that is not a variant, both impossible.
/// 4. Every `NoCell` reason is a reason. Weak, and it is the weakest check here on
///    purpose — the precedent is `dev-loop-check`'s "every row states a why", which
///    also cannot judge the why and is worth having anyway.
///
/// # Non-vacuity
///
/// A source scan that matches nothing passes every assertion above and reports
/// perfect accounting — a check whose refused set is empty. The floor below
/// is therefore asserted BEFORE anything else, and it is a floor rather than an
/// exact count so that adding a writer fails on the accounting (which names the
/// writer) rather than on a number.
#[test]
fn every_writer_transaction_is_accounted_for_on_the_transaction_axis() {
    const OWN_SOURCE: &str = include_str!("operational_crash_matrix.rs");
    /// The count at the time this guard landed was 53, across six files. A scan
    /// that finds fewer than this many has stopped parsing, not stopped finding.
    const FLOOR: usize = 50;

    let scanned = scan_writer_transactions();
    assert!(
        scanned.len() >= FLOOR,
        "the source scan found only {} `in_writer_txn` call sites; it found 53 when this guard \
         landed, so a result below {FLOOR} means the PARSER broke, not that production shrank. A \
         guard that silently scans nothing reports perfect accounting",
        scanned.len()
    );

    // (1) — a writer with no standing.
    let mut unaccounted = Vec::new();
    for (scope, line) in &scanned {
        if !WRITER_TRANSACTIONS.iter().any(|row| row.scope == scope) {
            unaccounted.push(format!("{scope} (src/ line {line})"));
        }
    }
    assert!(
        unaccounted.is_empty(),
        "these production transactions open an `in_writer_txn` and have NO standing on the crash \
         matrix's transaction axis: {unaccounted:?}.\nThe crash proof is stated over every \
         transaction boundary, so each one needs a row in `WRITER_TRANSACTIONS` declaring either \
         the `Group` whose cell drives it or the reason it needs none. A single-statement \
         transaction with no companion write is a legitimate reason — it is the reason the \
         stop writers carry — but it has to be WRITTEN DOWN"
    );

    // (2) — a standing whose writer is gone.
    let mut stale = Vec::new();
    for row in WRITER_TRANSACTIONS {
        if !scanned.iter().any(|(scope, _)| scope == row.scope) {
            stale.push(row.scope);
        }
    }
    assert!(
        stale.is_empty(),
        "these rows claim a standing for a transaction that no longer opens an `in_writer_txn`: \
         {stale:?}. Renamed, moved or deleted — either way the row describes nothing, and a \
         roster of rows that describe nothing is how this table would stop guarding"
    );

    // (3) — `Cell` and `Group` are a bijection.
    for group in Group::iter() {
        let claims: Vec<&'static str> = WRITER_TRANSACTIONS
            .iter()
            .filter(|row| matches!(row.standing, Standing::Cell(claimed) if claimed == group))
            .map(|row| row.scope)
            .collect();
        assert_eq!(
            claims.len(),
            1,
            "{group:?} must be claimed by exactly ONE writer transaction, found {claims:?}. Zero \
             means the group's cells drive a transaction this table does not know about; more \
             than one means two writers claim the same cell and only one of them is really driven"
        );
        // Coarse, and stated as coarse for the same reason `Elsewhere::source` is:
        // a mention is not a drive. It CAN tell a `Cell` naming a method this file
        // never touches from one it does, which is the failure that matters — the
        // method name reaches `Group::drive` through a helper (`submit`, `claim`,
        // `dispatch`) for three of the groups, so the search is over the whole file.
        let method = claims[0].rsplit("::").next().expect("a non-empty scope");
        assert!(
            OWN_SOURCE.contains(method),
            "{group:?} is claimed by {} but this file's source never names `{method}`, so nothing \
             here drives it",
            claims[0]
        );
    }

    // (4) — every `NoCell` states a why.
    for row in WRITER_TRANSACTIONS {
        if let Standing::NoCell(reason) = row.standing {
            assert!(
                reason.len() >= 40,
                "{}'s reason for having no cell is {} characters: {reason:?}. State what the \
                 transaction writes and why a crash cell is not owed — the next person to add a \
                 writer reads these to pick their own standing",
                row.scope,
                reason.len()
            );
        }
    }

    // Non-vacuity, second form: the table must not have quietly become all-`NoCell`
    // or all-`Cell`. Both are real states this file could reach by accident and
    // neither is a state anyone would choose.
    let cells = WRITER_TRANSACTIONS
        .iter()
        .filter(|row| matches!(row.standing, Standing::Cell(_)))
        .count();
    assert_eq!(
        cells,
        Group::iter().count(),
        "every group must be driven by exactly one of the {} rows in this table",
        WRITER_TRANSACTIONS.len()
    );
    assert!(
        cells < WRITER_TRANSACTIONS.len(),
        "non-vacuity: the table has stopped distinguishing driven writers from accounted-for ones"
    );
}
