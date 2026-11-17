//! AUTHORIZATION: the door between a lowered
//! operation and a durable, dispatched capsule attempt.
//!
//! # What this module is
//!
//! [`prepare_action`] and [`authorize_attempt`] are the two halves of "this node has
//! decided to run this occurrence". The first computes the [`PreparedAction`]
//! identity from values only (no row, no byte, no lock); the second makes that
//! decision durable, in the order ADR-0001's trust boundaries require, and enqueues
//! exactly one dispatch for it.
//!
//! This is the binder of the durable shape (`occurrences`,
//! `attempts.occurrence_id`, `AttemptClaimSpec.occurrence`): it binds
//! `prepared_action_id` and `capsule_id`.
//!
//! # BYTES BEFORE REFERENCES, at every step
//!
//! ADR-0001 trust boundary 2. [`authorize_attempt`] runs in exactly this order, and
//! the order is the invariant rather than an implementation detail:
//!
//! 1. the ENVIRONMENT GATE, which writes nothing and publishes nothing — so a
//!    refusal here leaves the CAS byte-for-byte unchanged;
//! 2. `CasStore::put_durable` for the capsule's canonical bytes, which mints the
//!    only [`DurableObject`](kata_core::store::cas::DurableObject) receipt that
//!    exists and does so only after the bytes are fsync-durable;
//! 3. `declare_capsule`, which writes the `capsules` row and the node-owned
//!    authoritative `cas_roots` row that RETAINS those bytes, in one transaction;
//! 4. `claim_attempt` with the [`OccurrenceBinding`](kata_core::OccurrenceBinding) —
//!    occurrence row, attempt row and claiming transition in ONE writer transaction,
//!    which is `claim_attempt`'s own transaction and not a second one;
//! 5. `dispatch_claimed_attempt`, which records the `dispatched` transition and the
//!    durable command in one further transaction.
//!
//! # A GATED occurrence stops at 4
//!
//! When the checked stage declares `approval = True`, step 4 claims the attempt PARKED
//! `awaiting_approval` (`claim_attempt_parked_for_approval`, still one transaction) and
//! step 5 does not happen: [`authorize_attempt`] returns `Authorization::Parked`. A
//! re-presentation re-reads the park (`parked_capsule_attempt_at_occurrence`) and
//! returns it unchanged; it never adopts and dispatches it. The dispatch happens only
//! through `OperationalDb::decide_capsule_approval`.
//!
//! # The crash windows this order leaves, named
//!
//! Between 2 and 3 the capsule's bytes are durable and NOTHING references them.
//! That window is **K8**, `operational.after_cas_object_durable_before_root`, and it
//! is registered at the end of `put_durable` itself. It needs no repair: an object no
//! `cas_roots` row names is an orphan, so a crash here costs bytes on disk (kata has
//! no CAS collection) and costs no correctness at all. That is why the publish is allowed to precede the
//! row while the reverse — a row naming bytes that may not exist — is not.
//!
//! Between 4 and 5 the occurrence is durable and AUTHORIZED and no dispatch command
//! has been written for it. That window is
//! `after_occurrence_authorized_before_dispatch`, in the Dispatch family, and it fires
//! inside `claim_attempt` after that transaction commits (one statement after K2,
//! `operational.after_claim_commit`, which names the same durable state as a
//! transaction edge). Its recovery obligation is the one the boundary was registered
//! for: a durable occurrence acquires exactly one dispatch. A restarted main
//! discharges it at the execution's runner boot, which dispatches the claim off its
//! durable row (`Dispatcher::dispatch_claims_left_undispatched`) — nothing presents
//! the occurrence to this door a second time. This door holds the same obligation for
//! a presentation that does find such a claim: it adopts it (`authorize.rs`,
//! `declare_up_to_the_claim`). This is also why the FUSED `dispatch_attempt` door
//! refuses an occurrence binding by name — it would close the window and make the
//! boundary unreachable.
//!
//! # What this module does NOT do
//!
//! It does not assemble the capsule ([`crate::capsule_assembly`] does, from values),
//! does not declare the capsule's INPUT artifacts (a capsule's inputs are bound
//! before it is assembled; `declare_capsule` refuses a mapping whose artifact has no
//! live row, and that refusal is the contract rather than something this door
//! papers over), does not resolve a sandbox profile, does not decide WHICH worker (it
//! calls the caller's `AuthorizeInput::place` once, and only when it dispatches), and
//! does not execute anything. Its production caller is the capsule submit path
//! (`runner::dispatch::capsule_submit`), the shell-stage class's route under the
//! `oci` execution profile.
//!
//! [`PreparedAction`]: kata_types::execution_contract::PreparedAction

mod authorize;
mod prepare;

pub use authorize::{
    Authorization, AuthorizeInput, Authorized, CAPSULE_PROGRAM_NOT_IN_ENVIRONMENT,
    CAPSULE_REQUIREMENT_NOT_IN_ENVIRONMENT, HostProgramProbe, ParkedGate, ProgramProbe,
    WORK_TREE_NOT_ROLE_BOUND, authorize_attempt, refuse_requirements_not_in_the_environment,
};
pub(crate) use authorize::{
    approval_gate_reason, authorize_attempt_reporting_claim, capsule_dispatch_command,
};
pub use prepare::prepare_action;
