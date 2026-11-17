//! Deterministic, env-gated crash fault-injection points.
//!
//! Used ONLY by the crash-recovery matrix's opt-in real-process smoke
//! (`crates/test-utils/tests/smokes.rs::smoke_crash_recovery_*`) to make a
//! live `kata` daemon abort at a PRECISE, reproducible code boundary — no
//! `sleep`/poll-then-kill timing races. The crash is triggered by a named
//! fault point matching the `KATA_FAULT_INJECT` env var, so it is fully
//! deterministic and reproducible.
//!
//! # Production is unaffected
//!
//! When `KATA_FAULT_INJECT` is unset — which is always the case in
//! production — every call site is a single cached [`OnceLock`] read that
//! returns `None`, followed by an early return. No allocation, no syscall
//! per call, and behaviour is byte-identical to having no call at all. The
//! env var is read exactly once for the lifetime of the process and cached.
//!
//! # Fault target grammar
//!
//! The target names an operational boundary; typed worker acceptance uses K6/K7
//! below.
//!
//! Current smoke example: `KATA_FAULT_INJECT=operational.after_accept_event`
//! aborts after typed acceptance, lifecycle/effect settlement and the inbox
//! watermark commit together, before the accepting handler returns. Independent
//! delivery may already observe the committed chain. Restart folds that
//! operational authority without reapplying the worker effect.
//!
//! # The action: abort, or stop
//!
//! `KATA_FAULT_INJECT_ACTION` picks what an armed point does once reached:
//!
//! | `KATA_FAULT_INJECT_ACTION` | At the point…                                                      |
//! |----------------------------|--------------------------------------------------------------------|
//! | unset, empty or `abort`    | writes the marker with `action=abort` and dies by SIGABRT           |
//! | `stop`                     | writes the marker with `action=stop` and SIGSTOPs the whole process from the calling thread (state `T`) |
//! | anything else              | writes the marker with `action=abort`, names the refused value, and aborts |
//!
//! `stop` exists for a kill that must land OUTSIDE the process: a harness waits for
//! the marker, confirms the whole process is stopped (every
//! `/proc/<pid>/task/*/stat` in state `T`, not only the leader's `/proc/<pid>/stat`),
//! then kills the machine under it (a VM's host process), which a process that has
//! already aborted cannot model. A stopped point never runs past its boundary:
//! resumed, it aborts.
//!
//! Every abort is first made not dumpable (best effort), so it dumps no core: a
//! `core_pattern` that pipes to a helper would otherwise hold each crash cell's
//! dying process while the helper reads the dump. A stopped point stays dumpable
//! while it is stopped.
//!
//! Durability scope: `operational.db` requests `synchronous=FULL` for its
//! authoritative execution evidence and claims. These fault points exercise a **process crash /
//! SIGKILL**; they do not simulate power loss or prove the filesystem and device
//! honor SQLite's synchronization requests. The repository's writes are held across a
//! power loss by a separate mechanism — a `syncfs` barrier before what depends on them
//! (`kata_vcs::jj` `durability`) — proven at the syscall boundary
//! (`just repository-barrier-live`), by torn-repository cells that write what a power loss
//! leaves, and by E3's host column, which kills the VM under a stopped node.
//!
//! # The `operational.<boundary>` namespace
//!
//! [`operational_crash_point`] is the sibling gate for the authoritative
//! `operational.db` plane. It carries NO status tag — an operational boundary
//! names a transaction edge, not a per-status latch — so its grammar is the flat
//! `operational.<boundary>`:
//!
//! | `KATA_FAULT_INJECT`                        | Crashes when…                                                        |
//! |--------------------------------------------|----------------------------------------------------------------------|
//! | `operational.before_claim_commit`          | an attempt claim is fully written and NOT committed (K1) |
//! | `operational.after_claim_commit`           | the claim is fsync-durable and nothing has been dispatched for it (K2) |
//! | `operational.before_txn_commit`            | ANY typed transaction is fully staged and has not committed (K3) |
//! | `operational.after_txn_commit`             | ANY typed transaction is fsync-durable and nothing downstream has run (K4) |
//! | `operational.before_accept_event`          | the arrival gate has BUFFERED a worker's failure report and its adjudication is about to accept it, uncommitted (K6); a completion is never buffered, so only the failure door reaches it |
//! | `operational.after_accept_event`           | new acceptance + attempt transition + inbox watermark have COMMITTED, before the accepting handler returns (K7); typed worker paths also commit effect/stop settlement, and independent delivery may observe the commit |
//! | `operational.after_cas_object_durable_before_root` | a CAS object's bytes are fsync-durable and its `cas_objects` row committed, and NO operational root references them yet (K8) |
//! | `operational.after_container_exited_before_result_published` | a capsule's container has EXITED, its `/out` bytes are on the worker's disk, and no CAS object or operational row references them (worker-side) |
//! | `operational.after_work_delta_published_before_completion` | a capsule's `/work` delta and its changed member objects are fsync-durable in the CAS, and NO `CompletedCapsule` frame names them (worker-side) |
//! | `operational.after_capsule_dispatched_before_send` | a CAPSULE attempt's placement (`dispatched` and its command) is durable and its frame has NOT been handed to the transport |
//! | `operational.after_nix_root_staged_before_manifest_durable` | the staging generation is NAMED in the declaration and no operational row/root references the environment manifest yet, so its bytes are an orphan (K14) |
//! | `operational.after_environment_row_committed_before_root_promoted` | the `nix_environments` row is fsync-durable and its gc root is still in its STAGING generation (K15) |
//! | `operational.after_base_tree_published_before_head_recorded` | an isolated execution's committed-base tree artifact + its `cas_roots` retention are durable, and NO `execution_work_tree_heads` row names it yet (K16) |
//! | `operational.after_scratch_seed_published_before_head_recorded` | a non-isolated `oci` execution's seeded scratch tree artifact + its `cas_roots` retention are durable, and NO root `execution_work_tree_heads` row names it yet (K16's non-isolated twin) |
//! | `operational.after_git_view_published_before_recorded` | an execution's git-history artifact + its `cas_roots` retention are durable, and NO `execution_git_views` row names it yet (K16's shape one plane over) |
//! | `operational.after_target_pinned_before_acceptance` | an isolated submission's execution target is resolved and its `refs/kata/targets/<id>/…` pins are written, and NOTHING is accepted — no `programs` row exists |
//! | `operational.after_first_provider_event` | the node's embedded harness observed its first completed model call — the provider answered, so a model request delivered output — and the attempt's terminal is not built (worker-side; the `Harness` family) |
//!
//! # Every row carries its BOUNDARY FAMILY
//!
//! Each entry names an [`OperationalBoundaryFamily`], because the crash proof's
//! obligation is stated over FAMILIES ("transaction/dispatch/CAS/jj") and a
//! flat list of names cannot express "this family has nothing in it". See that type
//! for the failure this closes.
//!
//! # Why K8 lives in the `operational.` namespace despite firing in the CAS
//!
//! The kill point is "between a CAS object byte becoming durable and its root
//! insertion". Both ends of that window belong to the
//! operational plane's authority even though the near end is inside
//! [`CasStore::put_durable`]: the thing being crashed around is the ROOT, and the
//! root is an `operational.db` row. Keeping one flat registry
//! ([`OPERATIONAL_CRASH_BOUNDARIES`]) is also what lets the crash harness enumerate its
//! own kill-point axis — a second namespace would be a second list to keep in sync,
//! and the accounting test could no longer prove every boundary has a cell.
//!
//! [`CasStore::put_durable`]: crate::store::cas::CasStore::put_durable
//!
//! # K14/K15 bracket the NIX plane's two edges, and the family is not a crash-proof one
//!
//! The managed-software profile splits the obligation: "Nix owns package
//! realization, closure transport, store verification mechanisms, and collection. Kata
//! owns which exact closure was authorized, its binding and evidence, retention
//! intent, privacy classification, and **crash-safe coordination with Nix roots**."
//! That last clause is a two-edged window, so it has two boundaries and one cell
//! cannot cover both.
//!
//! K14 is the STAGING edge: the staging generation is named in the declaration and no
//! `nix_environments` row and no manifest `cas_roots` row reference it, so the manifest's
//! bytes are written but UNREFERENCED — an orphan that costs disk. Recovery
//! converges by sweeping the orphan staging generation — there is nothing any reader can
//! mistake for an authorized environment, which is the fail-safe direction.
//!
//! WHAT THIS PLANE CAN AND CANNOT SEE, stated because the boundary's name invites the
//! stronger reading: `operational.db` holds the staging generation's NAME and nothing
//! else about it. The on-disk `nix-store --add-root` indirect root is created, promoted
//! and swept by `kata_core::environment`, and the crash proof for the DIRECTORY (staged
//! with no row, swept on boot) lives in `crates/core/tests/nix_environment_plane.rs`
//! beside that code. This boundary's own cell, in `cas_root_liveness.rs`, proves the
//! operational half: absent row, absent root, orphan manifest.
//!
//! K15 is the PROMOTION edge: the row is fsync-durable and unpromoted, so the
//! environment is DECLARED and NOT bindable. Recovery is
//! `OperationalDb::unpromoted_environments`, which the boot reconciler drives; the
//! index behind it is partial on exactly this state, so the cost of the scan is the
//! size of the crash residue.
//!
//! The near edge of K14 is the CALLER's obligation: nothing in this
//! plane can prove `nix-store --add-root` returned, and nothing in it can observe the
//! directory afterwards. The seam therefore sits in
//! [`OperationalDb::declare_environment`], the one place both halves of the window are
//! named at once (the staging generation is named in the declaration, the row is not yet
//! written), rather than in the declaration constructor, where only the manifest half is
//! provable.
//!
//! [`OperationalBoundaryFamily::Nix`] is deliberately NOT in the test-support
//! `OperationalBoundaryFamily::CRASH_PROOF_FAMILIES`: the crash proof
//! (`tests/operational_crash_matrix.rs`) names four families and this is not one
//! of them. Inventing a fifth would be a check restating what it should re-derive.
//!
//! [`OperationalDb::declare_environment`]: crate::operational::OperationalDb::declare_environment
//!
//! # Why K3/K4 are GENERIC and K1/K2/K6/K7 are specific
//!
//! K3 and K4 sit at [`OperationalDb::in_writer_txn`](crate::OperationalDb::in_writer_txn), the
//! single chokepoint every
//! typed method funnels through, so TWO call sites cover every transaction group —
//! and cover one added later without being touched. Per-group literal pairs would be
//! call sites a new group could silently miss.
//!
//! The specific boundaries stay because they name a moment the generic pair cannot
//! see: K1/K2 bracket the claim WITHIN a method that also writes an attempt row,
//! K6/K7 bracket the gate-then-fold COMPOSITION across two transactions.
//!
//! A matrix cell that wants K3/K4 for one specific group builds its fixture in a
//! FIRST, unarmed process and runs only the group's transaction in the ARMED
//! child, so the generic boundary fires on the transaction under test rather than
//! on fixture setup. That is also a more faithful crash model than arming a
//! process that is still constructing its own preconditions.
//!
//! Durability scope differs from the ledger's: `operational.db` commits at
//! `synchronous=FULL`, so a returned commit is fsync-durable and survives a power
//! loss as well as a process abort. That is what makes K4 and K7 meaningful — the
//! commit is durable while nothing downstream has run.

use std::sync::OnceLock;

/// Cached `KATA_FAULT_INJECT` value. Read once, on first call, for the
/// lifetime of the process. `None` (the production default) short-circuits
/// every fault point to an early return.
static TARGET: OnceLock<Option<String>> = OnceLock::new();

fn target() -> Option<&'static str> {
    TARGET
        .get_or_init(|| {
            std::env::var("KATA_FAULT_INJECT")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .as_deref()
}

/// The RESOURCE whose boundary a registered kill point crosses.
///
/// # Why this exists
///
/// The operational plane's CRASH PROOF is: crash at every
/// **transaction/dispatch/CAS/jj** boundary and prove no unjustified state
/// advances. A flat list of boundary names lets an accounting test tell you that a
/// REGISTERED boundary has no cell, and never that an entire named boundary class
/// has no boundary at all: a family with no seam, no registration and no cell is
/// invisible to it.
///
/// A guard that can only see what someone remembered to register cannot report the
/// thing it exists to report. So the families come from the proof's own enumeration —
/// an INDEPENDENT source from the registry — and `Self::CRASH_PROOF_FAMILIES` is
/// asserted NON-EMPTY per family. Deleting the last `jj` boundary now fails a test instead of
/// silently shrinking the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationalBoundaryFamily {
    /// The operational writer transaction itself (the single-writer path).
    Transaction,
    /// The dispatch handoff: a durable authorization or placement versus the
    /// frame that carries it to a worker.
    Dispatch,
    /// Content-addressed object bytes versus an operational reference.
    Cas,
    /// The jj/VCS repository: durable intent/claim, observed ref/tree identity,
    /// committed outcome.
    Jj,
    /// The Nix store/gc-root plane versus this node's declared-environment authority
    /// ("crash-safe coordination with Nix roots").
    ///
    /// Excluded from `Self::CRASH_PROOF_FAMILIES`: the crash proof enumerates four
    /// families and Nix is not among them. The exclusion is what keeps the family list a
    /// re-derivation of the proof rather than a restatement of whatever this registry happens to
    /// contain.
    Nix,
    /// The node's embedded harness: a model request the provider answered versus
    /// the attempt's settlement. Its edge is a PROCESS boundary, not a durable
    /// one — the point ends the process hosting the harness, and what it proves
    /// is which process that is and that the main settles the attempt it lost.
    ///
    /// Excluded from `Self::CRASH_PROOF_FAMILIES` for Nix's reason: the crash
    /// proof names four families and this is not one of them.
    Harness,
}

impl OperationalBoundaryFamily {
    /// The FOUR families the crash proof names, each of which must have at
    /// least one registered boundary.
    #[cfg(any(test, feature = "test-support"))]
    pub const CRASH_PROOF_FAMILIES: &'static [OperationalBoundaryFamily] = &[
        OperationalBoundaryFamily::Transaction,
        OperationalBoundaryFamily::Dispatch,
        OperationalBoundaryFamily::Cas,
        OperationalBoundaryFamily::Jj,
    ];

    /// Every family, including Nix and Harness, which the crash proof does not
    /// name.
    pub const ALL: &'static [OperationalBoundaryFamily] = &[
        OperationalBoundaryFamily::Transaction,
        OperationalBoundaryFamily::Dispatch,
        OperationalBoundaryFamily::Cas,
        OperationalBoundaryFamily::Jj,
        OperationalBoundaryFamily::Nix,
        OperationalBoundaryFamily::Harness,
    ];

    /// The stable label, spelled as the crash proof spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OperationalBoundaryFamily::Transaction => "transaction",
            OperationalBoundaryFamily::Dispatch => "dispatch",
            OperationalBoundaryFamily::Cas => "CAS",
            OperationalBoundaryFamily::Jj => "jj",
            OperationalBoundaryFamily::Nix => "nix",
            OperationalBoundaryFamily::Harness => "harness",
        }
    }
}

/// One registered `operational.<boundary>` kill point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationalCrashBoundary {
    /// The name that follows `operational.` in `KATA_FAULT_INJECT`.
    pub name: &'static str,
    /// Which cross-resource boundary family this one crosses.
    pub family: OperationalBoundaryFamily,
}

/// Every registered `operational.<boundary>`, in kill-point order, WITH the
/// boundary family each one crosses.
///
/// The one place a matrix cell names a boundary. Registering here rather than
/// spelling a literal at each cell is what lets the crash harness enumerate its own
/// kill-point axis instead of a reader having to trust that a prose table matches
/// the call sites — and carrying the family in the SAME row rather than a parallel
/// list is what keeps the two from drifting (this module's own "a second namespace
/// would be a second list to keep in sync" argument, applied to itself).
pub const OPERATIONAL_CRASH_BOUNDARIES: &[OperationalCrashBoundary] = &[
    OperationalCrashBoundary {
        name: "before_claim_commit",
        family: OperationalBoundaryFamily::Transaction,
    },
    OperationalCrashBoundary {
        // K2, as a transaction edge: the claim is durable and nothing was dispatched
        // for it. The durable state is `after_occurrence_authorized_before_dispatch`'s
        // (one statement later, in the Dispatch family), and so is its recovery: the
        // restarted main's runner dispatches the claim once, off its durable row.
        name: "after_claim_commit",
        family: OperationalBoundaryFamily::Transaction,
    },
    OperationalCrashBoundary {
        name: "before_txn_commit",
        family: OperationalBoundaryFamily::Transaction,
    },
    OperationalCrashBoundary {
        name: "after_txn_commit",
        family: OperationalBoundaryFamily::Transaction,
    },
    OperationalCrashBoundary {
        name: "before_accept_event",
        family: OperationalBoundaryFamily::Transaction,
    },
    OperationalCrashBoundary {
        name: "after_accept_event",
        family: OperationalBoundaryFamily::Transaction,
    },
    OperationalCrashBoundary {
        name: "after_cas_object_durable_before_root",
        family: OperationalBoundaryFamily::Cas,
    },
    OperationalCrashBoundary {
        // WORKER-SIDE. In the `operational.` namespace
        // and the `Cas` family for K8's own reason, which this module already argues
        // one section down: the edge being crashed around is "bytes exist and
        // nothing references them", and the namespace names the PLANE the reference
        // would have been written into, not the process the abort happens in.
        //
        // Recovery is SETTLEMENT, not repair: the abort ends the worker process,
        // its connection closes, and the main's worker-death leg settles the
        // attempt failed PROVEN AMBIGUOUS (`settle_lost_capsule_attempt`; a
        // restarted main's `settle_capsule_attempts_after_restart` records the
        // same verdict). `/out` is never adopted — the only thing that adopts one
        // is a `CompletedCapsule` frame this abort prevented from being sent — and
        // nothing re-runs the stage: the failure retry never re-runs a PROVEN
        // AMBIGUOUS attempt.
        name: "after_container_exited_before_result_published",
        family: OperationalBoundaryFamily::Cas,
    },
    OperationalCrashBoundary {
        // The same worker-side handoff, one publish later:
        // the `/work` delta's members and the delta object itself are durable
        // in the CAS, and the `CompletedCapsule` frame that could name them is
        // not built (it is constructed from `publish_work_delta`'s `Ok`).
        // Recovery is the container-exited window's own: the worker-death leg
        // settles the attempt PROVEN AMBIGUOUS and nothing re-runs the stage. The
        // objects carry no `cas_roots` row — the only writer of one is the
        // accepting transaction on the main — so the residue is a safe orphan.
        // Its cell is `work_delta`'s
        // `after_work_delta_published_before_completion_leaves_an_orphan_delta`,
        // which drives an unarmed re-publish to prove the delta's publish is
        // content-idempotent: a re-publish converges on the identical object.
        name: "after_work_delta_published_before_completion",
        family: OperationalBoundaryFamily::Cas,
    },
    // The FAR edge of the same handoff has NO boundary, by construction: the main
    // declares a capsule's result tree, its captures and its `/work` delta in the
    // SAME writer transaction that accepts the completion
    // (`OperationalDb::adopt_and_accept_capsule_completion`), so there is no
    // durable state between "artifacts retained" and "outcome accepted" for a
    // crash to land in. The first durable edge after the frame arrives is
    // `after_accept_event`.
    // The `/work` apply's own crash windows, shared by BOTH apply legs (the jj
    // leg for an isolated execution's root head, the CAS-only leg for every
    // branch and non-isolated head): the CLAIM committed and the leg's apply effect has
    // not run (the pending attempt is the sweep's enumeration input), and the
    // effect PUBLISHED — the tagged jj op, or the applied manifest's CAS
    // bytes — but the resolve, the head advance, has not committed (on the jj
    // leg the `kata.effect` tag is the reconcile evidence
    // `classify_work_apply` reads; on the CAS leg the pending attempt's own
    // base re-check is). A third jj-leg window — publish before the
    // working-copy checkout — is armed inside `kata-vcs`'s apply itself
    // (`KATA_WORK_APPLY_CRASH_ARM`), because the publish and the checkout are
    // one provider call no dispatcher line can sit between.
    OperationalCrashBoundary {
        name: "after_work_apply_claimed_before_apply",
        family: OperationalBoundaryFamily::Jj,
    },
    OperationalCrashBoundary {
        name: "after_work_apply_published_before_resolve",
        family: OperationalBoundaryFamily::Jj,
    },
    // ...and the acceptance half: the resolve transaction — apply attempt
    // terminal, `execution_work_tree_heads` advanced in the same commit — is
    // durable but the pass has not released the stage's successors. Recovery
    // needs no apply state at all: `pending_work_apply_for_stage` reads the
    // committed answer and the gate opens on the next advance.
    OperationalCrashBoundary {
        name: "after_work_apply_acceptance_before_successor_release",
        family: OperationalBoundaryFamily::Jj,
    },
    // The `oci` `workspace_effect`'s windows,
    // the same shape as the apply's: the CLAIM committed and the verb has not
    // run; the verb's jj op PUBLISHED (or the remote push landed, for
    // `forge_export`) and the attempt's resolve has not committed. Recovery is
    // the sweep's classify leg reading the repository — and for the export,
    // the REMOTE — for the published fact rather than re-driving.
    OperationalCrashBoundary {
        name: "after_workspace_effect_claimed_before_jj_publish",
        family: OperationalBoundaryFamily::Jj,
    },
    OperationalCrashBoundary {
        name: "after_workspace_effect_jj_publish_before_resolution",
        family: OperationalBoundaryFamily::Jj,
    },
    // A `forge_export`'s wire effects, each under an intent row (E1). Before
    // the push's intent: the remote's head is read (the lease), nothing is
    // issued, and recovery performs the export from the start. Intent
    // committed, push not sent: the push's observer reads the ref still at
    // the lease, NOT PERFORMED, and the push runs again under a fresh intent.
    // Push returned, its receipt not committed (`after_forge_push_before_pr`):
    // the observer reads kata's commit, PERFORMED, and the pull request
    // follows. The pull request's intent committed, create not sent; and the
    // create returned, its receipt not committed: the marker observer decides,
    // NOT PERFORMED (opened again under a fresh intent) or the marked pull
    // request in any state, adopted.
    OperationalCrashBoundary {
        name: "after_forge_read_before_push_intent",
        family: OperationalBoundaryFamily::Jj,
    },
    OperationalCrashBoundary {
        name: "after_forge_push_intent_before_push",
        family: OperationalBoundaryFamily::Jj,
    },
    OperationalCrashBoundary {
        name: "after_forge_push_before_pr",
        family: OperationalBoundaryFamily::Jj,
    },
    OperationalCrashBoundary {
        name: "after_forge_pr_intent_before_create",
        family: OperationalBoundaryFamily::Jj,
    },
    OperationalCrashBoundary {
        name: "after_forge_pr_create_before_receipt",
        family: OperationalBoundaryFamily::Jj,
    },
    OperationalCrashBoundary {
        name: "after_nix_root_staged_before_manifest_durable",
        family: OperationalBoundaryFamily::Nix,
    },
    OperationalCrashBoundary {
        // WORKER-SIDE, in the node that hosts the embedded harness
        // (`kata_worker::agent_turn`): the first `model_call_completed` the
        // harness reports. The provider answered, so the attempt can no longer
        // be PROVEN NOT PERFORMED; the abort ends the node, never the main, and
        // the main settles the attempt by its worker-death reconciliation.
        name: "after_first_provider_event",
        family: OperationalBoundaryFamily::Harness,
    },
    OperationalCrashBoundary {
        name: "after_environment_row_committed_before_root_promoted",
        family: OperationalBoundaryFamily::Nix,
    },
    OperationalCrashBoundary {
        // The claim's transaction committed — occurrence, attempt, claiming transition —
        // and no dispatch was written. Recovery is the DISPATCH the crash interrupted,
        // made once: a restarted main resumes the execution and its runner's boot
        // dispatches that attempt off its durable row and delivers its frame
        // (`Dispatcher::dispatch_claims_left_undispatched`), claiming no second
        // attempt; a dispatch that cannot be made settles the claim PROVEN NOT
        // PERFORMED and fails the run. A claim whose execution does not resume (it
        // latched an outcome) is settled PROVEN NOT PERFORMED by the abandoned-claim
        // legs. A claim PARKED awaiting approval is not in this window's recovery: it
        // stays parked.
        name: "after_occurrence_authorized_before_dispatch",
        family: OperationalBoundaryFamily::Dispatch,
    },
    OperationalCrashBoundary {
        // The CAPSULE ARM's dispatch boundary, main-side: the
        // placement transaction (`dispatched` and the command) committed and
        // the frame was never handed to the transport. There is no capsule re-delivery,
        // so recovery is SETTLEMENT: the next main's restart leg records the attempt
        // PROVEN AMBIGUOUS (the plane cannot tell this window from a frame that left)
        // before any runner resumes.
        name: "after_capsule_dispatched_before_send",
        family: OperationalBoundaryFamily::Dispatch,
    },
    OperationalCrashBoundary {
        // K8's window, one level up: the base
        // tree's members, manifest, `artifacts` row and owner `cas_roots` row
        // are all durable, and the `execution_work_tree_heads` row that makes
        // them THIS execution's `/work` is not yet written. Recovery is
        // RE-ADMISSION — the next admission finds no head row and re-publishes
        // the same committed tree (CAS dedup makes the republish content
        // idempotent; `record_work_tree_head`'s converge-or-refuse accepts the
        // same pair and refuses a divergent one). No capsule can outrun the
        // window: the head precedes `mark_running_after_admission`, so nothing
        // an attempt observes can exist before it closes.
        name: "after_base_tree_published_before_head_recorded",
        family: OperationalBoundaryFamily::Cas,
    },
    OperationalCrashBoundary {
        // K16's NON-ISOLATED twin: the seeded scratch tree's
        // members, manifest, `artifacts` and `cas_roots` rows are durable and
        // the root (`branch = ''`) `execution_work_tree_heads` row is not yet
        // written. Recovery is the same re-admission — CAS dedup makes the
        // re-seed content-idempotent and `record_work_tree_head` converges on
        // an identical row while refusing a divergent one.
        name: "after_scratch_seed_published_before_head_recorded",
        family: OperationalBoundaryFamily::Cas,
    },
    OperationalCrashBoundary {
        // The same window one table over: the git
        // history artifact's members, manifest, `artifacts` row and owner
        // `cas_roots` row are all durable, and the `execution_git_views` row
        // that makes them THIS execution's `/git-history` is not yet written.
        // Recovery is RE-ADMISSION — the producer walks the same base commit
        // so the republished artifact is identical (CAS dedup makes that
        // content-idempotent) and `record_execution_git_view` converges on the
        // same row. The row precedes `mark_running_after_admission`, so
        // no capsule can observe the window open.
        name: "after_git_view_published_before_recorded",
        family: OperationalBoundaryFamily::Cas,
    },
    OperationalCrashBoundary {
        // The jj/VCS plane's PRE-ACCEPTANCE edge: an isolated submission's target
        // is resolved and pinned under `refs/kata/targets/<id>/…` in the colocated
        // git store, and its acceptance has not committed — no `programs` row,
        // nothing the operational plane would recover. The residue is refs no
        // execution owns; recovery is the BOOT SWEEP, which deletes every pin whose
        // execution has no live admission before the node serves. Resolution
        // costs no spend, so a crash here spends nothing either.
        name: "after_target_pinned_before_acceptance",
        family: OperationalBoundaryFamily::Jj,
    },
];

/// Whether `name` is a registered operational crash boundary.
///
/// The registry is a table of typed rows, so `contains` on a bare name no longer
/// type-checks; this is the one-line replacement every caller wants.
#[must_use]
#[cfg(any(test, feature = "test-support"))]
pub fn operational_boundary_registered(name: &str) -> bool {
    OPERATIONAL_CRASH_BOUNDARIES
        .iter()
        .any(|boundary| boundary.name == name)
}

/// The family `name` is registered under, or `None` if it is not registered.
#[must_use]
#[cfg(any(test, feature = "test-support"))]
pub fn operational_boundary_family(name: &str) -> Option<OperationalBoundaryFamily> {
    OPERATIONAL_CRASH_BOUNDARIES
        .iter()
        .find(|boundary| boundary.name == name)
        .map(|boundary| boundary.family)
}

/// Whether `KATA_FAULT_INJECT` arms `operational.<boundary>` in this process.
///
/// For a call site that must put a hook in place before the point can fire
/// (the harness's observation sink); an unarmed process answers `false` from
/// the same cached read [`operational_crash_point`] takes.
#[must_use]
pub fn operational_point_armed(boundary: &str) -> bool {
    selected_operational_target(boundary).is_some()
}

/// Stop the process at the boundary, or abort it, iff `KATA_FAULT_INJECT` names
/// the operational boundary `operational.<boundary>`.
///
/// Cached-env production fast path, and the same stderr marker for every action so
/// an out-of-process crash cell can confirm the process reached the intended
/// boundary rather than dying by accident. What happens next is
/// `KATA_FAULT_INJECT_ACTION`'s `FaultAction`; the action is read only once a
/// point has fired, so an unarmed process never reads it. Either way the call
/// never returns: [`std::process::abort`] is uncatchable and skips `Drop`,
/// `atexit` and stdio flushing.
///
/// This takes NO status tag: an operational boundary is a
/// transaction edge (`before_*` / `after_*`), and the fact being crashed around is
/// identified by the boundary name alone.
#[doc(hidden)]
#[inline]
pub fn operational_crash_point(boundary: &str) {
    // Production fast-path: env unset → return immediately, no allocation.
    let Some(target) = selected_operational_target(boundary) else {
        return;
    };
    let reached = format!(
        "[kata-fault-inject] crash point reached: operational.{boundary} \
         (KATA_FAULT_INJECT={target}"
    );
    let raw = std::env::var_os(ACTION_VAR)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();
    match FaultAction::parse(&raw) {
        Ok(FaultAction::Abort) => eprintln!("{reached}, action=abort); aborting process now"),
        Ok(FaultAction::Stop) => {
            eprintln!("{reached}, action=stop); stopping process now (SIGSTOP)");
            // THREAD-directed, so this thread cannot run past the point. Linux
            // delivers a process-directed `kill(getpid(), SIGSTOP)` to the thread
            // group LEADER whenever the leader can take it (`complete_signal`),
            // not to the caller. When the caller is another thread (a libtest
            // test thread; a tokio worker in the daemon, whose leader is the main
            // thread), `kill` returns here before the leader is scheduled to begin
            // the group stop, and this thread runs on past the point (its
            // `resumed` line, even `abort()`) before the stop catches it. `raise`
            // queues SIGSTOP on THIS thread, which takes it on its way back from
            // the syscall and begins the group stop itself; a stop signal stops
            // every thread of the process whichever thread takes it. It returns
            // only once something resumes the process.
            let stopped = nix::sys::signal::raise(nix::sys::signal::Signal::SIGSTOP);
            match stopped {
                Ok(()) => eprintln!(
                    "[kata-fault-inject] resumed at operational.{boundary}; aborting process now"
                ),
                Err(error) => {
                    eprintln!("[kata-fault-inject] SIGSTOP failed ({error}); aborting process now");
                }
            }
        }
        Err(unrecognized) => eprintln!(
            "{reached}, action=abort); {ACTION_VAR}={unrecognized:?} is neither `abort` nor \
             `stop`; aborting process now"
        ),
    }
    // Not dumpable, so the abort dumps no core: a `core_pattern` that pipes to a
    // helper (apport) takes the dump whatever `RLIMIT_CORE` says and holds the
    // dying process while it reads it, about a second each and several beside a
    // burst of crash cells. Best effort: a refusal leaves the abort as it was.
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
    std::process::abort();
}

/// The variable that picks what an armed point does once reached.
const ACTION_VAR: &str = "KATA_FAULT_INJECT_ACTION";

/// What an armed fault point does once reached, from `KATA_FAULT_INJECT_ACTION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultAction {
    /// `abort`, or the variable unset or empty: die by SIGABRT at the boundary.
    Abort,
    /// `stop`: SIGSTOP the whole process at the boundary (state `T`), and abort if
    /// it is ever resumed.
    Stop,
}

impl FaultAction {
    /// The exact spellings only; anything else comes back as the refused value,
    /// which the point reports and then aborts on.
    fn parse(raw: &str) -> Result<Self, &str> {
        match raw {
            "" | "abort" => Ok(FaultAction::Abort),
            "stop" => Ok(FaultAction::Stop),
            unrecognized => Err(unrecognized),
        }
    }
}

/// Guard expensive fault-only witness reads with the same cached selector as
/// the actual crash point. An unarmed production call performs no storage IO.
pub(crate) fn selected_operational_target(boundary: &str) -> Option<&'static str> {
    let target = target()?;
    (target.strip_prefix("operational.") == Some(boundary)).then_some(target)
}

#[cfg(test)]
mod tests {
    //! In-process, these cover the no-op (production) path only: calling
    //! `std::process::abort()` in a unit test would kill the test runner. The
    //! stop action and the abort's missing core dump are exercised OUT of
    //! process, in a re-exec of this binary; the aborting path at a real
    //! boundary by the crash cells that arm one.

    // NOTE: `target()` caches the first read in a process-global `OnceLock`.
    // We must NOT set `KATA_FAULT_INJECT` in this process, or we would poison
    // every other test in this binary; only a re-executed child is armed.

    /// Set only in the re-executed child of
    /// [`an_armed_point_under_the_stop_action_stops_the_process_with_its_marker`].
    const STOP_CHILD: &str = "KATA_FAULT_INJECT_STOP_CHILD";

    /// Set only in the re-executed child of
    /// [`an_armed_point_aborts_without_a_core_dump`].
    const ABORT_CHILD: &str = "KATA_FAULT_INJECT_ABORT_CHILD";

    /// An armed point under the default action dies by SIGABRT and dumps no core:
    /// it is not dumpable by the time it aborts. Read off the child's wait status,
    /// the kernel's core-dump bit. The child is a re-exec of this test binary
    /// running only this test, at `RLIMIT_CORE` unlimited so that a dumpable abort
    /// would dump under any `core_pattern` that dumps at all; a host whose
    /// `core_pattern` never dumps cannot red this cell.
    ///
    /// **Would red if:** the point aborted dumpable (watched, on a host whose
    /// `core_pattern` pipes to apport, with the dumpable flag left set).
    #[test]
    fn an_armed_point_aborts_without_a_core_dump() {
        use std::os::unix::process::ExitStatusExt as _;

        const BOUNDARY: &str = "before_claim_commit";
        const THIS_TEST: &str = "fault_inject::tests::an_armed_point_aborts_without_a_core_dump";

        if std::env::var_os(ABORT_CHILD).is_some() {
            let unlimited = rustix::process::Rlimit {
                current: None,
                maximum: None,
            };
            rustix::process::setrlimit(rustix::process::Resource::Core, unlimited)
                .expect("raise RLIMIT_CORE to unlimited");
            super::operational_crash_point(BOUNDARY);
            panic!("the armed fault point returned to its caller");
        }

        // A core a `core_pattern` writes as a file lands in the child's working
        // directory: a scratch one, never the checkout.
        let scratch = tempfile::tempdir().expect("a scratch working directory");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([THIS_TEST, "--exact", "--nocapture"])
            .current_dir(scratch.path())
            .env(ABORT_CHILD, "1")
            .env("KATA_FAULT_INJECT", format!("operational.{BOUNDARY}"))
            .env_remove("KATA_FAULT_INJECT_ACTION")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run the armed child");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.signal(),
            Some(rustix::process::Signal::ABORT.as_raw()),
            "the armed child dies by SIGABRT at the boundary: {:?}; stderr: {stderr}",
            output.status
        );
        assert!(
            stderr.contains(&format!(
                "[kata-fault-inject] crash point reached: operational.{BOUNDARY}"
            )),
            "the child died at its marked boundary: {stderr}"
        );
        assert!(
            !output.status.core_dumped(),
            "the armed point's abort dumped core ({:?}): it was still dumpable",
            output.status
        );
    }

    /// A task's state letter, read from a `stat` file under `/proc` — the kernel's
    /// answer, not this module's. `comm` may hold spaces or parentheses, so the
    /// state is the first field after the LAST `)`.
    fn stat_state(path: &std::path::Path) -> Option<char> {
        let stat = std::fs::read_to_string(path).ok()?;
        stat.rsplit_once(')')?.1.trim_start().chars().next()
    }

    /// The state letter of EVERY thread of `pid`, from `/proc/<pid>/task/*/stat`.
    /// `/proc/<pid>/stat` alone is the leader's state: the leader can be stopped
    /// while another thread still runs, so "stopped" is all of them in `T`.
    fn thread_states(pid: u32) -> Vec<(String, Option<char>)> {
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            return Vec::new();
        };
        tasks
            .map_while(Result::ok)
            .map(|task| {
                let tid = task.file_name().to_string_lossy().into_owned();
                (tid, stat_state(&task.path().join("stat")))
            })
            .collect()
    }

    /// Whether `threads` names at least one thread and every one is in `T`.
    fn all_stopped(threads: &[(String, Option<char>)]) -> bool {
        !threads.is_empty() && threads.iter().all(|(_, state)| *state == Some('T'))
    }

    /// Appends whatever the non-blocking `pipe` holds now; `true` once it is at EOF.
    fn drain(pipe: &mut std::process::ChildStderr, into: &mut Vec<u8>) -> bool {
        use std::io::Read as _;
        let mut buffer = [0_u8; 4096];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => return true,
                Ok(read) => into.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return false,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("read the child's stderr: {error}"),
            }
        }
    }

    /// Kills the child on every exit path, so a failing assertion never leaves a
    /// stopped process behind. SIGKILL ends a stopped process too.
    struct KillOnDrop(std::process::Child);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `KATA_FAULT_INJECT_ACTION=stop`: an armed point writes its marker to stderr
    /// and the WHOLE process stops (state `T`) instead of dying, so a harness can
    /// kill the machine underneath it. Resumed with SIGCONT, it still dies at the
    /// boundary by SIGABRT and never runs past it.
    ///
    /// The armed process is a re-exec of this test binary running only this test,
    /// so `KATA_FAULT_INJECT` is never set in a process that runs other tests.
    #[test]
    fn an_armed_point_under_the_stop_action_stops_the_process_with_its_marker() {
        use std::os::unix::process::ExitStatusExt as _;
        use std::time::{Duration, Instant};

        const BOUNDARY: &str = "before_claim_commit";
        const THIS_TEST: &str = "fault_inject::tests::an_armed_point_under_the_stop_action_stops_the_process_with_its_marker";

        if std::env::var_os(STOP_CHILD).is_some() {
            super::operational_crash_point(BOUNDARY);
            panic!("the armed fault point returned to its caller");
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([THIS_TEST, "--exact", "--nocapture"])
            .env(STOP_CHILD, "1")
            .env("KATA_FAULT_INJECT", format!("operational.{BOUNDARY}"))
            .env("KATA_FAULT_INJECT_ACTION", "stop")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the armed child");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let pid = child.id();
        let mut child = KillOnDrop(child);

        // The pipe is read on THIS thread, non-blocking, so what it holds at any
        // moment is exactly what the child has written: a stopped child never
        // closes its stderr, and a forwarding thread would hold back lines it has
        // read but not yet handed over.
        let flags = rustix::fs::fcntl_getfl(&stderr).expect("stderr flags");
        rustix::fs::fcntl_setfl(&stderr, flags | rustix::fs::OFlags::NONBLOCK)
            .expect("make stderr non-blocking");
        let marker = format!("[kata-fault-inject] crash point reached: operational.{BOUNDARY}");
        let resumed = format!("[kata-fault-inject] resumed at operational.{BOUNDARY}");
        let mut written = Vec::new();
        // 30 s plus the 10 s stop wait below stays inside nextest's 60 s terminate,
        // so a late marker fails here naming the stderr so far, not as a TIMEOUT.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let eof = drain(&mut stderr, &mut written);
            let text = String::from_utf8_lossy(&written);
            if text.lines().any(|line| line.contains(&marker)) && text.ends_with('\n') {
                break;
            }
            assert!(
                !eof && Instant::now() < deadline,
                "no marker on stderr (eof: {eof}); stderr so far: {text}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        // Stopped is EVERY thread in `T`: the process-directed stop this cell
        // refuses stops the leader while the calling thread runs on.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut threads = thread_states(pid);
        while !all_stopped(&threads) && Instant::now() < deadline {
            if matches!(
                stat_state(std::path::Path::new(&format!("/proc/{pid}/stat"))),
                None | Some('Z' | 'X')
            ) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
            threads = thread_states(pid);
        }
        // With no thread able to run, nothing more can reach the pipe: this drain
        // reads everything the child wrote before it stopped.
        let eof = drain(&mut stderr, &mut written);
        let stopped_at = written.len();
        let before_resume = String::from_utf8_lossy(&written).into_owned();
        assert!(
            all_stopped(&threads),
            "every thread of the armed child must be STOPPED at the boundary (state T in \
             /proc/{pid}/task/*/stat), not dead or running: {threads:?}; stderr: {before_resume}"
        );
        assert!(
            !eof,
            "a stopped child cannot have closed its stderr: {before_resume}"
        );
        let marker_line = before_resume
            .lines()
            .find(|line| line.contains(&marker))
            .expect("the marker was read above");
        assert!(
            marker_line.contains("action=stop"),
            "the marker must name the action it takes: {marker_line}"
        );
        // A stop that is delivered elsewhere lets the caller run past the point and
        // write its `resumed` line before the stop catches up with it.
        assert!(
            !before_resume.contains(&resumed),
            "the armed child ran PAST its stop before anything resumed it: {before_resume}"
        );

        let pid = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::CONT).expect("SIGCONT");
        let status = child.0.wait().expect("reap the child");
        assert_eq!(
            status.signal(),
            Some(rustix::process::Signal::ABORT.as_raw()),
            "a resumed point must still die AT the boundary by SIGABRT: {status:?}"
        );
        // Reaped, the child holds no write end: the pipe drains to EOF.
        assert!(
            drain(&mut stderr, &mut written),
            "stderr at EOF after the reap"
        );
        let after_resume = String::from_utf8_lossy(&written[stopped_at..]).into_owned();
        assert!(
            after_resume.lines().any(|line| line.starts_with(&resumed)),
            "a resumed point must name its resumption once SIGCONT arrives: {after_resume:?}"
        );
    }

    /// The action grammar takes the exact spellings only. A near miss is refused
    /// (and then aborts), so a typo cannot silently pick a behavior.
    #[test]
    fn the_fault_action_takes_exact_spellings_and_refuses_the_rest() {
        use super::FaultAction;
        assert_eq!(FaultAction::parse(""), Ok(FaultAction::Abort));
        assert_eq!(FaultAction::parse("abort"), Ok(FaultAction::Abort));
        assert_eq!(FaultAction::parse("stop"), Ok(FaultAction::Stop));
        for refused in ["STOP", "Stop", " stop", "stop ", "stpo", "pause", "sigstop"] {
            assert_eq!(FaultAction::parse(refused), Err(refused), "{refused:?}");
        }
    }

    #[test]
    fn unset_env_is_a_noop_for_the_operational_namespace() {
        for boundary in super::OPERATIONAL_CRASH_BOUNDARIES {
            super::operational_crash_point(boundary.name);
        }
        // Reaching here proves the operational gate shares the production
        // fast path: one cached env read, then an early return — for EVERY
        // registered boundary, so a boundary added later is covered without
        // this test being touched.
    }

    /// EVERY family the crash proof names has at least one registered boundary.
    ///
    /// This is the guard the crash-matrix accounting test structurally cannot be.
    /// That test iterates the registry, so it can only ask "does this registered
    /// boundary have a cell?" — never "is a whole named boundary class missing?".
    ///
    /// The obligation is re-derived from the proof's own enumeration
    /// ([`OperationalBoundaryFamily::CRASH_PROOF_FAMILIES`]), not from the registry
    /// this test checks. A guard whose expected set comes from the thing under test is a
    /// tautology.
    #[test]
    fn every_crash_proof_boundary_family_has_a_registered_kill_point() {
        let empty: Vec<&str> = super::OperationalBoundaryFamily::CRASH_PROOF_FAMILIES
            .iter()
            .filter(|family| {
                !super::OPERATIONAL_CRASH_BOUNDARIES
                    .iter()
                    .any(|boundary| boundary.family == **family)
            })
            .map(|family| family.as_str())
            .collect();
        assert!(
            empty.is_empty(),
            "the crash proof requires a crash at every transaction/dispatch/CAS/jj boundary, and \
             these families have NO registered kill point at all: {empty:?}. A family with no \
             boundary is invisible to the crash-matrix accounting test, which can only enumerate \
             what is registered — so this assertion, not that one, is what makes the omission \
             reportable"
        );
    }

    /// The six family LABELS are a contract, not decoration: the protected-property
    /// ledger names a crash family by this spelling, so a renamed label orphans every
    /// ledger row that names it. Pinned here at the definition, against a literal list
    /// that does not share [`super::OperationalBoundaryFamily::as_str`]'s code.
    #[test]
    fn the_six_boundary_family_labels_are_pinned() {
        let labels: Vec<&str> = super::OperationalBoundaryFamily::ALL
            .iter()
            .map(|family| family.as_str())
            .collect();
        assert_eq!(
            labels,
            ["transaction", "dispatch", "CAS", "jj", "nix", "harness"],
            "a family label changed or a family was added or dropped; the ledger names \
             families by these spellings"
        );
        for family in super::OperationalBoundaryFamily::CRASH_PROOF_FAMILIES {
            assert!(
                super::OperationalBoundaryFamily::ALL.contains(family),
                "{} is a crash-proof family missing from ALL",
                family.as_str()
            );
        }
    }

    /// Registry hygiene: no duplicate names, and every name is non-empty and free of
    /// the `operational.` prefix the gate strips before comparing.
    ///
    /// A duplicate would let two families claim one boundary and make
    /// [`super::operational_boundary_family`] answer by list order; a name carrying
    /// its own prefix would never match a target and would register a kill point no
    /// `KATA_FAULT_INJECT` value can reach — a boundary that exists only on paper,
    /// which is exactly what every guard in this module is here to prevent.
    #[test]
    fn the_registry_has_no_duplicate_or_malformed_boundary_names() {
        let mut seen: Vec<&str> = Vec::new();
        for boundary in super::OPERATIONAL_CRASH_BOUNDARIES {
            assert!(
                !boundary.name.is_empty(),
                "a registered boundary must have a name"
            );
            assert!(
                !boundary.name.contains('.'),
                "{} must be the bare boundary, not the `operational.<boundary>` target: the gate \
                 strips the prefix before comparing, so a dotted name is unreachable",
                boundary.name
            );
            assert!(
                !seen.contains(&boundary.name),
                "{} is registered twice; a duplicate makes the family lookup answer by list order",
                boundary.name
            );
            seen.push(boundary.name);
        }
    }
}
