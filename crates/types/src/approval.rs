//! Pending-approval wire type — body of `GET /api/v1/approvals`.
//!
//! Pure data: the executor in `kata-api` builds a `Vec<PendingApproval>`
//! by scanning the in-flight ledger for entries parked in
//! `AwaitingApproval`. The struct itself has no dispatcher / ledger
//! dependency, so it lives here so the SDK and any future consumer
//! can share one canonical Rust definition rather than mirroring the
//! shape locally.

use serde::{Deserialize, Serialize};

/// One parked assignment waiting for operator review. One per
/// `GET /api/v1/approvals` list entry.
///
/// The shape is intentionally flat and string-typed so an operator
/// can read every field without a secondary lookup against the ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    /// Execution id this approval belongs to (Ulid as string).
    pub execution_id: String,
    /// Assignment id the operator will approve or reject.
    pub assignment_id: String,
    /// Stage name from the workflow definition.
    pub stage_name: String,
    /// Operator-visible reason, e.g. "stage review requires
    /// operator sign-off before dispatch".
    pub reason: String,
    /// When the gate FIRST fired, in wall-clock ms — or `null` when the plane
    /// that answered holds the park and not the instant.
    ///
    /// # Why `Option`, and never `0`
    ///
    /// The park anchor is durable on the authority chain as
    /// `transitions.recorded_at_ms` of the FIRST `awaiting_approval` frame; the
    /// wire must also be able to express ABSENCE. `0` is not that expression — it
    /// is a FABRICATED INSTANT (the `unknown` / `""` sentinel class) and it is
    /// simultaneously the FIFO SORT KEY of the operator's panel, so an anchorless
    /// gate would sort to the front ahead of genuinely older ones and render as
    /// 1970.
    ///
    /// STICKY, not latest: it is the FIRST park's instant, preserved across every
    /// re-park, on both planes. The in-flight ledger keeps it that way with
    /// `get_or_insert_with`; the chain reader takes the FIRST park frame. The
    /// distinction is load-bearing for the blocking input-await self-heal, whose
    /// deadline is `awaiting_since + timeout_ms` — latest-park semantics would
    /// restart the budget on every re-park.
    ///
    /// A consumer rendering an age MUST NOT substitute `now` for `null`: that
    /// reports a gate that has waited an unknown time as one that has waited zero.
    pub awaiting_since_ms: Option<u64>,
    /// The capsule this gate binds, for a capsule attempt's gate; absent for a
    /// workspace-effect or expansion gate, which binds no capsule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule: Option<PendingCapsuleGate>,
    /// The workspace effect this gate binds, for an `oci` `workspace_effect`
    /// stage's gate — the op, the ref it moves, the candidate tree it was
    /// recorded against, and for a `forge_export` the remote and base branch
    /// the push goes to. Absent on every other gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_effect: Option<PendingWorkspaceEffectGate>,
    /// The expansion this gate binds, for an `oci` bounded-expansion's parked
    /// `on_max = "escalate"` gate — the loop's coordinate and the
    /// bound it spent. Absent on every other gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expansion: Option<PendingExpansionGate>,
    /// The target the gate's execution FROZE at admission — what its `/work`
    /// forked from, the branch a landing would move (none for a `pr:` target),
    /// and a `pr:` target's forge facts (number, url, refs, title, body) — read off the stored
    /// invocation, the same value `kata run show` reports as the execution's
    /// `target`. Absent for an execution that forks no isolated workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<crate::target::ExecutionTarget>,
    /// The execution's invocation params an operator may read: every param the
    /// checked program declares and does NOT mark `secret = True`, with its
    /// admitted (default-filled) value, in the invocation's canonical order. A
    /// secret param — or one the program does not declare — is never listed.
    /// Empty (and omitted) for a param-less invocation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<crate::params::InvocationParam>,
}

/// The WORKSPACE EFFECT an approval gate binds, when the gate is an `oci`
/// `workspace_effect` stage's: exactly the
/// mutation approving it authorizes.
///
/// Approving authorizes ONE performance of THIS op against THIS candidate —
/// recorded at the park, so an operator sees `promote exec-… onto trunk` rather
/// than "a stage is waiting". The recorded candidate commit + tree is what the
/// perform arm re-fences on: a candidate that moved while the gate was parked
/// fails `workspace_effect_candidate_moved`, never runs a stale mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWorkspaceEffectGate {
    /// The op: `commit` / `park` / `promote` / `forge_export`.
    pub op: String,
    /// The ref or branch the op moves: `exec-<id>` (commit), `parked/<exec>`
    /// (park), the frozen landable branch (promote), `kata/<exec>`
    /// (forge_export).
    pub target: String,
    /// The recorded candidate commit (hex) the gate parked against — the head
    /// row's candidate at park time, re-fenced at perform time.
    pub candidate_commit: String,
    /// The candidate's tree id (hex) — the tree identity the op would carry.
    pub candidate_tree_id: String,
    /// Where a `forge_export` pushes `target`: the git remote its claim
    /// recorded, the one every leg of the export pushes to and reads back.
    /// Present exactly for a `forge_export` gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge_remote: Option<String>,
    /// The branch a `forge_export`'s pull request opens into: the landable
    /// branch the execution froze at admission. Present exactly for a
    /// `forge_export` gate whose execution froze one (an export claims only
    /// under such a target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge_base: Option<String>,
}

/// The EXPANSION an approval gate binds, when the gate is an `oci`
/// bounded-expansion's parked `on_max = "escalate"` gate: the loop whose bound
/// is spent, so the operator sees which loop is
/// asking and how much of it ran.
///
/// Approving resolves the expansion `completed` with the `Exhausted` record
/// the park carried — the last iteration's member outcomes adopted; rejecting
/// fails it with the operator's reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingExpansionGate {
    /// The expansion's own coordinate — `#op/<path>`.
    pub path: String,
    /// The authored stage the loop hangs off (its worker stage).
    pub stage: String,
    /// The authored bound — `max_iterations`.
    pub maximum: u32,
    /// How many full iterations the gate classified before the bound spent.
    pub iterations: u32,
}

/// The CAPSULE an approval gate binds, when the gate is a capsule attempt's (the `oci`
/// execution profile): exactly what approving it authorizes to run.
///
/// Approving a capsule gate authorizes ONE dispatch of THIS capsule — its argument
/// vector, over this `/work` tree, in this Nix environment, on this network — and
/// nothing else: the capsule id folds every one of them, and the occurrence is bound to
/// it immutably, so no later edit can change what the approval was for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCapsuleGate {
    /// The capsule id (hex), which folds everything below.
    pub capsule_id: String,
    /// The argument vector the container will `execve`.
    pub argv: Vec<String>,
    /// The content-addressed `/work` tree artifact the capsule maps (hex).
    pub work_tree_artifact_id: String,
    /// The Nix environment id (hex) the capsule binds.
    pub environment_id: String,
    /// The stage's declared `produces_files` output scope — what an approving operator authorizes
    /// the capsule to WRITE under `/work`. Empty means whole-tree scope. Surfaced, not advisory:
    /// the delta's scope check at adoption is judged against exactly these globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub produces_files: Vec<String>,
    /// What the capsule may reach over the network — its own allowlist.
    pub network: crate::execution_contract::CapsuleNetworkPosture,
}

/// WHO decided an approval gate, as far as the TRANSPORT that carried the decision
/// proves it — never more.
///
/// kata inherits the host's answer and refuses to invent one: a signed API token proves
/// the label it was issued for, and a loopback listener with API auth disabled proves
/// only that the caller reached the loopback interface — so that absence is recorded as
/// itself, not as a name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalPrincipal {
    /// A verified, signed API token, and the `issued_for` label its signature binds.
    Token {
        /// The token's signed `issued_for` label.
        issued_for: String,
    },
    /// A request on a LOOPBACK listener with API auth disabled: no identity was proved.
    UnauthenticatedLoopback,
}
