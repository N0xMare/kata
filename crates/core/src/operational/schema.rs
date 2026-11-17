//! The versioned `operational.db` schema: one coherent DDL for every
//! authoritative control-plane fact group, plus the forward-version refusal
//! gate and schema validation.
//!
//! # Invariant
//!
//! `operational.db` is the single SQLite transaction authority for the coupled
//! control-plane facts. This module is the SCHEMA — the whole coherent DDL,
//! every fact group at once; see the module docs on [`super`] for the planes
//! that write each group.
//!
//! # Failure mode
//!
//! A database stamped by a NEWER kata release than this binary understands is
//! refused BEFORE SQLITE IS EVER OPENED. The version gate is PLAIN FILE I/O:
//! the 4-byte big-endian `user_version` at database-header offset 60, folded with
//! the newest `user_version` any valid frame of a pending `-wal` sidecar carries.
//! Opening the file with the SQLite driver just to read the pragma is NOT
//! refuse-before-touch — on a WAL database the open itself materializes `-shm`
//! (and can block on a hot WAL or misreport an uncheckpointed stamp), which the
//! WAL / hot-WAL fixtures in `operational_substrate.rs` prove.
//!
//! # Enforcement
//!
//! [`open_operational_connection`] is the only product open path. It gates an
//! existing database's exact version by file I/O, opens, cross-checks the
//! driver's `user_version`, and validates the current shape before configuring
//! the runtime connection. A missing file receives the complete current DDL and
//! `user_version` stamp atomically, without traversing a historical ladder.
//! Every column carries its affinity, and constrained columns carry
//! `CHECK`/`FOREIGN KEY`/`UNIQUE` guards so a forged typed caller cannot write an
//! incoherent authoritative fact.

use std::path::Path;
use std::sync::LazyLock;

use kata_types::error::{KataError, KataResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension};

use super::attempt_state::state_check_list;

use crate::store::sqlite_backed::{self, apply_wal_pragmas};

/// Schema version stamped into `operational.db`'s `PRAGMA user_version`.
///
/// # Invariant
///
/// THE STAMP IDENTIFIES THE SHAPE. A database at version N has exactly the column
/// set [`OPERATIONAL_TABLE_COLUMNS`] declares for N — enforced on every open by
/// [`validate_schema`], which compares the real `PRAGMA table_info` column set,
/// not just table names. A stamp that meant two shapes would let a file of the
/// older shape open cleanly, pass validation, and then fail every write with
/// `table … has no column named …`; so an in-place DDL edit under an unchanged
/// stamp is never allowed, and the column-set assertion refuses the database
/// when one slips through.
///
/// # The stamp covers BLOB SHAPE, not only DDL
///
/// A change to what a durable payload HOLDS moves the stamp even when it moves no
/// DDL. A database that is byte-compatible at the SQL level but holds blobs no
/// current reader decodes would open and then be refused one sweep later, inside
/// a fold or a recovery decode, at a door with no operator recourse. Bumping the
/// stamp moves that refusal to BOOT, where the recourse exists: a new empty data
/// directory, with the old one kept offline. A column shape and a blob shape are
/// the same obligation; treating only the first as a schema change is how a plane
/// acquires a format it cannot read and cannot name. The blobs this covers
/// include `attempts.assignment_json` (an externally tagged
/// `kata_transport::types::DispatchFrame`, `{"capsule": {…}}`, or the at-rest
/// `{"main": {…}}` tag, which is never sent), the accepted `completed` payload's
/// `output`, the `kind='tree'` manifests CAS rows name, the buffered
/// `worker_failure` input, the terminal-charge transition payloads, and
/// `programs.program_json`.
///
/// # A checked-program schema bump bumps this stamp
///
/// `programs.program_json` holds a blob of shape
/// `kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION`,
/// so every bump of that constant moves this one: a directory at one stamp holds
/// programs of one schema. Boot and `kata upgrade` check only the programs of
/// non-terminal executions on the strength of it, and
/// `every_program_schema_bump_moves_the_operational_stamp` (kata-workflow) guards the
/// pairing: it fails a program-schema bump that leaves this stamp alone unless its
/// table is rewritten in place, which its doc forbids and review must catch.
///
/// # Disposition rule for a shape change
///
/// THERE IS NO UPGRADE LADDER, by design rather than by omission. The disposition
/// of a durable shape change is stated once, here, and it is REFUSAL PLUS A FRESH
/// DATA DIRECTORY:
///
/// 1. bump [`OPERATIONAL_SCHEMA_VERSION`];
/// 2. move the DDL, [`OPERATIONAL_TABLE_COLUMNS`], [`OPERATIONAL_TABLES`],
///    [`OPERATIONAL_INDEXES`] and the index/authority contracts together;
/// 3. write NO migration. An existing database at any other stamp — behind or
///    ahead — is refused by [`refuse_noncurrent_operational_schema`] before
///    SQLite is opened, with the "use a new empty data directory and preserve
///    this directory offline" recourse, and the operator keeps the old directory
///    offline rather than having it rewritten in place.
///
/// The disposition is enforced by the only open path, and
/// `a_stamp_one_version_behind_is_refused_with_the_new_data_directory_recourse`
/// (`crates/core/tests/operational_substrate.rs`) holds it. Retained data is never
/// silently reinterpreted; it is also never imported.
///
/// Halves of ONE property ride ONE stamp. A table without the column that names
/// it, or a column whose foreign key has no parent, is a regression on its own,
/// and a data directory that is current for one plane and behind for another is
/// the "one stamp, two meanings" ambiguity the invariant forbids. So
/// `occurrences` arrives with `attempts.occurrence_id`, and the execution-evidence
/// tables live in this file under the same stamp.
///
/// # Design notes the shape encodes
///
/// **Attempt attribution is REFERENTIAL.** `transitions.attempt_id` carries a
/// `DEFERRABLE INITIALLY DEFERRED` foreign key to `attempts`, and `attempts`
/// carries `run_ordinal`. Without that, an attempt-scope transition would name
/// `(stage_id, attempt_ordinal)` as two unchecked values, and a record could be
/// attributed to a stage that never existed or to an ordinal no attempt ever held.
///
/// **`attempts` holds the active-state registry the sweeps decide on** —
/// `worker_id`, `child_execution_id`, the three timestamps, `last_checkpoint` —
/// and no `state` column: the
/// stamped vocabulary CHECK sits on `attempt_projection.state`, the one value an
/// attempt-scope fold writes. `attempt_commands.attempt_id` has a foreign key, so
/// a pruned attempt cannot leave a command behind.
/// `attempts.occurrence_id` is `NOT NULL`: every claim door
/// (`claim_attempt_in_tx`, the main claim) mints the occurrence in the claim's own
/// transaction, so every attempt is an occurrence's attempt.
///
/// **A main-resolved attempt** is `attempts.executor = 'main'`, with the CHECK
/// that it names no worker, stays at lease epoch 0 and records no dispatch or
/// start; `attempts.wait_deadline_ms` and `idx_attempts_wait_due` serve its
/// timers. `idx_attempts_worker_started` is a partial index over a worker's
/// STARTED attempts keyed `(worker_id, finished_at_ms)`, so the start-deadline
/// settlement guard reads the worker's slot in two bounded queries instead of
/// walking every attempt the worker ever started under the write lock.
///
/// **A CAS root names who asserts it.** `cas_roots` carries `owner_kind` +
/// `owner_execution_id` (cascading exactly like the facts it protects), the 32-byte
/// `object_digest` it names, and `released_at_ms` (a released Nix environment's
/// manifest root).
/// Without an owner, deleting an execution would leave an orphan AUTHORITATIVE
/// root naming an object, with no operator query able to say who was responsible.
/// Nothing reclaims CAS bytes: kata has no CAS collection.
///
/// **An `artifacts` row is a NODE-LEVEL CONTENT CLAIM** with no owner column;
/// OWNERSHIP lives only in `cas_roots`. `artifact_id` is `H(object, size,
/// privacy)` and does NOT fold the owner, so two executions whose stages wrote
/// byte-identical `/out` trees (or both map the canonical EMPTY tree) produce ONE
/// `artifact_id`; a row carrying one owner would refuse the second as a divergent
/// re-declaration. `idx_cas_roots_artifact_object` and
/// `idx_cas_roots_owner_artifact` serve the two reads that creates — "does ANY
/// root name this object" (`declare_capsule`'s mapping check) and "which
/// artifacts does THIS owner retain" (`active_artifacts_for`). The
/// `artifacts.kind` CHECK admits `'tree_delta'`: a `/work` mutation is a `TreeDelta`
/// artifact whose `Write` nodes name member objects exactly like a tree manifest's.
///
/// **`attempt_stop_requests` is the DURABLE STOP-ACK, and a LATCH rather than
/// evidence.** It answers "may this execution's workspace be reclaimed?" by
/// reading evidence rather than by a categorical refusal.
///
/// Its three timestamps record three DIFFERENT observers, and no one of them
/// implies another:
///
/// * `requested_at_ms` — the MAIN decided to stop this generation. Written before
///   the frame is handed to any transport, so a crash in between leaves a stop
///   that is visible rather than lost.
/// * `delivered_at_ms` — a TRANSPORT accepted the frame. This proves the frame
///   left; it proves nothing whatever about the worker.
/// * `acknowledged_at_ms` — the FENCED WORKER's own attempt-terminal frame for
///   this `(attempt_id, lease_epoch)` passed the ingress fence. This one, alone,
///   proves no worker is still running the attempt — which is the question
///   parking asks.
///
/// A single `state TEXT` would force these into a total order they do not have
/// (see the deliberately-absent CHECK on the DDL below), and would let a reader
/// treat reaching `delivered` as progress toward safety when it is not.
///
/// The table carries its own `execution_id` and `discharge_json`, and its
/// `attempts` foreign key is `NO ACTION`. The column and the FK are the two
/// halves of one property and either alone is a regression. Under `CASCADE` a
/// prune of the attempt silently DELETES the latch rather than being refused.
/// Under `NO ACTION` without the column, the only route from an execution to its
/// stops is a join through `attempts`, so an orphaned stop row is INVISIBLE to the
/// scan and the parking predicate's first conjunct is satisfied VACUOUSLY on
/// exactly the case it exists to refuse. A LEFT JOIN does not fix that: the
/// execution scoping can only come from `attempts`, so the predicate is
/// `WHERE a.execution_id = ?1`, and a WHERE on the right-hand table of a LEFT
/// JOIN discards the NULL-extended rows and collapses it back to an inner join
/// (`a_left_join_would_not_find_the_orphan`). With the column the scan needs no
/// join at all. The latch's `execution_id` is `CASCADE` deliberately
/// (`pruning_the_whole_execution_carries_its_stops_away`): it gates the reclaim
/// of one execution's workspace, so once the execution is gone the latch has no
/// subject, and a latch that also blocked the deletion of the execution it
/// protects would make retention impossible rather than safe.
///
/// **`event_inbox` and `event_inbox_watermark` carry `execution_id`, with
/// `ON DELETE CASCADE`.** Keyed only by an opaque `attempt_id ++ attempt_ordinal`
/// stream, they would sit OUTSIDE the `programs`-rooted cascade and survive it
/// with their full payload JSON (`deleting_an_execution_now_reaches_the_event_inbox`
/// pins that they do not). A cascade cannot traverse a join, so a column is the
/// only representable fix. Both tables carry it: a watermark row surviving its
/// slots is an INCOHERENT durable state — `accepted_through_seq = N` over rows
/// that no longer exist is the exact condition `dedupe_accepted_event` raises
/// "watermark claims seq accepted but no row exists" for.
///
/// **`occurrences.work_tree_artifact_id` records BY ROLE the `/work` tree the
/// main WALKED for the occurrence.** `authorize_attempt` refuses a capsule whose
/// `/work` mapping is not the tree `kata_core::work_tree::publish_work_tree`
/// returned for this attempt, and the column makes a re-dispatch of the same
/// occurrence over a DIFFERENT walked tree a refused divergent re-declaration
/// rather than a second body of work under one occurrence.
///
/// **`nix_environments.verification_evidence`** holds the signatures and deriver
/// the store reported for each closure entry, as canonical JSON. They are not
/// part of the environment id — a `nix store sign` or a re-substitution changes
/// them without changing a byte — so they are recorded here as evidence of the
/// last verification instead.
///
/// **`execution_work_tree_heads` is the EXECUTION-LEVEL `/work` HEAD**, plural
/// per execution. `branch` is in its PRIMARY KEY — `''` is the execution head, a
/// branch coordinate spelling names a `parallel()` branch's own head forked from
/// its parent's — with `join_stage` and `forked_from` (which barrier and which
/// parent coordinate the branch belongs to) and `fork_base_artifact_id`, the
/// frozen fork-point artifact the join's fan-in computes every branch delta
/// against. `base_commit` is the provenance (the backend's own commit spelling)
/// and `work_tree_artifact_id` the declared `kind='tree'` artifact every isolated
/// capsule maps, so an isolated `oci` capsule's `/work` is the committed input,
/// never a per-attempt walk of mutable scratch state. `candidate_commit_id` (the
/// fence `apply_work_delta` re-checks) and `head_seq` (the apply's ordinal) are
/// the pair the head advance writes in the WorkApply acceptance transaction and
/// the recovery sweep reads to know which apply, if any, an accepted occurrence
/// is still owed. A head recorded off the scratch workspace or a branch head
/// (CAS-only) carries the empty string in `base_commit`/`candidate_commit_id`.
/// `committed_commit_id` is the commit the latest `commit` workspace effect
/// finalized, moved in the same compare-and-swap as the candidate (which becomes
/// the empty `@` on top of it), so `promote` and `forge_export` deliver the
/// described commit rather than its empty child; `''` until a commit resolves.
/// `record_work_tree_head` is write-once by PRIMARY KEY plus its own
/// converge-or-refuse (`work_tree_head_divergent`), so re-admission idempotence
/// is a property of the writer rather than a caller's discipline. The
/// `artifacts` foreign key is NO ACTION: a head that outlived the artifact row
/// it names would be a dangling mapping authority.
///
/// **`execution_git_views` is the EXECUTION-LEVEL git-history artifact record.**
/// One row per execution that admitted an agent stage under `oci`: the base
/// commit the view is rooted at, the branch ref (name and commit, off the
/// execution's frozen target, or none) the capsule's scratch repository names,
/// the `artifacts` row id of the history manifest (kind `'tree'` — a manifest
/// over `objects/pack/*`, `index`, `shallow`), and the inherited commit
/// identity the scratch repository's config carries — recorded rather than
/// re-resolved so a recovered admission and a late dispatch see the identity
/// admission saw. The publication crash window is
/// `after_git_view_published_before_recorded`: an orphaned history artifact is an
/// unreferenced object that costs disk, and re-admission reproduces the same view
/// because the producer walks the same base commit.
///
/// **`invocations.invocation_json` carries the frozen execution target** of every
/// `worktree_isolated` workflow invocation (invocation envelope schema 3): the
/// fork base, landable branch and review baseline admission resolved before
/// acceptance, bound by the admission digest, and for a pull-request target the
/// forge's facts with `title_truncated` / `body_truncated`, whether resolution's
/// cut of the title and body dropped anything. A schedule's PINNED invocation
/// carries none — its target is resolved at every fire and spliced into the fired
/// execution's envelope — and `schedule_firings` records a fire whose target was
/// refused (`refusal`, with no `execution_id`) instead of leaving it for a silent
/// retry. A directory at an earlier stamp holds schema-1 envelopes with no target
/// and a firing table without the refusal, or schema-2 envelopes whose
/// pull-request facts carry no truncation flags (which no reader may default to
/// "not cut"), and is refused at open like every other.
///
/// **A `forge_export` attempt's recorded spec names no remote or base the
/// pack wrote** (`ForgeExportSpec` is `{title, body}` and refuses any other
/// key) and carries the push remote its claim resolved (`forge_remote`). A
/// directory at an earlier stamp can hold export specs and frozen program
/// directives naming `remote`/`base` literals, which this build cannot read
/// as the export they were claimed as; it is refused at open like every other.
///
/// **A dispatched attempt's failure-class terminal carries its charge, and a
/// metering summary its token count.** Every `failed`/`cancelled`/`orphaned`
/// transition of an attempt whose dispatch is recorded carries a
/// `terminal_charge` (the writer refuses one without, `TERMINAL_CHARGE_REQUIRED`),
/// and every reader reads a missing one as an UNKNOWN charge; a
/// `MeteringSummary` (a record's `metering`, a `child_invocation_summary`'s)
/// carries `tokens` and `tokens_unknown`. A directory at an earlier stamp holds
/// settlements written with no charge and summaries with no token count, which
/// this build would read as unknown spend and as a known zero respectively; it is
/// refused at open like every other.
///
/// **A closeout park refused by name is recorded** (`execution_evidence`'s
/// `closeout_park_refusal`, one claimed row): the closeout parked nothing, and
/// the `parked/<exec>` the record names is never adopted as the run's park
/// unless the run's own parked-candidate evidence binds it. A directory at an
/// earlier stamp can hold terminal runs whose closeout refused with no record,
/// which this build would read as "nothing refused": its execution read would
/// adopt the standing foreign ref as the run's auto-parked candidate, and its
/// default park, once the workspace is reaped, as the run's park. It is refused
/// at open like every other.
///
/// **A worker-reported failure records its model provider's failure class.** The
/// buffered `worker_failure` input and its accepting transition carry
/// `provider_failure` (`"refused"`, `"transient"` or `null`) beside the verdict, and
/// the stage's retry chain reads it: a `transient` attempt is re-run on its agent,
/// and a `refused` attempt's agent is never run again on the chain. A directory at
/// an earlier stamp holds buffered inputs this build's replay would re-encode with a
/// field they never carried, and settlements whose missing class this build would
/// read as "the worker stated none"; it is refused at open like every other.
///
/// **A `forge_export`'s push and pull request each carry an intent row**
/// (`forge_intents`), committed before the wire effect's first byte, with the
/// verdict its receipt or its observer wrote. Recovery reads an export with no
/// intent as never issued and re-performs it. A directory at an earlier stamp can
/// hold a pending export whose push or pull request landed with no intent, which
/// this build would read as PROVEN NOT PERFORMED and issue again; it is refused at
/// open like every other.
///
/// **A capsule names a nanocode adapter and a `kata_login` or `env:` credential,
/// and its agent turn no launch vector.** The execution contract moved to v13 with
/// the vendor adapters' removal, and a directory at an earlier stamp holds v12
/// capsule bodies in its CAS — some naming a removed adapter or a host-login source,
/// which this build cannot decode, and every agent turn an `argv` this build no
/// longer folds into the capsule's id — so every
/// read of such a capsule (an execution's record, an approval park, a settlement)
/// would fail with no recourse. It is refused at open like every other.
///
/// **A capsule settlement, a rejected capsule approval and a dispatch refused after
/// terminal intent carry their typed `verdict`** (`MainSideTransition::verdict`) — the
/// same field a worker-reported failure carries, and the failure retry reads that
/// field alone. A main-resolved failure (`MainResolution::Fail`: a rejected
/// `workspace_effect`, a failed forge export) records no verdict and is never re-run. A
/// directory at an earlier stamp holds settlements that name their verdict only in
/// their reason, which this build would read as unclassified and never re-run; it is
/// refused at open like every other.
///
/// **There is no `stage_projection`**: no advancing transition has stage scope
/// (every stage-scope writer is `RecordOnly`, the halt settlements included), and
/// `transitions` carries the CHECK that makes "a stage transition never folds"
/// structural rather than a census of call sites.
///
/// **A forge intent counts its observer's unanswered reads and keeps its command's
/// error** (`forge_intents.unanswered_reads`, `last_unanswered_at_ms`,
/// `last_read_error`, `command_error`). A read the remote does not answer leaves
/// the intent open for a bounded re-ask, counted on the row, and a NOT PERFORMED
/// read after a command that returned an error fails the export rather than issuing
/// it again, which the row's `command_error` alone tells. A directory at an earlier
/// stamp has neither column; it is refused at open like every other.
///
/// **A capsule's agent turn names no proxy spelling and no `XDG_RUNTIME_DIR` in
/// its env or its `env:` source.** The execution contract moved to v14 when those
/// names were reserved, and a directory at an earlier stamp holds v13 capsule bodies
/// in its CAS — some declaring `http_proxy`, `https_proxy`, `ALL_PROXY`, `all_proxy`
/// or `XDG_RUNTIME_DIR`, which this build's decode refuses — so every read of such a
/// capsule (an execution's record, an approval park, a settlement) would fail with
/// no recourse. It is refused at open like every other.
///
/// A stamp ABOVE this is a newer binary's database and is refused before SQLite
/// is opened at all.
pub const OPERATIONAL_SCHEMA_VERSION: i64 = 49;

/// Milliseconds a blocked writer/reader waits on a held SQLite lock before it
/// surfaces `SQLITE_BUSY`. Mirrors the workspace-wide 5s posture so the single
/// operational writer — and every projection reader — waits out a transient
/// checkpoint/backup-reader collision instead of hard-erroring.
pub(crate) const OPERATIONAL_BUSY_TIMEOUT_MS: i64 = 5_000;

/// The complete, coherent operational DDL. Every table is `IF NOT EXISTS` so a
/// reopen of an already-stamped current database is a no-op.
///
/// The fact groups:
/// - program/invocation: `programs`, `invocations`
/// - lifecycle + transitions + projections + watermark:
///   `execution_lifecycle`, `transitions`, `transition_sequence`,
///   `execution_projection`, `attempt_projection`, `projection_watermark`
/// - attempts/commands/leases: `attempts`, `attempt_commands`,
///   `attempt_stop_requests`
/// - authoritative CAS roots: `cas_roots`
/// - schedules: `schedules`, `schedule_firings`
/// - accepted-event inbox: `event_inbox`, `event_inbox_watermark`
/// - declared Nix managed-software environments: `nix_environments`
/// - portable artifacts and capsules: `artifacts`, `capsules`
/// - durable occurrence identity: `occurrences`
/// - execution-level evidence: `execution_evidence`, `execution_evidence_claims`
/// - the execution's committed-base `/work` head: `execution_work_tree_heads`
/// - the execution's git-history view: `execution_git_views`
/// - a `forge_export`'s wire-effect intents: `forge_intents`
///
/// A TEMPLATE, with [`ATTEMPT_STATE_VOCABULARY_SLOT`] still unrendered.
/// Every consumer takes [`CREATE_OPERATIONAL_SCHEMA_SQL`], which is this rendered
/// against [`state_check_list`].
// kata-spacing: intentional
const CREATE_OPERATIONAL_SCHEMA_TEMPLATE: &str = "
-- Program/invocation: authoritative checked program + immutable normalized
-- invocation.
CREATE TABLE IF NOT EXISTS programs (
    execution_id    BLOB    NOT NULL PRIMARY KEY,
    program_hash    BLOB    NOT NULL,
    schema_version  INTEGER NOT NULL,
    program_json    BLOB    NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    CHECK (length(program_hash) = 32)
);
CREATE TABLE IF NOT EXISTS invocations (
    execution_id        BLOB    NOT NULL PRIMARY KEY,
    schema_version      INTEGER NOT NULL,
    kind                TEXT    NOT NULL,
    admission_digest    BLOB    NOT NULL,
    invocation_json     BLOB    NOT NULL,
    created_at_ms       INTEGER NOT NULL,
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    CHECK (kind IN ('workflow', 'direct_agent')),
    CHECK (length(admission_digest) = 32)
);

-- Lifecycle: coarse lifecycle latch. Mirrors the execution_program_store
-- lifecycle table FIELD-FOR-FIELD and CHECK-FOR-CHECK (including
-- `terminal_started_at_ms`, the instant terminal INTENT was latched): a terminal
-- outcome cannot be recorded without its reason and its intent instant, and an
-- in-flight row cannot carry either.
CREATE TABLE IF NOT EXISTS execution_lifecycle (
    execution_id            BLOB    NOT NULL PRIMARY KEY,
    state                   TEXT    NOT NULL,
    created_at_ms           INTEGER NOT NULL,
    terminal_outcome        TEXT,
    terminal_reason_json    BLOB,
    terminal_started_at_ms  INTEGER,
    finished_at_ms          INTEGER,
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    CHECK (state IN ('admitting', 'running', 'terminalizing', 'completed', 'failed', 'cancelled', 'timed_out')),
    CHECK (terminal_outcome IS NULL OR terminal_outcome IN ('completed', 'failed', 'cancelled', 'timed_out')),
    CHECK (
        (state IN ('admitting', 'running')
            AND terminal_outcome IS NULL
            AND terminal_reason_json IS NULL
            AND terminal_started_at_ms IS NULL
            AND finished_at_ms IS NULL)
        OR
        (state = 'terminalizing'
            AND terminal_outcome IS NOT NULL
            AND terminal_reason_json IS NOT NULL
            AND terminal_started_at_ms IS NOT NULL
            AND finished_at_ms IS NULL)
        OR
        (state IN ('completed', 'failed', 'cancelled', 'timed_out')
            AND terminal_outcome = state
            AND terminal_reason_json IS NOT NULL
            AND terminal_started_at_ms IS NOT NULL
            AND finished_at_ms IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_execution_lifecycle_active
    ON execution_lifecycle (execution_id)
    WHERE state IN ('admitting', 'running', 'terminalizing');
CREATE TABLE IF NOT EXISTS execution_cleanup_obligations (
    execution_id       BLOB    NOT NULL PRIMARY KEY,
    disposition        TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'pending',
    attempt_count      INTEGER NOT NULL DEFAULT 0,
    next_retry_at_ms   INTEGER NOT NULL,
    last_error         TEXT,
    completed_at_ms    INTEGER,
    FOREIGN KEY(execution_id) REFERENCES execution_lifecycle(execution_id) ON DELETE CASCADE,
    CHECK (disposition IN ('preserve_success', 'remove_submit_setup', 'park_failed', 'converge_absent')),
    CHECK (status IN ('pending', 'completed')),
    CHECK (attempt_count >= 0),
    CHECK ((status = 'pending' AND completed_at_ms IS NULL) OR
           (status = 'completed' AND completed_at_ms IS NOT NULL AND last_error IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_execution_cleanup_due
    ON execution_cleanup_obligations (next_retry_at_ms, execution_id)
    WHERE status = 'pending';

-- Transitions: the immutable accepted-transition record — the declared authority
-- from which current state can be rebuilt. `seq` is a GLOBAL monotonic ordering
-- reserved IN-TRANSACTION from `transition_sequence` (a rolled-back reservation
-- reverts the counter, so a failed transition leaves NO hole). Each
-- transition names the projection scope it advances and the resulting state,
-- so the projection is a pure fold of this chain.
CREATE TABLE IF NOT EXISTS transitions (
    seq             INTEGER NOT NULL PRIMARY KEY,
    execution_id    BLOB    NOT NULL,
    scope           TEXT    NOT NULL,
    stage_id        TEXT,
    attempt_ordinal INTEGER,
    kind            TEXT    NOT NULL,
    resulting_state TEXT    NOT NULL,
    -- Whether this transition ADVANCED its scope's latest-state projection.
    -- A record about an attempt (an outcome amendment, an approval decision, a
    -- generation bump) is appended to the chain for audit and ordering but must
    -- NOT advance the LIFECYCLE projection: its `resulting_state` names the record,
    -- not a lifecycle state. Persisting the choice is what lets
    -- `rebuild_from_chain` reproduce EXACTLY the fold that ran, so the integrity
    -- check compares two derivations of the same rule instead of two different ones.
    folds_projection INTEGER NOT NULL DEFAULT 1,
    payload_json    BLOB    NOT NULL,
    idempotency_key BLOB,
    recorded_at_ms  INTEGER NOT NULL,
    -- The ATTEMPT this transition is attributed to. `stage_id` and
    -- `attempt_ordinal` above are the attempt's COORDINATES; this is its
    -- IDENTITY, and the foreign key is what makes attribution referential
    -- instead of advisory. Every attempt-scope writer RESOLVES the
    -- coordinates from this row's `attempts` row inside the same transaction, so
    -- a caller cannot present a pair that disagrees with the identity.
    --
    -- DEFERRABLE INITIALLY DEFERRED for two independent reasons, both structural:
    -- `dispatch_attempt` records the transition BEFORE inserting the attempt
    -- whose `source_seq` it stamps, and a `programs` delete CASCADEs both
    -- `transitions` and `attempts` in an order SQLite does not promise.
    --
    -- ON DELETE SET NULL, not RESTRICT: the chain is retained past `attempts`
    -- (which a future retention contract may prune), so pruning an attempt must
    -- drop the reference, never the authority row. The coordinates survive on the
    -- row, which is what `rebuild_from_chain` reads.
    attempt_id      BLOB,
    -- A transition is scoped to a submitted execution: an orphan transition (no
    -- program) is unreachable, and dropping an execution drops its chain.
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
        ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
    -- Sequences are reserved from a counter that starts at 0 and pre-increments,
    -- so 1 is the lowest reachable seq; 0 would alias 'no transition'.
    CHECK (seq >= 1),
    CHECK (scope IN ('execution', 'stage', 'attempt')),
    CHECK (
        (scope = 'execution' AND stage_id IS NULL AND attempt_ordinal IS NULL)
        OR
        (scope = 'stage' AND stage_id IS NOT NULL AND attempt_ordinal IS NULL)
        OR
        (scope = 'attempt' AND stage_id IS NOT NULL AND attempt_ordinal IS NOT NULL)
    ),
    -- An attempt id NEVER appears outside attempt scope. Deliberately NOT an
    -- 'iff': an attempt-scope row whose attempt is pruned keeps its coordinates
    -- and loses its id (ON DELETE SET NULL above), and an 'iff' would refuse
    -- that prune or require deleting authority rows.
    CHECK (attempt_id IS NULL OR scope = 'attempt'),
    CHECK (idempotency_key IS NULL OR length(idempotency_key) > 0),
    CHECK (folds_projection IN (0, 1)),
    -- A stage-scope transition is RECORD-ONLY, always. There is no stage
    -- projection to fold into, and the halt settlements that are stage-scoped
    -- have no attempt to project.
    CHECK (scope <> 'stage' OR folds_projection = 0)
);
-- Serves `rebuild_from_chain` (SELECT ... FROM transitions WHERE execution_id = ?
-- ORDER BY seq) and the programs -> transitions ON DELETE CASCADE.
CREATE INDEX IF NOT EXISTS idx_transitions_execution
    ON transitions (execution_id, seq);
-- Serves the attempts -> transitions FK child scan (the ON DELETE SET NULL fires
-- per deleted attempt and would otherwise scan the whole chain) and the
-- 'every transition of this attempt' lookup. Partial: only attempt-scope rows
-- carry an id.
CREATE INDEX IF NOT EXISTS idx_transitions_attempt
    ON transitions (attempt_id) WHERE attempt_id IS NOT NULL;
-- Serves the stage-scope reads of one execution's chain. Partial: only
-- stage-scope rows are indexed, so those reads never scan attempt-scope rows.
CREATE INDEX IF NOT EXISTS idx_transitions_stage_history
    ON transitions (execution_id, stage_id, seq) WHERE scope = 'stage';
-- Serves ordinal allocation from the CHAIN: MAX(attempt_ordinal) per
-- (execution_id, stage_id) over attempt-scope rows. Allocating from the chain
-- rather than from `attempts` is what keeps a pruned attempt's ordinal from being
-- re-issued and colliding with a surviving `attempt_projection` row.
CREATE INDEX IF NOT EXISTS idx_transitions_attempt_ordinal
    ON transitions (execution_id, stage_id, attempt_ordinal) WHERE scope = 'attempt';
-- Approval/signal/external-input/bound-consumption idempotency: a non-null key
-- is globally unique, so re-submitting the same input conflicts and is an
-- idempotent no-op instead of a duplicate transition. Serves
-- `transition_exists_for_key`.
CREATE UNIQUE INDEX IF NOT EXISTS idx_transitions_idempotency
    ON transitions (idempotency_key) WHERE idempotency_key IS NOT NULL;

-- Transitions: the single-row in-transaction sequence reservation counter. `value` is
-- the highest reserved `transitions.seq`. Reserving bumps it INSIDE the caller's
-- transaction; a rollback reverts the bump.
CREATE TABLE IF NOT EXISTS transition_sequence (
    id      INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
    value   INTEGER NOT NULL CHECK (value >= 0)
);
INSERT OR IGNORE INTO transition_sequence (id, value) VALUES (0, 0);

-- Projections: the latest-state projections. Each row stores its SOURCE transition seq,
-- so an integrity check can rebuild the projection from the transition chain and
-- compare exactly (state + source_seq).
CREATE TABLE IF NOT EXISTS execution_projection (
    execution_id    BLOB    NOT NULL PRIMARY KEY,
    state           TEXT    NOT NULL,
    source_seq      INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL,
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(source_seq) REFERENCES transitions(seq)
);
CREATE INDEX IF NOT EXISTS idx_execution_projection_active
    ON execution_projection (execution_id)
    WHERE state IN ('admitting', 'running', 'terminalizing');
-- `state` carries the STAMPED attempt vocabulary: the assignment-status
-- spellings (kata_types::ledger::AssignmentStatus) plus the two main-resolved
-- waits, generated from `AttemptLifecycle::ALL`.
--
-- The CHECK lives HERE, on the one advancing projection, and not on `attempts`:
-- an `attempts.state` column would be a second, never-advanced representation of
-- the same fact with no adjudicator (`verify_projection_integrity` compares only
-- `attempt_projection` against a chain rebuild) — a status mirror. The vocabulary
-- sits on the value every attempt-scope `resulting_state` actually folds into.
CREATE TABLE IF NOT EXISTS attempt_projection (
    execution_id    BLOB    NOT NULL,
    stage_id        TEXT    NOT NULL,
    attempt_ordinal INTEGER NOT NULL,
    state           TEXT    NOT NULL,
    source_seq      INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL,
    PRIMARY KEY (execution_id, stage_id, attempt_ordinal),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(source_seq) REFERENCES transitions(seq),
    -- GENERATED from `AttemptLifecycle::ALL`. Do not restate the
    -- spellings here; add the member to the type.
    CHECK (state IN (@@ATTEMPT_STATE_VOCABULARY@@))
);
-- Projections: the projection rebuild cursor / consistency fence. `applied_through_seq`
-- is the highest transition seq folded into the projections above. Because every
-- transition-writing transaction folds its projection in the SAME commit, this
-- equals `max(transitions.seq)` on a coherent database — the integrity check
-- asserts exactly that.
CREATE TABLE IF NOT EXISTS projection_watermark (
    id                      INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
    applied_through_seq     INTEGER NOT NULL CHECK (applied_through_seq >= 0)
);
INSERT OR IGNORE INTO projection_watermark (id, applied_through_seq) VALUES (0, 0);

-- Attempts: attempts + their commands + fencing lease epoch. `assignment_json` is
-- the authoritative heavy blob, and it commits atomically with the attempt.
--
-- The attempt's lifecycle state is `attempt_projection.state` and ONLY that: a
-- pure fold of the transition chain, carrying the stamped vocabulary CHECK. There
-- is no `state` column here: one written at claim/dispatch and never advanced
-- would be a second representation of the same fact that no integrity path
-- adjudicates — a status mirror rather than a registry.
--
-- The columns below `run_ordinal` are the INDEXED ACTIVE-STATE REGISTRY: indexed
-- active-state queries reconstruct bounded hot registries. Each one is read by a
-- state-machine DECISION, so each is decision-bearing and none is a status
-- mirror: the state itself is not among them.
--
--   `worker_id`           -> worker-death reclaim + the stall sweep
--   `child_execution_id`  -> the child-completion sweep and parent lineage
--   `dispatched_at_ms` / `started_at_ms` / `finished_at_ms`
--                         -> the start/execution deadline sweeps, workspace
--                            reaping, and terminal eviction age
--   `last_checkpoint`     -> resume-from-safe-point vs re-run. Advanced under a
--                            SQL `MAX(existing, new)` clamp, so the no-rewind
--                            property does not depend on callers.
--
-- `run_ordinal` is the re-run marker for the generation this row represents,
-- set at claim time; a production attempt keeps it, since a retry is a new
-- attempt row. A dispatch premise compares the stored marker against the one
-- it expects, so a moved marker (only the test-support fixture
-- `advance_attempt_generation` moves one) reads as superseded. It is a
-- GENERATION BOUNDARY DETECTOR, never the attempt ordinal — `attempt_ordinal` is
-- always allocated from the transition chain, because one row's marker counts
-- neither the stage's other attempt rows nor its main-resolved waits.
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id           BLOB    NOT NULL PRIMARY KEY,
    execution_id         BLOB    NOT NULL,
    stage_id             TEXT    NOT NULL,
    attempt_ordinal      INTEGER NOT NULL,
    lease_epoch          INTEGER NOT NULL,
    assignment_json      BLOB    NOT NULL,
    source_seq           INTEGER NOT NULL,
    created_at_ms        INTEGER NOT NULL,
    run_ordinal          INTEGER NOT NULL DEFAULT 0,
    worker_id            TEXT,
    child_execution_id   BLOB,
    dispatched_at_ms     INTEGER,
    started_at_ms        INTEGER,
    finished_at_ms       INTEGER,
    last_checkpoint      INTEGER,
    occurrence_id        BLOB    NOT NULL,
    -- WHO RESOLVES this attempt. 'worker' is every attempt a worker is sent;
    -- 'main' is a MAIN-RESOLVED attempt (a wait, a join, an invocation), whose
    -- completion is a committed fact rather than a process exit. A main attempt is
    -- accepted through the SAME door as a worker one (`record_transition`'s
    -- occurrence acceptance) and is never dispatched: the CHECK below makes the
    -- worker-held shape unwritable for it, the executor latch in `record_transition`
    -- refuses every worker transition on it, and `dispatch_claimed_attempt` and
    -- `record_stop_request` refuse it by name before a command or stop request
    -- exists.
    executor             TEXT    NOT NULL DEFAULT 'worker',
    -- The instant a main-resolved WAIT becomes due, or NULL. Written by the
    -- main claim, cleared by the resolution, so the partial index below holds only
    -- the outstanding waits a due sweep reads.
    wait_deadline_ms     INTEGER,
    UNIQUE (execution_id, stage_id, attempt_ordinal),
    CHECK (executor IN ('worker', 'main')),
    -- The refused set, exactly: a 'main' row that names a worker, carries a lease
    -- epoch other than 0, or records a dispatch or a start (the occurrence
    -- binding every row needs is the column's own NOT NULL). A main attempt is
    -- adjudicated through its occurrence, is fenced by nothing, and no process
    -- ever holds it.
    CHECK (executor = 'worker' OR (worker_id IS NULL
           AND lease_epoch = 0 AND dispatched_at_ms IS NULL AND started_at_ms IS NULL)),
    CHECK (wait_deadline_ms IS NULL OR executor = 'main'),
    CHECK (run_ordinal >= 0),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(source_seq) REFERENCES transitions(seq),
    -- The LOGICAL work this generation is an attempt AT. NO ACTION (no
    -- `ON DELETE` clause), so deleting an occurrence a live attempt names is
    -- REFUSED rather than nulling the binding away -- the same polarity, and for
    -- the same reason, as `capsules.environment_id`: an attempt whose occurrence
    -- vanished could be accepted a second time under a reminted occurrence, which
    -- is the exact double-acceptance `occurrences.accepted_attempt_id` exists to
    -- make unrepresentable. The reverse edge (`occurrences.accepted_attempt_id`)
    -- is CASCADE and DEFERRED; the asymmetry is argued on that column.
    --
    -- NOT NULL: every attempt is an occurrence's attempt, because both claim doors mint the
    -- occurrence in the claim's own transaction. `admit_undispatched_stage`'s class writes
    -- NO attempt row (it is recorded at stage scope), so it never needed a binding here.
    FOREIGN KEY(occurrence_id) REFERENCES occurrences(occurrence_id) ON DELETE NO ACTION,
    CHECK (length(occurrence_id) = 32),
    CHECK (attempt_ordinal >= 0),
    CHECK (lease_epoch >= 0),
    CHECK (last_checkpoint IS NULL OR last_checkpoint >= 0)
);
-- Serves worker-death reclaim and the stall sweep. Partial: a released attempt
-- carries NULL and does not belong in the index.
CREATE INDEX IF NOT EXISTS idx_attempts_worker
    ON attempts (worker_id) WHERE worker_id IS NOT NULL;
-- Serves the start-deadline settlement guard's two reads of a worker's STARTED
-- history (`SettlementGuard::StartOverdue`): its unfinished attempts (the leading
-- `finished_at_ms IS NULL` range) and the latest freed slot (`MAX(finished_at_ms)`,
-- one seek). Without it both walk every attempt the worker ever started, under the
-- write lock, on every settlement. Partial: an attempt that never started has no slot.
CREATE INDEX IF NOT EXISTS idx_attempts_worker_started
    ON attempts (worker_id, finished_at_ms)
    WHERE worker_id IS NOT NULL AND started_at_ms IS NOT NULL;
-- Serves the due-wait read (`wait_deadline_ms <= now`) over main-resolved
-- waits. Partial: only an outstanding wait carries a deadline.
CREATE INDEX IF NOT EXISTS idx_attempts_wait_due
    ON attempts (wait_deadline_ms) WHERE wait_deadline_ms IS NOT NULL;
-- Serves the child-completion sweep and the parent -> child lineage lookup.
CREATE INDEX IF NOT EXISTS idx_attempts_child
    ON attempts (child_execution_id) WHERE child_execution_id IS NOT NULL;
-- Serves the per-execution attempt scan the boot orphan sweep issues, and the
-- `programs -> attempts` ON DELETE CASCADE, which without a child index scans the
-- whole attempt table per deleted execution.
CREATE INDEX IF NOT EXISTS idx_attempts_execution
    ON attempts (execution_id);
-- Serves the `occurrences -> attempts` NO ACTION parent check ('does any attempt
-- name this occurrence?', which without a child index SQLite answers by scanning
-- every attempt the node has) and the occurrence -> attempt lookup the acceptance
-- writer issues. Total: every attempt carries a binding.
CREATE INDEX IF NOT EXISTS idx_attempts_occurrence
    ON attempts (occurrence_id);
CREATE TABLE IF NOT EXISTS attempt_commands (
    command_id      BLOB    NOT NULL PRIMARY KEY,
    attempt_id      BLOB    NOT NULL,
    lease_epoch     INTEGER NOT NULL,
    command_json    BLOB    NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id) ON DELETE CASCADE,
    CHECK (lease_epoch >= 0)
);
-- Serves the per-attempt command lookup (WHERE attempt_id = ?) and the
-- attempts -> attempt_commands ON DELETE CASCADE, which without a child index
-- scans the whole command table per deleted attempt.
CREATE INDEX IF NOT EXISTS idx_attempt_commands_attempt
    ON attempt_commands (attempt_id);

-- Attempts: the durable STOP-ACK. One row per GENERATION of an attempt that an
-- operator asked to stop. See OPERATIONAL_SCHEMA_VERSION's design notes for why
-- it carries three timestamps rather than a state column.
--
-- KEYED BY (attempt_id, lease_epoch), NOT by attempt_id: a stop names the
-- dispatch it was addressed to, and only a worker terminal carrying that same
-- epoch acknowledges it. Production dispatches an attempt once, so an attempt
-- holds at most one stop; a row at another epoch stays individually outstanding
-- rather than overwriting or discharging this one.
--
-- THERE IS DELIBERATELY NO `CHECK (acknowledged_at_ms IS NULL OR
-- delivered_at_ms IS NOT NULL)`. It reads like an obvious integrity rule and it
-- is WRONG: the acknowledgement is written by the reactor thread when the
-- worker's terminal frame lands, and the delivery mark by the cancelling caller
-- after `send_control_to` returns. Nothing orders those two, so a worker that
-- stops fast enough acknowledges before the delivery mark is written. Under that
-- CHECK the ack — the one observation that actually proves safety — would be the
-- write that failed.
--
-- THIS ROW IS A LATCH, NOT PER-GENERATION EVIDENCE. It gates a DESTRUCTIVE operation: while it is
-- outstanding, `require_terminal_lifecycle_for_parking` refuses to reclaim the
-- execution's candidate worktree. A latch is read FAIL-CLOSED and is discharged
-- only by the fenced worker's own terminal or by an attributed operator
-- assertion — never by the disappearance of its subject.
--
-- Two clauses enact that reading, and NEITHER IS SOUND ALONE.
--
-- (1) `attempt_id` is NO ACTION (no `ON DELETE` clause), not CASCADE. Under
--     CASCADE, pruning the attempt would SILENTLY DELETE the latch — the latch's
--     subject vanishing treated as the question going away, which is the
--     evidence reading a latch refuses. Under NO ACTION, with the production
--     posture `foreign_keys = ON`, that prune is REFUSED. It is refused AT THE
--     DELETE STATEMENT and not at COMMIT, because this clause is deliberately
--     NOT `DEFERRABLE INITIALLY DEFERRED` (which would move the refusal to commit
--     time). Immediate is the right polarity here for two reasons:
--     `record_stop_request` documents an immediate refusal for a stop addressed
--     to a nonexistent attempt, and the statement that fails IS the diagnosis for
--     a prune. Pruning a whole `programs` row still works, because that cascades
--     this table away through clause (2) in the same statement.
--
-- (2) `execution_id` EXISTS AS A COLUMN, and it is what makes the latch
--     readable after its attempt is gone. Without it, the only route from an
--     execution to its stops is a join through `attempts`, which is sound ONLY
--     under CASCADE — an orphaned stop is invisible to an inner join, so
--     `unacknowledged_stops` EMPTIES and the parking predicate's first conjunct
--     is satisfied VACUOUSLY, opening parking on exactly the case it exists to
--     refuse.
--
--     `NO ACTION` + LEFT JOIN is NOT an alternative to this column. This table's execution
--     scoping can only come from `attempts`, so the predicate is `WHERE a.execution_id =
--     ?1` — and a WHERE on the right-hand table of a LEFT JOIN discards the NULL-extended
--     rows, collapsing it back into an INNER JOIN. The orphan stays invisible. The column
--     is not the alternative to the join fix; it is the only fix, and with it the scan
--     needs no join at all (see `stop_request_scan`).
--
--     It cascades from `programs`. That is not a hole in (1): a pruned
--     `programs` row is an execution that no longer exists, so there is no
--     candidate worktree left for the latch to protect, whereas a pruned
--     ATTEMPT leaves the execution — and its workspace — standing.
CREATE TABLE IF NOT EXISTS attempt_stop_requests (
    attempt_id          BLOB    NOT NULL,
    lease_epoch         INTEGER NOT NULL,
    execution_id        BLOB    NOT NULL,
    worker_id           TEXT    NOT NULL,
    reason              TEXT    NOT NULL,
    requested_at_ms     INTEGER NOT NULL,
    delivered_at_ms     INTEGER,
    acknowledged_at_ms  INTEGER,
    discharge_json      BLOB,
    PRIMARY KEY (attempt_id, lease_epoch),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id),
    CHECK (lease_epoch >= 0),
    CHECK (length(worker_id) > 0),
    -- A discharge record without an acknowledgement timestamp would be a
    -- discharge that discharges nothing. The converse is NOT constrained: the
    -- ordinary acknowledgement is the worker's own terminal and carries no
    -- record, so `acknowledged_at_ms IS NOT NULL AND discharge_json IS NULL` is
    -- the common case and means: the worker answered.
    CHECK (discharge_json IS NULL OR acknowledged_at_ms IS NOT NULL)
);
-- Serves the parking predicate's only question — does this execution hold an
-- unacknowledged stop? — which is answered from THIS TABLE ALONE
-- (`WHERE execution_id = ?1 AND acknowledged_at_ms IS NULL`), so the index is on
-- `execution_id` and not on `attempt_id`: an index on a column the predicate does
-- not name would leave the safety read scanning.
--
-- `attempt_id` needs no index of its own: it is the leftmost column of the
-- PRIMARY KEY, so the `attempts` foreign-key child scan rides the automatic
-- index.
--
-- Partial, so the index holds only the outstanding stops and shrinks to nothing
-- as they are acknowledged.
CREATE INDEX IF NOT EXISTS idx_attempt_stop_requests_unacknowledged
    ON attempt_stop_requests (execution_id) WHERE acknowledged_at_ms IS NULL;

-- CAS roots: authoritative references from this plane to CAS objects.
--
-- ROOT OWNERSHIP. A root names the entity whose retention obligation it discharges, and an
-- execution-owned root CASCADES with its owner: orphan object BYTES are safe while dangling
-- REFERENCES are not, and a root row whose owner is gone is a reference. The `node` arm
-- exists so a root that legitimately outlives every execution is DECLARED node-scoped
-- rather than being an execution root that lost its owner -- without it, 'no owner' and
-- 'node owner' are the same row and the leak returns by another name. `ON DELETE SET NULL`
-- was rejected for exactly that reason.
--
-- A root names exactly one 32-byte CAS `object_digest`, which a restore verifier can
-- recompute from the bytes.
--
-- RELEASE IS NOT DELETE. `released_at_ms` stamps a root its owner no longer asserts --
-- today only a released Nix environment's manifest root. The row stays: nothing deletes a
-- root row except its owning execution's cascade, and nothing reclaims CAS bytes at all.
CREATE TABLE IF NOT EXISTS cas_roots (
    root_id            BLOB    NOT NULL PRIMARY KEY,
    owner_kind         TEXT    NOT NULL,
    owner_execution_id BLOB,
    purpose            TEXT    NOT NULL,
    object_digest      BLOB    NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    released_at_ms     INTEGER,
    FOREIGN KEY(owner_execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    CHECK (owner_kind IN ('execution', 'node')),
    CHECK ((owner_kind = 'execution') = (owner_execution_id IS NOT NULL)),
    CHECK (length(root_id) > 0),
    CHECK (length(object_digest) = 32),
    CHECK (released_at_ms IS NULL OR released_at_ms >= created_at_ms)
);
-- Serves the programs -> cas_roots ON DELETE CASCADE child scan; the root_id
-- PRIMARY KEY cannot serve an owner predicate.
CREATE INDEX IF NOT EXISTS idx_cas_roots_owner
    ON cas_roots (owner_execution_id) WHERE owner_execution_id IS NOT NULL;
-- DOES ANY ROOT NAME THIS OBJECT? -- `declare_capsule`'s retention check for each
-- artifact a capsule maps. An artifact-object root is never released, so every one
-- retains its object. Without this index the check is a full scan of `cas_roots`
-- per mapping.
CREATE INDEX IF NOT EXISTS idx_cas_roots_artifact_object
    ON cas_roots (object_digest)
    WHERE purpose = 'artifact_object';
-- WHICH ARTIFACTS DOES THIS OWNER RETAIN? -- `active_artifacts_for`'s read, which joins
-- `cas_roots` to `artifacts`.
--
-- A SECOND index rather than a reordering of the one above, because the two reads lead
-- with different terms: the mapping check has no owner term at all (any owner's
-- root retains the object), and this one is keyed on the owner. One index ordered
-- `(object_digest, owner_execution_id)` would serve this read only by scanning every
-- artifact object on the node.
CREATE INDEX IF NOT EXISTS idx_cas_roots_owner_artifact
    ON cas_roots (owner_execution_id, object_digest)
    WHERE purpose = 'artifact_object';

-- Schedules: schedules pin the bound program hash + admission digest + program /
-- invocation JSON AT INSTALL, so a fire loads the pinned program instead of
-- recompiling by name. `schedule_firings` is keyed by (schedule_id,
-- fire_instant): a fire is an atomic, idempotent claim, so the claim and the
-- cursor advance cannot half-commit into a double fire.
--
-- `trigger` (quoted — SQLite keyword) holds the serialized trigger declaration
-- (interval or cron), `on_missed` the missed-while-down policy vocabulary shared
-- with kata_program::schedule::MissedPolicy, and `submit_pack` the authored
-- submit target the pinned program was compiled from (provenance for the
-- schedule-immutability guard: the fire path must NOT recompile by this name).
CREATE TABLE IF NOT EXISTS schedules (
    schedule_id             TEXT    NOT NULL PRIMARY KEY,
    submit_pack             TEXT    NOT NULL,
    \"trigger\"               TEXT    NOT NULL,
    on_missed               TEXT    NOT NULL,
    bound_program_hash      BLOB    NOT NULL,
    bound_admission_digest  BLOB    NOT NULL,
    program_json            BLOB    NOT NULL,
    invocation_json         BLOB    NOT NULL,
    cursor_ms               INTEGER NOT NULL,
    created_at_ms           INTEGER NOT NULL,
    CHECK (length(schedule_id) > 0),
    CHECK (length(submit_pack) > 0),
    CHECK (length(\"trigger\") > 0),
    CHECK (on_missed IN ('fire_once_on_boot', 'skip')),
    CHECK (length(bound_program_hash) = 32),
    CHECK (length(bound_admission_digest) = 32)
);
-- A firing either SUBMITTED an execution (`execution_id`) or was REFUSED before
-- any execution existed and records why (`refusal`: the fire's execution target
-- did not resolve, or did not pass the structural target check) — exactly one of
-- the two. A refused firing still spends its instant, so the occurrence is never
-- retried silently.
CREATE TABLE IF NOT EXISTS schedule_firings (
    schedule_id     TEXT    NOT NULL,
    fire_instant    INTEGER NOT NULL,
    execution_id    BLOB,
    refusal         TEXT,
    fired_at_ms     INTEGER NOT NULL,
    PRIMARY KEY (schedule_id, fire_instant),
    FOREIGN KEY(schedule_id) REFERENCES schedules(schedule_id) ON DELETE CASCADE,
    -- The firing is claimed BEFORE the execution it submits is inserted (same
    -- transaction), so this reference is deferred and checked at commit.
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((execution_id IS NULL) <> (refusal IS NULL)),
    CHECK (refusal IS NULL OR length(refusal) > 0)
);
-- Serves the 'which firing submitted this execution?' provenance lookup
-- (WHERE execution_id = ?) and the programs -> schedule_firings ON DELETE
-- CASCADE; the (schedule_id, fire_instant) PRIMARY KEY cannot serve it.
CREATE INDEX IF NOT EXISTS idx_schedule_firings_execution
    ON schedule_firings (execution_id);

-- Inbox: the accepted-event inbox. `accepted = 0` rows are retained worker failures
-- written by the arrival gate (`buffer_worker_failure`). `accepted = 1` rows and the
-- watermark are written only by `promote_event_slot` / `advance_inbox_watermark`,
-- inside a checked decision that records the slot's transition: the worker-failure
-- adjudication, the worker-completion acceptance, or the gate's supersession branch. Same (stream, seq) with the same
-- digest is an idempotent ACK; a different digest is a typed divergence refusal.
-- The watermark advances only over a contiguous accepted prefix.
--
-- `execution_id` IS THE RETENTION SCOPE. `stream_id` is an OPAQUE
-- `attempt_id ++ attempt_ordinal` key, so without this column the only route from
-- an execution to its inbox rows is through `attempts` — and there is no join at
-- all in the retention direction, because `DELETE FROM programs` is a foreign-key
-- cascade and a cascade cannot traverse a join. Both inbox tables would sit
-- OUTSIDE the `programs`-rooted unwind and survive it with their full payload
-- JSON; `deleting_an_execution_now_reaches_the_event_inbox` pins that they do not.
--
-- CASCADE, because an accepted frame is DERIVED buffer state whose authority was
-- already folded into `transitions` — which cascades — so retaining it past its
-- execution retains a payload nothing can read against a chain that is gone. It
-- names something a worker said about work whose record is being pruned on
-- purpose.
CREATE TABLE IF NOT EXISTS event_inbox (
    stream_id       BLOB    NOT NULL,
    event_seq       INTEGER NOT NULL,
    execution_id    BLOB    NOT NULL,
    event_digest    BLOB    NOT NULL,
    accepted        INTEGER NOT NULL,
    payload_json    BLOB    NOT NULL,
    received_at_ms  INTEGER NOT NULL,
    PRIMARY KEY (stream_id, event_seq),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    CHECK (accepted IN (0, 1)),
    CHECK (length(stream_id) > 0),
    CHECK (length(event_digest) = 32),
    -- Streams are 1-based: seq 0 is the 'nothing accepted yet' watermark value.
    CHECK (event_seq >= 1)
);
-- A partial index over the retained (accepted = 0) inputs, so the recovery
-- population's 'is any input still retained?' probe (`WHERE accepted = 0`) scans
-- only those rows — the PRIMARY KEY cannot serve the accepted = 0 predicate, so
-- the probe would otherwise scan the node's whole accepted history.
CREATE INDEX IF NOT EXISTS idx_event_inbox_buffered
    ON event_inbox (stream_id, event_seq) WHERE accepted = 0;
-- Serves the programs -> event_inbox ON DELETE CASCADE child scan, which without
-- it re-scans every inbox row in the node PER PRUNED EXECUTION — the same reason
-- every other execution-scoped child table here carries one.
CREATE INDEX IF NOT EXISTS idx_event_inbox_execution
    ON event_inbox (execution_id);
-- The watermark carries the scope too. Pruning the rows while leaving the
-- watermark behind is not a smaller version of the same fix, it is a DIFFERENT
-- durable state: a surviving watermark asserts `accepted_through_seq = N` over
-- slots that no longer exist, which is precisely the shape
-- `dedupe_accepted_event` raises `watermark claims seq accepted but no row
-- exists` for.
CREATE TABLE IF NOT EXISTS event_inbox_watermark (
    stream_id           BLOB    NOT NULL PRIMARY KEY,
    execution_id        BLOB    NOT NULL,
    accepted_through_seq INTEGER NOT NULL CHECK (accepted_through_seq >= 0),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE
);
-- Serves the programs -> event_inbox_watermark ON DELETE CASCADE child scan; the
-- stream_id PRIMARY KEY cannot serve an execution_id predicate.
CREATE INDEX IF NOT EXISTS idx_event_inbox_watermark_execution
    ON event_inbox_watermark (execution_id);

CREATE TABLE IF NOT EXISTS worker_effect_domains (
    source_main TEXT NOT NULL CHECK(length(source_main) BETWEEN 1 AND 128),
    membrane_id BLOB NOT NULL CHECK(length(membrane_id) = 16),
    enrollment_id BLOB NOT NULL CHECK(length(enrollment_id) = 16),
    PRIMARY KEY(source_main, membrane_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_worker_effect_domain_enrollment
    ON worker_effect_domains(enrollment_id);
CREATE TABLE IF NOT EXISTS worker_dispatch_domains (
    attempt_id BLOB NOT NULL,
    lease_epoch INTEGER NOT NULL CHECK(lease_epoch >= 0),
    enrollment_id BLOB NOT NULL,
    worker_label TEXT NOT NULL CHECK(length(worker_label) > 0),
    PRIMARY KEY(attempt_id, lease_epoch),
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id),
    FOREIGN KEY(enrollment_id) REFERENCES worker_effect_domains(enrollment_id)
);
CREATE INDEX IF NOT EXISTS idx_worker_dispatch_domain_attempt
    ON worker_dispatch_domains(enrollment_id, attempt_id);
CREATE TABLE IF NOT EXISTS recovery_imports (
    artifact_id BLOB NOT NULL PRIMARY KEY CHECK(length(artifact_id)=16),
    source_directory_id TEXT NOT NULL,
    target_directory_id TEXT NOT NULL,
    catalog_digest TEXT NOT NULL CHECK(length(catalog_digest)=64),
    released_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS recovery_import_subjects (
    artifact_id BLOB NOT NULL,
    subject_key TEXT NOT NULL,
    decision_json TEXT,
    PRIMARY KEY(artifact_id,subject_key),
    FOREIGN KEY(artifact_id) REFERENCES recovery_imports(artifact_id)
);

-- Environments: DECLARED NIX MANAGED-SOFTWARE ENVIRONMENTS.
--
-- `operational.db` is authoritative for WHICH closure was authorized; Nix owns
-- realization, transport and collection (Nix is mandatory for the managed
-- software profile). One row is the durable record that a closure was
-- declared, which manifest bytes describe it, and which staging generation its
-- protected Nix gc root was created under.
--
-- `manifest_object_id` is the CAS object id of the manifest bytes, stored the way
-- `cas_roots.object_digest` stores an object id: a raw 32-byte content digest, not
-- a rendered string. The row does NOT make those bytes retained — the node-owned
-- `cas_roots` row written in the SAME transaction
-- (`NIX_ENVIRONMENT_MANIFEST_ROOT_PURPOSE`) does, because reachability in this
-- plane is root ROW EXISTENCE (`stored_cas_roots`). Duplicating the retention
-- decision here would be a second answer to the question `cas_roots` already
-- answers.
--
-- `root_stage_id` is the staging ULID directory name the indirect gc root was
-- created under, BEFORE promotion to its stable per-environment path. It is
-- recorded rather than derived because it is the only thing that lets boot tell a
-- staging directory it must sweep (no row, or a row whose stage it does not match)
-- from the one a crashed declare legitimately left behind.
--
-- TWO NULLABLE INSTANTS, TWO DIFFERENT UNFINISHED STATES, and the pair is what the
-- reconciler reads:
--
--   `root_promoted_at_ms IS NULL` -- the row committed and the gc root has not been
--       promoted out of staging. K15's recovery state. The environment is NOT
--       usable: `unpromoted_environments` is what the boot reconciler drives, and
--       issuance must refuse an environment whose root is unpromoted.
--   `released_at_ms IS NOT NULL` -- the environment was released; its manifest CAS
--       root is released in the same transaction, and only
--       `delete_released_environment` removes the row.
--
-- AT MOST ONE LIVE ROW MAY NAME ONE MANIFEST OBJECT, enforced by
-- `idx_nix_environments_manifest_live` below: two live rows over one manifest share a
-- single derived `cas_roots` row, so releasing either would release the other's root.
-- That index carries the argument in full.
--
-- A RELEASED ROW IS ALWAYS A PROMOTED ROW, by refusal rather than by convention:
-- `release_environment` refuses an unpromoted environment and
-- `promote_environment_root` refuses a released one, so the two partial indexes
-- below are disjoint in one direction — every unpromoted row is unreleased. The
-- unpromoted index therefore needs no `released_at_ms IS NULL` conjunct, and adding
-- one would state a guarantee wider than its mechanism.
CREATE TABLE IF NOT EXISTS nix_environments (
    environment_id       BLOB    NOT NULL PRIMARY KEY,
    manifest_object_id   BLOB    NOT NULL,
    closure_digest       BLOB    NOT NULL,
    label                TEXT    NOT NULL,
    platform_id          BLOB    NOT NULL,
    root_stage_id        TEXT    NOT NULL,
    root_promoted_at_ms  INTEGER,
    released_at_ms       INTEGER,
    created_at_ms        INTEGER NOT NULL,
    verification_evidence BLOB,
    CHECK (length(environment_id) = 32),
    CHECK (length(manifest_object_id) = 32),
    CHECK (length(closure_digest) = 32),
    CHECK (length(platform_id) = 32),
    CHECK (length(label) > 0),
    CHECK (length(root_stage_id) > 0),
    CHECK (root_promoted_at_ms IS NULL OR root_promoted_at_ms >= created_at_ms),
    CHECK (released_at_ms IS NULL OR released_at_ms >= created_at_ms),
    -- A released environment is a promoted one; see the table comment.
    CHECK (released_at_ms IS NULL OR root_promoted_at_ms IS NOT NULL)
);
-- Serves `active_environments` -- the boot/issuance question `which environments
-- may still be bound?` -- and is PARTIAL so the scan is proportional to the live
-- population rather than to every environment the node has ever declared. Same
-- posture, and the same reason, as `idx_execution_lifecycle_active`.
CREATE INDEX IF NOT EXISTS idx_nix_environments_active
    ON nix_environments (environment_id) WHERE released_at_ms IS NULL;
-- Serves `unpromoted_environments`, the boot reconciliation scan. Partial on the
-- UNFINISHED state, so a node whose environments are all promoted carries an empty
-- index and the reconciler's cost is proportional to the crash window's residue,
-- not to the environment history.
CREATE INDEX IF NOT EXISTS idx_nix_environments_unpromoted
    ON nix_environments (environment_id) WHERE root_promoted_at_ms IS NULL;
-- AT MOST ONE LIVE ENVIRONMENT PER MANIFEST OBJECT, and this one is AUTHORITY rather
-- than a query hint.
--
-- A manifest root's id is `blake3(owner_kind, owner_execution_id, purpose, target)`
-- and every environment root is
-- `(node, NULL, nix_environment_manifest, Object(manifest_object_id))`
-- -- so two environments over the SAME manifest object derive the SAME root id and
-- share ONE `cas_roots` row. `release_environment` then releases that shared row on
-- behalf of one of them, and the OTHER environment's live row is left naming a manifest
-- whose only root no longer asserts it -- the dangling-root verifier passes over a
-- released root, so a lost manifest under that live row would go unnoticed.
--
-- The fix is refused here, in the shape that cannot be forgotten by a caller: a
-- UNIQUE partial index over the LIVE rows. Partial on `released_at_ms IS NULL` because
-- the constraint is about live claims on the root -- a released row has already
-- relinquished it, so re-declaring the same manifest after a release (or after a
-- delete) is legitimate and re-acquires the row through `upsert_cas_root`. A
-- non-partial UNIQUE would forbid that and make an environment id unreusable forever.
--
-- `declare_environment` refuses the second live declaration with a typed
-- `KataError::Validation` BEFORE reaching this index, so a caller gets a message that
-- names the colliding environment instead of a bare SQLite uniqueness error; this
-- index is what makes that refusal total against a writer that skipped the check.
CREATE UNIQUE INDEX IF NOT EXISTS idx_nix_environments_manifest_live
    ON nix_environments (manifest_object_id) WHERE released_at_ms IS NULL;

-- Artifacts: PORTABLE ARTIFACTS.
--
-- One row is the durable record that THIS node authorized one artifact reference:
-- `artifact_id` is `kata_types::execution_contract::ArtifactRef`'s id, which folds
-- `(object_id, size_bytes, privacy)` field-wise, and the three folded columns are
-- stored beside it so a reader can re-derive the id from the row instead of trusting
-- it. `kind` says how the OBJECT is to be read: `blob` -- the object IS the
-- artifact's bytes -- or `tree` -- the object is a `kata_types::tree_artifact`
-- manifest naming member objects -- or `tree_delta` -- the object is a
-- `kata_types::tree_delta` whose `Write` nodes name member objects.
--
-- The row does NOT reference the object on its own; the `cas_roots` row written in the
-- SAME transaction (`ARTIFACT_OBJECT_ROOT_PURPOSE`) does, exactly as for
-- `nix_environments`, and states which owner asserts it.
--
-- AT MOST ONE ROW MAY NAME ONE OBJECT, enforced by `idx_artifacts_object` below. That
-- is ONE PRIVACY CLASS PER OBJECT and nothing else: the id folds object, size and
-- privacy, and object and size are fixed by the bytes, so two distinct ids over one
-- object can differ ONLY in privacy. The index's argument is in full there.
--
-- A ROW HERE IS A NODE-LEVEL CONTENT CLAIM, and carries NO OWNER.
--
-- `artifact_id` is `H(object_id, size_bytes, privacy)` -- the execution contract's
-- derivation, which does not fold an owner -- and it is this table's PRIMARY KEY. A
-- column that named one owner would make the id and the row disagree about what
-- identifies an artifact, and the disagreement would be REACHABLE: two executions whose
-- stages write byte-identical `/out` trees produce one `artifact_id`, and every capsule
-- maps the CANONICAL EMPTY TREE at `/out`, so the second declarer would be refused as a
-- divergent re-declaration for being a different execution. OWNERSHIP lives in
-- `cas_roots`, one row per `(owner, artifact_object, object)`, which
-- is where a per-owner retention obligation can actually be represented.
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id        BLOB    NOT NULL PRIMARY KEY,
    object_id          BLOB    NOT NULL,
    size_bytes         INTEGER NOT NULL,
    privacy            TEXT    NOT NULL,
    kind               TEXT    NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    CHECK (length(artifact_id) = 32),
    CHECK (length(object_id) = 32),
    CHECK (size_bytes >= 0),
    CHECK (privacy IN ('public', 'private')),
    CHECK (kind IN ('blob', 'tree', 'tree_delta'))
);
-- ONE PRIVACY CLASS PER OBJECT, and this one is AUTHORITY rather than a query hint.
--
-- Two distinct `artifact_id`s over one object can differ only in PRIVACY: the id folds
-- `(object, size, privacy)` and the first two are fixed by the bytes. So this index's
-- whole refused set is: the same bytes declared both as a public artifact and as a
-- private one, which defeats the private-artifact plane -- the private classification
-- is discharged by the public twin naming the same object. (Two owners over one
-- artifact are ONE row and TWO roots, so sharing a `cas_roots` row is not a reason this
-- index has to state.) A row is never released or deleted, so the claim is permanent.
--
-- `declare_artifact` refuses the second declaration with a typed `KataError::Validation`
-- BEFORE reaching this index, so a caller gets a message that names the colliding
-- artifact instead of a bare SQLite uniqueness error; this index is what makes that
-- refusal total against a writer that skipped the check.
CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_object
    ON artifacts (object_id);

-- Capsules: DECLARED CAPSULES -- ADR-0001 trust boundary 3.
--
-- A capsule is 'an immutable, versioned capsule containing identities, guest paths,
-- budgets, permissions, and artifact/environment references -- not main-host paths',
-- and `capsule_id` folds ALL of it (`kata_types::execution_contract::Capsule::new`).
-- So this table stores the id, the coordinates a reader looks a capsule up by, and the
-- CAS object holding the capsule's canonical serialization -- and NOT a second copy of
-- the mapping list. The BYTES are the mapping list, and the id is recomputed from them
-- on decode, so a `capsule_inputs` child table could only either restate them (dead
-- weight that can disagree) or contradict them.
--
-- THERE IS NO `released_at_ms` AND NO RELEASE VERB: a declared capsule's bytes are
-- asserted for the node's lifetime by a node-owned authoritative root, which is why
-- `declare_capsule` is the only verb here.
--
-- `environment_id` REFERENCES `nix_environments` with NO ACTION, which is the FK
-- action that matches the claim: a capsule must name a DECLARED environment, and
-- deleting an environment a capsule names must be refused rather than cascading the
-- capsule away or nulling the binding. `declare_capsule` additionally refuses an
-- environment that is declared but RELEASED, and an artifact mapping with no live
-- `artifacts` row -- neither of which an FK can express, because 'live' is a column
-- state and the mappings live inside the capsule's bytes.
CREATE TABLE IF NOT EXISTS capsules (
    capsule_id         BLOB    NOT NULL PRIMARY KEY,
    occurrence_id      BLOB    NOT NULL,
    prepared_action_id BLOB    NOT NULL,
    environment_id     BLOB    NOT NULL,
    platform_id        BLOB    NOT NULL,
    capsule_object_id  BLOB    NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    FOREIGN KEY(environment_id) REFERENCES nix_environments(environment_id) ON DELETE NO ACTION,
    CHECK (length(capsule_id) = 32),
    CHECK (length(occurrence_id) = 32),
    CHECK (length(prepared_action_id) = 32),
    CHECK (length(environment_id) = 32),
    CHECK (length(platform_id) = 32),
    CHECK (length(capsule_object_id) = 32)
);
-- Serves the nix_environments -> capsules foreign-key child scan. A NO ACTION parent
-- delete has to prove no child references the row, and without this index SQLite proves
-- it by scanning every capsule the node has ever declared.
CREATE INDEX IF NOT EXISTS idx_capsules_environment
    ON capsules (environment_id);

-- Occurrences: DURABLE OCCURRENCE IDENTITY -- ADR-0001 trust boundary 2.
--
-- An OCCURRENCE is one logical invocation of one checked operation: 'retry, lease,
-- worker, and attempt facts are deliberately absent so they cannot rotate logical
-- identity' (`kata_types::execution_contract::OccurrenceRef`). An ATTEMPT is one
-- generation of work AT an occurrence. This table is where that distinction becomes
-- DURABLE rather than a type in RAM, and it exists so the engine can answer 'has
-- this logical work already been accepted?' without asking 'did this attempt
-- finish?' -- which is the question that cannot be answered after a re-dispatch.
--
-- `occurrence_id` IS `OccurrenceRef::id()`, a content id over (execution, program
-- hash, operation contract id, operation path). It is NOT a ULID, so it recurs
-- exactly when the logical work recurs, which is what makes re-presentation
-- idempotent rather than a new row.
--
-- The three LOOKUP coordinates are stored beside it because the id is a hash and a
-- hash is not a key anyone can query BY: a caller holding a program and an operation
-- path must be able to find the row without already knowing its id, which is what
-- `UNIQUE(execution_id, operation_contract_id, operation_path)` serves.
-- `program_hash` is deliberately NOT part of that key: it is folded into
-- `occurrence_id` and is retained here as the divergence CHECK the minting verb
-- reads -- two programs over one execution and one operation path is a repointed
-- execution, and the refusal names it rather than silently adopting the stored row.
--
-- `operation_path` holds `OperationPath::canonical_bytes()` -- the u64 LE coordinate
-- count followed by each coordinate as u32 LE -- which is byte-for-byte what
-- `OccurrenceRef::id()` folds. ONE ENCODING, TWO CONSUMERS: the SQL uniqueness
-- constraint and the content id are derived from the same bytes, so they cannot
-- answer different questions about whether two occurrences are the same one. The
-- `% 4 = 0` CHECK is the structural half of that (8 + 4n is always divisible by
-- four); `kata_types::execution_contract`'s
-- `hash_path_folds_exactly_the_canonical_bytes_field_wise` is the semantic half.
--
-- `prepared_action_id` and `capsule_id` are NULLABLE because MINTING PRECEDES
-- PREPARATION: the occurrence is minted at claim time, and the capsule that will
-- run it is declared after. A NOT NULL column here
-- would force the claim to invent a capsule id, which is the 'kata never invents
-- one' rule. `capsule_id` REFERENCES `capsules` with NO ACTION for the reason
-- `capsules.environment_id` does: a capsule a live occurrence names must not be
-- deletable out from under it.
--
-- ONE ACCEPTED OUTCOME PER OCCURRENCE, and it is enforced THREE TIMES rather than
-- once, deliberately -- see `idx_occurrences_accepted_attempt` below and
-- `refuse_second_occurrence_acceptance` (`operational/mod.rs`) for the other two.
-- The pair of columns is the durable fact, and the CHECK below is what stops the
-- pair from ever half-existing: a row that named an accepting attempt with no
-- instant, or an instant with no attempt, would satisfy the partial unique index
-- (which keys on the attempt alone) while making 'is this occurrence accepted?'
-- return two different answers depending on which column the reader consults: two
-- disagreeing representations of one fact, inside one row.
--
-- `accepted_attempt_id` REFERENCES `attempts` ON DELETE CASCADE DEFERRABLE
-- INITIALLY DEFERRED, and every word of that is load-bearing:
--
-- * CASCADE rather than NO ACTION, because the acceptance is not a LATCH over an
--   outside-world obligation the way `attempt_stop_requests` is. It is a
--   statement about WHICH GENERATION produced the accepted result, and an
--   execution-scoped prune that takes the attempts away takes the occurrence away
--   in the same statement through `execution_id` -- so there is no window in
--   which a surviving occurrence points at a deleted attempt.
-- * DEFERRED, and the reason is the PRUNE rather than the claim. The claim does not
--   need it: `claim_attempt` inserts the occurrence BEFORE the attempt row, and this
--   column is NULL at that point, so neither direction's key is ever momentarily
--   unsatisfied. (This comment asserted the opposite -- that the two tables
--   referencing each other left one FK unsatisfied whichever order the claim used --
--   which is false for a NULL column, and is corrected here rather than left as a
--   reason a reader could not reproduce.)
--
--   What DOES need it is the cycle an execution-scoped delete has to unwind. kata
--   deletes no execution in production; the one `DELETE FROM programs` is the
--   test-support `debug_delete_execution`, and a retention sweep, should one ever
--   exist, would issue the same statement. An accepted
--   occurrence and its attempt reference each other: `DELETE FROM programs` cascades
--   into both tables in ONE statement, and an IMMEDIATE check on this column would
--   fire mid-cascade on whichever row SQLite reaches first. Deferred to COMMIT the
--   cascade is complete and both sides are gone.
--   `an_execution_scoped_prune_unwinds_its_occurrences_and_their_attempts`
--   (`crates/core/tests/operational_occurrences.rs`) measures it rather than arguing
--   it, because cascade ordering is SQLite's behaviour and not kata's.
CREATE TABLE IF NOT EXISTS occurrences (
    occurrence_id         BLOB    NOT NULL PRIMARY KEY,
    execution_id          BLOB    NOT NULL,
    program_hash          BLOB    NOT NULL,
    operation_contract_id BLOB    NOT NULL,
    operation_path        BLOB    NOT NULL,
    prepared_action_id    BLOB,
    capsule_id            BLOB,
    created_at_ms         INTEGER NOT NULL,
    accepted_at_ms        INTEGER,
    accepted_attempt_id   BLOB,
    work_tree_artifact_id BLOB,
    UNIQUE (execution_id, operation_contract_id, operation_path),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(capsule_id) REFERENCES capsules(capsule_id) ON DELETE NO ACTION,
    FOREIGN KEY(accepted_attempt_id) REFERENCES attempts(attempt_id)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    CHECK (length(occurrence_id) = 32),
    CHECK (length(execution_id) = 16),
    CHECK (length(program_hash) = 32),
    CHECK (length(operation_contract_id) = 32),
    CHECK (length(operation_path) % 4 = 0),
    CHECK (prepared_action_id IS NULL OR length(prepared_action_id) = 32),
    CHECK (capsule_id IS NULL OR length(capsule_id) = 32),
    CHECK (accepted_attempt_id IS NULL OR length(accepted_attempt_id) = 16),
    CHECK (work_tree_artifact_id IS NULL OR length(work_tree_artifact_id) = 32),
    CHECK ((accepted_at_ms IS NULL) = (accepted_attempt_id IS NULL))
);
-- Serves the `programs -> occurrences` ON DELETE CASCADE child scan and the 'which
-- occurrences does this execution hold?' read. The `occurrence_id` PRIMARY KEY
-- cannot serve an execution predicate, and the UNIQUE lookup key leads with
-- `execution_id` but is a THREE-column index whose leading-column scan SQLite will
-- use -- this index is nevertheless kept explicit because the cascade child scan is
-- the one consumer that must not depend on the planner preferring the wider index.
CREATE INDEX IF NOT EXISTS idx_occurrences_execution
    ON occurrences (execution_id);
-- AT MOST ONE OCCURRENCE PER ACCEPTING ATTEMPT, and this one is AUTHORITY.
--
-- Read in the direction the name suggests it is a bijection guard: one attempt
-- cannot be the accepted outcome of two occurrences. That is real -- an attempt is
-- one generation of work at ONE occurrence, so an attempt accepted by two of them
-- would mean the durable binding disagreed with `attempts.occurrence_id` -- but it
-- is NOT the property the acceptance invariant needs, and that is stated here so a
-- later reader does not mistake one for the other.
--
-- The property the invariant needs -- at most one ACCEPTED ATTEMPT per occurrence --
-- is carried by the PRIMARY KEY plus the write-once UPDATE:
-- `accept_occurrence_outcome` issues `UPDATE occurrences SET ... WHERE
-- occurrence_id = ? AND accepted_attempt_id IS NULL` and asserts `rowcount == 1`,
-- so a second acceptance of one occurrence matches zero rows and refuses. One row
-- per occurrence is structural; the conditional predicate is what makes the column
-- write-once within it.
--
-- So the THREE mechanisms are not three spellings of one guard: the CHECK stops a
-- half-written pair, this index stops one attempt accepting two occurrences, and the
-- conditional UPDATE plus `refuse_second_occurrence_acceptance` stop one occurrence
-- accepting two attempts. `crates/core/tests/operational_occurrences.rs` falsifies
-- the CHECK, this index and the Rust latch separately; the UPDATE's predicate is NOT
-- separately falsifiable through the API, because `accept_occurrence_outcome` reads
-- and refuses a second acceptance in the same transaction before the UPDATE runs --
-- it is the in-SQL restatement for a writer that skipped that read.
--
-- Partial on `accepted_attempt_id IS NOT NULL` because SQLite treats NULLs as
-- distinct in a UNIQUE index, so the predicate does not change WHAT is refused. It
-- is written anyway so the index is proportional to the ACCEPTED population rather
-- than to every occurrence the node has ever minted.
CREATE UNIQUE INDEX IF NOT EXISTS idx_occurrences_accepted_attempt
    ON occurrences (accepted_attempt_id) WHERE accepted_attempt_id IS NOT NULL;

-- Evidence: EXECUTION-LEVEL EVIDENCE.
--
-- These rows have no source sequence on the transition chain. `append_execution_evidence`
-- appends 'without creating a worker assignment or emitting a lifecycle ledger event', so
-- there is no transition to attribute them to and inventing one would make an
-- observation look like a decision in the audit chain.
--
-- `execution_id` REFERENCES `programs` ON DELETE CASCADE, so these rows never
-- outlive their execution with their full payload, and 'evidence for an execution
-- this node never admitted' is unwritable rather than merely unlikely.
--
-- `execution_evidence_claims` deliberately carries NO index of its own: the
-- composite PRIMARY KEY's implicit index already leads with `execution_id`, so an
-- explicit one would be a second copy of an index SQLite maintains anyway, and the
-- implicit one serves the CASCADE child scan too.
CREATE TABLE IF NOT EXISTS execution_evidence (
    evidence_id   BLOB    NOT NULL PRIMARY KEY,
    execution_id  BLOB    NOT NULL,
    created_at_ms INTEGER NOT NULL,
    evidence_json BLOB    NOT NULL,
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    CHECK (length(evidence_id) = 16),
    CHECK (length(execution_id) = 16)
);
-- Serves `execution_evidence_records`' deterministic per-execution replay order and
-- the `programs -> execution_evidence` ON DELETE CASCADE child scan: the ORDER BY
-- is `(created_at_ms, evidence_id)` and an index that stopped at `execution_id`
-- would leave the sort to a temp b-tree.
CREATE INDEX IF NOT EXISTS idx_execution_evidence_execution
    ON execution_evidence (execution_id, created_at_ms, evidence_id);
CREATE TABLE IF NOT EXISTS execution_evidence_claims (
    execution_id  BLOB    NOT NULL,
    claim_key     TEXT    NOT NULL,
    evidence_id   BLOB    NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (execution_id, claim_key),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    CHECK (length(execution_id) = 16),
    CHECK (length(evidence_id) = 16),
    CHECK (length(claim_key) > 0)
);

-- Work-tree head: THE EXECUTION'S /work HEAD -- one row per
-- execution naming the committed base tree published into CAS at admission.
--
-- What it is NOT: not a per-attempt record. `occurrences.work_tree_artifact_id`
-- binds the tree one attempt WALKED; this row binds the tree the EXECUTION's
-- every isolated capsule maps -- the difference between what this attempt
-- saw and what this execution is allowed to see at all. Two executions can
-- record the same artifact id (a base tree's content address recurs whenever
-- the base's content does, as for `artifacts`); the PRIMARY KEY is the
-- execution, and the row is write-once by
-- `OperationalDb::record_work_tree_head`'s converge-or-refuse rather than by
-- INSERT OR REPLACE, because a second head over one execution is a second
-- input and never an update.
--
-- `base_commit` is TEXT because it is the BACKEND'S spelling (jj's commit hex),
-- not an address this plane interprets: the capsule's /work derives from
-- `work_tree_artifact_id` alone, and the commit string is provenance for the
-- divergent check and for an operator asking where the input came from.
--
-- `execution_id` REFERENCES `programs` ON DELETE CASCADE -- the head is a fact
-- about the execution and dies with the execution's own prune. ON the
-- `artifacts` side the action is NO ACTION: the head NAMES the declared tree,
-- and deleting the artifact row under a live head would leave a mapping
-- authority no object backs. An `artifacts` row is never released or deleted,
-- so the NO ACTION never fires on a writer kata ships; it is what keeps one
-- that skipped the rule from orphaning a head.
-- `branch` is the head's COORDINATE inside the execution: '' the execution's
-- own head, otherwise the canonical spelling of the stack of `parallel()`
-- branches enclosing the stages it serves (`WorkTreeHeadCoordinate` — a JSON
-- list of [join stage, exit stage] pairs, outermost first). One row per
-- (execution, branch): the execution head is recorded once at admission
-- (isolated: the committed base tree; non-isolated under `oci`: the seeded
-- scratch workspace walk), a branch head is forked off its parent's row the
-- first time a stage inside the branch is dispatched, and every row is
-- CAS-advanced by its own `#apply/<stage>` (or `#apply/<join>`) effect.
-- `join_stage`/`forked_from` name the barrier and the parent coordinate a
-- branch row was forked under ('' on the execution head);
-- `fork_base_artifact_id` is the parent artifact the branch forked AT —
-- frozen, so the join computes `between(fork_base, head)` per branch no matter
-- how far the parent head advanced meanwhile. `base_commit` and
-- `candidate_commit_id` carry '' for a head with no jj workspace behind it
-- (a scratch-seeded or branch row); they are provenance, never an input.
-- `committed_commit_id` is the commit the execution's latest `commit`
-- workspace effect finalized ('' until one resolves), written in the same
-- compare-and-swap that moves `candidate_commit_id` onto the empty `@` the
-- commit leaves: `promote` and `forge_export` deliver it while the candidate
-- is still its empty child.
CREATE TABLE IF NOT EXISTS execution_work_tree_heads (
    execution_id           BLOB    NOT NULL,
    branch                 TEXT    NOT NULL,
    base_commit            TEXT    NOT NULL,
    work_tree_artifact_id  BLOB    NOT NULL,
    candidate_commit_id    TEXT    NOT NULL,
    committed_commit_id    TEXT    NOT NULL,
    head_seq               INTEGER NOT NULL,
    join_stage             TEXT    NOT NULL,
    forked_from            TEXT    NOT NULL,
    fork_base_artifact_id  BLOB,
    recorded_at_ms         INTEGER NOT NULL,
    PRIMARY KEY (execution_id, branch),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(work_tree_artifact_id) REFERENCES artifacts(artifact_id) ON DELETE NO ACTION,
    FOREIGN KEY(fork_base_artifact_id) REFERENCES artifacts(artifact_id) ON DELETE NO ACTION,
    CHECK (length(work_tree_artifact_id) = 32),
    CHECK (fork_base_artifact_id IS NULL OR length(fork_base_artifact_id) = 32),
    CHECK (head_seq >= 0)
);
-- Serves the artifacts -> execution_work_tree_heads ON DELETE NO ACTION child
-- scan: refusing a parent's delete has to prove no head names the row, and
-- without this index SQLite proves it by scanning every head the node has ever
-- recorded. The PRIMARY KEY cannot serve the predicate -- it leads with
-- execution_id.
CREATE INDEX IF NOT EXISTS idx_execution_work_tree_heads_artifact
    ON execution_work_tree_heads (work_tree_artifact_id);

-- Git view: the execution's git-history artifact — one row
-- per `oci` execution whose program contains an agent stage, recorded LAST
-- after the artifact's members, manifest, `artifacts` row and owner
-- `cas_roots` row are durable (the `after_git_view_published_before_recorded`
-- window). `base_commit` is the base the worker's scratch repository's
-- `kata/<execution>` ref names, `branch_name`/`branch_commit` its second
-- scratch ref off the execution's frozen target (both NULL for a view with
-- none), and `identity_*` the committer identity its config carries; `history_artifact_id` names the manifest (`kind = 'tree'`) over
-- `objects/pack/pack-*.{pack,idx}`, `index` and a possible `shallow`.
CREATE TABLE IF NOT EXISTS execution_git_views (
    execution_id          BLOB    NOT NULL PRIMARY KEY,
    base_commit           TEXT    NOT NULL,
    branch_name           TEXT,
    branch_commit         TEXT,
    identity_name         TEXT    NOT NULL,
    identity_email        TEXT    NOT NULL,
    history_artifact_id   BLOB    NOT NULL,
    recorded_at_ms        INTEGER NOT NULL,
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(history_artifact_id) REFERENCES artifacts(artifact_id) ON DELETE NO ACTION,
    CHECK (base_commit <> ''),
    CHECK ((branch_name IS NULL AND branch_commit IS NULL) OR
           (branch_name <> '' AND branch_commit <> '')),
    CHECK (length(history_artifact_id) = 32)
);
-- Serves the artifacts -> execution_git_views ON DELETE NO ACTION child scan,
-- exactly as idx_execution_work_tree_heads_artifact serves the head table.
CREATE INDEX IF NOT EXISTS idx_execution_git_views_artifact
    ON execution_git_views (history_artifact_id);

-- Forge intents: ONE ROW PER WIRE EFFECT a `forge_export` attempt issues -- the
-- `git push` of `kata/<exec>`, or the `gh pr create` from it. The row commits
-- after every step of its effect that can fail without issuing it (the export's
-- refusals, its local branch write, and for a push the read of the remote head,
-- whose answer is `lease`) and before the effect's first byte; its verdict is
-- written once, by the receipt in the transaction that records the effect's
-- result, or by the effect's observer when a crash or a failed command left the
-- outcome unknown. No row: never issued. A row with no verdict: owed its
-- observer's answer, and nothing is issued again under it.
--
-- An intent's identity is (attempt_id, effect_index), the UNIQUE key: its
-- coordinates, which a pull request carries as its marker. `effect_index` orders
-- one attempt's wire effects (a push, its pull request, a fresh intent after a
-- `not_performed` verdict); `seq` orders every intent the node recorded, so the
-- commit kata last pushed to a branch is one read.
-- `lease` is the head the pre-intent read found, NULL when the branch was absent,
-- and NULL on every pull-request row; `base` is a pull request's base and NULL on
-- every push row. A receipt is only ever `performed`.
--
-- `command_error` is the error the effect's own command returned, written once
-- before its observer is asked; NULL when no command answered (a crash left the
-- outcome). `unanswered_reads` counts the observer's reads the remote did not
-- answer while the intent stayed open, the last of them at `last_unanswered_at_ms`
-- with `last_read_error`; the read that reaches the driver's bound settles the
-- intent `unclassified`.
--
-- `execution_id` CASCADEs from `programs`, the stop latch's pairing: an intent is
-- a fact about one execution's effects. `attempt_id` is NO ACTION, so an attempt
-- prune cannot silently take the record of what it issued with it.
CREATE TABLE IF NOT EXISTS forge_intents (
    seq             INTEGER NOT NULL PRIMARY KEY,
    execution_id    BLOB    NOT NULL,
    attempt_id      BLOB    NOT NULL,
    stage_id        TEXT    NOT NULL,
    effect_index    INTEGER NOT NULL,
    effect          TEXT    NOT NULL,
    remote          TEXT    NOT NULL,
    branch          TEXT    NOT NULL,
    commit_sha      TEXT    NOT NULL,
    lease           TEXT,
    base            TEXT,
    recorded_at_ms  INTEGER NOT NULL,
    verdict         TEXT,
    verdict_by      TEXT,
    verdict_json    BLOB,
    verdict_at_ms   INTEGER,
    command_error   TEXT,
    unanswered_reads      INTEGER NOT NULL DEFAULT 0,
    last_unanswered_at_ms INTEGER,
    last_read_error       TEXT,
    UNIQUE (attempt_id, effect_index),
    FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id),
    CHECK (length(execution_id) = 16),
    CHECK (length(attempt_id) = 16),
    CHECK (effect_index >= 0),
    CHECK (effect IN ('push', 'pull_request')),
    CHECK (remote <> '' AND branch <> '' AND commit_sha <> ''),
    CHECK (effect = 'push' OR lease IS NULL),
    CHECK ((effect = 'pull_request') = (base IS NOT NULL)),
    CHECK (verdict IS NULL OR verdict IN ('performed', 'not_performed', 'unclassified')),
    CHECK (verdict_by IS NULL OR verdict_by IN ('receipt', 'observer')),
    CHECK ((verdict IS NULL) = (verdict_by IS NULL)),
    CHECK ((verdict IS NULL) = (verdict_json IS NULL)),
    CHECK ((verdict IS NULL) = (verdict_at_ms IS NULL)),
    CHECK (verdict_by IS NOT 'receipt' OR verdict = 'performed'),
    CHECK (command_error IS NULL OR command_error <> ''),
    CHECK (unanswered_reads >= 0),
    CHECK ((unanswered_reads = 0) = (last_unanswered_at_ms IS NULL)),
    CHECK ((unanswered_reads = 0) = (last_read_error IS NULL))
);
-- Serves `last_performed_forge_push` (one execution's intents, newest first) and
-- the `programs -> forge_intents` ON DELETE CASCADE child scan. The per-attempt
-- read and the `attempts` foreign-key child scan ride the UNIQUE
-- (attempt_id, effect_index) index.
CREATE INDEX IF NOT EXISTS idx_forge_intents_execution
    ON forge_intents (execution_id, seq);
";

/// The complete, coherent operational DDL — [`CREATE_OPERATIONAL_SCHEMA_TEMPLATE`]
/// with the attempt-lifecycle vocabulary rendered from
/// [`AttemptLifecycle::ALL`](super::attempt_state::AttemptLifecycle::ALL).
///
/// # Invariant
///
/// ONE VOCABULARY, ZERO COPIES. This column's `IN` list is interpolated from
/// [`state_check_list`], never hand-written: a hand-written copy of the spellings
/// beside the type is one nothing compares, and a member added to one and not the
/// other would produce a CHECK that admits a different vocabulary from the one the
/// code writes.
static CREATE_OPERATIONAL_SCHEMA_SQL: LazyLock<String> = LazyLock::new(|| {
    CREATE_OPERATIONAL_SCHEMA_TEMPLATE.replace(ATTEMPT_STATE_VOCABULARY_SLOT, &state_check_list())
});

/// The slot the DDL renders the attempt vocabulary into.
///
/// A SLOT rather than a `format!` placeholder because the DDL is one 600-line
/// string literal: a `{}` placeholder would make every future brace in it a
/// compile error at a distance, and `{{`-escaping a schema is how a schema acquires
/// a typo nobody reads.
///
/// It is deliberately NOT a SQL comment. An unrendered slot must be a SYNTAX
/// ERROR, not a silently empty `IN ()` list — a slot that failed open would produce
/// a column whose CHECK admits nothing, which SQLite would then enforce as a
/// refusal of every write on a plane that had just been declared healthy.
const ATTEMPT_STATE_VOCABULARY_SLOT: &str = "@@ATTEMPT_STATE_VOCABULARY@@";

/// Every table name the current schema declares, in a stable order. The
/// validator asserts each exists after creation; a caller-facing integrity check
/// can iterate it.
pub const OPERATIONAL_TABLES: &[&str] = &[
    "recovery_imports",
    "recovery_import_subjects",
    "worker_effect_domains",
    "worker_dispatch_domains",
    "programs",
    "invocations",
    "execution_lifecycle",
    "execution_cleanup_obligations",
    "transitions",
    "transition_sequence",
    "execution_projection",
    "attempt_projection",
    "projection_watermark",
    "attempts",
    "attempt_commands",
    "attempt_stop_requests",
    "cas_roots",
    "schedules",
    "schedule_firings",
    "event_inbox",
    "event_inbox_watermark",
    "nix_environments",
    "artifacts",
    "capsules",
    "occurrences",
    "execution_evidence",
    "execution_evidence_claims",
    "execution_work_tree_heads",
    "execution_git_views",
    "forge_intents",
];

/// Every table's declared COLUMN SET, in declaration order — the SHAPE the
/// current [`OPERATIONAL_SCHEMA_VERSION`] stamp identifies.
///
/// [`validate_schema`] compares this against the real `PRAGMA table_info` on
/// every open, EXACTLY: a missing column and an undeclared extra column are both
/// refusals. Name-only validation is what let one version stamp mean two
/// different shapes.
pub const OPERATIONAL_TABLE_COLUMNS: &[(&str, &[&str])] = &[
    (
        "recovery_imports",
        &[
            "artifact_id",
            "source_directory_id",
            "target_directory_id",
            "catalog_digest",
            "released_at_ms",
        ],
    ),
    (
        "recovery_import_subjects",
        &["artifact_id", "subject_key", "decision_json"],
    ),
    (
        "worker_effect_domains",
        &["source_main", "membrane_id", "enrollment_id"],
    ),
    (
        "worker_dispatch_domains",
        &["attempt_id", "lease_epoch", "enrollment_id", "worker_label"],
    ),
    (
        "programs",
        &[
            "execution_id",
            "program_hash",
            "schema_version",
            "program_json",
            "created_at_ms",
        ],
    ),
    (
        "invocations",
        &[
            "execution_id",
            "schema_version",
            "kind",
            "admission_digest",
            "invocation_json",
            "created_at_ms",
        ],
    ),
    (
        "execution_lifecycle",
        &[
            "execution_id",
            "state",
            "created_at_ms",
            "terminal_outcome",
            "terminal_reason_json",
            "terminal_started_at_ms",
            "finished_at_ms",
        ],
    ),
    (
        "execution_cleanup_obligations",
        &[
            "execution_id",
            "disposition",
            "status",
            "attempt_count",
            "next_retry_at_ms",
            "last_error",
            "completed_at_ms",
        ],
    ),
    (
        "transitions",
        &[
            "seq",
            "execution_id",
            "scope",
            "stage_id",
            "attempt_ordinal",
            "kind",
            "resulting_state",
            "folds_projection",
            "payload_json",
            "idempotency_key",
            "recorded_at_ms",
            "attempt_id",
        ],
    ),
    ("transition_sequence", &["id", "value"]),
    (
        "execution_projection",
        &["execution_id", "state", "source_seq", "updated_at_ms"],
    ),
    (
        "attempt_projection",
        &[
            "execution_id",
            "stage_id",
            "attempt_ordinal",
            "state",
            "source_seq",
            "updated_at_ms",
        ],
    ),
    ("projection_watermark", &["id", "applied_through_seq"]),
    (
        "attempts",
        &[
            "attempt_id",
            "execution_id",
            "stage_id",
            "attempt_ordinal",
            "lease_epoch",
            "assignment_json",
            "source_seq",
            "created_at_ms",
            "run_ordinal",
            "worker_id",
            "child_execution_id",
            "dispatched_at_ms",
            "started_at_ms",
            "finished_at_ms",
            "last_checkpoint",
            "occurrence_id",
            "executor",
            "wait_deadline_ms",
        ],
    ),
    (
        "attempt_commands",
        &[
            "command_id",
            "attempt_id",
            "lease_epoch",
            "command_json",
            "created_at_ms",
        ],
    ),
    (
        "attempt_stop_requests",
        &[
            "attempt_id",
            "lease_epoch",
            "execution_id",
            "worker_id",
            "reason",
            "requested_at_ms",
            "delivered_at_ms",
            "acknowledged_at_ms",
            "discharge_json",
        ],
    ),
    (
        "cas_roots",
        &[
            "root_id",
            "owner_kind",
            "owner_execution_id",
            "purpose",
            "object_digest",
            "created_at_ms",
            "released_at_ms",
        ],
    ),
    (
        "schedules",
        &[
            "schedule_id",
            "submit_pack",
            "trigger",
            "on_missed",
            "bound_program_hash",
            "bound_admission_digest",
            "program_json",
            "invocation_json",
            "cursor_ms",
            "created_at_ms",
        ],
    ),
    (
        "schedule_firings",
        &[
            "schedule_id",
            "fire_instant",
            "execution_id",
            "refusal",
            "fired_at_ms",
        ],
    ),
    (
        "event_inbox",
        &[
            "stream_id",
            "event_seq",
            "execution_id",
            "event_digest",
            "accepted",
            "payload_json",
            "received_at_ms",
        ],
    ),
    (
        "event_inbox_watermark",
        &["stream_id", "execution_id", "accepted_through_seq"],
    ),
    (
        "nix_environments",
        &[
            "environment_id",
            "manifest_object_id",
            "closure_digest",
            "label",
            "platform_id",
            "root_stage_id",
            "root_promoted_at_ms",
            "released_at_ms",
            "created_at_ms",
            "verification_evidence",
        ],
    ),
    (
        "artifacts",
        &[
            "artifact_id",
            "object_id",
            "size_bytes",
            "privacy",
            "kind",
            "created_at_ms",
        ],
    ),
    (
        "capsules",
        &[
            "capsule_id",
            "occurrence_id",
            "prepared_action_id",
            "environment_id",
            "platform_id",
            "capsule_object_id",
            "created_at_ms",
        ],
    ),
    (
        "occurrences",
        &[
            "occurrence_id",
            "execution_id",
            "program_hash",
            "operation_contract_id",
            "operation_path",
            "prepared_action_id",
            "capsule_id",
            "created_at_ms",
            "accepted_at_ms",
            "accepted_attempt_id",
            "work_tree_artifact_id",
        ],
    ),
    (
        "execution_evidence",
        &[
            "evidence_id",
            "execution_id",
            "created_at_ms",
            "evidence_json",
        ],
    ),
    (
        "execution_evidence_claims",
        &["execution_id", "claim_key", "evidence_id", "created_at_ms"],
    ),
    (
        "execution_work_tree_heads",
        &[
            "execution_id",
            "branch",
            "base_commit",
            "work_tree_artifact_id",
            "candidate_commit_id",
            "committed_commit_id",
            "head_seq",
            "join_stage",
            "forked_from",
            "fork_base_artifact_id",
            "recorded_at_ms",
        ],
    ),
    (
        "execution_git_views",
        &[
            "execution_id",
            "base_commit",
            "branch_name",
            "branch_commit",
            "identity_name",
            "identity_email",
            "history_artifact_id",
            "recorded_at_ms",
        ],
    ),
    (
        "forge_intents",
        &[
            "seq",
            "execution_id",
            "attempt_id",
            "stage_id",
            "effect_index",
            "effect",
            "remote",
            "branch",
            "commit_sha",
            "lease",
            "base",
            "recorded_at_ms",
            "verdict",
            "verdict_by",
            "verdict_json",
            "verdict_at_ms",
            "command_error",
            "unanswered_reads",
            "last_unanswered_at_ms",
            "last_read_error",
        ],
    ),
];

/// Every index the current schema declares. Each entry names a hot lookup path
/// the [`OperationalDb`](super::OperationalDb) query surface actually issues (or
/// an FK child column whose parent CASCADEs); the validator asserts each exists,
/// so a dropped index is a test failure rather than a silent table scan.
pub const OPERATIONAL_INDEXES: &[&str] = &[
    "idx_execution_cleanup_due",
    "idx_execution_lifecycle_active",
    "idx_execution_projection_active",
    "idx_worker_effect_domain_enrollment",
    "idx_worker_dispatch_domain_attempt",
    "idx_transitions_execution",
    "idx_transitions_idempotency",
    "idx_transitions_attempt",
    "idx_transitions_stage_history",
    "idx_transitions_attempt_ordinal",
    "idx_attempts_worker",
    "idx_attempts_worker_started",
    "idx_attempts_wait_due",
    "idx_attempts_child",
    "idx_attempts_execution",
    "idx_attempt_commands_attempt",
    "idx_attempt_stop_requests_unacknowledged",
    "idx_cas_roots_owner",
    "idx_cas_roots_artifact_object",
    "idx_cas_roots_owner_artifact",
    "idx_schedule_firings_execution",
    "idx_event_inbox_buffered",
    "idx_event_inbox_execution",
    "idx_event_inbox_watermark_execution",
    "idx_nix_environments_active",
    "idx_nix_environments_unpromoted",
    "idx_nix_environments_manifest_live",
    "idx_artifacts_object",
    "idx_capsules_environment",
    "idx_attempts_occurrence",
    "idx_occurrences_execution",
    "idx_occurrences_accepted_attempt",
    "idx_execution_evidence_execution",
    "idx_execution_work_tree_heads_artifact",
    "idx_execution_git_views_artifact",
    "idx_forge_intents_execution",
];

struct OperationalIndexContract {
    name: &'static str,
    table: &'static str,
    columns: &'static [&'static str],
    unique: bool,
    predicate: Option<&'static str>,
}

const OPERATIONAL_INDEX_CONTRACTS: &[OperationalIndexContract] = &[
    OperationalIndexContract {
        name: "idx_execution_cleanup_due",
        table: "execution_cleanup_obligations",
        columns: &["next_retry_at_ms", "execution_id"],
        unique: false,
        predicate: Some("status = 'pending'"),
    },
    OperationalIndexContract {
        name: "idx_execution_lifecycle_active",
        table: "execution_lifecycle",
        columns: &["execution_id"],
        unique: false,
        predicate: Some("state IN ('admitting', 'running', 'terminalizing')"),
    },
    OperationalIndexContract {
        name: "idx_execution_projection_active",
        table: "execution_projection",
        columns: &["execution_id"],
        unique: false,
        predicate: Some("state IN ('admitting', 'running', 'terminalizing')"),
    },
    OperationalIndexContract {
        name: "idx_worker_effect_domain_enrollment",
        table: "worker_effect_domains",
        columns: &["enrollment_id"],
        unique: true,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_worker_dispatch_domain_attempt",
        table: "worker_dispatch_domains",
        columns: &["enrollment_id", "attempt_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_transitions_execution",
        table: "transitions",
        columns: &["execution_id", "seq"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_transitions_idempotency",
        table: "transitions",
        columns: &["idempotency_key"],
        unique: true,
        predicate: Some("idempotency_key IS NOT NULL"),
    },
    OperationalIndexContract {
        name: "idx_transitions_attempt",
        table: "transitions",
        columns: &["attempt_id"],
        unique: false,
        predicate: Some("attempt_id IS NOT NULL"),
    },
    OperationalIndexContract {
        name: "idx_transitions_stage_history",
        table: "transitions",
        columns: &["execution_id", "stage_id", "seq"],
        unique: false,
        predicate: Some("scope = 'stage'"),
    },
    OperationalIndexContract {
        name: "idx_transitions_attempt_ordinal",
        table: "transitions",
        columns: &["execution_id", "stage_id", "attempt_ordinal"],
        unique: false,
        predicate: Some("scope = 'attempt'"),
    },
    OperationalIndexContract {
        name: "idx_attempts_worker",
        table: "attempts",
        columns: &["worker_id"],
        unique: false,
        predicate: Some("worker_id IS NOT NULL"),
    },
    OperationalIndexContract {
        name: "idx_attempts_worker_started",
        table: "attempts",
        columns: &["worker_id", "finished_at_ms"],
        unique: false,
        predicate: Some("worker_id IS NOT NULL AND started_at_ms IS NOT NULL"),
    },
    OperationalIndexContract {
        name: "idx_attempts_wait_due",
        table: "attempts",
        columns: &["wait_deadline_ms"],
        unique: false,
        predicate: Some("wait_deadline_ms IS NOT NULL"),
    },
    OperationalIndexContract {
        name: "idx_attempts_child",
        table: "attempts",
        columns: &["child_execution_id"],
        unique: false,
        predicate: Some("child_execution_id IS NOT NULL"),
    },
    OperationalIndexContract {
        name: "idx_attempts_execution",
        table: "attempts",
        columns: &["execution_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_attempt_commands_attempt",
        table: "attempt_commands",
        columns: &["attempt_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_attempt_stop_requests_unacknowledged",
        table: "attempt_stop_requests",
        columns: &["execution_id"],
        unique: false,
        predicate: Some("acknowledged_at_ms IS NULL"),
    },
    OperationalIndexContract {
        name: "idx_cas_roots_owner",
        table: "cas_roots",
        columns: &["owner_execution_id"],
        unique: false,
        predicate: Some("owner_execution_id IS NOT NULL"),
    },
    OperationalIndexContract {
        name: "idx_cas_roots_artifact_object",
        table: "cas_roots",
        columns: &["object_digest"],
        unique: false,
        predicate: Some("purpose = 'artifact_object'"),
    },
    OperationalIndexContract {
        name: "idx_cas_roots_owner_artifact",
        table: "cas_roots",
        columns: &["owner_execution_id", "object_digest"],
        unique: false,
        predicate: Some("purpose = 'artifact_object'"),
    },
    OperationalIndexContract {
        name: "idx_schedule_firings_execution",
        table: "schedule_firings",
        columns: &["execution_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_event_inbox_buffered",
        table: "event_inbox",
        columns: &["stream_id", "event_seq"],
        unique: false,
        predicate: Some("accepted = 0"),
    },
    OperationalIndexContract {
        name: "idx_event_inbox_execution",
        table: "event_inbox",
        columns: &["execution_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_event_inbox_watermark_execution",
        table: "event_inbox_watermark",
        columns: &["execution_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_nix_environments_active",
        table: "nix_environments",
        columns: &["environment_id"],
        unique: false,
        predicate: Some("released_at_ms IS NULL"),
    },
    OperationalIndexContract {
        name: "idx_nix_environments_unpromoted",
        table: "nix_environments",
        columns: &["environment_id"],
        unique: false,
        predicate: Some("root_promoted_at_ms IS NULL"),
    },
    OperationalIndexContract {
        name: "idx_nix_environments_manifest_live",
        table: "nix_environments",
        columns: &["manifest_object_id"],
        unique: true,
        predicate: Some("released_at_ms IS NULL"),
    },
    OperationalIndexContract {
        name: "idx_artifacts_object",
        table: "artifacts",
        columns: &["object_id"],
        unique: true,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_capsules_environment",
        table: "capsules",
        columns: &["environment_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_attempts_occurrence",
        table: "attempts",
        columns: &["occurrence_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_occurrences_execution",
        table: "occurrences",
        columns: &["execution_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_occurrences_accepted_attempt",
        table: "occurrences",
        columns: &["accepted_attempt_id"],
        unique: true,
        predicate: Some("accepted_attempt_id IS NOT NULL"),
    },
    OperationalIndexContract {
        name: "idx_execution_evidence_execution",
        table: "execution_evidence",
        columns: &["execution_id", "created_at_ms", "evidence_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_execution_work_tree_heads_artifact",
        table: "execution_work_tree_heads",
        columns: &["work_tree_artifact_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_execution_git_views_artifact",
        table: "execution_git_views",
        columns: &["history_artifact_id"],
        unique: false,
        predicate: None,
    },
    OperationalIndexContract {
        name: "idx_forge_intents_execution",
        table: "forge_intents",
        columns: &["execution_id", "seq"],
        unique: false,
        predicate: None,
    },
];

const TRANSITION_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("seq", "INTEGER", 1, 1),
    ("execution_id", "BLOB", 1, 0),
    ("scope", "TEXT", 1, 0),
    ("stage_id", "TEXT", 0, 0),
    ("attempt_ordinal", "INTEGER", 0, 0),
    ("kind", "TEXT", 1, 0),
    ("resulting_state", "TEXT", 1, 0),
    ("folds_projection", "INTEGER", 1, 0),
    ("payload_json", "BLOB", 1, 0),
    ("idempotency_key", "BLOB", 0, 0),
    ("recorded_at_ms", "INTEGER", 1, 0),
    ("attempt_id", "BLOB", 0, 0),
];

const TRANSITION_SEQUENCE_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] =
    &[("id", "INTEGER", 1, 1), ("value", "INTEGER", 1, 0)];

/// `nix_environments`'s column/type/null/key contract.
///
/// Validated on every open for the reason the column SET alone is not enough here:
/// the two reconciliation reads are driven by NULLABILITY (`root_promoted_at_ms IS
/// NULL`, `released_at_ms IS NULL`). A future edit that made either column
/// `NOT NULL DEFAULT 0` would keep the column set identical, keep both partial
/// indexes valid SQL, and silently empty the scans that the boot reconciler and the
/// issuance gate depend on being total.
/// `artifacts`'s column/type/null/key contract.
///
/// `owner_execution_id` IS DELIBERATELY ABSENT, and this contract is one of the two
/// mechanisms that keeps it absent (the other is
/// [`OPERATIONAL_TABLE_COLUMNS`]): `artifact_id` is `H(object, size, privacy)` and does
/// not fold an owner, so a row that carried one made the id and the row disagree about
/// what identifies an artifact. Re-adding the column would fail here on every open.
const ARTIFACT_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("artifact_id", "BLOB", 1, 1),
    ("object_id", "BLOB", 1, 0),
    ("size_bytes", "INTEGER", 1, 0),
    ("privacy", "TEXT", 1, 0),
    ("kind", "TEXT", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
];

/// `capsules`'s column/type/null/key contract.
///
/// Every column is NOT NULL, and THAT is what this contract protects: a capsule is
/// immutable and total — it names its occurrence, its prepared action, its
/// environment, its platform and its bytes, or it is not a capsule. A column that
/// became nullable would keep the column set identical while letting a row claim a
/// binding it does not carry, and `declare_capsule`'s refusals (unknown artifact,
/// inactive environment) would then be reachable around rather than through.
const CAPSULE_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("capsule_id", "BLOB", 1, 1),
    ("occurrence_id", "BLOB", 1, 0),
    ("prepared_action_id", "BLOB", 1, 0),
    ("environment_id", "BLOB", 1, 0),
    ("platform_id", "BLOB", 1, 0),
    ("capsule_object_id", "BLOB", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
];

/// `occurrences`'s column/type/null/key contract.
///
/// Validated on every open because FOUR nullabilities here are the invariant, not a
/// detail a column-set comparison could see:
///
/// * `accepted_at_ms` and `accepted_attempt_id` are the pair the stored
///   `CHECK ((accepted_at_ms IS NULL) = (accepted_attempt_id IS NULL))` relates and
///   the pair `idx_occurrences_accepted_attempt`'s partial predicate keys on. An
///   edit making either `NOT NULL DEFAULT 0` would keep the column set identical,
///   keep the index valid SQL, and make every freshly minted occurrence look
///   ACCEPTED -- so the write-once UPDATE's `WHERE accepted_attempt_id IS NULL`
///   would match nothing and NO occurrence could ever be accepted, on a plane that
///   had just reported itself healthy. That pair CHECK is also the only thing
///   standing between a missing accepting transition and a half-accepted row, since
///   `accepted_at_ms` is written as a subquery over `transitions`
///   (`accept_occurrence_outcome`) and a subquery that matched nothing would supply
///   NULL.
/// * `prepared_action_id` and `capsule_id` are nullable because minting precedes
///   preparation; NOT NULL would force the claim to invent ids it does not hold.
/// * `work_tree_artifact_id` is nullable for the same reason, and because an
///   occurrence minted without a capsule maps no `/work`.
const OCCURRENCE_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("occurrence_id", "BLOB", 1, 1),
    ("execution_id", "BLOB", 1, 0),
    ("program_hash", "BLOB", 1, 0),
    ("operation_contract_id", "BLOB", 1, 0),
    ("operation_path", "BLOB", 1, 0),
    ("prepared_action_id", "BLOB", 0, 0),
    ("capsule_id", "BLOB", 0, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("accepted_at_ms", "INTEGER", 0, 0),
    ("accepted_attempt_id", "BLOB", 0, 0),
    ("work_tree_artifact_id", "BLOB", 0, 0),
];

/// `attempts.occurrence_id`'s half of the occurrence binding, validated as a FULL
/// table contract for the reason the other authority tables are: the column is
/// `NOT NULL` (see the DDL), and a shape that kept the column set
/// identical while relaxing that — or adding a `DEFAULT` that let an insert omit
/// the binding — would let an attempt exist that no occurrence can adjudicate.
const ATTEMPT_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("attempt_id", "BLOB", 1, 1),
    ("execution_id", "BLOB", 1, 0),
    ("stage_id", "TEXT", 1, 0),
    ("attempt_ordinal", "INTEGER", 1, 0),
    ("lease_epoch", "INTEGER", 1, 0),
    ("assignment_json", "BLOB", 1, 0),
    ("source_seq", "INTEGER", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("run_ordinal", "INTEGER", 1, 0),
    ("worker_id", "TEXT", 0, 0),
    ("child_execution_id", "BLOB", 0, 0),
    ("dispatched_at_ms", "INTEGER", 0, 0),
    ("started_at_ms", "INTEGER", 0, 0),
    ("finished_at_ms", "INTEGER", 0, 0),
    ("last_checkpoint", "INTEGER", 0, 0),
    ("occurrence_id", "BLOB", 1, 0),
    ("executor", "TEXT", 1, 0),
    ("wait_deadline_ms", "INTEGER", 0, 0),
];

/// The two execution-evidence tables' contracts.
///
/// EVERY column is NOT NULL on both, and that is what these protect: an evidence row
/// is its id, its execution, its instant and its payload, or it is not a record of
/// anything.
const EXECUTION_EVIDENCE_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("evidence_id", "BLOB", 1, 1),
    ("execution_id", "BLOB", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("evidence_json", "BLOB", 1, 0),
];

const EXECUTION_EVIDENCE_CLAIM_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("execution_id", "BLOB", 1, 1),
    ("claim_key", "TEXT", 1, 2),
    ("evidence_id", "BLOB", 1, 0),
    ("created_at_ms", "INTEGER", 1, 0),
];

const FORGE_INTENT_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("seq", "INTEGER", 1, 1),
    ("execution_id", "BLOB", 1, 0),
    ("attempt_id", "BLOB", 1, 0),
    ("stage_id", "TEXT", 1, 0),
    ("effect_index", "INTEGER", 1, 0),
    ("effect", "TEXT", 1, 0),
    ("remote", "TEXT", 1, 0),
    ("branch", "TEXT", 1, 0),
    ("commit_sha", "TEXT", 1, 0),
    ("lease", "TEXT", 0, 0),
    ("base", "TEXT", 0, 0),
    ("recorded_at_ms", "INTEGER", 1, 0),
    ("verdict", "TEXT", 0, 0),
    ("verdict_by", "TEXT", 0, 0),
    ("verdict_json", "BLOB", 0, 0),
    ("verdict_at_ms", "INTEGER", 0, 0),
    ("command_error", "TEXT", 0, 0),
    ("unanswered_reads", "INTEGER", 1, 0),
    ("last_unanswered_at_ms", "INTEGER", 0, 0),
    ("last_read_error", "TEXT", 0, 0),
];

const NIX_ENVIRONMENT_COLUMN_CONTRACT: &[(&str, &str, i64, i64)] = &[
    ("environment_id", "BLOB", 1, 1),
    ("manifest_object_id", "BLOB", 1, 0),
    ("closure_digest", "BLOB", 1, 0),
    ("label", "TEXT", 1, 0),
    ("platform_id", "BLOB", 1, 0),
    ("root_stage_id", "TEXT", 1, 0),
    ("root_promoted_at_ms", "INTEGER", 0, 0),
    ("released_at_ms", "INTEGER", 0, 0),
    ("created_at_ms", "INTEGER", 1, 0),
    ("verification_evidence", "BLOB", 0, 0),
];

/// Open (or create) the operational connection at `path`, accepting only the
/// exact current format when a database already exists.
///
/// # Failure
///
/// A stamped `user_version` other than [`OPERATIONAL_SCHEMA_VERSION`] returns
/// [`KataError::SchemaMigrationRequired`], from one of two gates:
///
/// - The stamp in the database header or in pending `-wal` frames is read by PLAIN
///   FILE I/O, never by opening SQLite, and refused having touched nothing on disk
///   (no `-wal`/`-shm`/`-journal` sidecar created, no page rewritten), proven by
///   the rollback-journal-mode, WAL, and hot-WAL byte-identity fixtures.
/// - The file probe does not read a `-journal` sidecar. A stamp that a HOT rollback
///   journal restores is played back into the main file when SQLite opens it, and
///   `refuse_noncurrent_schema_on_conn` refuses it AFTER that rewrite
///   (`a_behind_stamp_restored_by_a_hot_rollback_journal_is_refused_by_the_driver_gate`).
///   The plane runs in WAL mode and writes no rollback journal, so that shape
///   arrives only in a copied or restored file.
pub fn open_operational_connection(path: &Path) -> KataResult<Connection> {
    let exists = operational_source_is_regular_file(path)?;
    sqlite_backed::refuse_orphan_sidecars_for_missing_main(path, "operational.db")?;
    // Gate the version by FILE I/O, before SQLite is opened at all: opening a WAL
    // database materializes `-shm` and can block on a hot WAL, so a
    // driver-mediated version read is not refuse-before-touch.
    if exists {
        refuse_noncurrent_operational_schema(path)?;
    }
    if !exists && let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            KataError::Storage(format!(
                "operational.db create_dir_all({}) failed: {error}",
                parent.display()
            ))
        })?;
    }
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if !exists {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let conn = Connection::open_with_flags(path, flags).map_err(|error| {
        KataError::Storage(format!(
            "operational.db open({}) failed: {error}",
            path.display()
        ))
    })?;
    // Cross-check the driver's post-recovery view BEFORE any pragma or DDL. The
    // file gate above refuses before touch for the header and WAL; this gate is
    // the only one that sees a stamp a hot rollback journal restores.
    if exists {
        refuse_noncurrent_schema_on_conn(&conn)?;
    }
    if exists {
        validate_schema(&conn)?;
        configure_open_connection(&conn)?;
    } else {
        configure_open_connection(&conn)?;
        create_fresh_current_schema(&conn)?;
    }
    Ok(conn)
}

/// Open an in-memory operational connection (tests).
pub fn open_operational_in_memory() -> KataResult<Connection> {
    let conn = Connection::open_in_memory().map_err(|error| {
        KataError::Storage(format!("operational.db open_in_memory failed: {error}"))
    })?;
    configure_open_connection(&conn)?;
    create_fresh_current_schema(&conn)?;
    Ok(conn)
}

/// Apply the runtime durability and integrity pragmas to an already-gated
/// connection.
fn configure_open_connection(conn: &Connection) -> KataResult<()> {
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| {
            KataError::Storage(format!("operational.db pragma foreign_keys=ON: {error}"))
        })?;
    // Authoritative control-plane facts pay FULL's per-commit fsync.
    apply_wal_pragmas(conn, "operational.db")?;
    conn.pragma_update(None, "busy_timeout", OPERATIONAL_BUSY_TIMEOUT_MS)
        .map_err(|error| {
            KataError::Storage(format!("operational.db pragma busy_timeout: {error}"))
        })?;
    Ok(())
}

/// Create a NEW operational database directly at this binary's current schema.
///
/// This is initialization, not migration: the current DDL and its identifying
/// stamp commit atomically, and no upgrade step runs.
fn create_fresh_current_schema(conn: &Connection) -> KataResult<()> {
    let tx = conn.unchecked_transaction().map_err(|error| {
        KataError::Storage(format!(
            "operational.db begin fresh current schema: {error}"
        ))
    })?;
    tx.execute_batch(&CREATE_OPERATIONAL_SCHEMA_SQL)
        .map_err(|error| {
            KataError::Storage(format!(
                "operational.db create fresh current schema: {error}"
            ))
        })?;
    tx.pragma_update(None, "user_version", OPERATIONAL_SCHEMA_VERSION)
        .map_err(|error| {
            KataError::Storage(format!(
                "operational.db stamp fresh current schema: {error}"
            ))
        })?;
    tx.commit().map_err(|error| {
        KataError::Storage(format!(
            "operational.db commit fresh current schema: {error}"
        ))
    })?;
    validate_schema(conn)
}

/// Refuse a forward stamp read by PLAIN FILE I/O — no SQLite handle, no sidecar,
/// no page rewrite.
///
/// Public because it is not only the open path's business: any IMMUTABLE probe of
/// a data dir (`kata upgrade`'s preflight) must apply the same gate, or it
/// reports green on a data dir that boot then refuses. It is safe to call on a
/// missing file (a fresh database reads as version 0).
pub fn refuse_newer_operational_schema(path: &Path) -> KataResult<()> {
    refuse_newer_schema_from_files(path)
}

/// Require an existing operational database to carry exactly this binary's
/// current schema stamp, using the same pre-open main-header/WAL inspection as
/// the forward-version gate. Boot never upgrades a behind database in place; an
/// older data directory stays offline.
pub fn refuse_noncurrent_operational_schema(path: &Path) -> KataResult<()> {
    // Reads first: it refuses a missing main beside an orphan sidecar by name.
    let observed = sqlite_backed::stamped_user_version_from_files(path, OPERATIONAL_LABEL)?;
    // It reads a missing file as stamp 0; that is neither an interrupted creation
    // nor an older format, so it is refused by name.
    if !path.exists() {
        return Err(KataError::SchemaMigrationRequired(format!(
            "operational.db {} does not exist; use a new empty data directory and preserve this \
             directory offline",
            path.display()
        )));
    }
    refuse_noncurrent_stamp(observed)
}

/// The one refusal of a non-current `user_version`, for both version gates.
///
/// Stamp 0 is not evidence of an older format: `create_fresh_current_schema`
/// commits the DDL and the stamp together, after SQLite has already created the
/// file, so a first creation interrupted in between leaves exactly stamp 0 — and
/// so does a file this lineage never stamped. The stamp is all the pre-open probe
/// reads and it does not tell the two apart, so the refusal names both; the
/// recourse is the same for each. Which surface meets which: the installed main
/// publishes `main-identity.json` only after every store is created, and boot
/// refuses an identity-less directory before this probe, so boot meets stamp 0
/// only in a file older, foreign or replaced since; `kata upgrade` reads the stamp
/// without the identity and can meet an interrupted creation too.
fn refuse_noncurrent_stamp(observed: i64) -> KataResult<()> {
    if observed == OPERATIONAL_SCHEMA_VERSION {
        return Ok(());
    }
    if observed == 0 {
        return Err(KataError::SchemaMigrationRequired(
            "operational.db carries no schema stamp (version 0): either its first creation was \
             interrupted before the schema committed, or it is an older or foreign file; use a \
             new empty data directory and preserve this directory offline"
                .to_string(),
        ));
    }
    Err(KataError::SchemaMigrationRequired(format!(
        "operational.db schema version {observed} is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}; use a new empty data directory and preserve this directory offline"
    )))
}

fn refuse_noncurrent_schema_on_conn(conn: &Connection) -> KataResult<()> {
    let observed: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| {
            KataError::Storage(format!(
                "operational.db read current user_version failed: {error}"
            ))
        })?;
    refuse_noncurrent_stamp(observed)
}

/// This store's label in every shared-gate error message.
const OPERATIONAL_LABEL: &str = "operational.db";

/// [`refuse_newer_schema_from_files`](crate::store::sqlite_backed::refuse_newer_schema_from_files)
/// bound to this store's ceiling and label. The reader itself is store-agnostic
/// and lives beside `open_sqlite`; only the ceiling and the label are ours.
fn refuse_newer_schema_from_files(path: &Path) -> KataResult<()> {
    sqlite_backed::refuse_newer_schema_from_files(
        path,
        OPERATIONAL_SCHEMA_VERSION,
        OPERATIONAL_LABEL,
    )
}

/// Confirm every declared table and column exists, no table carries an
/// undeclared column, and every named index retains its exact authority/query
/// contract (owner table, ordered columns, uniqueness, and partial predicate).
///
/// # Failure mode
///
/// Name-only validation would let one `user_version` stamp mean two different
/// shapes: a file written before a column was added in place would pass validation
/// and then fail every write. The column set IS the shape, so it is what the stamp
/// must be checked against.
fn validate_schema(conn: &Connection) -> KataResult<()> {
    let mut foreign_keys = conn.prepare("SELECT \"table\", \"from\", \"to\", on_update, on_delete FROM pragma_foreign_key_list('worker_dispatch_domains') ORDER BY \"from\"")
        .map_err(|e| KataError::Storage(format!("worker domain foreign keys: {e}")))?;
    let observed = foreign_keys
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| KataError::Storage(format!("worker domain foreign keys: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KataError::Storage(format!("worker domain foreign keys: {e}")))?;
    let expected = [
        (
            "attempts",
            "attempt_id",
            "attempt_id",
            "NO ACTION",
            "NO ACTION",
        ),
        (
            "worker_effect_domains",
            "enrollment_id",
            "enrollment_id",
            "NO ACTION",
            "NO ACTION",
        ),
    ]
    .map(|(table, from, to, update, delete)| {
        (
            table.to_string(),
            from.to_string(),
            to.to_string(),
            update.to_string(),
            delete.to_string(),
        )
    });
    if observed != expected {
        return Err(KataError::Storage(
            "worker dispatch domain foreign-key contract is missing or changed".into(),
        ));
    }
    validate_authority_column_contract(
        conn,
        "worker_effect_domains",
        &[
            ("source_main", "TEXT", 1, 1),
            ("membrane_id", "BLOB", 1, 2),
            ("enrollment_id", "BLOB", 1, 0),
        ],
    )?;
    validate_authority_column_contract(
        conn,
        "worker_dispatch_domains",
        &[
            ("attempt_id", "BLOB", 1, 1),
            ("lease_epoch", "INTEGER", 1, 2),
            ("enrollment_id", "BLOB", 1, 0),
            ("worker_label", "TEXT", 1, 0),
        ],
    )?;
    // TABLES, then COLUMNS, then INDEXES. The order is the diagnosis order: a table
    // whose SHAPE is behind will also be missing every index over its new columns,
    // and reporting the missing index first names a symptom while the column-set
    // message names the cause.
    assert_schema_objects_exist(conn, "table", OPERATIONAL_TABLES)?;
    for (table, declared) in OPERATIONAL_TABLE_COLUMNS {
        if !table_columns_match(conn, table, declared)? {
            let observed = table_columns(conn, table)?;
            return Err(KataError::Storage(format!(
                "operational.db table {table} has column set {observed:?} but schema version \
                 {OPERATIONAL_SCHEMA_VERSION} declares {declared:?}; refusing to adopt a database \
                 whose shape does not match its stamp (the stamp identifies the shape — bump the \
                 version and start a new empty data directory rather than editing the DDL in \
                 place; there is no upgrade ladder)"
            )));
        }
    }
    validate_authority_column_contract(conn, "transitions", TRANSITION_COLUMN_CONTRACT)?;
    validate_authority_column_contract(
        conn,
        "recovery_imports",
        &[
            ("artifact_id", "BLOB", 1, 1),
            ("source_directory_id", "TEXT", 1, 0),
            ("target_directory_id", "TEXT", 1, 0),
            ("catalog_digest", "TEXT", 1, 0),
            ("released_at_ms", "INTEGER", 0, 0),
        ],
    )?;
    validate_authority_column_contract(
        conn,
        "recovery_import_subjects",
        &[
            ("artifact_id", "BLOB", 1, 1),
            ("subject_key", "TEXT", 1, 2),
            ("decision_json", "TEXT", 0, 0),
        ],
    )?;
    validate_authority_column_contract(
        conn,
        "transition_sequence",
        TRANSITION_SEQUENCE_COLUMN_CONTRACT,
    )?;
    validate_authority_column_contract(conn, "nix_environments", NIX_ENVIRONMENT_COLUMN_CONTRACT)?;
    validate_authority_column_contract(conn, "artifacts", ARTIFACT_COLUMN_CONTRACT)?;
    validate_authority_column_contract(conn, "capsules", CAPSULE_COLUMN_CONTRACT)?;
    validate_authority_column_contract(conn, "attempts", ATTEMPT_COLUMN_CONTRACT)?;
    validate_authority_column_contract(conn, "occurrences", OCCURRENCE_COLUMN_CONTRACT)?;
    validate_authority_column_contract(
        conn,
        "execution_evidence",
        EXECUTION_EVIDENCE_COLUMN_CONTRACT,
    )?;
    validate_authority_column_contract(
        conn,
        "execution_evidence_claims",
        EXECUTION_EVIDENCE_CLAIM_COLUMN_CONTRACT,
    )?;
    validate_authority_column_contract(conn, "forge_intents", FORGE_INTENT_COLUMN_CONTRACT)?;
    validate_index_contracts(conn)
}

fn validate_authority_column_contract(
    conn: &Connection,
    table: &str,
    expected: &[(&str, &str, i64, i64)],
) -> KataResult<()> {
    let mut statement = conn
        .prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1) ORDER BY cid")
        .map_err(|error| {
            KataError::Storage(format!(
                "operational.db prepare authority column contract for {table}: {error}"
            ))
        })?;
    let mut observed = statement
        .query_map([table], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| {
            KataError::Storage(format!(
                "operational.db read authority column contract for {table}: {error}"
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            KataError::Storage(format!(
                "operational.db collect authority column contract for {table}: {error}"
            ))
        })?;
    let mut expected = expected
        .iter()
        .map(|(name, ty, not_null, primary_key)| {
            (
                (*name).to_string(),
                (*ty).to_string(),
                *not_null,
                *primary_key,
            )
        })
        .collect::<Vec<_>>();
    // Ordinal position is not a semantic part of the contract. Names, declared types,
    // nullability, and PK ordinals are; compare that keyed set exactly.
    observed.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    expected.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    if observed != expected {
        return Err(KataError::Storage(format!(
            "operational.db authority table {table} has column/type/null/key contract {observed:?}; expected {expected:?}"
        )));
    }
    Ok(())
}

fn validate_index_contracts(conn: &Connection) -> KataResult<()> {
    let declared_names = OPERATIONAL_INDEX_CONTRACTS
        .iter()
        .map(|contract| contract.name)
        .collect::<Vec<_>>();
    if declared_names != OPERATIONAL_INDEXES {
        return Err(KataError::Storage(format!(
            "operational.db internal index declarations disagree: names={OPERATIONAL_INDEXES:?}, contracts={declared_names:?}"
        )));
    }

    for contract in OPERATIONAL_INDEX_CONTRACTS {
        let metadata = conn
            .query_row(
                "SELECT \"unique\", partial
                   FROM pragma_index_list(?1)
                  WHERE name = ?2",
                rusqlite::params![contract.table, contract.name],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| {
                KataError::Storage(format!(
                    "operational.db inspect index {} on {}: {error}",
                    contract.name, contract.table
                ))
            })?;
        let Some((unique, partial)) = metadata else {
            return Err(KataError::Storage(format!(
                "operational.db missing required index {} on {}",
                contract.name, contract.table
            )));
        };

        let mut statement = conn
            .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")
            .map_err(|error| {
                KataError::Storage(format!(
                    "operational.db prepare index_info({}): {error}",
                    contract.name
                ))
            })?;
        let columns = statement
            .query_map(rusqlite::params![contract.name], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| {
                KataError::Storage(format!(
                    "operational.db read index_info({}): {error}",
                    contract.name
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                KataError::Storage(format!(
                    "operational.db collect index_info({}): {error}",
                    contract.name
                ))
            })?;
        let expected_columns = contract
            .columns
            .iter()
            .map(|column| (*column).to_string())
            .collect::<Vec<_>>();

        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?1",
                [contract.name],
                |row| row.get(0),
            )
            .map_err(|error| {
                KataError::Storage(format!(
                    "operational.db read index SQL for {}: {error}",
                    contract.name
                ))
            })?;
        // Preserve quoted literal bytes while normalizing layout. Lowercasing
        // the whole SQL would incorrectly make `scope = 'ATTEMPT'` appear
        // equivalent to the required `scope = 'attempt'` predicate.
        let normalized_sql = sql.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
        let observed_predicate = normalized_sql
            .split_once(" WHERE ")
            .map(|(_, predicate)| predicate);

        if unique != i64::from(contract.unique)
            || partial != i64::from(contract.predicate.is_some())
            || columns != expected_columns
            || observed_predicate != contract.predicate
        {
            return Err(KataError::Storage(format!(
                "operational.db index {} has contract unique={unique}, partial={partial}, columns={columns:?}, predicate={observed_predicate:?}; expected unique={}, partial={}, columns={:?}, predicate={:?}",
                contract.name,
                contract.unique,
                contract.predicate.is_some(),
                contract.columns,
                contract.predicate
            )));
        }
    }
    Ok(())
}

/// Assert every named `sqlite_schema` object of `kind` exists.
fn assert_schema_objects_exist(conn: &Connection, kind: &str, names: &[&str]) -> KataResult<()> {
    for name in names {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM sqlite_schema WHERE type = ?1 AND name = ?2
                 )",
                rusqlite::params![kind, name],
                |row| row.get(0),
            )
            .map_err(|error| {
                KataError::Storage(format!(
                    "operational.db validate schema for {kind} {name}: {error}"
                ))
            })?;
        if !exists {
            return Err(KataError::Storage(format!(
                "operational.db missing required {kind} {name}"
            )));
        }
    }
    Ok(())
}

/// Whether `table`'s real column SET equals the declared one, exactly — a missing
/// column and an undeclared extra column are both a mismatch.
///
/// # Enforcement
///
/// SET, not sequence. Ordinal position is not part of the shape here because no
/// query in this plane selects by position: every statement names its columns, and
/// there is no `SELECT *`. The ORDERED per-column contract is asserted separately,
/// and only where a column's declared type, nullability or key ordinal is itself
/// decision-bearing — see [`validate_authority_column_contract`], which is what
/// catches a same-named column whose nullability moved.
pub(crate) fn table_columns_match(
    conn: &Connection,
    table: &str,
    declared: &[&str],
) -> KataResult<bool> {
    let mut observed = table_columns(conn, table)?;
    observed.sort_unstable();
    let mut declared: Vec<&str> = declared.to_vec();
    declared.sort_unstable();
    Ok(observed.iter().map(String::as_str).eq(declared))
}

/// One table's column names in declaration order, or an empty vector when the
/// table does not exist.
fn table_columns(conn: &Connection, table: &str) -> KataResult<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .map_err(|error| {
            KataError::Storage(format!("operational.db prepare table_info: {error}"))
        })?;
    let rows = stmt
        .query_map(rusqlite::params![table], |row| row.get::<_, String>(0))
        .map_err(|error| {
            KataError::Storage(format!("operational.db read table_info({table}): {error}"))
        })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|error| {
        KataError::Storage(format!(
            "operational.db collect table_info({table}): {error}"
        ))
    })
}

/// Require a regular, non-symlink file at `path` when it exists. A missing file
/// is a fresh database (returns `false`).
fn operational_source_is_regular_file(path: &Path) -> KataResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(KataError::Storage(format!(
                    "operational.db requires a regular non-symlink database at {}",
                    path.display()
                )));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(KataError::Storage(format!(
            "operational.db cannot stat {}: {error}",
            path.display()
        ))),
    }
}
