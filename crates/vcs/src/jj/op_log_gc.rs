//! Bounded jj operation-log GC for kata's growth vectors.
//!
//! Trunk-move imports ([`super::vcs_backend`] `import_git_history_tx` /
//! `refresh_trunk_from_git`) and land/promote
//! traffic ([`super::merge_queue`]) each publish a jj operation-log entry. On a
//! long-lived *adopted* repo those vectors grow the op-log — and the
//! transitively-reachable commit/tree/file objects behind abandoned operations
//! — without bound, inflating boot fold cost and disk. The skip-when-equal
//! import optimization suppresses only *no-op* trunk imports; a
//! repo that actually moves (every real operator commit, every
//! land) still accretes an operation per event.
//!
//! ## Policy: abandon-then-gc, bounded by count AND time
//!
//! [`JjBackend::compact_op_log`] mirrors what `jj operation abandon` + `jj util
//! gc` do, driven by kata's own conservative horizon instead of an interactive
//! operator:
//!
//! 1. Walk the operation log from the current head (newest first) and find the
//!    **abandon boundary**: the newest operation that is BOTH beyond the
//!    `max_operations` retention count AND older than the `keep_newer` safety
//!    floor. Everything from the boundary back to (but not including) the root
//!    operation is stale.
//! 2. **Reparent** the retained range (`boundary..head`) onto the root operation
//!    ([`jj_lib::op_walk::reparent_range`]) — the abandon step. The retained
//!    operations keep their view verbatim (only their *parentage* is rewritten),
//!    so the live view — every bookmark, every workspace working-copy commit —
//!    is preserved byte-for-byte; only the undo history behind the boundary is
//!    dropped.
//! 3. Point the op-heads store at the new head, then GC the now-unreachable
//!    operations/views ([`jj_lib::op_store::OpStore::gc`]) and the store objects
//!    they alone kept alive ([`jj_lib::store::Store::gc`]).
//!
//! ## Safety invariant (why this never eats something live)
//!
//! The single soundness-critical claim is *nothing live is behind the abandon
//! boundary*. It holds on three independent legs:
//!
//! * **Commit reachability protects parked candidates + live workspaces.** A
//!   parked candidate is a `parked/*` bookmark and a live execution workspace is
//!   a working-copy commit; both sit in the retained head operation's view,
//!   which reparenting preserves verbatim. [`Store::gc`] only collects commits
//!   **unreachable** from that view, so a parked/checked-out commit is NEVER
//!   collected regardless of how old its *operation* is. This is the leg the
//!   op-log GC safety regression pins.
//! * **The retention count protects the recent operation history.** The newest
//!   `max_operations` operations are always retained, so any workspace touched
//!   within that window keeps the exact operation it was checked out at (no
//!   stale-working-copy surprise mid-execution).
//! * **The op-heads lock makes the whole pass atomic w.r.t. concurrent
//!   committers.** The abandon boundary is computed on a pre-lock snapshot, but
//!   before reparenting we take the same op-heads lock jj's own
//!   `Transaction::publish` takes and RE-READ the heads: if a landing published
//!   in that window (the log moved or diverged) we bail rather than reparent a
//!   stale head. The reparent, the op-heads update, and BOTH gc calls all run
//!   under that lock, so no publish can interleave and no concurrent branch is
//!   ever abandoned or collected out from under a live writer. The keep-newer
//!   floor (`now - keep_newer`) is a second, independent guard: nothing newer
//!   than the cutoff is abandoned or collected even setting the lock aside.
//!
//! Conservative by construction: multi-headed operation logs (a transient
//! divergence) are skipped rather than merged, the boundary decision is
//! re-validated under the lock, and the root operation is never rewritten.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jj_lib::backend::MillisSinceEpoch;
use jj_lib::op_walk;
use jj_lib::operation::Operation as WalkOperation;
use jj_lib::repo::Repo as _;
use kata_types::{KataError, KataResult};

use super::JjBackend;

/// Conservative op-log GC horizon derived from kata's own retention knobs
/// ([`kata_types::config::VcsConfig`]). Carried on [`JjBackend`] and read by the
/// boot sweep and the post-land cadence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpLogGcPolicy {
    /// Master switch. `false` leaves the op-log to jj's own cadence.
    pub enabled: bool,
    /// The newest `max_operations` operations are ALWAYS retained. `0` disables
    /// the count bound (keep-newer window only).
    pub max_operations: u64,
    /// Never abandon/collect anything newer than this. The undo-horizon +
    /// concurrent-writer safety floor.
    pub keep_newer: Duration,
    /// Run a compaction pass after every N landed executions. `0` disables the
    /// land cadence (boot sweep only).
    pub every_n_lands: u64,
}

impl Default for OpLogGcPolicy {
    fn default() -> Self {
        // Mirrors `VcsConfig::default()` so a config-less JjBackend and the
        // boot-wired one bound the log identically.
        Self {
            enabled: true,
            max_operations: 1_000,
            keep_newer: Duration::from_secs(600),
            every_n_lands: 100,
        }
    }
}

/// Outcome of a [`JjBackend::compact_op_log`] pass — an honest, side-effect-free
/// report used by callers for logging and by the op-log GC soak/safety tests for
/// their bound assertions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpLogGcStats {
    /// Whether a reparent+gc actually ran (`false` when disabled, multi-headed,
    /// or nothing was old enough to abandon).
    pub ran: bool,
    /// Operation count reachable from head BEFORE compaction (incl. root).
    pub ops_before: u64,
    /// Operations that became unreachable from the new head (the abandoned undo
    /// history). Equals [`jj_lib::op_walk::ReparentStats::unreachable_count`].
    pub ops_abandoned: u64,
    /// Operations retained + reparented onto root (the newest slice).
    pub ops_retained: u64,
}

impl JjBackend {
    /// Convert a jj operation's end timestamp to a `SystemTime` for age
    /// comparison. Negative (pre-epoch) millis clamp to the epoch — such an op
    /// is unambiguously "old" and safe to consider abandonable.
    fn op_end_time(op: &WalkOperation) -> SystemTime {
        let MillisSinceEpoch(millis) = op.metadata().time.end.timestamp;
        match u64::try_from(millis) {
            Ok(millis) => UNIX_EPOCH + Duration::from_millis(millis),
            // Negative (pre-epoch) millis clamp to the epoch — such an op is
            // unambiguously "old" and safe to consider abandonable.
            Err(_) => UNIX_EPOCH,
        }
    }

    /// Count the operations reachable from the current head (including the root
    /// operation). The natural "is the op-log bounded?" probe for the op-log GC
    /// soak; also used to short-circuit compaction when the log is already small.
    ///
    /// Returns `Ok(0)` for the pathological multi-/no-head case so callers treat
    /// it as "nothing to measure" rather than erroring.
    pub fn op_log_len(&self) -> KataResult<u64> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let loader = workspace.repo_loader();
        let op_store = loader.op_store();
        let op_heads_store = loader.op_heads_store();
        let head_ops = op_walk::get_current_head_ops(op_store, op_heads_store.as_ref())
            .map_err(|err| KataError::Internal(format!("failed to read jj op heads: {err}")))?;
        if head_ops.len() != 1 {
            return Ok(0);
        }
        let mut count = 0u64;
        for op in op_walk::walk_ancestors(&head_ops) {
            op.map_err(|err| {
                KataError::Internal(format!("failed to walk jj op ancestors: {err}"))
            })?;
            count += 1;
        }
        Ok(count)
    }

    /// Run one bounded op-log compaction pass under `policy`.
    ///
    /// Best-effort and conservative: a disabled policy, a multi-headed log, or a
    /// log with nothing old enough to abandon all return `ran = false` with the
    /// repo untouched. See the module docs for the safety invariant.
    pub fn compact_op_log(&self, policy: &OpLogGcPolicy) -> KataResult<OpLogGcStats> {
        if !policy.enabled {
            return Ok(OpLogGcStats::default());
        }
        super::record_vcs_op("op_log_gc", || self.compact_op_log_inner(policy))
    }

    fn compact_op_log_inner(&self, policy: &OpLogGcPolicy) -> KataResult<OpLogGcStats> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let loader = workspace.repo_loader();
        let op_store = loader.op_store().clone();
        let op_heads_store = loader.op_heads_store().clone();

        let head_ops = op_walk::get_current_head_ops(&op_store, op_heads_store.as_ref())
            .map_err(|err| KataError::Internal(format!("failed to read jj op heads: {err}")))?;
        // Conservative: a transient divergence (concurrent ops not yet merged)
        // is left alone — a normal operation or the next pass will merge and
        // bound it. Never abandon under ambiguity.
        if head_ops.len() != 1 {
            return Ok(OpLogGcStats::default());
        }
        let head = head_ops.into_iter().next().expect("len checked == 1");

        let now = SystemTime::now();
        let cutoff = now.checked_sub(policy.keep_newer).unwrap_or(UNIX_EPOCH);
        let root_op_id = op_store.root_operation_id().clone();

        // Walk newest-first; the abandon boundary is the newest op that is BOTH
        // beyond the retention count AND older than the keep-newer floor. The
        // root operation is never a valid boundary (it cannot be rewritten).
        let mut ops_before = 0u64;
        let mut boundary: Option<WalkOperation> = None;
        for op in op_walk::walk_ancestors(std::slice::from_ref(&head)) {
            let op = op.map_err(|err| {
                KataError::Internal(format!("failed to walk jj op ancestors: {err}"))
            })?;
            ops_before += 1;
            if boundary.is_some() {
                // Keep counting `ops_before` for the honest report, but the
                // boundary is already fixed.
                continue;
            }
            if op.id() == &root_op_id {
                continue;
            }
            let beyond_count = ops_before > policy.max_operations;
            let older_than_floor = Self::op_end_time(&op) < cutoff;
            if beyond_count && older_than_floor {
                boundary = Some(op);
            }
        }

        let Some(boundary) = boundary else {
            // Nothing old + surplus enough to abandon: already bounded.
            return Ok(OpLogGcStats {
                ran: false,
                ops_before,
                ops_abandoned: 0,
                ops_retained: ops_before,
            });
        };

        // Serialize with any concurrent op-heads resolver AND any concurrent
        // committer: jj's own `Transaction::publish` takes this exact op-heads
        // lock before it calls `update_op_heads` (`jj_lib::transaction`), so
        // holding it here makes our whole read-decide-reparent-gc sequence
        // atomic w.r.t. every publish, in-process and cross-process (it is a
        // FileLock). The lock is advisory and released on drop / process death,
        // so it can never wedge the log.
        let heads_lock = Self::block_on(op_heads_store.lock())
            .map_err(|err| KataError::Internal(format!("failed to lock jj op heads: {err}")))?;

        // TOCTOU guard: the abandon boundary above was computed on a snapshot read
        // BEFORE we held the lock. A landing that published in that window is now
        // visible under the lock. Re-read the heads and bail unless the log is
        // still the exact single head we decided against — reparenting a stale
        // head would leave the concurrent committer's head divergent (op-heads =
        // {their head, our reparented head}), and gc'ing with only our head could
        // physically collect the operation/objects their branch still references.
        // Never reparent under ambiguity.
        let locked_heads = op_walk::get_current_head_ops(&op_store, op_heads_store.as_ref())
            .map_err(|err| {
                KataError::Internal(format!("failed to re-read jj op heads under lock: {err}"))
            })?;
        if locked_heads.len() != 1 || locked_heads[0].id() != head.id() {
            return Ok(OpLogGcStats {
                ran: false,
                ops_before,
                ops_abandoned: 0,
                ops_retained: ops_before,
            });
        }

        // Opened before the reparented operations and the new head are written,
        // so the sync below reports a writeback error of any of them.
        let barrier = self.barrier()?;
        let root_op = Self::block_on(loader.root_operation());
        let stats = op_walk::reparent_range(
            op_store.as_ref(),
            std::slice::from_ref(&boundary),
            std::slice::from_ref(&head),
            &root_op,
        )
        .map_err(|err| KataError::Internal(format!("failed to reparent jj op range: {err}")))?;

        // reparent_range on a non-empty range always yields exactly one new head
        // for our single-head input. If it rewrote nothing, leave the log alone.
        if stats.rewritten_count == 0 {
            return Ok(OpLogGcStats {
                ran: false,
                ops_before,
                ops_abandoned: 0,
                ops_retained: ops_before,
            });
        }
        let new_head_id =
            stats.new_head_ids.first().cloned().ok_or_else(|| {
                KataError::Internal("jj reparent produced no new head".to_owned())
            })?;

        Self::block_on(
            op_heads_store.update_op_heads(std::slice::from_ref(head.id()), &new_head_id),
        )
        .map_err(|err| KataError::Internal(format!("failed to update jj op heads: {err}")))?;
        // The reparented operations and the head naming them are durable before
        // the operations they replace are deleted: a power loss between the two
        // never leaves the op heads naming a collected operation.
        barrier.sync("op-log GC")?;

        // Still under the lock: re-read the authoritative op-head set to feed gc.
        // We confirmed a single head above and only added `new_head_id`, so this
        // is `[new_head_id]` — but reading it back (rather than hard-coding the
        // one id) means gc is handed the FULL live head set, so a concurrent
        // head's ancestry can never be collected out from under it even if jj's
        // internals ever surface an extra head here.
        let gc_heads: Vec<jj_lib::op_store::OperationId> =
            op_walk::get_current_head_ops(&op_store, op_heads_store.as_ref())
                .map_err(|err| {
                    KataError::Internal(format!("failed to read jj op heads for gc: {err}"))
                })?
                .into_iter()
                .map(|op| op.id().clone())
                .collect();

        // GC the now-unreachable operations/views, then the store objects they
        // alone kept reachable. `cutoff` as keep_newer preserves anything a
        // concurrent writer created after it — the same floor the abandon
        // boundary respected. Both gc calls run while the op-heads lock is still
        // held, so no publish can interleave between the reparent and the
        // collection.
        op_store
            .gc(&gc_heads, cutoff)
            .map_err(|err| KataError::Internal(format!("failed to gc jj op store: {err}")))?;

        // Reindex at the reparented head so store gc sees the true reachable set,
        // then collect unreachable commit/tree/file objects.
        let new_head_op = Self::block_on(loader.load_operation(&new_head_id))
            .map_err(|err| KataError::Internal(format!("failed to load new jj head op: {err}")))?;
        let repo = Self::block_on(loader.load_at(&new_head_op)).map_err(|err| {
            KataError::Internal(format!("failed to reload jj repo at compacted head: {err}"))
        })?;
        repo.store()
            .gc(repo.index(), cutoff)
            .map_err(|err| KataError::Internal(format!("failed to gc jj store objects: {err}")))?;

        // Release the op-heads lock only after collection completes — the entire
        // read-decide-reparent-gc window was mutually exclusive with publish.
        drop(heads_lock);

        Ok(OpLogGcStats {
            ran: true,
            ops_before,
            ops_abandoned: stats.unreachable_count as u64,
            ops_retained: stats.rewritten_count as u64,
        })
    }
}
