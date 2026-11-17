//! The operational plane's LIVENESS WAKE.
//!
//! # Why the wake must come from this plane
//!
//! A runner that folds the operational chain while its wake comes from the ledger
//! broadcast (`ledger/mod.rs`'s `subscribe()`) would produce a **permanent hang**,
//! not a delay:
//!
//! ```text
//! a ledger write commits and broadcasts  ->  the runner wakes
//! the runner folds the CHAIN                 the chain write has not committed
//! nothing moved                          ->  the runner parks again
//! the chain write commits                    nobody broadcasts on the ledger
//! (silence, forever)
//! ```
//!
//! The wake and the fact would not be the same commit. No care at the reader could
//! fix that, because the two planes are disjoint publishers.
//!
//! # The contract: this is LIVENESS, never AUTHORITY
//!
//! Two disagreeing *authorities* per consultation are never allowed. This primitive
//! is built so it cannot become the second one — not by convention, by shape:
//!
//! - [`Wake`] has **no payload**. It names no execution, no attempt, no sequence,
//!   no state and no count. `size_of::<Wake>() == 1` is asserted below, so giving
//!   it a field breaks the build rather than a review.
//! - A caller **cannot distinguish a real commit from an expired budget**. Both
//!   return [`Wake::Recheck`], on purpose: the correct response is identical, and a
//!   caller able to tell them apart could mistake a quiet plane for a settled one —
//!   which is a decision, and a wrong one.
//! - The only other value, [`Wake::Closed`], is a fact about the CHANNEL (the plane
//!   handle is gone), not about the plane's contents. Collapsing it into `Recheck`
//!   would leave a consumer spinning on a database that no longer exists.
//!
//! So the entire value space is *"read the plane again"* and *"there is no plane"*.
//! Every question about executions, attempts and sequences is answered by reading
//! the plane.
//!
//! # Why a level, not an event
//!
//! An event-shaped notifier — a broadcast, or `Notify::notify_waiters()` — loses a
//! wake published while nobody is parked, and there is no way for a listener to
//! learn afterwards that it happened. That is the same permanent hang one plane
//! over. This is therefore a **monotone commit counter behind a `watch`**, and the
//! waiter compares what it has been handed against what the plane has reached. The
//! consequences are structural rather than tested-for:
//!
//! - **zero listeners** — publishing takes no lock on a subscriber and returns no
//!   `Result`, so a transaction can never fail on a listener's behalf;
//! - **a slow listener** — a `watch` holds one value, so N missed commits coalesce
//!   into one wake; there is no capacity to exceed and no `Lagged` arm to mishandle;
//! - **a listener that subscribes after the write** — a new waiter starts at 0,
//!   deliberately BEHIND any plane that has ever committed, so its first `wait`
//!   returns immediately instead of parking on a plane that already moved;
//! - **a lagging receiver** — cannot exist; there is no queue to fall behind.
//!
//! In every ambiguous case the failure direction is a redundant fold, never a
//! missed one.
//!
//! # Why the ordering cannot be got wrong by a caller
//!
//! The dangerous protocol error is "sample the notifier AFTER reading the plane",
//! which reopens the window this exists to close. There is no sampling knob to get
//! wrong: [`PlaneLiveness::wait`] advances its own high-water mark **only as it
//! returns**, which is always before the caller's next read. A commit concurrent
//! with that read is therefore still unobserved when the park begins, and the park
//! returns at once.
//!
//! # Why the wake is global rather than per-execution
//!
//! A waiter is woken by ANY operational commit, not only ones touching an execution
//! it cares about; filtering is the consumer's fold. This matches the ledger's
//! documented stance for the same reason ("callers filter by `execution_id` …
//! client-side … avoids coupling the lock-free hot path to an arbitrary predicate
//! set"), and it removes a whole defect class: a routed wake would have to carry an
//! execution id, which is decidable content, and a writer that forgot to tag one
//! would produce a silent hang. The publish takes **no arguments**, so there is
//! nothing to forget.

use std::time::Duration;

use tokio::sync::watch;

/// The only thing an operational wake can say.
///
/// # Invariant
///
/// CARRIES NO PLANE STATE. See the module docs: this is what keeps a wake from
/// becoming a second authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a discarded wake is a fold that never happens, and `Closed` discarded \
              is a loop that spins on a plane that no longer exists"]
pub enum Wake {
    /// Read the durable plane again.
    ///
    /// Returned when a transaction committed **and** when the budget expired.
    /// Deliberately indistinguishable — see the module docs.
    Recheck,
    /// The plane handle was dropped. No further wake can arrive, and re-reading is
    /// no longer possible.
    Closed,
}

/// A [`Wake`] with a field would be a wake that could be consulted instead of the
/// plane. Enforced at COMPILE time rather than by review or by a test, because the
/// tempting version of this change ("just carry the seq, the caller already wants
/// it") is exactly a co-authority.
const _: () = assert!(
    std::mem::size_of::<Wake>() == 1,
    "Wake must stay payload-free: a field makes it a second answer to a question \
     the operational plane already answers"
);

/// A liveness handle on the operational plane. Obtained from
/// `OperationalDb::liveness`.
///
/// One handle belongs to one consumer loop; it is not shared, because its
/// high-water mark tracks what THIS consumer has been told.
#[derive(Debug)]
pub struct PlaneLiveness {
    plane: watch::Receiver<u64>,
    /// The plane's commit count as last HANDED BACK to this waiter's caller.
    ///
    /// Starts at zero — deliberately behind any plane that has ever committed, so
    /// a waiter created after a write does not park on a plane that already moved.
    handed_back: u64,
}

impl PlaneLiveness {
    /// Park until the plane commits something, or until `budget` expires.
    ///
    /// # Invariant
    ///
    /// THE BUDGET IS MANDATORY, and there is no unbounded variant. An in-process
    /// signal structurally cannot cover a writer that never reached the publish —
    /// a future transaction added outside `in_writer_txn`, or a mutation from
    /// another process holding the data directory. Under an unbounded park that
    /// residue is a permanent hang, which is the exact failure an unbounded
    /// `events.recv().await` carries; under a budget it is bounded latency
    /// and a fold that rescues itself. The budget only ever elapses on a plane
    /// that genuinely committed nothing.
    ///
    /// A commit that lands between the caller's read and this call is NOT lost:
    /// the waiter's high-water mark advanced when the previous `wait` returned,
    /// which is strictly before that read.
    ///
    /// # Cancel safety
    ///
    /// CANCEL-SAFE, which a consumer driving this from a `select!` alongside a
    /// shutdown signal depends on. The high-water mark moves only on the
    /// synchronous path immediately before a `Recheck` is returned, and the sole
    /// await point is the park itself. Dropping the future therefore cannot
    /// consume a wake: a commit that landed while it was parked is still
    /// unobserved, and the next `wait` reports it at once.
    pub async fn wait(&mut self, budget: Duration) -> Wake {
        match tokio::time::timeout(budget, self.wait_for_plane()).await {
            Ok(wake) => wake,
            Err(_elapsed) => {
                // Surfaced for operators, never returned to the caller: a caller
                // able to see this could infer "the plane is quiet, so I am done",
                // and quiet is not settled.
                tracing::trace!(
                    budget_ms = budget.as_millis(),
                    "operational liveness: budget elapsed with no commit; re-read anyway"
                );
                Wake::Recheck
            }
        }
    }

    /// The unbounded core. PRIVATE — an unbounded park is unrepresentable at the
    /// public API by construction, not by documentation.
    async fn wait_for_plane(&mut self) -> Wake {
        loop {
            // Checked BEFORE parking, and against this waiter's own high-water
            // mark rather than the channel's notion of "seen". This is the line
            // that makes a missed wake unrepresentable: anything committed since
            // the previous return is already visible here.
            let reached = *self.plane.borrow_and_update();
            if reached != self.handed_back {
                self.handed_back = reached;
                return Wake::Recheck;
            }
            if self.plane.changed().await.is_err() {
                return Wake::Closed;
            }
        }
    }
}

/// The publish side. Owned by `OperationalDb` and welded to its commit.
#[derive(Debug)]
pub(crate) struct WakeSource {
    plane: watch::Sender<u64>,
}

impl WakeSource {
    pub(crate) fn new() -> Self {
        let (plane, _initial) = watch::channel(0);
        Self { plane }
    }

    /// Record that the plane committed once more.
    ///
    /// # Invariant
    ///
    /// INFALLIBLE, and takes no arguments. `send_modify` succeeds with zero
    /// receivers, so the caller — a transaction that has already committed — has
    /// no error to propagate and cannot be made to fail on a listener's behalf.
    /// Taking no arguments means there is no execution to mis-scope and no tag to
    /// forget, so a new writer cannot publish a wake that is quietly wrong.
    ///
    /// The counter is not any durable value: not `transitions.seq`, not a head,
    /// not a row count. It therefore has no durable counterpart it could disagree
    /// with, which is why it is not a second representation of anything.
    pub(crate) fn publish(&self) {
        self.plane
            .send_modify(|committed| *committed = committed.wrapping_add(1));
    }

    pub(crate) fn waiter(&self) -> PlaneLiveness {
        PlaneLiveness {
            plane: self.plane.subscribe(),
            handed_back: 0,
        }
    }
}
