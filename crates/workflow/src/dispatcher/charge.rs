//! Process-local, consume-once dispatch load charges.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use parking_lot::Mutex;
use smol_str::SmolStr;
use ulid::Ulid;

use super::attempt_chain::DispatchToken;

/// One load charge against one concrete worker registration.
#[derive(Debug)]
struct DispatchCharge {
    token: ChargeToken,
    dispatch: DispatchToken,
    worker_id: SmolStr,
    counter: Arc<AtomicU32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ChargeToken(u64);

pub(super) struct AcquiredCharge {
    pub(super) token: ChargeToken,
    pub(super) counter: Arc<AtomicU32>,
}

pub(super) struct ChargeSnapshot {
    pub(super) assignment_id: Ulid,
    pub(super) token: ChargeToken,
    pub(super) dispatch: DispatchToken,
    pub(super) worker_id: SmolStr,
}

/// Assignment-indexed ownership for the advisory scheduler counter.
///
/// The map is process-local for the same reason `DispatchToken` is: no pending
/// send survives a process crash. Replacing an entry consumes its predecessor
/// before incrementing the successor, so one assignment owns at most one load
/// charge even while placement generations race.
#[derive(Debug, Default)]
pub(super) struct DispatchCharges {
    next: AtomicU64,
    owners: Mutex<HashMap<Ulid, DispatchCharge>>,
}

impl DispatchCharges {
    /// Install a generation's charge, consuming any predecessor exactly once.
    pub(super) fn acquire(
        &self,
        assignment_id: Ulid,
        dispatch: DispatchToken,
        worker_id: SmolStr,
        counter: Arc<AtomicU32>,
    ) -> AcquiredCharge {
        let mut owners = self.owners.lock();
        if let Some(prior) = owners.remove(&assignment_id) {
            decrement(&prior.counter);
        }
        let token = ChargeToken(self.next.fetch_add(1, Ordering::Relaxed));
        counter.fetch_add(1, Ordering::Relaxed);
        owners.insert(
            assignment_id,
            DispatchCharge {
                token,
                dispatch,
                worker_id,
                counter: Arc::clone(&counter),
            },
        );
        AcquiredCharge { token, counter }
    }

    /// Consume the assignment's charge only if this exact acquisition still owns it.
    pub(super) fn release_if_owned(&self, assignment_id: Ulid, token: ChargeToken) -> bool {
        let mut owners = self.owners.lock();
        let matches = owners
            .get(&assignment_id)
            .is_some_and(|charge| token == charge.token);
        if !matches {
            return false;
        }
        let charge = owners
            .remove(&assignment_id)
            .expect("matching dispatch charge remains under the map lock");
        decrement(&charge.counter);
        true
    }

    pub(super) fn owner(&self, assignment_id: Ulid) -> Option<ChargeSnapshot> {
        self.owners
            .lock()
            .get(&assignment_id)
            .map(|charge| ChargeSnapshot {
                assignment_id,
                token: charge.token,
                dispatch: charge.dispatch,
                worker_id: charge.worker_id.clone(),
            })
    }

    pub(super) fn snapshot(&self) -> Vec<ChargeSnapshot> {
        self.owners
            .lock()
            .iter()
            .map(|(assignment_id, charge)| ChargeSnapshot {
                assignment_id: *assignment_id,
                token: charge.token,
                dispatch: charge.dispatch,
                worker_id: charge.worker_id.clone(),
            })
            .collect()
    }
}

fn decrement(counter: &AtomicU32) {
    // A charge created here increments exactly once, but saturating the advisory
    // counter keeps external diagnostics/test mutations from turning a cleanup
    // anomaly into `u32::MAX`, which would poison scheduler ordering indefinitely.
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_sub(1)
    });
}
