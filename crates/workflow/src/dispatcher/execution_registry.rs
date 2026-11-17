//! Process-local checked authority, pinned by the runner that owns the graph,
//! invocation, and replay-local waits. Historical queries never register here.
//! This retires hot authority; it does not impose admission caps or discharge
//! provider/workspace cleanup obligations.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};

use super::{CheckedProgramAuthority, Dispatcher, KataError, KataResult, Ulid};

struct Entry {
    authority: CheckedProgramAuthority,
    roots: usize,
    generation: Arc<()>,
}

#[derive(Default)]
pub(super) struct ExecutionRegistry {
    entries: Mutex<HashMap<Ulid, Entry>>,
}

impl ExecutionRegistry {
    pub(super) fn register(&self, id: Ulid, authority: CheckedProgramAuthority) -> KataResult<()> {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get_mut(&id) {
            if entry.authority != authority {
                return Err(KataError::Validation(format!(
                    "execution {id} already retains different checked program authority"
                )));
            }
            entry.roots += 1;
            entry.generation = Arc::new(());
        } else {
            entries.insert(
                id,
                Entry {
                    authority,
                    roots: 1,
                    generation: Arc::new(()),
                },
            );
        }
        Ok(())
    }

    pub(super) fn get(&self, id: &Ulid) -> Option<MappedMutexGuard<'_, CheckedProgramAuthority>> {
        MutexGuard::try_map(self.entries.lock(), |entries| {
            entries.get_mut(id).map(|entry| &mut entry.authority)
        })
        .ok()
    }

    fn release(&self, id: Ulid) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get_mut(&id) {
            entry.roots -= 1;
        }
    }

    fn candidates(&self) -> Vec<(Ulid, Arc<()>)> {
        self.entries
            .lock()
            .iter()
            .filter(|(_, entry)| entry.roots == 0)
            .map(|(id, entry)| (*id, Arc::clone(&entry.generation)))
            .collect()
    }

    fn candidate(&self, id: Ulid) -> Option<Arc<()>> {
        let entries = self.entries.lock();
        let entry = entries.get(&id)?;
        (entry.roots == 0).then(|| Arc::clone(&entry.generation))
    }

    fn retire(&self, id: Ulid, generation: &Arc<()>) {
        let mut entries = self.entries.lock();
        if entries
            .get(&id)
            .is_some_and(|entry| entry.roots == 0 && Arc::ptr_eq(&entry.generation, generation))
        {
            entries.remove(&id);
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

/// Kept as the runner's final field so graph, invocation and wait state drop
/// before the authority root. A pre-admission runner has this root too.
pub(crate) struct ExecutionProgramLease {
    pub(super) dispatcher: Arc<Dispatcher>,
    pub(super) execution_id: Ulid,
}

impl Drop for ExecutionProgramLease {
    fn drop(&mut self) {
        self.dispatcher.release_execution_root(self.execution_id);
    }
}

impl Dispatcher {
    fn release_execution_root(&self, execution_id: Ulid) {
        self.checked_program_authority.release(execution_id);
        if let Some(generation) = self.checked_program_authority.candidate(execution_id) {
            self.reconcile_execution_hot_state_candidate(execution_id, &generation);
        }
    }

    pub(super) fn reconcile_execution_hot_state(&self) {
        for (id, generation) in self.checked_program_authority.candidates() {
            self.reconcile_execution_hot_state_candidate(id, &generation);
        }
    }

    fn reconcile_execution_hot_state_candidate(&self, id: Ulid, generation: &Arc<()>) {
        match self.execution_hot_state_can_retire(id) {
            Ok(true) => self.checked_program_authority.retire(id, generation),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(execution_id = %id, %error, "execution hot-state reconciliation deferred");
            }
        }
    }

    fn execution_hot_state_can_retire(&self, id: Ulid) -> KataResult<bool> {
        let face = self.execution_lifecycle();
        let Some(lifecycle) = face.lifecycle(id)? else {
            // Only the runner can publish a production registration. Its guard
            // pins this entry from before admission through all setup failures.
            return Ok(true);
        };
        if !lifecycle.state.is_terminal() {
            return Ok(false);
        }
        // Includes workerless input/timer/approval/child waits, not just attempts.
        for stage in self.execution_stage_states(id)? {
            if !stage.is_terminal() {
                return Ok(false);
            }
            if let Some(child) = stage.child_execution_id
                && !face
                    .lifecycle(child)?
                    .is_some_and(|row| row.state.is_terminal())
            {
                return Ok(false);
            }
        }
        // A child is admitted before the parent parks. Later parent transitions
        // can clear the parked link, so retain the immutable spawn obligation.
        for child in face.db().dynamic_children_for_execution(id)? {
            if !face
                .lifecycle(child)?
                .is_some_and(|row| row.state.is_terminal())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn execution_hot_state_count_for_test(&self) -> usize {
        self.checked_program_authority.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_hot_state_stale_sweep_cannot_remove_reacquired_generation() {
        let registry = ExecutionRegistry::default();
        let id = Ulid::new();
        let authority = CheckedProgramAuthority {
            program_hash: [7; 32].into(),
            input_timeouts: std::collections::BTreeMap::default(),
        };
        registry.register(id, authority.clone()).unwrap();
        assert!(registry.candidates().is_empty());
        registry.release(id);
        let old = registry.candidate(id).unwrap();
        registry.register(id, authority).unwrap();
        registry.release(id);
        registry.retire(id, &old);
        assert_eq!(registry.len(), 1);
        registry.retire(id, &registry.candidate(id).unwrap());
        assert_eq!(registry.len(), 0);
    }
}
