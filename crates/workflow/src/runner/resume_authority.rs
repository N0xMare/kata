//! Resume authority for the workflow runner (the shared crash-recovery
//! helpers the durable-replay boot depends on).
//!
//! Recovery is replay: the pure-fold boot (`boot_pure_fold`) is the sole
//! recovery engine. What remains here is `resume_via_replay`, the public
//! pure-fold boot shim inspection tests use to rebuild orchestrator state from
//! the durable ledger without running.

use std::collections::BTreeMap;

use kata_types::error::KataResult;
use smol_str::SmolStr;

use super::WorkflowRunner;

impl WorkflowRunner {
    /// Rebuild orchestrator + loop state from the durable ledger by
    /// pure fold, WITHOUT driving the workflow. The production executor uses
    /// this as its recovery-preparation barrier before activating the same runner;
    /// crash-recovery inspection tests also use it: it runs the exact same reconstruction
    /// `run_replay` performs on boot (`boot_pure_fold` — fold the whole durable
    /// log through `apply_event`, reconstruct loop iteration state, then
    /// rehydrate any in-flight-at-crash assignment's checked dispatch authority),
    /// so a resumed runner's orchestrator reaches the SAME state the live run
    /// left it in. Activation folds again with a fresh output map, so an already
    /// completed stage must repopulate that map without repeating completion work.
    /// It never invokes a model, but it may append idempotent
    /// recovery transitions such as orphaning an authority-less pending row or
    /// re-parking a durably declared sleep.
    pub fn resume_via_replay(
        &self,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        let mut applied: i64 = 0;
        self.boot_pure_fold(&mut applied, outputs)
    }
}
