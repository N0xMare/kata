//! The worker-death fixture — an inline two-stage workflow submitted by
//! `crates/test-utils/tests/smokes.rs`'s
//! `smoke_main_local_socket_two_workers_kill_refuses_ambiguous_redelivery` to a
//! live installed main over two real `kata-worker` processes.
//!
//! It has no re-executable twin: under the capsule route a dead worker's attempt
//! is PROVEN AMBIGUOUS and settled `uncertainty-not-reissued` whatever its
//! class, so there is no permitted re-execution arm to prove.

/// Two-stage worker-death fixture: a confined offline shell `work` stage the
/// smoke's victim worker is SIGKILLed under, and a `finish` stage that depends
/// on it.
///
/// `finish` runs only after `work` completes, so its ABSENCE proves the graph
/// did not advance past an unobserved effect. Pure `agent = "shell"` — no model
/// spend.
///
/// The `work` prompt's `sleep 20` costs this fixture nothing: its worker is
/// SIGKILLed as soon as the stage is attributed, and the capsule settlement then
/// fails the run (PROVEN AMBIGUOUS, never re-delivered), so the sleep never runs
/// to completion here.
pub const KILL_MID_RUN_WF: &str = r#"
work = stage(
    id = "work",
    agent = "shell",
    sandbox = "iso",
    prompt = "set -eu\nsleep 20\nprintf '{\"done\": true}\\n'\n",
    outputs = {"done": "bool"},
)

finish = stage(
    id = "finish",
    agent = "shell",
    sandbox = "iso",
    depends_on = ["work"],
    prompt = "set -eu\nprintf '{\"final\": true}\\n'\n",
    outputs = {"final": "bool"},
)

workflow(
    "kill-redispatch",
    description = "Two-stage kill-redispatch proof: a confined shell stage whose orphaned capsule attempt must be settled PROVEN AMBIGUOUS rather than re-delivered to the survivor.",
    root = [work],
    sandbox_profiles = {
        "iso": sandbox_profile(net = "offline"),
    },
)
"#;
