//! **E3 — the crash / restart matrix's HOST column** (D2 §5.4): the process column's
//! P1–P4 (`e3_crash_matrix_live`, whose module doc states the cells, their positive
//! controls, the agent, the forge and the evidence record) with the WHOLE machine
//! killed instead of one process. It shares that binary's rig (`e3_matrix/`).
//!
//! # The machine kill
//!
//! `KATA_E3_HOST_KILL_CMD` is a shell command that kills the WHOLE node (the machine the
//! node runs on); `KATA_E3_HOST_STATE_DIR` is a directory on that machine's persistent
//! disk. The arm phase boots the node there with `KATA_FAULT_INJECT_ACTION=stop` on the
//! armed process (P3-host: the worker; else the main), makes the local forge one that keeps
//! what it acknowledged (`keep_what_the_forge_acknowledges`: the bare fsyncs every object
//! and ref it receives, the fake `gh` its log), runs `sync` once before it submits (the
//! rig's fixture, provider and booted node, the node's boot-time state included, are then
//! on disk, so the column does not test kata's boot-time durability; nothing the run
//! writes is flushed by the rig), waits for the point's `action=stop` marker, every thread
//! of that process in state `T` and no `resumed at` line in its log (P2-host: the open
//! model call), then FREEZES the whole node (`freeze_node`: SIGSTOP the main and the
//! worker, every thread `T`) and reads the case's pre-kill state (`host_pre_kill`:
//! P1-host / P3-host, `plan` unsettled in the raw database, read outside kata, so no
//! heartbeat leg settled it before the kill, and a read that fails is VOID; P2-host, the
//! call still open in kata's own progress frames, the kernel's sockets recorded beside it,
//! not judged; P4-host, exactly one acknowledged `kata/<exec>` and no pull request on the
//! forge),
//! writes `<state dir>/<case>.json` and runs the command, which must not return. After the
//! machine restarts on the same disk, `KATA_E3_HOST_RESUME=<state dir>/<case>.json`
//! re-runs the same test: it reads what the arm phase left before anything boots
//! (P2-host: the arm transcript's open call; every case: the forge's `kata/<exec>`, its
//! `git fsck` and the fake `gh`'s pull requests, P4-host VOID unless they are what was
//! acknowledged before the kill), boots the main, then the worker, and judges the
//! settlement as the process column does (P2-host's through the next main's restart pass,
//! `the main restarted`, where P2's is the worker-death leg: `P2Restart`); a node that
//! does not come back (its main exiting on recovery) is recorded as the process column's
//! `not_restarted`, the main's last `Error:` line leading its detail, ahead of the rig's
//! symptom, and in the oracle. A host cell without the command refuses by name.
//!
//! # Where it runs
//!
//! On the VM, one cell at a time, through `scripts/e9-vm.sh e3-host <case> <out>` (after
//! `e3-prep`): it runs `cargo nextest run -p kata -P live-smoke --test-threads=1
//! --run-ignored all -E 'binary(e3_crash_matrix_host_live) & test(=<test>)'` in the guest
//! with `KATA_E3_HOST_STATE_DIR` set and a `KATA_E3_HOST_KILL_CMD` that asks the host for
//! the kill, copies this binary's own arm files (the state JSON, `arm-oracle.txt`, the SSE
//! transcript) out of the guest, SIGKILLs the machine's qemu (`kill-host`), boots the same
//! disk, copies them back, runs the cell again with `KATA_E3_HOST_RESUME`, and copies the
//! case's records and the kept node's data out on every exit path. The guest's cargo
//! must build nothing in a cell (its runner holds the key), so nothing a cell runs in the
//! checkout writes the fresh clone's racy index, which `bin/kata/build.rs` watches: the
//! rig reads the status without the index lock (`tree_status`,
//! `the_rigs_tree_reads_leave_a_racy_index_untouched`), and so does `kata run`'s
//! uncommitted-edits notice, which the rig's submit runs from the checkout
//! (`dirty_checkout`, `the_uncommitted_edits_read_leaves_a_racy_index_untouched`). Any machine
//! whose kill command the operator supplies runs it the same way. No gate runs it: it needs
//! a machine to kill, so `gate_exclusion` lists it outside the containment lane.

#![cfg(target_os = "linux")]
mod agent_change_rig;
mod e3_matrix;
#[allow(dead_code)]
mod mock_model;
#[path = "../../../crates/agent-nanocode/tests/fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
use e3_matrix::*;

/// **P1-host.** P1 with the machine killed while the main is stopped at the point.
#[test]
#[ignore = "E3 host column: needs the VM and KATA_E3_HOST_KILL_CMD"]
fn e3_p1_host_live() {
    host_cell("P1-host", Armed::Main, Some(P1_BOUNDARY));
}
/// **P2-host.** P2 with the machine killed on the transcript's open model call.
#[test]
#[ignore = "E3 host column: needs the VM and KATA_E3_HOST_KILL_CMD"]
fn e3_p2_host_live() {
    host_cell("P2-host", Armed::Main, None);
}
/// **P3-host.** P3 with the machine killed while the worker is stopped at the point.
#[test]
#[ignore = "E3 host column: needs the VM and KATA_E3_HOST_KILL_CMD"]
fn e3_p3_host_live() {
    host_cell("P3-host", Armed::Worker, Some(P3_BOUNDARY));
}
/// **P4-host.** P4 with the machine killed while the main is stopped at the point.
#[test]
#[ignore = "E3 host column: needs the VM and KATA_E3_HOST_KILL_CMD"]
fn e3_p4_host_live() {
    host_cell("P4-host", Armed::Main, Some(P4_BOUNDARY));
}
