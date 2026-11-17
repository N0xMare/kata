//! The representative CHECKED-COMMAND
//! workflow, end to end on a REAL node: the `agent_change_rig` (an installed `kata serve` main, an external `kata-worker`
//! daemon holding the certified
//! rootless-youki route, `kata run --submit` / `kata approvals` /
//! `kata run approve` through the ordinary client path) but the shipped pack
//! is `workflows/std/checked-command.star` — the shell twin whose `implement`
//! is a DETERMINISTIC checked command in a real container, not an agent turn.
//!
//! # The cell matrix (A/B/C, plus the node-death arm)
//!
//! * **A — the happy path** (`the_checked_command_pack_completes_end_to_end_live`):
//!   the shell capsule writes the fixture's `src/app.txt` inside its declared
//!   `produces_files` fence, `test` proves the criterion, `approve` parks
//!   bound to its capsule, `commit`/`promote` land the candidate, `export`
//!   pushes `kata/<exec>` to a LOCAL bare remote and opens ONE PR through the
//!   fake `gh` shim. Every assertion reads state OUTSIDE kata — raw
//!   `operational.db`, `git` on the fixture and remote, the shim's log, the
//!   filesystem — `kata run show` only cross-checks.
//! * **B — the interruption matrix** (`a_killed_main_resumes_the_parked_gate_live`,
//!   `a_killed_worker_at_the_parked_gate_resumes_live`): a kill at a durable
//!   park converges on the SAME final state after restart;
//!   `a_killed_worker_mid_capsule_settles_proven_ambiguous_live`: a kill
//!   DURING the capsule is terminal `PROVEN AMBIGUOUS`, never re-delivered;
//!   `a_dead_node_mid_capsule_settles_ambiguous_on_the_next_main_live`: the
//!   whole node dies mid-capsule — the container is gone with the worker's
//!   scope, and the NEXT main settles the attempt, still ambiguous, still
//!   never re-delivered.
//! * **C — the abort paths** (`a_rejected_gate_lands_nothing_and_parks_the_candidate_live`,
//!   `a_cancel_mid_capsule_asks_the_assignment_to_stop_and_settles_cancelled_live`):
//!   reject at the gate and a delivered cancel mid-capsule both leave the
//!   repo, remote and forge untouched — the candidate parked, inspectable;
//!   `an_implement_write_outside_the_declared_fence_is_refused_and_nothing_lands_live`
//!   writes outside `produces_files` on purpose — adoption refuses the whole
//!   delta `work_delta_out_of_scope`, the parked candidate still carries the
//!   seed tree.
//!
//! # The suite's instrument
//!
//! The interruption cells need the implement capsule provably LIVE at the
//! moment they act. The pack runs the REPO's `tools/implement.sh` verbatim —
//! `fixture_repo_with(.., ImplementScript::Hold(seconds))` commits a script
//! that sleeps the window out inside `/work` before editing — a
//! deterministic "the container is running" shape the positive control
//! reads off `/proc` and the filesystem before the kill or the cancel, and
//! the pack itself carries no instrument.
//!
//! # Host preconditions
//!
//! Same as the sibling OCI live lanes: `--ignore`d so a host without the
//! delegated user scope, the pin, or `nix-store` fails the lane with the
//! named refusal rather than silently skipping. `oci-live-smoke` selects this
//! binary.

#![cfg(target_os = "linux")]
mod agent_change_rig;
use agent_change_rig::*;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The shipped checked-command pack every cell runs, by path.
const CHECKED_PACK: &str = "workflows/std/checked-command.star";

/// The capsule window the mid-capsule cells park inside: the fixture's
/// `tools/implement.sh` opens with `sleep <HOLD_SECONDS>` ahead of the edit —
/// far past every heartbeat grace and settle deadline the cells race.
const HOLD_SECONDS: u64 = 240;

/// `[node] environment` for the checked-command suite: busybox alone. `sh`, `printf`,
/// `[`, `sleep`, `cat`, `grep` are all busybox applets; no agent stage exists
/// in the pack, so no vendor dir and no git-minimal ride along.
fn checked_environment() -> String {
    format!(
        "environment = {{ label = \"checked-command-e2e\", system = \"x86_64-linux\", \
         nixpkgs_attribute = \"nixpkgs#pkgsStatic.busybox\", store_paths = [\"{BUSYBOX}\"], \
         path_prepend = [\"{BUSYBOX}/bin\"], integrity_policy = {{ \
         verify = \"nar_hash_only\", sigs_needed = 0, required_signers = [], \
         allow_unsigned_content_addressed = true, verify_contents_at_declare = true }} }}\n"
    )
}

/// Boot the node for the checked pack: the suite's own fixture (its check
/// demands `check_expects`; `implement` is the repo's `tools/implement.sh`
/// shape — the hold window, or the out-of-fence wedge), a busybox-only
/// environment, no `[agents.*]` declaration, and a node id that names the
/// suite in the logs.
fn boot_checked(check_expects: &str, implement: ImplementScript) -> Node {
    let root = node_root();
    let fixture = fixture_repo_with(root.path(), check_expects, Some(implement));
    finish_boot_fixture(
        root,
        fixture,
        checked_environment(),
        String::new(),
        &["checked-command"],
        "checked-command-e2e",
    )
}

/// The positive control every mid-capsule cell shares: poll the kernel and
/// the filesystem until the run's `kata-<capsule>` container AND its attempt
/// roots exist — a kill or a cancel into an empty window would prove
/// nothing. Answers the live container ids and the attempt-root paths seen.
fn wait_live_capsule(node: &Node, execution: &str) -> (Vec<String>, Vec<PathBuf>) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let live = live_kata_containers(node, execution);
        let roots = attempt_roots(node);
        if !live.is_empty() && !roots.is_empty() {
            return (live, roots);
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the implement capsule never showed a live container + attempt roots; \
             the worker's log is {}:\n{}",
            node.worker.log.display(),
            std::fs::read_to_string(&node.worker.log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// The raw `implement`-stage terminal reason — the settled verdict the show
/// document's own projection never colours.
fn settled_reason(node: &Node, execution: &str, state: &str) -> String {
    let conn = raw_db(&node.root_path.join("data"));
    conn.query_row(
        "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
         AND stage_id = 'implement' AND resulting_state = ?2 ORDER BY seq DESC LIMIT 1",
        rusqlite::params![
            ulid::Ulid::from_string(execution).unwrap().to_bytes(),
            state
        ],
        |row| row.get(0),
    )
    .unwrap()
}

/// `implement`'s LAST terminal transition, read raw as
/// `(resulting_state, payload)` and polled until one exists — a red run
/// fails on the observed verdict, never on a no-row panic.
fn implement_terminal(node: &Node, execution: &str) -> (String, String) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let row: Option<(String, String)> = {
            let conn = raw_db(&node.root_path.join("data"));
            conn.query_row(
                "SELECT resulting_state, CAST(payload_json AS TEXT) FROM transitions \
                 WHERE execution_id = ?1 AND stage_id = 'implement' \
                 AND resulting_state IN ('completed', 'failed', 'cancelled') \
                 ORDER BY seq DESC LIMIT 1",
                [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok()
        };
        if let Some(row) = row {
            return row;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the implement attempt never reached a terminal transition"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// How many `claimed` transitions the run's `implement` stage ever recorded
/// — the re-delivery count, read raw.
fn implement_claims(node: &Node, execution: &str) -> i64 {
    let conn = raw_db(&node.root_path.join("data"));
    conn.query_row(
        "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = 'implement' \
         AND kind = 'claimed'",
        [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
        |row| row.get(0),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// CELL A — the happy path, asserted from OUTSIDE kata
// ---------------------------------------------------------------------------

/// **Cell A.** The whole `checked-command` run on a real node: a REAL
/// container runs the checked `implement` command (its write lands inside
/// the `produces_files` fence), `test` proves the deterministic criterion
/// read-only and offline, `approve` parks bound to its own capsule, the
/// `commit`→`promote`→`forge_export` effect chain lands on trunk and pushes
/// `kata/<exec>` — then every outcome read off the filesystem, git and raw
/// `operational.db`, cross-checked against `kata run show`.
#[test]
#[ignore = "the rootless-OCI prerequisite — `just _containment-preconditions`"]
fn the_checked_command_pack_completes_end_to_end_live() {
    let node = boot_checked("implemented-change", ImplementScript::Hold(15));
    let execution = node.main.submit(Path::new(CHECKED_PACK));

    // POSITIVE CONTROL — a real capsule runs the checked command: while the
    // hold parks `implement` mid-run the kernel answers a live
    // `kata-<capsule>` container and the filesystem answers its attempt
    // roots, so the terminal state below cannot be a run that never
    // contained anything.
    wait_until_claimed(&node, &execution, "implement", 1);
    let (live, roots) = wait_live_capsule(&node, &execution);
    eprintln!("POSITIVE CONTROL happy: live containers {live:?}; attempt roots {roots:?}");

    // The run parks at `approve` — and the gate row binds the capsule it
    // authorizes.
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");
    assert_eq!(gate["stage_name"].as_str(), Some("approve"));
    let capsule_id = gate["capsule"]["capsule_id"]
        .as_str()
        .expect("the gate row names the capsule it binds");
    assert!(
        !capsule_id.is_empty(),
        "the gate's capsule binding is non-empty"
    );

    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the run completes: {doc}"
    );

    // The approval's decision is recorded against the SAME capsule the gate
    // showed, on the RAW plane; the approve occurrence binds it immutably.
    {
        let conn = raw_db(&node.root_path.join("data"));
        let approvals: Vec<String> = conn
            .prepare(
                "SELECT CAST(payload_json AS TEXT) FROM transitions \
                 WHERE execution_id = ?1 AND kind = 'approval_decided'",
            )
            .unwrap()
            .query_map(
                [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            approvals.len(),
            1,
            "{TEST}: exactly one approval decision is recorded: {approvals:?}"
        );
        let recorded: serde_json::Value = serde_json::from_str(&approvals[0]).unwrap();
        assert_eq!(
            recorded["capsule_id"].as_str(),
            Some(capsule_id),
            "{TEST}: the recorded decision binds the capsule the gate showed"
        );
        let occurrence_capsule: Option<String> = conn
            .prepare(
                "SELECT hex(o.capsule_id) FROM occurrences o \
                 JOIN attempts a ON a.attempt_id = o.accepted_attempt_id \
                 WHERE o.execution_id = ?1 AND a.stage_id = 'approve'",
            )
            .unwrap()
            .query_map(
                [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .next()
            .transpose()
            .unwrap()
            .map(|id: String| id.to_ascii_lowercase());
        assert_eq!(
            occurrence_capsule.as_deref(),
            Some(capsule_id),
            "{TEST}: the approve occurrence binds the capsule the gate showed"
        );
    }

    // `kata run show` cross-checks the SHELL stage's declared output — the
    // checked-command evidence where the agent twin read a metered usage. The
    // stage's `outputs` contract lands under `parsed`, a sibling of the
    // capsule envelope's own fields.
    let implement = &doc["outputs"]["implement"];
    assert_eq!(
        implement["parsed"]["edited"].as_str(),
        Some("src/app.txt"),
        "the checked command's declared output names the file it wrote: {implement}"
    );

    assert_final_state(&node, &execution);
}

// ---------------------------------------------------------------------------
// CELLS B — durable interruption
// ---------------------------------------------------------------------------

/// **Cell B, main arm.** SIGKILL the installed main while the approval gate
/// is parked, restart it on the same data directory, and the SAME parked
/// attempt re-lists — durable state, not memory. The decision lands after
/// the restart and the run completes once: one commit, one promote, one PR.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_killed_main_resumes_the_parked_gate_live() {
    let mut node = boot_checked("implemented-change", ImplementScript::Edit);
    let execution = node.main.submit(Path::new(CHECKED_PACK));
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");

    node.main.kill();
    node.restart_main();
    // The worker's transport died with the main and the daemon does not
    // re-dial a rebound socket — a fresh daemon re-registers with the same
    // secret and capabilities.
    node.restart_worker();

    let resumed = node
        .main
        .next_gate(&execution)
        .expect("the gate re-parks after the main's restart");
    assert_eq!(
        resumed["assignment_id"], gate["assignment_id"],
        "{TEST}: the restarted main re-lists the SAME parked attempt"
    );
    node.main.decide(&resumed, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the run completes after the main's restart: {doc}"
    );
    assert_final_state(&node, &execution);
}

/// **Cell B, worker arm.** SIGKILL the external worker while the gate is
/// parked — nothing the worker owns is live — respawn it against the same
/// socket and secret, and the decision + downstream effects land once.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_killed_worker_at_the_parked_gate_resumes_live() {
    let mut node = boot_checked("implemented-change", ImplementScript::Edit);
    let execution = node.main.submit(Path::new(CHECKED_PACK));
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");

    node.worker.kill();
    node.restart_worker();

    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the run completes after the worker's restart: {doc}"
    );
    assert_final_state(&node, &execution);
}

/// **Cell B, mid-capsule arm.** SIGKILL the worker while its container runs
/// the checked command — the fixture's `tools/implement.sh` sleeps the capsule deterministically —
/// and the answer is the honest one, by name: the attempt settles `PROVEN
/// AMBIGUOUS` (the main cannot observe what the container did), terminal,
/// and is NOT re-delivered. The run fails, nothing mutates, and a respawned
/// worker claims NOTHING for the dead occurrence.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_killed_worker_mid_capsule_settles_proven_ambiguous_live() {
    let mut node = boot_checked("implemented-change", ImplementScript::Hold(HOLD_SECONDS));
    let execution = node.main.submit(Path::new(CHECKED_PACK));
    wait_until_claimed(&node, &execution, "implement", 1);

    // POSITIVE CONTROL — the capsule is provably in flight: the kernel
    // answers a live `kata-<capsule>` container AND a non-empty attempt root
    // before the kill, so the post-kill sweeps measure a real teardown, not
    // a run that never reached a container.
    let (live, roots) = wait_live_capsule(&node, &execution);
    eprintln!("POSITIVE CONTROL mid-capsule: live containers {live:?}; attempt roots {roots:?}");

    node.worker.kill();
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "the ambiguous attempt fails the run: {doc}"
    );
    let reason = settled_reason(&node, &execution, "failed");
    assert!(
        reason.contains("AMBIGUOUS") && reason.contains("died"),
        "{TEST}: the settled attempt names the worker's death and its ambiguity: {reason}"
    );

    // A fresh worker registers and claims NOTHING — the dead occurrence is
    // never re-delivered. Poll long enough for a re-delivery to appear.
    node.restart_worker();
    std::thread::sleep(Duration::from_secs(10));
    assert_eq!(
        implement_claims(&node, &execution),
        1,
        "{TEST}: exactly one implement attempt was ever claimed — no silent re-delivery"
    );
    assert_no_mutation(&node, &execution);
    assert_no_container_residue(&node, &execution);
}

/// **Cell B, node-death arm.** SIGKILL the main AND the worker while the
/// container runs: the whole node is gone mid-capsule. In THIS rig the
/// worker's delegated scope owns the provider and container cgroups — a lone
/// main death would leave the container running — so the honest "the node
/// died" arm kills the main first (it can never settle the worker's death
/// itself) and the worker second (systemd reaps the scope: container and
/// cgroup go with it). The NEXT main's restart settlement then answers
/// `failed`, `PROVEN AMBIGUOUS` — before any runner resumes — and a
/// respawned worker claims nothing: still never re-delivered, still no
/// residue.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_dead_node_mid_capsule_settles_ambiguous_on_the_next_main_live() {
    let mut node = boot_checked("implemented-change", ImplementScript::Hold(HOLD_SECONDS));
    let execution = node.main.submit(Path::new(CHECKED_PACK));
    wait_until_claimed(&node, &execution, "implement", 1);

    // POSITIVE CONTROL — the capsule is live in a container the kernel can
    // name, holding attempt roots on disk, before the node dies.
    let (live, roots) = wait_live_capsule(&node, &execution);
    eprintln!("POSITIVE CONTROL node-death: live containers {live:?}; attempt roots {roots:?}");

    // The main dies FIRST — inside the heartbeat grace, so it cannot settle
    // the worker's death itself — then the worker's scope dies, taking the
    // provider and the container's cgroup with it.
    node.main.kill();
    node.worker.kill();
    assert_no_container_residue(&node, &execution);

    node.restart_main();
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "the next main settles the unobservable capsule failed: {doc}"
    );
    let reason = settled_reason(&node, &execution, "failed");
    assert!(
        reason.contains("AMBIGUOUS"),
        "{TEST}: the restart settlement is the honest ambiguous verdict: {reason}"
    );

    node.restart_worker();
    std::thread::sleep(Duration::from_secs(10));
    assert_eq!(
        implement_claims(&node, &execution),
        1,
        "{TEST}: exactly one implement attempt was ever claimed — no silent re-delivery"
    );
    assert_no_mutation(&node, &execution);
    // The restarted worker's start sweep reclaims the dead attempt's root —
    // no runtime residue outlives a node death.
    assert_no_container_residue(&node, &execution);
    assert!(
        attempt_roots(&node).is_empty(),
        "{TEST}: the dead node's run leaves no attempt roots: {:?}",
        attempt_roots(&node)
    );
}

// ---------------------------------------------------------------------------
// CELLS C — the refusal and abort paths
// ---------------------------------------------------------------------------

/// **Cell C, reject arm.** The operator rejects the parked gate — the approve
/// attempt fails by name, the run fails, and the terminal closeout parks the
/// candidate for inspection (`parked/<exec>` names the judged tree, read
/// from git) while nothing mutates: no commit, no promote, no forge call,
/// trunk unmoved.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_rejected_gate_lands_nothing_and_parks_the_candidate_live() {
    let node = boot_checked("implemented-change", ImplementScript::Edit);
    let execution = node.main.submit(Path::new(CHECKED_PACK));
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");

    node.main.decide(&gate, Some("not the change we want"));
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "a rejected gate fails the run: {doc}"
    );
    assert_no_mutation(&node, &execution);

    // The parked candidate is INSPECTABLE, off git: `parked/<exec>` resolves
    // and names the tree the gate judged — the checked edit inside its
    // declared fence. The closeout mints the ref during terminal cleanup, so
    // it can lag the failed status by a beat — poll, never assume.
    let parked = format!("parked/{execution}");
    let deadline = Instant::now() + Duration::from_secs(60);
    let parked_rev = loop {
        if let Some(rev) = git_rev(&node.fixture.repo, &parked) {
            break rev;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the terminal closeout parked no candidate under {parked}"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert_eq!(
        git_show(&node.fixture.repo, &parked_rev, "src/app.txt").as_deref(),
        Some("implemented-change\n"),
        "{TEST}: the parked candidate carries the judged tree"
    );
}

/// **Cell C, cancel arm.** `kata run cancel` during a live capsule is
/// DELIVERED on `local_socket` — the acknowledgement answers
/// `assignments_asked_to_stop: 1`, the worker's fenced stop kills the
/// container, and the attempt settles `cancelled`: no commit, no promote, no
/// export, the remote and the forge untouched, and no container, cgroup or
/// attempt-root residue.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_cancel_mid_capsule_asks_the_assignment_to_stop_and_settles_cancelled_live() {
    let node = boot_checked("implemented-change", ImplementScript::Hold(HOLD_SECONDS));
    let execution = node.main.submit(Path::new(CHECKED_PACK));
    wait_until_claimed(&node, &execution, "implement", 1);

    // POSITIVE CONTROL — the container is live before the cancel, so the
    // delivered stop's teardown is a measured kill, not a no-op into an
    // empty window.
    let (live, roots) = wait_live_capsule(&node, &execution);
    eprintln!("POSITIVE CONTROL cancel: live containers {live:?}; attempt roots {roots:?}");

    let ack = node.main.cancel(&execution);
    assert_eq!(
        ack["assignments_asked_to_stop"].as_u64(),
        Some(1),
        "{TEST}: the cancel was asked of exactly the live capsule assignment: {ack}"
    );

    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("cancelled"),
        "the delivered stop settles the run cancelled: {doc}"
    );
    assert_eq!(
        implement_claims(&node, &execution),
        1,
        "{TEST}: exactly one implement attempt was ever claimed — a cancelled attempt is \
         not re-delivered"
    );
    assert_no_mutation(&node, &execution);
    assert_no_container_residue(&node, &execution);
    assert!(
        attempt_roots(&node).is_empty(),
        "{TEST}: the cancelled run leaves no attempt roots: {:?}",
        attempt_roots(&node)
    );
}

/// **Cell C, fence arm.** The repo's checked command writes OUTSIDE the
/// stage's declared `produces_files` scope — `beyond-fence.txt` at the
/// workspace root — and adoption refuses the WHOLE delta by name:
/// `work_delta_out_of_scope`, performed but failed, nothing of it applied.
/// Read raw and off git: the implement attempt settles `failed` naming the
/// refusal and the offending path, the run fails, trunk never moves, no
/// `kata/<exec>` branch, no forge call — and the parked candidate the
/// closeout mints carries the UNEDITED seed tree, the refused write absent.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn an_implement_write_outside_the_declared_fence_is_refused_and_nothing_lands_live() {
    let node = boot_checked("implemented-change", ImplementScript::BeyondFence);
    let execution = node.main.submit(Path::new(CHECKED_PACK));

    // The refusal, read RAW off the attempt's terminal transition — before
    // the run's own terminal, so a widened fence reds here on the observed
    // `completed`, not on a slow park.
    let (state, payload) = implement_terminal(&node, &execution);
    assert_eq!(
        state, "failed",
        "{TEST}: the out-of-fence delta must fail the attempt: {state} — {payload}"
    );
    assert!(
        payload.contains("work_delta_out_of_scope") && payload.contains("beyond-fence.txt"),
        "{TEST}: the refusal names the scope check and the offending path: {payload}"
    );

    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "the refused adoption fails the run: {doc}"
    );
    assert_no_mutation(&node, &execution);

    // NOTHING OF THE DELTA LANDS — the closeout parks the candidate for
    // inspection, and the parked ref (read from git) carries the seed tree:
    // `src/app.txt` still says `needs-change` and `beyond-fence.txt` never
    // existed. The mint can lag the failed status by a beat — poll.
    let parked = format!("parked/{execution}");
    let deadline = Instant::now() + Duration::from_secs(60);
    let parked_rev = loop {
        if let Some(rev) = git_rev(&node.fixture.repo, &parked) {
            break rev;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the terminal closeout parked no candidate under {parked}"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert_eq!(
        git_show(&node.fixture.repo, &parked_rev, "src/app.txt").as_deref(),
        Some("needs-change\n"),
        "{TEST}: the parked candidate carries the seed tree — the refused delta applied nothing"
    );
    assert_eq!(
        git_show(&node.fixture.repo, &parked_rev, "beyond-fence.txt"),
        None,
        "{TEST}: the refused write is absent from the parked candidate"
    );
}
