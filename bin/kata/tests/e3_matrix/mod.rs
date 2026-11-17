//! The E3 crash / restart matrix's rig, shared by its two test binaries:
//! `e3_crash_matrix_live` (the process column, which also states the cells, their
//! positive controls, the agent, the forge and the evidence record) and
//! `e3_crash_matrix_host_live` (the host column). Each binary uses part of it.

#![allow(dead_code)]

use crate::agent_change_rig::*;
use crate::mock_model::{MockModel, Turn, change_pack_turn};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The shipped pack every cell runs a progress-visible copy of.
pub(crate) const CHANGE_PACK: &str = "workflows/std/change.star";

/// The agent label the pack selects (`agent = "default"` on `plan` and `implement`).
pub(crate) const AGENT_LABEL: &str = "default";

/// The run's params: the task text both agent prompts render, and the test command.
pub(crate) const PARAMS: [(&str, &str); 2] = [
    (
        "task",
        "Make src/app.txt contain exactly the line implemented-change.",
    ),
    ("test_command", "sh tests/check.sh"),
];

/// SIGABRT and SIGKILL, by number, as `ExitStatus::signal` reports them.
pub(crate) const SIGABRT: i32 = libc::SIGABRT;
pub(crate) const SIGKILL: i32 = libc::SIGKILL;

/// How long a main or worker has to reach its kill point after the cell set it moving.
pub(crate) const CRASH_DEADLINE: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// The agent the node runs
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum E3Agent {
    /// kata's embedded nanocode harness on OpenAI (`nanocode_openai`) against a scripted
    /// mock provider on the loopback, through the worker's `test-support` endpoint door
    /// under a fake key: no model, no spend.
    Mock,
    /// kata's embedded nanocode harness on OpenAI (`nanocode_openai`, `kata_login`).
    NanocodeOpenai,
    /// kata's embedded nanocode harness on Anthropic (`nanocode_anthropic`,
    /// `env:ANTHROPIC_API_KEY`).
    NanocodeAnthropic,
}

impl E3Agent {
    /// `KATA_E3_AGENT` and `KATA_E3_FUNDED` as the process environment holds them —
    /// every cell's first call, so it also refuses a caller's environment that would arm
    /// the node's processes behind the cell's back ([`refuse_inherited_fault_env`]).
    pub(crate) fn selected() -> Self {
        refuse_inherited_fault_env(|name| std::env::var_os(name))
            .unwrap_or_else(|refusal| panic!("{TEST}: {refusal}"));
        let agent = std::env::var("KATA_E3_AGENT").ok();
        let funded = std::env::var("KATA_E3_FUNDED").ok();
        select_agent(agent.as_deref(), funded.as_deref())
            .unwrap_or_else(|refusal| panic!("{TEST}: {refusal}"))
    }

    /// The record's `harness` (`nanocode-mock` is no harness the evidence check
    /// admits, so a no-spend run can never be committed as evidence).
    pub(crate) fn harness(self) -> &'static str {
        match self {
            Self::Mock => "nanocode-mock",
            Self::NanocodeOpenai => "nanocode-openai",
            Self::NanocodeAnthropic => "nanocode-anthropic",
        }
    }

    /// The progress-frame preview kinds that open and close one model call.
    pub(crate) fn call_markers(self) -> CallMarkers {
        match self {
            // nanocode's event fold (`kata_agent_nanocode::adapter::events`): a tool call
            // or result follows only a COMPLETED call, so one after the last start means
            // the start's completion was coalesced away, not that the call is open.
            Self::Mock | Self::NanocodeOpenai | Self::NanocodeAnthropic => CallMarkers {
                started: "model_call_started",
                completed: "model_call_completed",
                failed: &["model_call_failed"],
                after_completion: &["tool_call", "tool_result"],
                in_call: &["agent_message_chunk"],
            },
        }
    }

    pub(crate) fn model_and_effort(self) -> (String, String) {
        let (model, effort) = match self {
            Self::Mock | Self::NanocodeOpenai => ("gpt-6-luna", "medium"),
            Self::NanocodeAnthropic => ("claude-sonnet-5-5", "medium"),
        };
        (
            std::env::var("KATA_E3_MODEL").unwrap_or_else(|_| model.to_owned()),
            std::env::var("KATA_E3_EFFORT").unwrap_or_else(|_| effort.to_owned()),
        )
    }

    pub(crate) fn credential_mode(self) -> &'static str {
        match self {
            Self::NanocodeOpenai => "subscription",
            Self::Mock | Self::NanocodeAnthropic => "api_key",
        }
    }

    pub(crate) fn capsule_network(self) -> &'static str {
        match self {
            Self::Mock | Self::NanocodeOpenai | Self::NanocodeAnthropic => "offline",
        }
    }
}

/// The agent `KATA_E3_AGENT` names (`nanocode-mock` when unset), refusing an unknown
/// name and a provider-backed agent without `KATA_E3_FUNDED=1`: it spends model budget.
pub(crate) fn select_agent(agent: Option<&str>, funded: Option<&str>) -> Result<E3Agent, String> {
    let selected = match agent.unwrap_or("nanocode-mock") {
        "nanocode-mock" => return Ok(E3Agent::Mock),
        "nanocode-openai" => E3Agent::NanocodeOpenai,
        "nanocode-anthropic" => E3Agent::NanocodeAnthropic,
        other => {
            return Err(format!(
                "KATA_E3_AGENT = {other:?} is none of nanocode-mock, nanocode-openai, \
                 nanocode-anthropic"
            ));
        }
    };
    if funded != Some("1") {
        return Err(format!(
            "KATA_E3_AGENT = {} spends model budget; the matrix refuses it unless \
             KATA_E3_FUNDED=1 is set",
            selected.harness()
        ));
    }
    Ok(selected)
}

/// The fault-injection variables a cell sets itself. The rig's main and worker inherit
/// the test process's environment, so one of these in the caller's shell would arm
/// EVERY main — the restarted "unarmed" ones included — or change what an armed point
/// does; the matrix refuses to start instead.
pub(crate) const FAULT_ENV: [&str; 2] = ["KATA_FAULT_INJECT", "KATA_FAULT_INJECT_ACTION"];

/// Refuses when `lookup` (the caller's environment) sets any of [`FAULT_ENV`].
pub(crate) fn refuse_inherited_fault_env(
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<(), String> {
    let inherited: Vec<String> = FAULT_ENV
        .iter()
        .filter_map(|name| {
            lookup(name).map(|value| format!("{name}=\"{}\"", value.to_string_lossy()))
        })
        .collect();
    if inherited.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the caller's environment sets {}: every main and worker the cell boots would \
         inherit it, so the matrix refuses to start; unset it",
        inherited.join(", ")
    ))
}

/// The preview kinds one model call opens and closes with.
#[derive(Clone, Copy)]
pub(crate) struct CallMarkers {
    pub(crate) started: &'static str,
    pub(crate) completed: &'static str,
    /// Kinds that end a call WITHOUT a completion: the call was issued and is not
    /// metered.
    pub(crate) failed: &'static [&'static str],
    /// Kinds that only ever follow a completed call: one seen while a call is open
    /// implies that call's completion, coalesced away.
    pub(crate) after_completion: &'static [&'static str],
    /// Kinds that only ever occur INSIDE an open call: one seen with no start counted
    /// since the last completion implies a start the emitter coalesced away.
    pub(crate) in_call: &'static [&'static str],
}

// ---------------------------------------------------------------------------
// Positive control 1: the boundary is registered
// ---------------------------------------------------------------------------

/// The `KATA_FAULT_INJECT` value for `boundary`, or the refusal: a name outside
/// `OPERATIONAL_CRASH_BOUNDARIES` never fires (`selected_operational_target` matches only
/// `operational.<registered name>`), so a cell armed with one would wait for a crash that
/// cannot come.
pub(crate) fn fault_inject_value(boundary: &str) -> Result<String, String> {
    let registered = kata_core::fault_inject::OPERATIONAL_CRASH_BOUNDARIES;
    if registered.iter().any(|row| row.name == boundary) {
        return Ok(format!("operational.{boundary}"));
    }
    Err(format!(
        "`{boundary}` is not a member of kata_core::fault_inject::OPERATIONAL_CRASH_BOUNDARIES \
         ({}); a point outside the registry never fires, so the cell refuses to start",
        registered
            .iter()
            .map(|row| row.name)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// The marker `operational_crash_point` prints at `boundary`, whatever the action.
pub(crate) fn crash_marker(boundary: &str) -> String {
    format!("[kata-fault-inject] crash point reached: operational.{boundary}")
}

/// The WHOLE line `operational_crash_point` prints at `boundary` armed with the default
/// `abort` action. Control 2 matches this line, not the bare marker: a main that
/// stopped there (`action=stop`) and was resumed also aborts, but it is not the
/// process-column cell.
pub(crate) fn abort_line(boundary: &str) -> String {
    format!(
        "{} (KATA_FAULT_INJECT=operational.{boundary}, action=abort); aborting process now",
        crash_marker(boundary)
    )
}

/// One attempt's model calls, read off its progress frames as a sequence of calls,
/// each opened (by its start, or by an in-call frame that implies one) and closed (by
/// its completion, by a frame that only follows a completion, by a failure, or by the
/// attempt's terminal ledger frame).
///
/// `completed` counts the calls closed by a completion, seen or implied; `unclosed`
/// the calls a later START closed, whose completion-or-failure the emitter coalesced
/// away. Both are recorded, not spend: a call's usage reaches a durable row only in its
/// ATTEMPT's terminal frame, so on a killed attempt a completed call is as unmetered as
/// the open one. [`CallCount::unmetered`] is therefore every call the transcript shows
/// issued. A call whose every frame was coalesced away is in no count — it is invisible,
/// so the count is a lower bound on what the attempt issued.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CallCount {
    pub(crate) started: u64,
    pub(crate) completed: u64,
    pub(crate) unclosed: u64,
    /// A call is open at the end of the transcript: started, not closed.
    pub(crate) open: bool,
}

impl CallCount {
    /// Calls issued whose usage is unknown (D2 §5.4 spend (b); README E3: "the number of
    /// issued calls whose usage is unknown") of attempts that never published a terminal
    /// frame, which every judge records: every call such an attempt issued, completed ones
    /// included, since their usage rode the terminal frame that never came.
    pub(crate) fn unmetered(&self) -> u64 {
        self.started
    }

    pub(crate) fn open_one(&mut self) {
        if !self.open {
            self.started += 1;
            self.open = true;
        }
    }
}

/// The model calls `assignment` made, per the transcript.
pub(crate) fn calls_of(events: &[SseEvent], assignment: &str, markers: CallMarkers) -> CallCount {
    let mut count = CallCount::default();
    let is_any = |preview: &str, kinds: &[&str]| kinds.iter().any(|kind| preview.starts_with(kind));
    for event in events
        .iter()
        .filter(|event| event.assignment() == Some(assignment))
    {
        if event.is_terminal_ledger() {
            count.open = false;
            continue;
        }
        if event.name != "progress" {
            continue;
        }
        let preview = event.preview();
        if preview.starts_with(markers.started) {
            // A start while a call is open: the open one's completion or failure was
            // coalesced away, and the transcript cannot say which.
            if count.open {
                count.unclosed += 1;
                count.open = false;
            }
            count.open_one();
        } else if preview.starts_with(markers.completed) {
            // A completion with no call open implies its start.
            count.open_one();
            count.completed += 1;
            count.open = false;
        } else if is_any(preview, markers.failed) {
            count.open_one();
            count.open = false;
        } else if is_any(preview, markers.after_completion) {
            if count.open {
                count.completed += 1;
                count.open = false;
            }
        } else if is_any(preview, markers.in_call) {
            count.open_one();
        }
    }
    count
}

impl std::iter::Sum for CallCount {
    /// Several attempts' counts as one: each count summed, open when any one is.
    fn sum<I: Iterator<Item = Self>>(counts: I) -> Self {
        counts.fold(Self::default(), |sum, count| Self {
            started: sum.started + count.started,
            completed: sum.completed + count.completed,
            unclosed: sum.unclosed + count.unclosed,
            open: sum.open || count.open,
        })
    }
}

/// The model calls of every agent attempt (`plan`, `implement`) the transcript shows that
/// never COMPLETED (no `completed` terminal ledger frame: failed, cancelled, or never
/// settled), summed: the attempts whose usage reached no durable row. A completed attempt's
/// usage rode its terminal frame, so none of its calls is in this count.
pub(crate) fn uncompleted_calls(events: &[SseEvent], markers: CallMarkers) -> CallCount {
    let completed = |assignment: &str| {
        events.iter().any(|event| {
            event.assignment() == Some(assignment)
                && event.is_terminal_ledger()
                && event.data["new_status"]["kind"] == "completed"
        })
    };
    ["plan", "implement"]
        .iter()
        .flat_map(|stage| assignments_of(events, stage))
        .filter(|assignment| !completed(assignment))
        .map(|assignment| calls_of(events, &assignment, markers))
        .sum()
}

/// The oracle of a case whose design kills no model call (P1's never-sent attempt, the
/// gate, P4): the observed count of `calls` [`CallCount::unmetered`] is 0. Any other
/// count is refused, naming it and `why` the design requires 0.
pub(crate) fn none_unmetered(calls: &CallCount, why: &str) -> Result<(), String> {
    let unmetered = calls.unmetered();
    require(
        unmetered == 0,
        format!(
            "{unmetered} issued model call(s) of unknown usage (started {}, completed {}, \
             unclosed {}, open {}), where {why}",
            calls.started, calls.completed, calls.unclosed, calls.open
        ),
    )
}

/// The oracle line beside [`none_unmetered`]: the observed count, recorded either way.
pub(crate) fn note_none_unmetered(cell: &mut Cell, calls: &CallCount) {
    cell.oracle.note(format!(
        "spend: issued calls of the agent attempts that never completed {} (unmetered_calls; \
         started {}, completed {}, unclosed {}, open {}); the case kills no model call, so 0",
        calls.unmetered(),
        calls.started,
        calls.completed,
        calls.unclosed,
        calls.open
    ));
}

/// Every assignment of `stage` the transcript saw, in first-seen order.
pub(crate) fn assignments_of(events: &[SseEvent], stage: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for event in events {
        if event.stage().starts_with(stage)
            && let Some(id) = event.assignment()
            && !seen.iter().any(|known| known == id)
        {
            seen.push(id.to_owned());
        }
    }
    seen
}

// ---------------------------------------------------------------------------
// Evidence records
// ---------------------------------------------------------------------------

/// The settlement D2 §5.4 expects per case — the table `scripts/evidence-page.py`'s
/// `EXPECTED_SETTLEMENT` holds too (`the_expected_settlements_are_the_evidence_checks`).
pub(crate) const EXPECTED_SETTLEMENT: &[(&str, &str)] = &[
    ("gate-main-kill", "resumed-at-gate"),
    ("gate-worker-kill", "resumed-at-gate"),
    ("P1", "proven-ambiguous"),
    ("P2", "proven-ambiguous"),
    ("P3", "proven-ambiguous"),
    ("P4", "pr-opened-once"),
    ("P1-host", "proven-ambiguous"),
    ("P2-host", "proven-ambiguous"),
    ("P3-host", "proven-ambiguous"),
    ("P4-host", "pr-opened-once"),
];

pub(crate) fn expected_settlement(case: &str) -> &'static str {
    EXPECTED_SETTLEMENT
        .iter()
        .find(|(known, _)| *known == case)
        .map_or_else(
            || panic!("{TEST}: no expected settlement for case {case}"),
            |(_, settlement)| *settlement,
        )
}

/// What a cell observed, before its outcome is judged.
#[derive(Debug)]
pub(crate) struct Observed {
    pub(crate) settlement: String,
    pub(crate) detail: Option<String>,
    pub(crate) tokens: Tokens,
    pub(crate) unmetered_calls: u64,
}

#[derive(Debug)]
pub(crate) enum Tokens {
    Unknown,
    Counts([u64; 4]),
}

/// How a cell ended: void (a positive control did not hold), or judged.
pub(crate) enum Ended {
    Void(String),
    Judged {
        observed: Observed,
        /// The first oracle that did not hold, if any.
        violation: Option<String>,
    },
}

/// The oracle lines one cell collects, written to `oracle.txt`.
#[derive(Default)]
pub(crate) struct Oracle {
    pub(crate) lines: Vec<String>,
}

impl Oracle {
    pub(crate) fn note(&mut self, line: impl Into<String>) {
        let line = line.into();
        eprintln!("E3 oracle: {line}");
        self.lines.push(line);
    }
}

/// One cell's run: its case, agent, clock, oracle and transcript.
pub(crate) struct Cell {
    pub(crate) case: &'static str,
    pub(crate) agent: E3Agent,
    pub(crate) started: SystemTime,
    pub(crate) clock: Instant,
    pub(crate) oracle: Oracle,
    pub(crate) transcript: Option<PathBuf>,
    /// Further files the record carries: (source, name in the record, what it holds).
    pub(crate) artifacts: Vec<(PathBuf, &'static str, &'static str)>,
}

impl Cell {
    pub(crate) fn new(case: &'static str, agent: E3Agent) -> Self {
        Self {
            case,
            agent,
            started: SystemTime::now(),
            clock: Instant::now(),
            oracle: Oracle::default(),
            transcript: None,
            artifacts: Vec::new(),
        }
    }

    /// Record this node's transcript and the pack copy it submits.
    pub(crate) fn attach(&mut self, e3: &E3Node) {
        self.transcript = Some(e3.sse.path.clone());
        self.artifacts.push((
            e3.pack.clone(),
            "change.star",
            "the pack this run submitted: workflows/std/change.star at kata_sha with \
             progress_visibility = \"summary\" added to plan and implement, nothing else",
        ));
    }

    /// Judge `ended`, write the record under [`evidence_dir`], and return the outcome
    /// word and the record's directory.
    pub(crate) fn record(&self, ended: &Ended) -> (&'static str, String, PathBuf) {
        self.record_in(&evidence_dir(), ended)
    }

    /// [`Cell::record`] under `root`.
    pub(crate) fn record_in(&self, root: &Path, ended: &Ended) -> (&'static str, String, PathBuf) {
        let expected = expected_settlement(self.case);
        let (outcome, reason, settlement, detail, tokens, unmetered) = match ended {
            Ended::Void(reason) => (
                "void",
                format!("VOID: {reason}"),
                "other".to_owned(),
                Some(format!("void, not judged: {reason}")),
                &Tokens::Unknown,
                0,
            ),
            Ended::Judged {
                observed,
                violation,
            } => {
                let (outcome, reason) = match violation {
                    Some(violation) => ("fail", format!("an oracle did not hold: {violation}")),
                    None if observed.settlement != expected => (
                        "fail",
                        format!(
                            "observed settlement {} is not the expected {expected}",
                            observed.settlement
                        ),
                    ),
                    None => ("pass", format!("settled {expected}, every oracle held")),
                };
                (
                    outcome,
                    reason,
                    observed.settlement.clone(),
                    observed.detail.clone(),
                    &observed.tokens,
                    observed.unmetered_calls,
                )
            }
        };
        let compact = chrono::DateTime::<chrono::Utc>::from(self.started);
        let run_id = format!(
            "e3-{}-{}-{}",
            self.case,
            self.agent.harness(),
            compact.format("%Y%m%dT%H%M%SZ")
        );
        let dir = root.join(&run_id);
        std::fs::create_dir_all(&dir).expect("the record directory");
        let mut oracle = self.oracle.lines.join("\n");
        {
            use std::fmt::Write as _;
            let _ = write!(oracle, "\noutcome: {outcome}: {reason}\n");
        }
        std::fs::write(dir.join("oracle.txt"), oracle).unwrap();
        let mut artifacts = vec![toml_artifact(
            "oracle.txt",
            "every outside-kata read this cell's outcome rests on, in order",
        )];
        if let Some(transcript) = &self.transcript {
            std::fs::copy(transcript, dir.join("sse-transcript.txt")).unwrap();
            artifacts.push(toml_artifact(
                "sse-transcript.txt",
                "the client-side GET /api/v1/events transcript, one received-ms-stamped line \
                 per SSE line",
            ));
        }
        for (source, name, what) in &self.artifacts {
            std::fs::copy(source, dir.join(name)).unwrap();
            artifacts.push(toml_artifact(name, what));
        }
        let (sha, tree) = kata_tree();
        std::fs::write(dir.join("tree.txt"), &tree.text).unwrap();
        artifacts.push(toml_artifact(
            "tree.txt",
            "git rev-parse HEAD, HEAD^{tree} and git status --porcelain of the tree the \
             binaries were built from: kata_sha names exactly what ran only when the status \
             is empty",
        ));
        let (model, effort) = self.agent.model_and_effort();
        let mut record = toml::Table::new();
        let mut put = |key: &str, value: toml::Value| {
            record.insert(key.to_owned(), value);
        };
        put("cell", "E3".into());
        put("case", self.case.into());
        put("harness", self.agent.harness().into());
        put("surface", "cli".into());
        put("kata_sha", sha.into());
        put("kata_tree", tree.tree.clone().into());
        put("nanocode_rev", nanocode_rev().into());
        put("model", model.into());
        put("effort", effort.into());
        put("credential_mode", self.agent.credential_mode().into());
        put("capsule_network", self.agent.capsule_network().into());
        put(
            "started_utc",
            compact.format("%Y-%m-%dT%H:%M:%SZ").to_string().into(),
        );
        put(
            "wall_seconds",
            i64::try_from(self.clock.elapsed().as_secs())
                .unwrap_or(i64::MAX)
                .into(),
        );
        put("outcome", outcome.into());
        let dirty = if tree.dirty {
            "; the tree was DIRTY at the run, so kata_sha is its base, not what ran (tree.txt)"
        } else {
            ""
        };
        put(
            "outcome_source",
            format!("oracle.txt: {reason} (expected {expected}){dirty}").into(),
        );
        if outcome == "void" {
            // The control that did not hold, read from the record's own oracle.txt, whose
            // last line states it.
            put("void_reason", format!("oracle.txt: {reason}").into());
        }
        put("settlement", settlement.into());
        if let Some(detail) = detail {
            put("settlement_detail", detail.into());
        }
        put(
            "tokens_recorded",
            match tokens {
                Tokens::Unknown => "unknown".into(),
                Tokens::Counts([input, cache_read, cache_write, output]) => {
                    let mut counts = toml::Table::new();
                    for (key, value) in [
                        ("input", input),
                        ("cache_read", cache_read),
                        ("cache_write", cache_write),
                        ("output", output),
                    ] {
                        counts.insert(
                            key.to_owned(),
                            i64::try_from(*value).unwrap_or(i64::MAX).into(),
                        );
                    }
                    toml::Value::Table(counts)
                }
            },
        );
        put(
            "tokens_provider",
            "unavailable: read from the provider by the operator after the run".into(),
        );
        put(
            "unmetered_calls",
            i64::try_from(unmetered).unwrap_or(i64::MAX).into(),
        );
        put("cost_recorded", "unavailable".into());
        put(
            "cost_provider",
            "unavailable: read from the provider by the operator after the run".into(),
        );
        put("artifacts", toml::Value::Array(artifacts));
        std::fs::write(
            dir.join("run.toml"),
            toml::to_string(&record).expect("the record serializes"),
        )
        .unwrap();
        eprintln!(
            "E3 RECORD {}: outcome = {outcome}: {reason}",
            dir.join("run.toml").display()
        );
        (outcome, reason, dir)
    }

    /// Record `ended` and fail the test unless it passed.
    pub(crate) fn finish(&self, ended: &Ended) {
        let (outcome, reason, dir) = self.record(ended);
        assert_eq!(
            outcome,
            "pass",
            "{TEST}: E3 {} on {}: {reason} (record {})",
            self.case,
            self.agent.harness(),
            dir.display()
        );
    }
}

pub(crate) fn toml_artifact(path: &str, what: &str) -> toml::Value {
    let mut artifact = toml::Table::new();
    artifact.insert("path".to_owned(), path.into());
    artifact.insert("what".to_owned(), what.into());
    toml::Value::Table(artifact)
}

pub(crate) fn evidence_dir() -> PathBuf {
    std::env::var_os("KATA_E3_EVIDENCE_DIR")
        .map_or_else(|| repo_root().join("target/e3-evidence"), PathBuf::from)
}

/// The tree the binaries were built from, as git states it.
pub(crate) struct TreeState {
    /// `git rev-parse HEAD^{tree}`: the record's `kata_tree`.
    pub(crate) tree: String,
    pub(crate) dirty: bool,
    pub(crate) text: String,
}

/// The commit under test, its tree and whether the work tree matched it, from git.
pub(crate) fn kata_tree() -> (String, TreeState) {
    kata_tree_in(&repo_root())
}

/// [`kata_tree`] of the checkout at `root`.
pub(crate) fn kata_tree_in(root: &Path) -> (String, TreeState) {
    let git = |args: &[&str]| {
        let out = kata_test_utils::git::hermetic_git_in(root)
            .args(args)
            .output()
            .expect("git runs");
        String::from_utf8_lossy(&out.stdout).trim_end().to_owned()
    };
    let sha = git(&["rev-parse", "HEAD"]);
    let tree = git(&["rev-parse", "HEAD^{tree}"]);
    let status = tree_status(root);
    let text = format!(
        "$ git rev-parse HEAD\n{sha}\n$ git rev-parse HEAD^{{tree}}\n{tree}\n$ git status \
         --porcelain\n{status}\n"
    );
    (
        sha,
        TreeState {
            tree,
            dirty: !status.is_empty(),
            text,
        },
    )
}

/// The nanocode revision the tree pins: `NANOCODE_REV`, read from its source file.
pub(crate) fn nanocode_rev() -> String {
    let source =
        std::fs::read_to_string(repo_root().join("crates/agent-nanocode/src/lib.rs")).unwrap();
    source
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("pub const NANOCODE_REV: &str = \"")
        })
        .and_then(|rest| rest.strip_suffix("\";"))
        .expect("crates/agent-nanocode/src/lib.rs defines NANOCODE_REV")
        .to_owned()
}

// ---------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------

/// The shipped change pack with `progress_visibility = "summary"` on its two agent
/// stages, written beside the node; refuses if either splice no longer applies.
pub(crate) fn progress_visible_pack(root: &Path) -> PathBuf {
    let shipped = std::fs::read_to_string(repo_root().join(CHANGE_PACK)).unwrap();
    let mut pack = shipped.clone();
    for stage in ["plan", "implement"] {
        let anchor = format!("    id = \"{stage}\",\n");
        assert_eq!(
            pack.matches(&anchor).count(),
            1,
            "{TEST}: the change pack no longer declares `{anchor}` exactly once"
        );
        pack = pack.replacen(
            &anchor,
            // The pack's own four-space stage-argument indent.
            // kata-spacing: intentional
            &format!("{anchor}    progress_visibility = \"summary\",\n"),
            1,
        );
    }
    assert_ne!(pack, shipped);
    let path = root.join("change.star");
    std::fs::write(&path, pack).unwrap();
    path
}

/// The `[node] environment` a nanocode node binds: busybox and `git`, no vendor.
pub(crate) fn nanocode_environment_decl() -> String {
    format!(
        "environment = {{ label = \"e3-nanocode\", system = \"x86_64-linux\", \
         nixpkgs_attribute = \"nixpkgs#pkgsStatic.busybox\", store_paths = [\"{BUSYBOX}\", \
         \"{GIT_MINIMAL}\"], path_prepend = [\"{BUSYBOX}/bin\", \"{GIT_MINIMAL}/bin\"], \
         integrity_policy = {{ verify = \"nar_hash_only\", sigs_needed = 0, \
         required_signers = [], allow_unsigned_content_addressed = true, \
         verify_contents_at_declare = true }} }}\n"
    )
}

/// `[agents.default]` for a nanocode agent: kata's own login (OpenAI), the
/// environment's key (Anthropic) or the fake key the mock's worker carries. Every kind
/// is a harness block, the variant that carries `adapter` and `credential`.
pub(crate) fn nanocode_agent_decl(agent: E3Agent) -> String {
    let (model, effort) = agent.model_and_effort();
    let (adapter, credential) = match agent {
        E3Agent::Mock => (
            "nanocode_openai",
            "{ mode = \"api_key\", source = \"env:OPENAI_API_KEY\" }",
        ),
        E3Agent::NanocodeOpenai => (
            "nanocode_openai",
            "{ mode = \"subscription\", source = \"kata_login\" }",
        ),
        E3Agent::NanocodeAnthropic => (
            "nanocode_anthropic",
            "{ mode = \"api_key\", source = \"env:ANTHROPIC_API_KEY\" }",
        ),
    };
    format!(
        "[agents.{AGENT_LABEL}]\nadapter = \"{adapter}\"\nmodel = \
         \"{model}\"\nreasoning_effort = \"{effort}\"\ncredential = {credential}\n"
    )
}

pub(crate) fn toolhost_path() -> PathBuf {
    std::env::var_os("KATA_E3_TOOLHOST").map_or_else(
        || {
            PathBuf::from(env!("CARGO_BIN_EXE_kata"))
                .parent()
                .and_then(Path::parent)
                .expect("the kata binary lives at <target>/<profile>/kata")
                .join("x86_64-unknown-linux-musl/debug/kata-toolhost")
        },
        PathBuf::from,
    )
}

/// What one cell runs on: the node, its pack copy, its transcript and, on the mock
/// agent, its model.
pub(crate) struct E3Node {
    // `sse` first: it drops (stops its thread) before the node's processes.
    pub(crate) sse: SseRecorder,
    pub(crate) pack: PathBuf,
    pub(crate) node: Node,
    /// LAST, so it outlives every process the node started.
    pub(crate) model: Option<MockModel>,
}

/// What the mock agent's `implement` turn does: write the fix and answer, or hold its
/// first model request open (P2's in-flight call).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MockImplement {
    Fix,
    Hold,
}

/// The mock agent's model for the `change` pack: `plan` answers its `Plan`, and
/// `implement` writes the fix at once or holds.
pub(crate) fn mock_change_model(implement: MockImplement) -> MockModel {
    let fix = Turn::running("printf 'implemented-change\\n' > src/app.txt", "done");
    MockModel::answering(move |request| {
        change_pack_turn(request, || match implement {
            MockImplement::Fix => fix.clone(),
            MockImplement::Hold => Turn::held(),
        })
    })
}

/// What a node needs re-rendered when it is re-opened on the same root.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct NodeShape {
    pub(crate) root: PathBuf,
    pub(crate) environment: String,
    pub(crate) agents: String,
}

/// Render the node's environment and agent block for `agent` under `root`.
pub(crate) fn node_shape(root: &Path, agent: E3Agent) -> NodeShape {
    NodeShape {
        root: root.to_path_buf(),
        environment: nanocode_environment_decl(),
        agents: nanocode_agent_decl(agent),
    }
}

pub(crate) fn provider_for(root: &Path) -> Vec<(String, String)> {
    provision_provider_with_toolhost(root, &toolhost_path())
}

/// The rig's fixture at `<root>/repo` + `<root>/remote.git`, on `main`.
pub(crate) fn fixture_at(root: &Path) -> Fixture {
    Fixture {
        repo: root.join("repo"),
        remote: root.join("remote.git"),
        trunk: "main".to_owned(),
        origin: Origin::LocalBare,
    }
}

/// Boot a fresh node for `agent` on the rig's local fixture; `armed_env` arms the FIRST
/// main or the FIRST worker only, so a restarted one is unarmed.
pub(crate) fn boot_e3(
    root: NodeRoot,
    agent: E3Agent,
    armed_env: (Armed, &[(String, String)]),
) -> E3Node {
    let fixture = fixture_repo(root.path());
    boot_e3_on(root, fixture, agent, armed_env)
}

/// [`boot_e3`] on `fixture`.
pub(crate) fn boot_e3_on(
    root: NodeRoot,
    fixture: Fixture,
    agent: E3Agent,
    armed_env: (Armed, &[(String, String)]),
) -> E3Node {
    boot_e3_with(root, fixture, agent, armed_env, MockImplement::Fix)
}

/// [`boot_e3`] whose mock agent holds `implement`'s first model request open: P2's
/// in-flight call. A provider-backed agent's call is open while its model thinks.
pub(crate) fn boot_e3_holding_implement(
    root: NodeRoot,
    agent: E3Agent,
    armed_env: (Armed, &[(String, String)]),
) -> E3Node {
    let fixture = fixture_repo(root.path());
    boot_e3_with(root, fixture, agent, armed_env, MockImplement::Hold)
}

fn boot_e3_with(
    root: NodeRoot,
    fixture: Fixture,
    agent: E3Agent,
    armed_env: (Armed, &[(String, String)]),
    implement: MockImplement,
) -> E3Node {
    let shape = node_shape(root.path(), agent);
    let pack = progress_visible_pack(root.path());
    let mut provider = provider_for(root.path());
    let model = (agent == E3Agent::Mock).then(|| mock_change_model(implement));
    if let Some(model) = &model {
        let harness = crate::agent_change_rig::nanocode::Harness::OpenaiMock;
        provider.extend(harness.worker_env(Some(&model.url(harness))));
    }
    let transcript = root.path().join("sse-transcript.txt");
    let (armed, env) = armed_env;
    let (first_main_env, first_worker_env) = match armed {
        Armed::Main => (env, &[][..]),
        Armed::Worker => (&[][..], env),
    };
    let node = boot_node_main(
        root,
        fixture,
        shape.environment,
        shape.agents,
        &[AGENT_LABEL],
        "e3-crash-matrix",
        provider,
        first_main_env,
    )
    .start_worker_with(first_worker_env);
    if model.is_some() {
        crate::agent_change_rig::nanocode::assert_door_open(
            crate::agent_change_rig::nanocode::Harness::OpenaiMock,
            "worker daemon",
            &node.worker.log,
        );
    }
    let sse = SseRecorder::start(node.main.port(), transcript);
    E3Node {
        sse,
        pack,
        node,
        model,
    }
}

pub(crate) fn submit(e3: &E3Node) -> String {
    // The recorder's first connection must precede the submit: progress frames are
    // not replayed to a late subscriber.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !std::fs::read_to_string(&e3.sse.path)
        .unwrap_or_default()
        .contains("#connected")
    {
        assert!(
            Instant::now() < deadline,
            "{TEST}: the SSE recorder never connected"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    e3.node.main.submit_with_params(&e3.pack, &PARAMS)
}

pub(crate) fn execution_blob(execution: &str) -> Vec<u8> {
    ulid::Ulid::from_string(execution)
        .unwrap()
        .to_bytes()
        .to_vec()
}

/// The process a cell arms: the main, or (P3) the external worker daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Armed {
    Main,
    Worker,
}

impl Armed {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Worker => "worker",
        }
    }

    pub(crate) fn child(self, node: &mut Node) -> &mut std::process::Child {
        match self {
            Self::Main => &mut node.main.child,
            Self::Worker => &mut node.worker.child,
        }
    }

    pub(crate) fn pid(self, node: &Node) -> u32 {
        match self {
            Self::Main => node.main.child.id(),
            Self::Worker => node.worker.pid,
        }
    }

    /// The armed process's log. The main's stdout and stderr share the rig's
    /// `serve.log`; the worker's share its own `kata-worker.log`.
    pub(crate) fn log(self, node: &Node) -> PathBuf {
        match self {
            Self::Main => node.main.log.clone(),
            Self::Worker => node.worker.log.clone(),
        }
    }
}

/// Wait for the armed process to die on its own; `Err` when it is still alive at the
/// deadline or the run is already past the point (`passed` names how), so the point never
/// fired.
pub(crate) fn wait_for_death(
    node: &mut Node,
    armed: Armed,
    deadline: Duration,
    passed: &impl Fn(&Node) -> Option<String>,
) -> Result<std::process::ExitStatus, String> {
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if let Ok(Some(status)) = armed.child(node).try_wait() {
            return Ok(status);
        }
        if let Some(past) = passed(node) {
            // A process that reached the point may still be inside its abort: give it a
            // grace before calling the point missed.
            let grace = Instant::now() + Duration::from_secs(5);
            while Instant::now() < grace {
                if let Ok(Some(status)) = armed.child(node).try_wait() {
                    return Ok(status);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            return Err(format!(
                "the {} is alive and the run is past the point: {past}",
                armed.name()
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "the {} was alive {}s after the cell armed it",
        armed.name(),
        deadline.as_secs()
    ))
}

/// Positive controls 2 and 3 on an armed process that died (or did not) at `boundary`.
/// The marker is printed to stderr, which shares the process's log with its stdout, and
/// nothing else prints [`abort_line`].
pub(crate) fn crash_controls(
    cell: &mut Cell,
    node: &mut Node,
    armed: Armed,
    boundary: &str,
    passed: impl Fn(&Node) -> Option<String>,
) -> Result<(), String> {
    let deadline = CRASH_DEADLINE;
    let status = wait_for_death(node, armed, deadline, &passed);
    let log = std::fs::read_to_string(armed.log(node)).unwrap_or_default();
    // The next main truncates `serve.log`: keep the killed main's. A restarted worker
    // logs into its own new directory, so the killed worker's log stays where it is.
    if armed == Armed::Main {
        let _ = std::fs::write(node.root_path.join("serve-killed.log"), &log);
    }
    let line = abort_line(boundary);
    cell.oracle.note(format!(
        "control 2 (the abort line in the killed {}'s log): {}",
        armed.name(),
        log.lines()
            .find(|seen| seen.contains(&line))
            .unwrap_or("ABSENT")
    ));
    cell.oracle.note(format!(
        "control 3 (wait status): {}",
        status.as_ref().map_or_else(Clone::clone, |status| format!(
            "{status:?}, signal {:?}",
            status.signal()
        ))
    ));
    judge_crash(armed, &log, status, boundary)
}

/// Controls 2 and 3, judged: the armed process died, its log carries [`abort_line`], and
/// its wait status is death by SIGABRT. `Err` is the VOID reason.
pub(crate) fn judge_crash(
    armed: Armed,
    log: &str,
    status: Result<std::process::ExitStatus, String>,
    boundary: &str,
) -> Result<(), String> {
    let who = armed.name();
    let status =
        status.map_err(|why| format!("the {who} never died at operational.{boundary}: {why}"))?;
    let line = abort_line(boundary);
    if !log.lines().any(|seen| seen.contains(&line)) {
        return Err(format!(
            "the killed {who}'s log does not carry `{line}`: it died, but not aborting at the \
             point"
        ));
    }
    if status.signal() != Some(SIGABRT) {
        return Err(format!(
            "the {who}'s wait status is {status:?}, not death by SIGABRT"
        ));
    }
    Ok(())
}

/// The armed main's environment for `boundary`, or the control-1 refusal.
pub(crate) fn armed(boundary: &str, action: Option<&str>) -> Result<Vec<(String, String)>, String> {
    let mut env = vec![(
        "KATA_FAULT_INJECT".to_owned(),
        fault_inject_value(boundary)?,
    )];
    if let Some(action) = action {
        env.push(("KATA_FAULT_INJECT_ACTION".to_owned(), action.to_owned()));
    }
    Ok(env)
}

/// After a main kill: the next main, then a fresh worker daemon (restart = main AND
/// worker), the recorder following the main. `Err` names why the node did not come
/// back (the rig's boot assertion, e.g. a main that refuses to become healthy).
pub(crate) fn restart_node(e3: &mut E3Node) -> Result<(), String> {
    let restarted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e3.node.restart_main();
        e3.sse.follow(e3.node.main.port());
        e3.node.restart_worker();
    }));
    restarted.map_err(|panic| panic_text(&*panic))
}

/// The last line a main's serve log starts with `Error:`: the refusal it exited on.
pub(crate) fn main_exit_line(serve_log: &str) -> Option<&str> {
    serve_log
        .lines()
        .rev()
        .find(|line| line.starts_with("Error:"))
}

/// The settlement of a node that did not come back after the kill. `main_exit`, the
/// restarted main's own last `Error:` line when it exited, leads the detail: the cause,
/// ahead of the symptom the rig saw (`why`, e.g. a worker that never registered). `calls`
/// is the transcript's count of the attempts that never completed ([`uncompleted_calls`]),
/// recorded as its [`CallCount::unmetered`].
pub(crate) fn not_restarted(
    cell: &mut Cell,
    why: String,
    main_exit: Option<&str>,
    calls: &CallCount,
) -> Ended {
    cell.oracle
        .note(format!("the node did not come back after the kill: {why}"));
    let unmetered = calls.unmetered();
    cell.oracle.note(format!(
        "spend: issued calls of the attempts that never completed {unmetered} (unmetered_calls; \
         started {}, completed {}, unclosed {}, open {})",
        calls.started, calls.completed, calls.unclosed, calls.open
    ));
    let symptom = first_line(&why);
    let cause = match main_exit {
        Some(exit) => format!("the restarted main exited (`{exit}`); then {symptom}"),
        None => symptom,
    };
    Ended::Judged {
        observed: Observed {
            settlement: "other".to_owned(),
            detail: Some(format!("the restarted node did not come up: {cause}")),
            tokens: Tokens::Unknown,
            unmetered_calls: unmetered,
        },
        violation: Some(format!("the node did not restart: {cause}")),
    }
}

/// A rig panic's last `Caused by` line when it has one (the main's own refusal), else
/// its first line.
pub(crate) fn first_line(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    lines
        .iter()
        .rev()
        .find(|line| line.starts_with("1: ") || line.starts_with("0: "))
        .or_else(|| lines.first())
        .map_or_else(String::new, |line| (*line).to_owned())
}

pub(crate) fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_else(|| "a rig assertion panicked".to_owned())
}

// ---------------------------------------------------------------------------
// Outside-kata reads
// ---------------------------------------------------------------------------

/// The raw failed transition of `stage`, if any — the settled reason. A read that fails
/// panics: it is never folded into "no failed transition".
pub(crate) fn failed_reason(node: &Node, execution: &str, stage: &str) -> Option<String> {
    raw_failed_transition(&node.root_path.join("data"), execution, stage).unwrap_or_else(|error| {
        panic!("{TEST}: the raw read of `{stage}`'s failed transition failed: {error}")
    })
}

/// The raw failed transition of `stage` through a second read-only handle on `data_dir`'s
/// `operational.db`: `Ok(None)` exactly when the query returns no row; an open failure or any
/// other SQLite error (busy, a missing table, a malformed file) is `Err`.
pub(crate) fn raw_failed_transition(
    data_dir: &Path,
    execution: &str,
    stage: &str,
) -> Result<Option<String>, String> {
    let db = rusqlite::Connection::open_with_flags(
        data_dir.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("operational.db does not open read-only: {error}"))?;
    match db.query_row(
        "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
         AND stage_id = ?2 AND resulting_state = 'failed' ORDER BY seq LIMIT 1",
        rusqlite::params![execution_blob(execution), stage],
        |row| row.get(0),
    ) {
        Ok(reason) => Ok(Some(reason)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

pub(crate) fn claimed_count(node: &Node, execution: &str, stage: &str) -> i64 {
    raw_db(&node.root_path.join("data"))
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND stage_id = ?2 \
             AND kind = 'claimed'",
            rusqlite::params![execution_blob(execution), stage],
            |row| row.get(0),
        )
        .unwrap()
}

/// `event_inbox` rows of the execution: (buffered, accepted).
pub(crate) fn inbox_counts(data_dir: &Path, execution: &str) -> (i64, i64) {
    raw_db(data_dir)
        .query_row(
            "SELECT (SELECT count(*) FROM event_inbox WHERE execution_id = ?1 AND accepted = 0), \
             (SELECT count(*) FROM event_inbox WHERE execution_id = ?1 AND accepted = 1)",
            [execution_blob(execution)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

/// The execution's `/work` heads: (branch, work tree artifact, head_seq).
pub(crate) fn work_heads(node: &Node, execution: &str) -> Vec<(String, String, i64)> {
    let conn = raw_db(&node.root_path.join("data"));
    let mut statement = conn
        .prepare(
            "SELECT branch, hex(work_tree_artifact_id), head_seq FROM execution_work_tree_heads \
             WHERE execution_id = ?1 ORDER BY branch",
        )
        .unwrap();
    statement
        .query_map([execution_blob(execution)], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The recorded usage of every COMPLETED agent attempt, summed off the raw accepting
/// transitions (`output.token_usage`), as `[input, cache_read, cache_write, output]`.
pub(crate) fn completed_agent_usage(node: &Node, execution: &str) -> [u64; 4] {
    let conn = raw_db(&node.root_path.join("data"));
    let payloads: Vec<String> = conn
        .prepare(
            "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
             AND stage_id IN ('plan', 'implement') AND resulting_state = 'completed' \
             AND kind = 'event_accepted'",
        )
        .unwrap()
        .query_map([execution_blob(execution)], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut sum = [0u64; 4];
    for payload in payloads {
        let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let usage = &payload["output"]["token_usage"];
        for (slot, key) in ["input", "cache_read", "cache_write", "output"]
            .iter()
            .enumerate()
        {
            sum[slot] += usage[key].as_u64().unwrap_or(0);
        }
    }
    sum
}

/// A settled cell's `tokens_recorded`: kata's KNOWN part, the completed agent attempts'
/// recorded usage ([`completed_agent_usage`]), noted in the oracle. A killed attempt's
/// usage is unknown and is counted in `unmetered_calls`, never folded in here.
pub(crate) fn known_tokens(cell: &mut Cell, e3: &E3Node, execution: &str) -> Tokens {
    let known = completed_agent_usage(&e3.node, execution);
    cell.oracle.note(format!(
        "kata's known tokens (completed plan/implement attempts, raw accepting transitions; \
         [input, cache_read, cache_write, output]): {known:?}"
    ));
    Tokens::Counts(known)
}

/// `refs/heads/kata/<exec>` on the fixture's remote, one `git ls-remote` line per ref:
/// the local bare's, or (a real forge) `git ls-remote origin` in the repository.
pub(crate) fn remote_export_refs(fixture: &Fixture, execution: &str) -> Vec<String> {
    let (dir, remote) = match fixture.origin {
        Origin::LocalBare => (&fixture.remote, fixture.remote.as_os_str()),
        Origin::Forge => (&fixture.repo, std::ffi::OsStr::new("origin")),
    };
    let out = kata_test_utils::git::hermetic_git_in(dir)
        .arg("ls-remote")
        .arg(remote)
        .arg(format!("refs/heads/kata/{execution}"))
        .output()
        .expect("git ls-remote runs");
    assert!(
        out.status.success(),
        "{TEST}: `git ls-remote` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// The pull requests opened for `kata/<exec>`: the fake `gh`'s recorded `pr create`
/// calls, or (a real forge) the entries of `gh pr list --state all --head kata/<exec>
/// --json number`, run by the host's `gh` in the repository.
pub(crate) fn pull_requests(node: &Node, execution: &str) -> usize {
    match node.fixture.origin {
        Origin::LocalBare => gh_creates(node),
        Origin::Forge => {
            let head = format!("kata/{execution}");
            let out = std::process::Command::new("gh")
                .args([
                    "pr", "list", "--state", "all", "--head", &head, "--json", "number",
                ])
                .current_dir(&node.fixture.repo)
                .output()
                .expect("the host's gh runs");
            assert!(
                out.status.success(),
                "{TEST}: `gh pr list` failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            pull_request_count(&out.stdout).unwrap_or_else(|why| panic!("{TEST}: {why}"))
        }
    }
}

/// The entries of a `gh pr list --json number` answer: a JSON array whose every entry
/// carries an integer `number`; anything else is refused.
pub(crate) fn pull_request_count(answer: &[u8]) -> Result<usize, String> {
    let entries: Vec<serde_json::Value> = serde_json::from_slice(answer).map_err(|err| {
        format!(
            "`gh pr list` answered {:?}, not a JSON array: {err}",
            String::from_utf8_lossy(answer)
        )
    })?;
    if let Some(entry) = entries.iter().find(|entry| !entry["number"].is_u64()) {
        return Err(format!(
            "`gh pr list` answered an entry with no number: {entry}"
        ));
    }
    Ok(entries.len())
}

/// The real-forge P4 selector: `KATA_E3_FORGE_CLONE` names a local clone of our
/// `kata-e2-fixture` whose `origin` is the forge. It pushes a branch to that forge and
/// opens a pull request on it, so it is refused unless `KATA_E3_FUNDED=1` is set too;
/// unset, P4 runs on the rig's local bare and fake `gh`.
pub(crate) fn select_forge_clone(
    clone: Option<&str>,
    funded: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    let Some(clone) = clone else {
        return Ok(None);
    };
    if clone.is_empty() {
        return Err("KATA_E3_FORGE_CLONE is set but names no clone".to_owned());
    }
    if funded != Some("1") {
        return Err(format!(
            "KATA_E3_FORGE_CLONE = {clone:?} pushes to and opens a pull request on a real \
             forge; the matrix refuses it unless KATA_E3_FUNDED=1 is set"
        ));
    }
    Ok(Some(PathBuf::from(clone)))
}

pub(crate) fn gh_creates(node: &Node) -> usize {
    gh_creates_in(&node.gh_log)
}

/// The fake `gh`'s recorded `pr create` calls in the log at `gh_log`.
pub(crate) fn gh_creates_in(gh_log: &Path) -> usize {
    std::fs::read_to_string(gh_log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.split('|').nth(1) == Some("create"))
        .count()
}

/// The control the gate cells and every completed agent turn share: no model call of
/// any agent attempt is open in the transcript.
pub(crate) fn open_calls(e3: &E3Node, agent: E3Agent) -> Vec<String> {
    let events = e3.sse.events();
    ["plan", "implement"]
        .iter()
        .flat_map(|stage| assignments_of(&events, stage))
        .filter(|assignment| calls_of(&events, assignment, agent.call_markers()).open)
        .collect()
}

/// Run `oracles`, turning a panicking rig assertion into the violation it names.
pub(crate) fn checked(oracles: impl FnOnce() -> Result<(), String>) -> Option<String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(oracles)) {
        Ok(Ok(())) => None,
        Ok(Err(violation)) => Some(violation),
        Err(panic) => Some(panic_text(&*panic)),
    }
}

pub(crate) fn require(holds: bool, what: impl Into<String>) -> Result<(), String> {
    if holds { Ok(()) } else { Err(what.into()) }
}

// ---------------------------------------------------------------------------
// The gate cells
// ---------------------------------------------------------------------------

/// Which process the gate cell kills.
#[derive(Clone, Copy)]
pub(crate) enum GateKill {
    Main,
    Worker,
}

pub(crate) fn gate_cell(case: &'static str, kill: GateKill) {
    let agent = E3Agent::selected();
    let mut cell = Cell::new(case, agent);
    let mut e3 = boot_e3(node_root(), agent, (Armed::Main, &[]));
    cell.attach(&e3);
    let execution = submit(&e3);
    cell.oracle.note(format!("execution {execution}"));
    let gate = e3
        .node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");
    let open = open_calls(&e3, agent);
    cell.oracle.note(format!(
        "control (no model call open at the kill, from the transcript): open = {open:?}"
    ));
    if !open.is_empty() {
        cell.finish(&Ended::Void(format!(
            "a model call was open at the gate kill: {open:?}"
        )));
        return;
    }
    match kill {
        GateKill::Main => {
            e3.node.main.kill();
            let status = e3.node.main.child.try_wait().ok().flatten();
            cell.oracle.note(format!(
                "killed the main: wait status {status:?}, signal {:?}",
                status.and_then(|status| status.signal())
            ));
            if status.and_then(|status| status.signal()) != Some(SIGKILL) {
                cell.finish(&Ended::Void("the main did not die by SIGKILL".to_owned()));
                return;
            }
            if let Err(why) = restart_node(&mut e3) {
                let calls = uncompleted_calls(&e3.sse.events(), agent.call_markers());
                let ended = not_restarted(&mut cell, why, None, &calls);
                cell.finish(&ended);
                return;
            }
        }
        GateKill::Worker => {
            e3.node.worker.kill();
            cell.oracle
                .note("killed the worker daemon (SIGKILL) at the parked gate");
            e3.node.restart_worker();
        }
    }
    let resumed = e3.node.main.next_gate(&execution);
    let same = resumed
        .as_ref()
        .is_some_and(|resumed| resumed["assignment_id"] == gate["assignment_id"]);
    cell.oracle.note(format!(
        "kata approvals after the restart: the same assignment {} re-listed: {same}",
        gate["assignment_id"]
    ));
    let mut status = None;
    if let Some(resumed) = &resumed {
        e3.node.main.decide(resumed, None);
        let doc = e3.node.main.wait_terminal(&execution);
        status = doc["status"].as_str().map(str::to_owned);
    }
    cell.oracle.note(format!(
        "kata run show status after the decision: {status:?}"
    ));
    let calls = uncompleted_calls(&e3.sse.events(), agent.call_markers());
    let settlement = if same && status.as_deref() == Some("completed") {
        ("resumed-at-gate".to_owned(), None)
    } else {
        (
            "other".to_owned(),
            Some(format!(
                "same assignment re-listed: {same}; terminal status {status:?}"
            )),
        )
    };
    let violation = checked(|| {
        assert_final_state(&e3.node, &execution);
        cell.oracle.note(
            "assert_final_state: one accepted attempt per occurrence, trunk = kata/<exec> = \
             the committed commit, one `gh pr create`, no attempt roots, containers or cgroups",
        );
        note_none_unmetered(&mut cell, &calls);
        none_unmetered(
            &calls,
            "the gate kill falls between agent turns, killing no model call",
        )
    });
    let usage = completed_agent_usage(&e3.node, &execution);
    cell.oracle.note(format!(
        "recorded usage [in, cache_read, cache_write, out]: {usage:?}"
    ));
    cell.finish(&Ended::Judged {
        observed: Observed {
            settlement: settlement.0,
            detail: settlement.1,
            tokens: Tokens::Counts(usage),
            unmetered_calls: calls.unmetered(),
        },
        violation,
    });
}

// ---------------------------------------------------------------------------
// P1 — placed, not sent
// ---------------------------------------------------------------------------

pub(crate) const P1_BOUNDARY: &str = "after_capsule_dispatched_before_send";

/// The plan attempt's projected state, read raw.
pub(crate) fn plan_attempt_state(node: &Node, execution: &str) -> Option<String> {
    raw_db(&node.root_path.join("data"))
        .query_row(
            "SELECT p.state FROM attempts a JOIN attempt_projection p \
             ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
             AND p.attempt_ordinal = a.attempt_ordinal \
             WHERE a.execution_id = ?1 AND a.stage_id = 'plan'",
            [execution_blob(execution)],
            |row| row.get(0),
        )
        .ok()
}

/// What P1 observes after the restart, shared by the process and host columns.
pub(crate) fn judge_p1(cell: &mut Cell, e3: &mut E3Node, execution: &str) -> Ended {
    let doc = e3.node.main.wait_terminal(execution);
    let status = doc["status"].as_str().unwrap_or("?").to_owned();
    let reason = failed_reason(&e3.node, execution, "plan");
    cell.oracle.note(format!("kata run show status: {status}"));
    cell.oracle
        .note(format!("raw failed `plan` transition: {reason:?}"));
    let ambiguous = reason
        .as_deref()
        .is_some_and(|reason| reason.contains("PROVEN AMBIGUOUS"));
    let settlement = if ambiguous && status == "failed" {
        ("proven-ambiguous".to_owned(), None)
    } else {
        (
            "other".to_owned(),
            Some(format!("status {status}; plan failed reason {reason:?}")),
        )
    };
    let calls = uncompleted_calls(&e3.sse.events(), cell.agent.call_markers());
    let violation = checked(|| {
        // Never re-delivered: past a recovery window, one claim and one attempt row.
        std::thread::sleep(Duration::from_secs(10));
        let claims = claimed_count(&e3.node, execution, "plan");
        let attempts = attempt_count(&e3.node, execution, "plan");
        cell.oracle.note(format!(
            "after 10 s: plan claimed transitions {claims}, plan attempt rows {attempts}"
        ));
        note_none_unmetered(cell, &calls);
        none_unmetered(&calls, "P1's killed attempt is never sent")?;
        require(attempts == 1, "a second plan attempt was minted")?;
        require(claims <= 1, "the plan attempt was claimed more than once")?;
        let events = e3.sse.events();
        let plan_frames: Vec<&SseEvent> = events
            .iter()
            .filter(|event| event.name == "progress" && event.stage().starts_with("plan"))
            .collect();
        cell.oracle.note(format!(
            "transcript: plan progress frames {} (zero model calls for the attempt)",
            plan_frames.len()
        ));
        require(
            plan_frames.is_empty(),
            "the never-sent plan attempt streamed progress",
        )?;
        // D2 §5.4: the run fails and the candidate auto-parks — read out of git.
        let parked = git_rev(&e3.node.fixture.repo, &format!("parked/{execution}"));
        cell.oracle
            .note(format!("git: parked/{execution} = {parked:?}"));
        require(
            parked.is_some(),
            format!("the failed run's candidate did not auto-park: no parked/{execution}"),
        )?;
        assert_no_mutation(&e3.node, execution);
        cell.oracle.note(
            "assert_no_mutation: trunk unmoved, no kata/<exec> on the remote, the fake gh ran \
             nothing, no commit/promote/export resolved",
        );
        assert_no_container_residue(&e3.node, execution);
        cell.oracle
            .note("assert_no_container_residue: no live container, no kata.* cgroup");
        Ok(())
    });
    Ended::Judged {
        observed: Observed {
            settlement: settlement.0,
            detail: settlement.1,
            tokens: known_tokens(cell, e3, execution),
            unmetered_calls: calls.unmetered(),
        },
        violation,
    }
}

// ---------------------------------------------------------------------------
// P2 — model call in flight
// ---------------------------------------------------------------------------

/// Wait until `implement`'s attempt has an open model call in the transcript; `None`
/// past the deadline.
pub(crate) fn wait_for_open_implement_call(e3: &E3Node, agent: E3Agent) -> Option<String> {
    let deadline = Instant::now() + CRASH_DEADLINE;
    while Instant::now() < deadline {
        let events = e3.sse.events();
        if let Some(open) = assignments_of(&events, "implement")
            .into_iter()
            .find(|assignment| calls_of(&events, assignment, agent.call_markers()).open)
        {
            return Some(open);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// One P2 try on a fresh node, recorded before the node (and its transcript) drops:
/// `true` when the try was VOID; a judged try that did not pass fails the test.
pub(crate) fn p2_try(agent: E3Agent) -> bool {
    let (cell, ended, _node) = p2_run(agent);
    if let Ended::Void(reason) = &ended {
        let (_, _, dir) = cell.record(&ended);
        eprintln!("E3 P2: VOID ({reason}); record {}", dir.display());
        return true;
    }
    cell.finish(&ended);
    false
}

/// The P2 cell body; the node rides back so the caller records while it stands.
pub(crate) fn p2_run(agent: E3Agent) -> (Cell, Ended, E3Node) {
    let mut cell = Cell::new("P2", agent);
    let mut e3 = boot_e3_holding_implement(node_root(), agent, (Armed::Main, &[]));
    cell.attach(&e3);
    let execution = submit(&e3);
    cell.oracle.note(format!("execution {execution}"));
    let Some(assignment) = wait_for_open_implement_call(&e3, agent) else {
        return (
            cell,
            Ended::Void("the transcript never showed an open implement model call".to_owned()),
            e3,
        );
    };
    let heads_before = work_heads(&e3.node, &execution);
    note_kernel_sockets(&mut cell, "the worker", e3.node.worker.pid);
    // Stamped BEFORE the kill: the rig's kill waits for the daemon's exit, and the
    // settlement's terminal frame can arrive inside that wait. A frame received before
    // this stamp was certainly sent by a live worker.
    let kill_ms = now_ms();
    kill_worker_mid_turn(&mut e3.node, &execution);
    cell.oracle.note(format!(
        "killed the worker daemon (SIGKILL) at {kill_ms} ms with implement assignment \
         {assignment}'s model call open"
    ));
    // Post hoc, over EVERY frame of the attempt (a frame received after the kill was
    // still sent before it): the last model-call frame is a start, never completed.
    let doc = e3.node.main.wait_terminal(&execution);
    // The settlement's own terminal frame arrives after the kill and says nothing about
    // the call at the kill; every progress frame counts, whenever it arrived.
    let events: Vec<SseEvent> = e3
        .sse
        .events()
        .into_iter()
        .filter(|event| !(event.is_terminal_ledger() && event.received_ms >= kill_ms))
        .collect();
    let calls = calls_of(&events, &assignment, agent.call_markers());
    cell.oracle.note(format!(
        "control (post hoc, the whole transcript): implement {assignment}: started {}, \
         completed {}, open {}",
        calls.started, calls.completed, calls.open
    ));
    let terminal_before_kill = events.iter().any(|event| {
        event.assignment() == Some(assignment.as_str())
            && event.is_terminal_ledger()
            && event.received_ms < kill_ms
    });
    if !calls.open || terminal_before_kill {
        return (
            cell,
            Ended::Void(format!(
                "no open model call at the kill timestamp (open {}, terminal frame before the \
                 kill {terminal_before_kill})",
                calls.open
            )),
            e3,
        );
    }
    let ended = judge_p2(
        &mut cell,
        &mut e3,
        &execution,
        P2Restart::WorkerDied,
        &calls,
        &heads_before,
        &doc,
    );
    (cell, ended, e3)
}

/// The killed attempt's `terminal_charge` (off its raw failed transition) against D2
/// §5.4 spend (a): its usage is UNKNOWN, never zero — no charge, a charge stating no
/// usage, or usage whose cost is `unavailable`. Anything else (an `authoritative` or
/// `estimated` cost, usage with no cost) is a recorded usage for a call nobody metered.
pub(crate) fn killed_charge_is_unknown(charge: &serde_json::Value) -> Result<(), String> {
    let usage = &charge["token_usage"];
    if charge.is_null() || usage.is_null() {
        return Ok(());
    }
    match usage["cost"]["quality"].as_str() {
        Some("unavailable") => Ok(()),
        quality => Err(format!(
            "the killed attempt's usage is recorded (cost quality {quality:?}), not unknown: \
             {charge}"
        )),
    }
}

/// Every raw `implement` transition's `token_usage`, as (kind, usage) — the [verify]
/// of D2 §5.4 spend (a): whether any durable row holds the killed attempt's usage.
pub(crate) fn implement_usage_rows(
    node: &Node,
    execution: &str,
) -> Vec<(String, serde_json::Value)> {
    let conn = raw_db(&node.root_path.join("data"));
    let rows: Vec<(String, String)> = conn
        .prepare(
            "SELECT kind, CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
             AND stage_id = 'implement' ORDER BY seq",
        )
        .unwrap()
        .query_map([execution_blob(execution)], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    rows.into_iter()
        .filter_map(|(kind, payload)| {
            let payload: serde_json::Value = serde_json::from_str(&payload).ok()?;
            let usage = [
                &payload["output"]["token_usage"],
                &payload["terminal_charge"]["token_usage"],
                &payload["token_usage"],
            ]
            .into_iter()
            .find(|usage| !usage.is_null())?
            .clone();
            Some((kind, usage))
        })
        .collect()
}

/// The leg that settles P2's killed attempt, which the column's kill decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum P2Restart {
    /// The process column: the worker daemon is SIGKILLed and the main's worker-death leg
    /// settles the attempt.
    WorkerDied,
    /// The host column: the whole machine restarts and the next main's restart pass
    /// settles the attempt.
    MainRestarted,
}

/// One raw transition of a stage, as a second read-only handle reads it.
#[derive(Clone, Debug)]
pub(crate) struct ChainRow {
    pub(crate) attempt_ordinal: Option<i64>,
    pub(crate) kind: String,
    pub(crate) resulting_state: String,
    pub(crate) payload: serde_json::Value,
}

/// `implement`'s durable chain once the recovery window has passed: every transition in
/// `seq` order, and its `attempts` row count.
#[derive(Clone, Debug)]
pub(crate) struct P2Chain {
    pub(crate) transitions: Vec<ChainRow>,
    pub(crate) attempt_rows: i64,
}

/// [`P2Chain`] of `execution`, read through a second read-only handle on the node's
/// `operational.db`.
pub(crate) fn p2_chain(node: &Node, execution: &str) -> P2Chain {
    let conn = raw_db(&node.root_path.join("data"));
    let transitions = conn
        .prepare(
            "SELECT attempt_ordinal, kind, resulting_state, IFNULL(CAST(payload_json AS TEXT), \
             '') FROM transitions WHERE execution_id = ?1 AND stage_id = 'implement' ORDER BY seq",
        )
        .unwrap()
        .query_map([execution_blob(execution)], |row| {
            let payload: String = row.get(3)?;
            Ok(ChainRow {
                attempt_ordinal: row.get(0)?,
                kind: row.get(1)?,
                resulting_state: row.get(2)?,
                payload: serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null),
            })
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    P2Chain {
        transitions,
        attempt_rows: attempt_count(node, execution, "implement"),
    }
}

impl P2Restart {
    /// Whether `reason` opens with this leg's cause, as the operator guide states the
    /// recorded reasons (under "A capsule attempt that the main loses sight of is settled
    /// terminal and not re-delivered"): the worker-death leg's `worker <id> died: …`, and
    /// the restart's `the main restarted` (`kata_workflow::dispatcher::
    /// CAPSULE_MAIN_RESTARTED`), each followed by `. ` and the verdict clause
    /// (`Dispatcher::settle_capsule_attempt`).
    fn names_cause(self, reason: &str) -> bool {
        match self {
            Self::WorkerDied => reason
                .strip_prefix("worker ")
                .and_then(|rest| rest.split_once(' '))
                .is_some_and(|(_, rest)| rest.starts_with("died: ")),
            Self::MainRestarted => reason.starts_with("the main restarted. "),
        }
    }
}

/// P2's settlement, judged off the durable chain rather than the reason's prose: exactly
/// one attempt row, exactly one claim and one dispatch of it (a re-delivery shows as a
/// second of either), no accepting transition, and exactly one `failed` terminal whose
/// typed `verdict` is `proven_ambiguous`. Its reason must then state that verdict and
/// open with the cause of the leg `restart` names — a settlement by the other leg means
/// the kill did not land as the column claims. `Ok` carries the settled reason.
pub(crate) fn judge_p2_settlement(restart: P2Restart, chain: &P2Chain) -> Result<String, String> {
    let count = |kind: &str| {
        chain
            .transitions
            .iter()
            .filter(|row| row.kind == kind)
            .count()
    };
    require(
        chain.attempt_rows == 1,
        format!("{} implement attempt rows, not one", chain.attempt_rows),
    )?;
    require(
        count("claimed") == 1,
        format!("{} implement claims, not one", count("claimed")),
    )?;
    require(
        count("dispatched") == 1,
        format!("{} implement dispatches, not one", count("dispatched")),
    )?;
    require(
        !chain
            .transitions
            .iter()
            .any(|row| row.resulting_state == "completed"),
        "the killed implement attempt was accepted",
    )?;
    let failed: Vec<&ChainRow> = chain
        .transitions
        .iter()
        .filter(|row| row.resulting_state == "failed")
        .collect();
    let [settled] = failed.as_slice() else {
        return Err(format!(
            "{} failed implement transitions, not one",
            failed.len()
        ));
    };
    require(
        settled.payload["verdict"] == "proven_ambiguous",
        format!(
            "the settlement's typed verdict is {}, not proven_ambiguous",
            settled.payload["verdict"]
        ),
    )?;
    let reason = settled.payload["reason"].as_str().unwrap_or_default();
    require(
        reason.contains(". PROVEN AMBIGUOUS: ") && reason.contains("NOT re-delivered"),
        format!("the settled reason does not state PROVEN AMBIGUOUS, NOT re-delivered: {reason}"),
    )?;
    require(
        restart.names_cause(reason),
        format!("the settled reason does not open with the {restart:?} leg's cause: {reason}"),
    )?;
    Ok(reason.to_owned())
}

/// The operator's recourse for a PROVEN AMBIGUOUS run, run as the CLI flow an operator
/// types and kept as `recourse.txt`: `kata run show` names the failure; the candidate
/// is parked (auto, or `kata run park`); git shows what the ambiguous turn may have left
/// on it; the last step, re-running the pack, is stated and NOT run (it is a second
/// model turn). `Err` when a step the flow rests on does not hold.
pub(crate) fn recourse_flow(cell: &mut Cell, e3: &E3Node, execution: &str) -> Result<(), String> {
    use std::fmt::Write as _;
    let mut flow = String::new();
    let step = |flow: &mut String, args: &[&str]| -> (bool, String) {
        let out = kata()
            .args(["--api-url", &e3.node.main.url])
            .args(args)
            .output()
            .expect("kata runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = writeln!(
            flow,
            "$ kata {}\n{}\n(exit {:?})\n",
            args.join(" "),
            text.trim_end(),
            out.status.code()
        );
        (out.status.success(), text)
    };
    let (shown, show) = step(&mut flow, &["run", "show", execution]);
    require(shown, "`kata run show` failed")?;
    let failed = serde_json::from_str::<serde_json::Value>(&show)
        .ok()
        .and_then(|doc| doc["status"].as_str().map(str::to_owned));
    require(
        failed.as_deref() == Some("failed"),
        format!("`kata run show` does not say failed: {failed:?}"),
    )?;
    let parked_ref = format!("parked/{execution}");
    let auto = git_rev(&e3.node.fixture.repo, &parked_ref);
    let _ = writeln!(
        flow,
        "# git rev-parse {parked_ref}: {auto:?} (the run's own auto-park)\n"
    );
    if auto.is_none() {
        let (ok, _) = step(&mut flow, &["run", "park", execution]);
        require(ok, "`kata run park` failed")?;
    }
    let parked = git_rev(&e3.node.fixture.repo, &parked_ref);
    require(
        parked.is_some(),
        format!("no {parked_ref} after the recourse"),
    )?;
    let trunk = e3.node.fixture.trunk.clone();
    let diff = kata_test_utils::git::hermetic_git_in(&e3.node.fixture.repo)
        .args(["diff", "--stat", &trunk, &parked_ref])
        .output()
        .expect("git diff runs");
    let _ = writeln!(
        flow,
        "$ git diff --stat {trunk} {parked_ref}\n{}\n",
        String::from_utf8_lossy(&diff.stdout).trim_end()
    );
    let _ = writeln!(
        flow,
        "# then, having judged what the ambiguous turn left: re-run the pack (NOT run here: \
         a second model turn; change.star is this record's copy of the pack)\n$ kata run \
         change.star --param task=... --param test_command=..."
    );
    let path = e3.node.root_path.join("recourse.txt");
    std::fs::write(&path, &flow).unwrap();
    cell.oracle.note(format!(
        "operator recourse (recourse.txt): run show = failed; {parked_ref} = {parked:?} ({})",
        if auto.is_some() {
            "auto-parked"
        } else {
            "parked by `kata run park`"
        }
    ));
    cell.artifacts.push((
        path,
        "recourse.txt",
        "the operator's recourse for the PROVEN AMBIGUOUS run, as the CLI flow it types: \
         run show, the parked candidate, its diff against trunk, and the re-run it would type",
    ));
    Ok(())
}

/// P2's spend, the count [`judge_p2`] records: the killed implement attempt's `calls`, every
/// one of unknown usage ([`CallCount::unmetered`]), noted on `oracle`.
pub(crate) fn p2_spend(oracle: &mut Oracle, calls: &CallCount) -> u64 {
    let unmetered = calls.unmetered();
    oracle.note(format!(
        "spend: issued calls of the killed attempt {unmetered}, every one of unknown usage \
         (unmetered_calls; none is on any durable row): completed {}, closed only by the next \
         start {}, open at the end {}; no second attempt",
        calls.completed, calls.unclosed, calls.open
    ));
    unmetered
}

/// What P2 reads off the node, each read through a second read-only handle: the
/// execution's status and raw failed `implement` transition as the run settled, then,
/// once a respawned worker has had its recovery window, `implement`'s chain, the
/// execution's `/work` heads and the `implement` transitions holding a usage. A read
/// that panicked carries its panic text, so it is a violation, not a stopped judge.
#[derive(Clone, Debug)]
pub(crate) struct P2Facts {
    pub(crate) status: String,
    pub(crate) failed_reason: Option<String>,
    pub(crate) chain: Result<P2Chain, String>,
    pub(crate) heads_after: Result<Vec<(String, String, i64)>, String>,
    pub(crate) usage_rows: Result<Vec<(String, serde_json::Value)>, String>,
}

/// `read`'s value, or the text it panicked with.
fn caught<T>(read: impl FnOnce() -> T) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(read))
        .map_err(|panic| panic_text(&*panic))
}

/// P2's judgement of what it read, with no node: the observed settlement (PROVEN
/// AMBIGUOUS when the status is `failed` and the failed transition's typed `verdict`
/// says so) and, in this order, each read oracle that did not hold — the settlement
/// ([`judge_p2_settlement`] for the leg `restart` names, over `facts.chain`), the `/work`
/// heads against `heads_before`, and the killed attempt's unknown charge. Every oracle is
/// judged whatever an earlier one found. Each step is noted in `oracle`.
pub(crate) fn judge_p2_facts(
    restart: P2Restart,
    heads_before: &[(String, String, i64)],
    facts: &P2Facts,
    oracle: &mut Oracle,
) -> ((String, Option<String>), Vec<String>) {
    let P2Facts {
        status,
        failed_reason,
        chain,
        heads_after,
        usage_rows,
    } = facts;
    oracle.note(format!("kata run show status: {status}"));
    oracle.note(format!(
        "raw failed `implement` transition: {failed_reason:?}"
    ));
    let settled = failed_reason
        .as_deref()
        .and_then(|reason| serde_json::from_str::<serde_json::Value>(reason).ok())
        .unwrap_or(serde_json::Value::Null);
    let settlement = if settled["verdict"] == "proven_ambiguous" && status == "failed" {
        ("proven-ambiguous".to_owned(), None)
    } else {
        (
            "other".to_owned(),
            Some(format!(
                "status {status}; implement failed reason {failed_reason:?}"
            )),
        )
    };
    let mut violations: Vec<String> = Vec::new();
    let mut judged = |verdict: Result<(), String>| violations.extend(verdict.err());
    judged(chain.clone().and_then(|chain| {
        oracle.note(format!(
            "after a respawned worker and 10 s, the raw implement chain: {} attempt row(s); \
             transitions {:?}",
            chain.attempt_rows,
            chain
                .transitions
                .iter()
                .map(|row| format!(
                    "{:?} {} {}",
                    row.attempt_ordinal, row.kind, row.resulting_state
                ))
                .collect::<Vec<_>>()
        ));
        let reason = judge_p2_settlement(restart, &chain)?;
        oracle.note(format!(
            "judge_p2_settlement ({restart:?}): one attempt, one claim, one dispatch, no \
             acceptance, verdict proven_ambiguous; reason {reason}"
        ));
        Ok(())
    }));
    judged(heads_after.clone().and_then(|heads_after| {
        oracle.note(format!(
            "/work heads before the kill {heads_before:?}, after settlement {heads_after:?}"
        ));
        require(
            heads_before == heads_after.as_slice(),
            "a /work delta was published for the killed attempt",
        )
    }));
    judged(usage_rows.clone().and_then(|usage_rows| {
        // D2 §5.4 spend (a), [verify]: the durable rows that hold any implement usage,
        // and the killed attempt's charge, which must state its usage unknown.
        oracle.note(format!(
            "[verify] raw implement transitions holding a token_usage: {usage_rows:?}"
        ));
        let charge = settled["terminal_charge"].clone();
        oracle.note(format!("the killed attempt's terminal_charge: {charge}"));
        killed_charge_is_unknown(&charge)?;
        for (kind, usage) in &usage_rows {
            killed_charge_is_unknown(&serde_json::json!({ "token_usage": usage }))
                .map_err(|why| format!("implement transition `{kind}`: {why}"))?;
        }
        Ok(())
    }));
    (settlement, violations)
}

/// What P2 observes once the run settled, shared by the process and host columns:
/// `restart` is the leg the column's kill settles through, `calls` the killed attempt's
/// post-hoc transcript count, `heads_before` the execution's `/work` heads at the kill.
///
/// Every oracle runs, whatever an earlier one found, and the violation names each one
/// that did not hold: a respawned worker given 10 s to claim a re-delivery, then the
/// read oracles ([`judge_p2_facts`] over [`P2Facts`]), no mutation, no container
/// residue, and the operator's recourse.
pub(crate) fn judge_p2(
    cell: &mut Cell,
    e3: &mut E3Node,
    execution: &str,
    restart: P2Restart,
    calls: &CallCount,
    heads_before: &[(String, String, i64)],
    doc: &serde_json::Value,
) -> Ended {
    let status = doc["status"].as_str().unwrap_or("?").to_owned();
    let failed_reason = failed_reason(&e3.node, execution, "implement");
    let mut violations: Vec<String> = Vec::new();
    // A fresh worker, given a recovery window to claim a re-delivery.
    violations.extend(checked(|| {
        e3.node.restart_worker();
        Ok(())
    }));
    std::thread::sleep(Duration::from_secs(10));
    let facts = P2Facts {
        status,
        failed_reason,
        chain: caught(|| p2_chain(&e3.node, execution)),
        heads_after: caught(|| work_heads(&e3.node, execution)),
        usage_rows: caught(|| implement_usage_rows(&e3.node, execution)),
    };
    let (settlement, read) = judge_p2_facts(restart, heads_before, &facts, &mut cell.oracle);
    violations.extend(read);
    violations.extend(checked(|| {
        assert_no_mutation(&e3.node, execution);
        cell.oracle
            .note("assert_no_mutation: nothing landed, pushed or opened");
        Ok(())
    }));
    violations.extend(checked(|| {
        assert_no_container_residue(&e3.node, execution);
        cell.oracle
            .note("assert_no_container_residue: no live container, no kata.* cgroup");
        Ok(())
    }));
    violations.extend(checked(|| recourse_flow(cell, e3, execution)));
    let violation = (!violations.is_empty()).then(|| violations.join("; "));
    let unmetered = p2_spend(&mut cell.oracle, calls);
    Ended::Judged {
        observed: Observed {
            settlement: settlement.0,
            detail: settlement.1,
            tokens: known_tokens(cell, e3, execution),
            unmetered_calls: unmetered,
        },
        violation,
    }
}

// ---------------------------------------------------------------------------
// P3 — after the turn, before acceptance
// ---------------------------------------------------------------------------

pub(crate) const P3_BOUNDARY: &str = "after_container_exited_before_result_published";

/// The recorded reason's cause when the main's worker-death leg settled the attempt on
/// the aborted worker's closed connection (`handle_worker_death`: "worker <id> died: its
/// connection closed (…); its process <pid> is gone. PROVEN AMBIGUOUS …").
pub(crate) const WORKER_DIED: &str = " died: its connection closed";

/// P3's crash state, read the moment the worker died: nothing reached the main (no
/// `event_inbox` row, `plan` never accepted), and the finished turn's result is only on
/// the dead worker's disk (its attempt root).
pub(crate) fn note_p3_crash_state(cell: &mut Cell, node: &Node, execution: &str) {
    let (buffered, accepted) = inbox_counts(&node.root_path.join("data"), execution);
    cell.oracle.note(format!(
        "at the worker's death: event_inbox buffered {buffered}, accepted {accepted}; plan \
         event_accepted {}; plan attempt state {:?}; the worker's attempt roots {:?}",
        completed_transitions(node, execution, "plan", "event_accepted"),
        plan_attempt_state(node, execution),
        attempt_roots(node),
    ));
}

/// What P3 observes, to the end of the run. `leg` is the recorded cause the column
/// expects (the process column's worker-death leg); `None` when the column does not
/// fix it (the host column, where the main died too and its restart leg may settle it).
pub(crate) fn judge_p3(
    cell: &mut Cell,
    e3: &mut E3Node,
    execution: &str,
    leg: Option<&str>,
) -> Ended {
    let doc = e3.node.main.wait_terminal(execution);
    let status = doc["status"].as_str().unwrap_or("?").to_owned();
    let reason = failed_reason(&e3.node, execution, "plan");
    cell.oracle.note(format!("kata run show status: {status}"));
    cell.oracle
        .note(format!("raw failed `plan` transition: {reason:?}"));
    let ambiguous = reason
        .as_deref()
        .is_some_and(|reason| reason.contains("PROVEN AMBIGUOUS"));
    let settlement = if ambiguous && status == "failed" {
        ("proven-ambiguous".to_owned(), None)
    } else {
        (
            "other".to_owned(),
            Some(format!("status {status}; plan failed reason {reason:?}")),
        )
    };
    let plan_unmetered = p3_spend(&e3.sse.events(), cell.agent.call_markers());
    let violation = checked(|| {
        if let Some(leg) = leg {
            require(
                reason.as_deref().is_some_and(|reason| reason.contains(leg)),
                format!("the attempt was not settled by the expected leg (`{leg}`)"),
            )?;
        }
        // Never re-delivered: past a recovery window, one claim and one attempt row.
        std::thread::sleep(Duration::from_secs(10));
        let claims = claimed_count(&e3.node, execution, "plan");
        let attempts = attempt_count(&e3.node, execution, "plan");
        let accepted = completed_transitions(&e3.node, execution, "plan", "event_accepted");
        cell.oracle.note(format!(
            "after 10 s: plan claimed transitions {claims}, plan attempt rows {attempts}, plan \
             event_accepted {accepted}; the worker's attempt roots {:?}",
            attempt_roots(&e3.node)
        ));
        judge_p3_counts(claims, attempts, accepted)?;
        // Recorded, not judged: the dead worker never flushed `plan`'s coalesced frames,
        // so a second turn could read here as one call and the count refuses nothing.
        // One attempt row and one claim are what refuse a second turn.
        cell.oracle.note(format!(
            "transcript: plan issued model calls {plan_unmetered} (recorded only: the dead \
             worker's coalesced frames never left it)"
        ));
        // D2 §5.4: the run fails and the candidate auto-parks — read out of git.
        let parked = git_rev(&e3.node.fixture.repo, &format!("parked/{execution}"));
        cell.oracle
            .note(format!("git: parked/{execution} = {parked:?}"));
        require(
            parked.is_some(),
            format!("the failed run's candidate did not auto-park: no parked/{execution}"),
        )?;
        assert_no_mutation(&e3.node, execution);
        cell.oracle.note(
            "assert_no_mutation: trunk unmoved, no kata/<exec> on the remote, the fake gh ran \
             nothing, no commit/promote/export resolved",
        );
        assert_no_container_residue(&e3.node, execution);
        cell.oracle
            .note("assert_no_container_residue: no live container, no kata.* cgroup");
        Ok(())
    });
    Ended::Judged {
        observed: Observed {
            settlement: settlement.0,
            detail: settlement.1,
            // The turn's usage rode the `CompletedCapsule` frame the abort prevented, so
            // its calls are counted unmetered (`CallCount::unmetered`, as P2's are), not in
            // the known part.
            tokens: known_tokens(cell, e3, execution),
            unmetered_calls: plan_unmetered,
        },
        violation,
    }
}

/// P3's spend, the count [`judge_p3`] records: every `plan` attempt's calls in the
/// transcript, each of unknown usage ([`CallCount::unmetered`]): the turn's usage rode the
/// `CompletedCapsule` frame the abort prevented.
pub(crate) fn p3_spend(events: &[SseEvent], markers: CallMarkers) -> u64 {
    let plan_calls: Vec<CallCount> = assignments_of(events, "plan")
        .iter()
        .map(|assignment| calls_of(events, assignment, markers))
        .collect();
    plan_calls.iter().map(CallCount::unmetered).sum()
}

/// P3's durable counts past the recovery window, read through a second handle: exactly
/// one attempt row (no second attempt minted), exactly one claim (the attempt was claimed
/// before the worker died, and never claimed again), and no `event_accepted`. Any other
/// count is refused.
pub(crate) fn judge_p3_counts(claims: i64, attempts: i64, accepted: i64) -> Result<(), String> {
    require(
        attempts == 1,
        format!("{attempts} plan attempt rows, not one"),
    )?;
    require(claims == 1, format!("{claims} plan claims, not one"))?;
    require(accepted == 0, "the unsent result was accepted")
}

// ---------------------------------------------------------------------------
// P4 — between the push and the PR
// ---------------------------------------------------------------------------

pub(crate) const P4_BOUNDARY: &str = "after_forge_push_before_pr";

/// What P4 observes after the restart.
pub(crate) fn judge_p4(cell: &mut Cell, e3: &mut E3Node, execution: &str) -> Ended {
    let doc = e3.node.main.wait_terminal(execution);
    let status = doc["status"].as_str().unwrap_or("?").to_owned();
    let refs = remote_export_refs(&e3.node.fixture, execution);
    let creates = pull_requests(&e3.node, execution);
    cell.oracle.note(format!(
        "after the restart: status {status}; remote refs/heads/kata/<exec> {refs:?}; pull \
         requests for kata/<exec> {creates} ({:?} forge)",
        e3.node.fixture.origin
    ));
    let calls = uncompleted_calls(&e3.sse.events(), cell.agent.call_markers());
    let settlement = if status == "completed" && refs.len() == 1 && creates == 1 {
        ("pr-opened-once".to_owned(), None)
    } else {
        (
            "other".to_owned(),
            Some(format!(
                "status {status}; {} export ref(s); {creates} pr create(s)",
                refs.len()
            )),
        )
    };
    let violation = checked(|| {
        let trunk = git_rev(&e3.node.fixture.repo, &e3.node.fixture.trunk);
        let delivered = refs
            .first()
            .and_then(|line| line.split_whitespace().next())
            .map(str::to_owned);
        cell.oracle.note(format!(
            "the one export ref {delivered:?} against trunk's tip {trunk:?}"
        ));
        require(
            refs.len() == 1,
            "not exactly one kata/<exec> ref on the remote",
        )?;
        require(
            delivered == trunk,
            "the export ref is not the delivered commit",
        )?;
        require(creates == 1, "not exactly one pull request for kata/<exec>")?;
        match e3.node.fixture.origin {
            Origin::LocalBare => {
                assert_final_state(&e3.node, execution);
                cell.oracle.note(
                    "assert_final_state: trunk = kata/<exec> = the commit effect's \
                     commit_sha, exactly one `gh pr create`, no residue",
                );
            }
            Origin::Forge => {
                assert_landed_state(&e3.node, execution);
                cell.oracle.note(
                    "assert_landed_state: trunk = the commit effect's commit_sha, no residue; \
                     the forge's one kata/<exec> and one pull request read above",
                );
            }
        }
        note_none_unmetered(cell, &calls);
        none_unmetered(
            &calls,
            "P4's kill falls after every agent turn, killing no model call",
        )
    });
    Ended::Judged {
        observed: Observed {
            settlement: settlement.0,
            detail: settlement.1,
            tokens: Tokens::Counts(completed_agent_usage(&e3.node, execution)),
            unmetered_calls: calls.unmetered(),
        },
        violation,
    }
}

/// The P4 crash state, read before the restart: the push landed and no PR was opened.
pub(crate) fn note_p4_crash_state(cell: &mut Cell, e3: &E3Node, execution: &str) {
    let refs = remote_export_refs(&e3.node.fixture, execution);
    let creates = pull_requests(&e3.node, execution);
    cell.oracle.note(format!(
        "at the crash: remote refs/heads/kata/<exec> {refs:?}; pull requests for \
         kata/<exec> {creates}"
    ));
}

// ---------------------------------------------------------------------------
// The host column: the whole machine, through a supplied command
// ---------------------------------------------------------------------------

/// What the arm phase leaves on the machine's disk for the resume phase.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct HostState {
    pub(crate) case: String,
    pub(crate) agent: String,
    pub(crate) execution: String,
    pub(crate) shape: NodeShape,
    pub(crate) started_unix_ms: u64,
    /// P2-host: the implement assignment whose model call was open, and the
    /// execution's `/work` heads when the arm phase saw it open.
    pub(crate) open_assignment: Option<String>,
    pub(crate) heads_at_arm: Vec<(String, String, i64)>,
    /// The local forge's `refs/heads/kata/<exec>` (`git ls-remote` lines) with every node
    /// process frozen, right before the kill: P4-host's acknowledged push.
    pub(crate) forge_refs_at_arm: Vec<String>,
}

pub(crate) fn host_state_dir() -> PathBuf {
    let dir = std::env::var_os("KATA_E3_HOST_STATE_DIR").unwrap_or_else(|| {
        panic!(
            "{TEST}: the host column needs KATA_E3_HOST_STATE_DIR, a directory on the \
             persistent disk of the machine the command kills"
        )
    });
    PathBuf::from(dir)
}

/// Every thread's scheduler state, from `/proc/<pid>/task/*/stat`. `/proc/<pid>/stat`
/// alone is the LEADER thread's, and a process is stopped only when every thread is.
pub(crate) fn thread_states(pid: u32) -> Vec<char> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|tasks| {
            tasks
                .flatten()
                .filter_map(|task| {
                    let stat = std::fs::read_to_string(task.path().join("stat")).ok()?;
                    stat.rsplit_once(')')?.1.trim_start().chars().next()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `states` (one per thread) is a STOPPED process: at least one thread, all `T`.
pub(crate) fn all_stopped(states: &[char]) -> bool {
    !states.is_empty() && states.iter().all(|state| *state == 'T')
}

/// `pid`'s thread states once every thread is `T`, or the last read at `within`. The
/// point prints its `action=stop` marker BEFORE it raises SIGSTOP, so a read right after
/// the marker can still see the armed thread running.
pub(crate) fn stopped_thread_states(pid: u32, within: Duration) -> Vec<char> {
    let until = Instant::now() + within;
    loop {
        let states = thread_states(pid);
        if all_stopped(&states) || Instant::now() >= until {
            return states;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The host column's stop control, on a process that printed the point's `action=stop`
/// marker. It refuses exactly: a thread not in `T` ([`all_stopped`]), or, read once no
/// thread can write, a `resumed at` line in its log — the face of a process-directed
/// SIGSTOP whose armed thread ran on, printed that line and stopped late, though nothing
/// sent SIGCONT. A thread stopped past the point before it printed anything is not in that
/// set; the point's thread-directed `raise` is what keeps it from happening.
pub(crate) fn judge_host_stop(log: &str, states: &[char], boundary: &str) -> Result<(), String> {
    if !all_stopped(states) {
        return Err(format!(
            "it is not stopped at the point (thread states {states:?})"
        ));
    }
    let resumed = format!("[kata-fault-inject] resumed at operational.{boundary}");
    if log.lines().any(|line| line.contains(&resumed)) {
        return Err(format!(
            "it ran past the point: its log carries `{resumed}` though nothing resumed it"
        ));
    }
    Ok(())
}

/// The arm phase's positive control, or the VOID reason: the armed process printed the
/// point's `action=stop` marker, every thread then reads `T` within 10 s
/// ([`stopped_thread_states`]), and [`judge_host_stop`] admits it (P2-host: the transcript
/// shows the open implement call). Returns the open assignment for P2-host.
pub(crate) fn host_arm_control(
    cell: &mut Cell,
    e3: &E3Node,
    agent: E3Agent,
    armed: Armed,
    boundary: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(boundary) = boundary else {
        return wait_for_open_implement_call(e3, agent)
            .map(Some)
            .ok_or_else(|| "the transcript never showed an open implement model call".to_owned());
    };
    let marker = crash_marker(boundary);
    let until = Instant::now() + CRASH_DEADLINE;
    loop {
        let log = std::fs::read_to_string(armed.log(&e3.node)).unwrap_or_default();
        if let Some(line) = log
            .lines()
            .find(|line| line.contains(&marker) && line.contains("action=stop"))
        {
            cell.oracle.note(format!("control: {line}"));
            break;
        }
        if Instant::now() >= until {
            return Err(format!(
                "the {} never printed `{marker}` with action=stop",
                armed.name()
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let pid = armed.pid(&e3.node);
    let states = stopped_thread_states(pid, Duration::from_secs(10));
    cell.oracle.note(format!(
        "control: the {} (pid {pid}), every thread's state {states:?}",
        armed.name()
    ));
    // Every thread is stopped, so nothing writes the log after this read.
    let log = std::fs::read_to_string(armed.log(&e3.node)).unwrap_or_default();
    judge_host_stop(&log, &states, boundary)
        .map_err(|why| format!("the {}: {why}", armed.name()))?;
    Ok(None)
}

/// The host column's agent: a provider-backed one. The mock lives in the test process,
/// which the machine's kill ends, so the resumed node would reach no model.
pub(crate) fn host_agent() -> E3Agent {
    let agent = E3Agent::selected();
    assert!(
        agent != E3Agent::Mock,
        "{TEST}: the host column needs a model that survives the machine's kill: set \
         KATA_E3_AGENT to nanocode-openai or nanocode-anthropic, with KATA_E3_FUNDED=1"
    );
    agent
}

/// The local forge's `reference-transaction` hook: once a ref update is committed, and before
/// receive-pack acknowledges the push, fsync each updated ref file and its directory.
/// Measured (git 2.56, 11-11): with `core.fsync=all` alone git fsyncs each loose object and
/// the ref's lock file, but links the objects into place and renames the lock AFTER its last
/// fsync, so a power loss inside the file system's commit window could still drop an
/// acknowledged ref. A local push does not forward its `-c` settings (kata's
/// `core.hooksPath=/dev/null` among them) to receive-pack, so the bare's own hook runs.
pub(crate) const FORGE_DURABLE_HOOK: &str = "#!/bin/sh\n\
     [ \"$1\" = committed ] || exit 0\n\
     while read -r _old _new ref; do\n\
     \tif [ -e \"$ref\" ]; then sync \"$ref\" || exit 1; fi\n\
     \tsync \"$(dirname \"$ref\")\" || exit 1\n\
     done\n";

/// Make the host column's local forge one that keeps what it acknowledged, as a real forge on
/// another machine does: its bare repository fsyncs every object and ref it receives
/// (`core.fsync=all`, `core.fsyncMethod=fsync`, [`FORGE_DURABLE_HOOK`]); the fake `gh` fsyncs
/// `gh.log` after each call ([`write_gh_shim`]). The forge still shares the machine's file
/// system, so its fsync also commits the journal transaction that holds kata's pending
/// metadata (never kata's unflushed file data): stated beside P4-host, not hidden.
pub(crate) fn keep_what_the_forge_acknowledges(cell: &mut Cell, remote: &Path) {
    for (key, value) in [("core.fsync", "all"), ("core.fsyncMethod", "fsync")] {
        let out = kata_test_utils::git::hermetic_git_in(remote)
            .args(["config", key, value])
            .output()
            .expect("git config runs");
        assert!(
            out.status.success(),
            "{TEST}: `git config {key} {value}` in the forge failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let hook = remote.join("hooks/reference-transaction");
    std::fs::create_dir_all(remote.join("hooks")).unwrap();
    std::fs::write(&hook, FORGE_DURABLE_HOOK).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    cell.oracle.note(
        "forge: the local bare fsyncs what it acknowledges (core.fsync=all, \
         core.fsyncMethod=fsync, a reference-transaction hook fsyncing each committed ref and \
         its directory); the fake gh fsyncs gh.log after each call",
    );
}

/// The worker's established TCP sockets as the kernel lists them (`ss -tinpH state
/// established`, the lines naming `pid`), RECORDED beside P2's in-flight control. That
/// control is read from kata's own SSE progress frames; this read is not judged, because a
/// kept-alive connection is established with no request in flight.
pub(crate) fn note_kernel_sockets(cell: &mut Cell, who: &str, pid: u32) {
    let listed = std::process::Command::new("ss")
        .args(["-tinpH", "state", "established"])
        .output();
    let line = match listed {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let needle = format!("pid={pid},");
            let mut mine = Vec::new();
            let mut lines = text.lines().peekable();
            while let Some(line) = lines.next() {
                if line.contains(&needle) {
                    // `-i` prints each socket's TCP counters on the line after it.
                    let detail = lines.next_if(|next| next.starts_with(char::is_whitespace));
                    mine.push(match detail {
                        Some(detail) => format!("{} | {}", line.trim(), detail.trim()),
                        None => line.trim().to_owned(),
                    });
                }
            }
            format!("{} established socket(s): {mine:?}", mine.len())
        }
        Ok(out) => format!("ss exited {}", out.status),
        Err(err) => format!("ss did not run: {err}"),
    };
    cell.oracle.note(format!(
        "kernel (recorded, not judged): {who} (pid {pid}) at the kill: {line}"
    ));
}

/// Freeze every node process (SIGSTOP the main and the worker; the armed one may already be
/// stopped at its point) and require every thread of each to read `T`: from here until the
/// machine dies, nothing of kata writes its database, its transcript frames or its forge.
/// The case's pre-kill state is read after this, so it is the state the kill finds.
pub(crate) fn freeze_node(cell: &mut Cell, node: &Node) -> Result<(), String> {
    for (who, pid) in [("main", node.main.child.id()), ("worker", node.worker.pid)] {
        let sent = std::process::Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status()
            .expect("kill runs");
        if !sent.success() {
            return Err(format!("SIGSTOP to the {who} (pid {pid}) failed: {sent}"));
        }
        let states = stopped_thread_states(pid, Duration::from_secs(10));
        cell.oracle.note(format!(
            "control: froze the {who} (pid {pid}) before the kill; every thread's state {states:?}"
        ));
        if !all_stopped(&states) {
            return Err(format!("the {who} did not stop (thread states {states:?})"));
        }
    }
    Ok(())
}

/// The P1-host / P3-host pre-kill state: `plan`'s attempt carries no `failed` transition
/// (read raw, the node frozen), so a settlement the resume finds was made after the
/// restart, not by a leg (the worker's missed heartbeats) that ran before the kill. Admits
/// exactly a read that found no row ([`raw_failed_transition`]'s `Ok(None)`); a recorded
/// settlement and a read that failed each refuse (the caller records the cell VOID).
pub(crate) fn judge_unsettled_at_kill(read: &Result<Option<String>, String>) -> Result<(), String> {
    match read {
        Ok(None) => Ok(()),
        Ok(Some(reason)) => Err(format!(
            "plan's attempt was already settled before the kill: {reason}"
        )),
        Err(error) => Err(format!(
            "the pre-kill raw read of plan's failed transition failed: {error}"
        )),
    }
}

/// P4-host's forge, read before the restarted main boots, against what the arm phase read
/// with the node frozen: the same one `kata/<exec>` ref, a forge `git fsck` that holds, and
/// no pull request yet. Any other read means the forge lost or changed what it had
/// acknowledged, so the cell would judge the forge, not kata: the caller records it VOID.
pub(crate) fn judge_forge_kept(
    at_arm: &[String],
    before_boot: &[String],
    fsck: &Result<(), String>,
    creates_before_boot: usize,
) -> Result<(), String> {
    if at_arm.len() != 1 {
        return Err(format!(
            "the arm phase did not see exactly one acknowledged kata/<exec> ref: {at_arm:?}"
        ));
    }
    if before_boot != at_arm {
        return Err(format!(
            "the forge lost an acknowledged push: kata/<exec> {before_boot:?} after the restart, \
             {at_arm:?} before the kill"
        ));
    }
    if let Err(why) = fsck {
        return Err(format!(
            "the forge's git fsck failed after the restart: {why}"
        ));
    }
    if creates_before_boot != 0 {
        return Err(format!(
            "the forge already holds {creates_before_boot} pull request(s) before the main boots"
        ));
    }
    Ok(())
}

/// `git fsck --full` of the forge's bare repository: Ok, or its exit and first stderr line.
pub(crate) fn forge_fsck(remote: &Path) -> Result<(), String> {
    let out = kata_test_utils::git::hermetic_git_in(remote)
        .args(["fsck", "--full", "--no-progress"])
        .output()
        .expect("git fsck runs");
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "exit {:?}: {}",
            out.status.code(),
            first_line(&String::from_utf8_lossy(&out.stderr))
        ))
    }
}

/// Flush every file system before the run is submitted. The fixture repository, the
/// provisioned provider and the booted node exist BEFORE a real run starts, but the rig wrote
/// them seconds ago, and a guest file system holds new data in its page cache for up to
/// `dirty_expire_centisecs` (30 s by default): without this, the machine kill would lose the
/// rig's own setup and judge that, not what the RUN left unflushed. Nothing here flushes
/// anything the run writes: the kill lands after the submit.
pub(crate) fn sync_before_the_run(cell: &mut Cell) {
    let status = std::process::Command::new("sync")
        .status()
        .expect("sync runs");
    assert!(
        status.success(),
        "{TEST}: sync before the run failed: {status}"
    );
    cell.oracle.note(
        "control: sync(1) before the submit: the fixture, the provider and the booted node \
         are on disk; the run's own writes are not flushed by the rig",
    );
}

/// The case's state with the node frozen, right before the kill, or the VOID reason:
/// P1-host / P3-host, `plan`'s attempt unsettled in the raw database, read outside kata
/// ([`judge_unsettled_at_kill`]); P2-host, the implement call still open in the client-side
/// transcript of kata's own progress frames (the kernel's sockets recorded beside it, not
/// judged); P4-host, the forge holding exactly one `kata/<exec>` and no pull request.
pub(crate) fn host_pre_kill(
    cell: &mut Cell,
    e3: &E3Node,
    agent: E3Agent,
    case: &str,
    execution: &str,
    open_assignment: Option<&str>,
    forge_refs: &[String],
) -> Result<(), String> {
    match case {
        "P1-host" | "P3-host" => {
            let failed = raw_failed_transition(&e3.node.root_path.join("data"), execution, "plan");
            cell.oracle.note(format!(
                "control: frozen, before the kill: plan attempt state {:?}, raw failed `plan` \
                 transition {failed:?}",
                plan_attempt_state(&e3.node, execution)
            ));
            judge_unsettled_at_kill(&failed)
        }
        "P2-host" => {
            let assignment = open_assignment.expect("P2-host's control returns the open call");
            let calls = calls_of(&e3.sse.events(), assignment, agent.call_markers());
            cell.oracle.note(format!(
                "control: frozen, before the kill: implement {assignment}: started {}, \
                 completed {}, open {}",
                calls.started, calls.completed, calls.open
            ));
            note_kernel_sockets(cell, "the worker", e3.node.worker.pid);
            require(
                calls.open,
                "the implement call closed before the node froze",
            )
        }
        "P4-host" => {
            let creates = gh_creates(&e3.node);
            cell.oracle.note(format!(
                "control: frozen, before the kill: the forge's kata/<exec> {forge_refs:?}; pull \
                 requests for kata/<exec> {creates}"
            ));
            require(
                forge_refs.len() == 1,
                "the forge did not acknowledge exactly one kata/<exec> push",
            )?;
            require(creates == 0, "a pull request was opened before the kill")
        }
        other => Err(format!("no host case {other}")),
    }
}

/// The host-column arm phase: boot on the persistent disk with a forge that keeps what it
/// acknowledged, reach the point with the armed process STOPPED there (P2-host: the open
/// model call), freeze the whole node, read the case's pre-kill state ([`host_pre_kill`]),
/// save the state, run the kill command, which must not return. A control that does not
/// hold is recorded VOID.
pub(crate) fn host_arm(case: &'static str, process: Armed, boundary: Option<&str>) {
    let agent = host_agent();
    let command = std::env::var("KATA_E3_HOST_KILL_CMD").unwrap_or_else(|_| {
        panic!(
            "{TEST}: {case} needs KATA_E3_HOST_KILL_CMD, a shell command that kills the whole \
             machine this node runs on (it must not return); the host column never skips"
        )
    });
    let state_dir = host_state_dir();
    let root_path = state_dir.join(case);
    assert!(
        !root_path.exists(),
        "{TEST}: {} exists: a host cell arms on a fresh node root",
        root_path.display()
    );
    let mut cell = Cell::new(case, agent);
    let env = match boundary {
        Some(boundary) => {
            armed(boundary, Some("stop")).unwrap_or_else(|refusal| panic!("{TEST}: {refusal}"))
        }
        None => Vec::new(),
    };
    let shape = node_shape(&root_path, agent);
    let e3 = boot_e3(node_root_at(&root_path), agent, (process, &env));
    cell.attach(&e3);
    keep_what_the_forge_acknowledges(&mut cell, &e3.node.fixture.remote);
    sync_before_the_run(&mut cell);
    let execution = submit(&e3);
    cell.oracle.note(format!("execution {execution}"));
    if case == "P4-host" {
        let gate = e3
            .node
            .main
            .next_gate(&execution)
            .expect("the approve stage parks a gate");
        e3.node.main.decide(&gate, None);
    }
    let open_assignment = match host_arm_control(&mut cell, &e3, agent, process, boundary) {
        Ok(open) => open,
        Err(void) => {
            cell.finish(&Ended::Void(void));
            return;
        }
    };
    if let Err(void) = freeze_node(&mut cell, &e3.node) {
        cell.finish(&Ended::Void(void));
        return;
    }
    let forge_refs_at_arm = remote_export_refs(&e3.node.fixture, &execution);
    let pre_kill = host_pre_kill(
        &mut cell,
        &e3,
        agent,
        case,
        &execution,
        open_assignment.as_deref(),
        &forge_refs_at_arm,
    );
    if let Err(void) = pre_kill {
        cell.finish(&Ended::Void(void));
        return;
    }
    let state = HostState {
        case: case.to_owned(),
        agent: agent.harness().to_owned(),
        execution: execution.clone(),
        shape,
        started_unix_ms: u64::try_from(
            cell.started.duration_since(UNIX_EPOCH).unwrap().as_millis(),
        )
        .unwrap_or(u64::MAX),
        open_assignment,
        heads_at_arm: work_heads(&e3.node, &execution),
        forge_refs_at_arm,
    };
    let state_path = state_dir.join(format!("{case}.json"));
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    std::fs::write(
        root_path.join("arm-oracle.txt"),
        cell.oracle.lines.join("\n"),
    )
    .unwrap();
    eprintln!(
        "E3 {case}: armed; state {}; running KATA_E3_HOST_KILL_CMD",
        state_path.display()
    );
    let ran = std::process::Command::new("sh")
        .args(["-c", &command])
        .env("KATA_E3_MAIN_PID", e3.node.main.child.id().to_string())
        .env("KATA_E3_WORKER_PID", e3.node.worker.pid.to_string())
        .env("KATA_E3_NODE_ROOT", &root_path)
        .status();
    std::thread::sleep(Duration::from_secs(120));
    panic!(
        "{TEST}: {case}: KATA_E3_HOST_KILL_CMD returned ({ran:?}) and the machine is still up \
         120 s later: the host kill did not happen"
    );
}

/// The host-column resume phase: the machine restarted on the same disk. Read what
/// the arm phase left BEFORE anything boots (P2-host: the arm transcript, every frame of
/// which preceded the kill), boot the main, then the worker, and judge.
pub(crate) fn host_resume(case: &'static str, state_path: &Path) {
    let state: HostState = serde_json::from_slice(&std::fs::read(state_path).unwrap())
        .expect("the host state decodes");
    assert_eq!(state.case, case, "{TEST}: the state file is another case's");
    let agent = host_agent();
    assert_eq!(
        state.agent,
        agent.harness(),
        "{TEST}: resume with the agent the arm phase ran"
    );
    let mut cell = Cell::new(case, agent);
    cell.started = UNIX_EPOCH + Duration::from_millis(state.started_unix_ms);
    if let Ok(arm) = std::fs::read_to_string(state.shape.root.join("arm-oracle.txt")) {
        for line in arm.lines() {
            cell.oracle.note(format!("arm: {line}"));
        }
    }
    let execution = state.execution.clone();
    let transcript = state.shape.root.join("sse-transcript.txt");
    let arm_calls = state.open_assignment.as_ref().map(|assignment| {
        let events = parse_transcript(&std::fs::read_to_string(&transcript).unwrap_or_default());
        let calls = calls_of(&events, assignment, agent.call_markers());
        cell.oracle.note(format!(
            "control (post hoc, the arm transcript): implement {assignment}: started {}, \
             completed {}, open {}",
            calls.started, calls.completed, calls.open
        ));
        calls
    });
    // The forge as the restarted machine holds it, read BEFORE the main boots: what the
    // resume judges is kata's recovery against that forge, never a forge the kill rolled back.
    let forge = fixture_at(&state.shape.root);
    let refs_before_boot = remote_export_refs(&forge, &execution);
    let fsck = forge_fsck(&forge.remote);
    let creates_before_boot = gh_creates_in(&state.shape.root.join("gh.log"));
    cell.oracle.note(format!(
        "the forge after the restart, before the main boots: kata/<exec> {refs_before_boot:?}; \
         git fsck {fsck:?}; pull requests for kata/<exec> {creates_before_boot}; at the kill \
         {:?}",
        state.forge_refs_at_arm
    ));
    if case == "P4-host"
        && let Err(void) = judge_forge_kept(
            &state.forge_refs_at_arm,
            &refs_before_boot,
            &fsck,
            creates_before_boot,
        )
    {
        cell.finish(&Ended::Void(void));
        return;
    }
    let root = node_root_at(&state.shape.root);
    let provider = provider_for(root.path());
    // The restarted node may not come back (its main refusing recovery and exiting): that is
    // the cell's outcome, recorded as the process column's `not_restarted`, never a panic
    // that leaves no record.
    let booted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let main_only = boot_node_main(
            root,
            fixture_at(&state.shape.root),
            state.shape.environment.clone(),
            state.shape.agents.clone(),
            &[AGENT_LABEL],
            "e3-crash-matrix",
            provider,
            &[],
        );
        let sse = SseRecorder::start(main_only.main.port(), transcript.clone());
        let node = main_only.start_worker();
        E3Node {
            sse,
            pack: state.shape.root.join("change.star"),
            node,
            model: None,
        }
    }));
    let mut e3 = match booted {
        Ok(e3) => e3,
        Err(panic) => {
            let events =
                parse_transcript(&std::fs::read_to_string(&transcript).unwrap_or_default());
            cell.transcript = Some(transcript);
            let serve =
                std::fs::read_to_string(state.shape.root.join("serve.log")).unwrap_or_default();
            let exit = main_exit_line(&serve);
            cell.oracle.note(format!(
                "the restarted main's last `Error:` line (serve.log): {exit:?}"
            ));
            let calls = uncompleted_calls(&events, agent.call_markers());
            let ended = not_restarted(&mut cell, panic_text(&*panic), exit, &calls);
            cell.finish(&ended);
            return;
        }
    };
    cell.attach(&e3);
    cell.oracle.note(format!(
        "resumed execution {execution} on {} after the machine restarted",
        state.shape.root.display()
    ));
    let ended = match case {
        "P1-host" => judge_p1(&mut cell, &mut e3, &execution),
        "P3-host" => judge_p3(&mut cell, &mut e3, &execution, None),
        "P4-host" => judge_p4(&mut cell, &mut e3, &execution),
        "P2-host" => {
            let calls = arm_calls.expect("the P2-host arm phase saved its open assignment");
            let doc = e3.node.main.wait_terminal(&execution);
            if calls.open {
                judge_p2(
                    &mut cell,
                    &mut e3,
                    &execution,
                    P2Restart::MainRestarted,
                    &calls,
                    &state.heads_at_arm,
                    &doc,
                )
            } else {
                Ended::Void(
                    "the arm transcript shows no open implement model call at the host kill"
                        .to_owned(),
                )
            }
        }
        other => panic!("{TEST}: no host case {other}"),
    };
    cell.finish(&ended);
}

pub(crate) fn host_cell(case: &'static str, armed: Armed, boundary: Option<&'static str>) {
    match std::env::var_os("KATA_E3_HOST_RESUME") {
        Some(state) => host_resume(case, Path::new(&state)),
        None => host_arm(case, armed, boundary),
    }
}
