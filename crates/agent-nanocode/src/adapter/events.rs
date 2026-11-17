//! nanocode's agent events folded into what kata keeps of a turn: the usage
//! summed per model call (the metering source), the model the provider
//! reported, the bounded evidence record, and the ephemeral progress
//! observations.
//!
//! Usage is summed over `model.call.completed`, not read from `TurnResult`
//! alone, so a cancelled or ambiguous turn keeps the spend observed so far, and
//! a turn on which no call reported usage stays `None` — never a zero.

use std::sync::Arc;

use kata_agent::adapter::FailedTurnCharge;
use kata_agent::adapter::scope::{ObservationClass, SessionObservation, SessionProgressSink};
use kata_types::agent::{SESSION_EVIDENCE_EVENTS, SessionEvidence, SessionEvidenceEvent};
use kata_types::cache::TokenUsage;
use kata_types::effect::ProviderFailureClass;
use kata_types::redaction::{LiftedSecrets, RollingScrub, elide};
use nanocode_backend_codex::events::{
    AgentEvent, AgentEventKind, AssistantDelta, ModelCallCompleted, ModelCallFailed, RunError,
    ToolCall, ToolNotification,
};
use smol_str::SmolStr;

/// The records one turn's end makes at most, which the evidence bound keeps
/// room for: the `KillAll` that did not complete (`TurnEnd`) and the Code Mode
/// workers live after the harness's shutdown (`CodeModeWorkersLive`).
const TURN_END_RECORDS: usize = 2;

/// What one session has observed.
#[derive(Debug, Default)]
pub(crate) struct Observed {
    usage: Option<TokenUsage>,
    model: Option<SmolStr>,
    events: Vec<SessionEvidenceEvent>,
    events_dropped: u32,
    /// `model.call.completed` events seen, whether or not each reported usage.
    calls_completed: u32,
    /// `model.attempt.retrying` events seen: attempts the harness sent again.
    attempts_retried: u32,
    /// The session's assistant deltas, scrubbed as ONE stream: a lifted value
    /// the provider splits across deltas is in no single delta.
    delta_scrub: RollingScrub,
}

impl Observed {
    /// The usage summed over every call that reported it, or `None`.
    pub(crate) const fn usage(&self) -> Option<TokenUsage> {
        self.usage
    }

    /// What a turn its provider failed with `class` is charged, never less than
    /// the provider billed. A known charge only when no response stream of
    /// the turn can have billed output kata never saw: the provider REFUSED
    /// the failing request (an error answer, no output) and nanocode re-sent
    /// no attempt of any call (a re-sent attempt may be one whose stream was
    /// cut after it billed, and no event reports an unfinished attempt's
    /// usage). Then the charge is the usage the completed calls reported, or
    /// nothing at all when none completed. Every other failure — a transient
    /// one, or any turn with a re-sent attempt — is UNKNOWN, whatever the
    /// completed calls reported: since nanocode 8ec3b215 a stream cut
    /// mid-response is transient and re-sent, each re-send possibly billed.
    pub(crate) const fn failed_turn_charge(&self, class: ProviderFailureClass) -> FailedTurnCharge {
        if !matches!(class, ProviderFailureClass::Refused) || self.attempts_retried > 0 {
            return FailedTurnCharge::Unknown;
        }
        match self.usage {
            Some(usage) => FailedTurnCharge::Metered(usage),
            None if self.calls_completed == 0 => FailedTurnCharge::Nothing,
            None => FailedTurnCharge::Unknown,
        }
    }

    /// The model the last completed call reported.
    pub(crate) fn model(&self) -> Option<SmolStr> {
        self.model.clone()
    }

    /// Drain the evidence record.
    pub(crate) fn take_evidence(&mut self) -> SessionEvidence {
        SessionEvidence {
            events: std::mem::take(&mut self.events),
            events_dropped: std::mem::take(&mut self.events_dropped),
            scratch_commits: Vec::new(),
        }
    }

    /// Take the turn-end records (`TurnEnd`, `CodeModeWorkersLive`) the record
    /// still holds, leaving every other event: what a turn end recorded after
    /// the caller last drained the evidence, which `close` reports instead.
    pub(crate) fn take_turn_end(&mut self) -> Vec<SessionEvidenceEvent> {
        let (turn_end, rest) = std::mem::take(&mut self.events)
            .into_iter()
            .partition(|event| {
                matches!(
                    event,
                    SessionEvidenceEvent::TurnEnd { .. }
                        | SessionEvidenceEvent::CodeModeWorkersLive { .. }
                )
            });
        self.events = rest;
        turn_end
    }

    /// Record a step of the turn's end that did not complete as planned.
    pub(crate) fn turn_end(&mut self, step: &'static str, outcome: &'static str) {
        self.record_turn_end(SessionEvidenceEvent::TurnEnd {
            step: SmolStr::new_static(step),
            outcome: SmolStr::new_static(outcome),
        });
    }

    /// Record the Code Mode workers live in the process once the turn's end
    /// has shut the harness down.
    pub(crate) fn code_mode_workers_live(&mut self, live: usize) {
        self.record_turn_end(SessionEvidenceEvent::CodeModeWorkersLive {
            live: u64::try_from(live).unwrap_or(u64::MAX),
        });
    }

    /// A turn's events, bounded below [`SESSION_EVIDENCE_EVENTS`] by the
    /// [`TURN_END_RECORDS`] its end may still need.
    fn record(&mut self, event: SessionEvidenceEvent) {
        if self.events.len() < SESSION_EVIDENCE_EVENTS - TURN_END_RECORDS {
            self.events.push(event);
        } else {
            self.events_dropped = self.events_dropped.saturating_add(1);
        }
    }

    /// A turn end's record, into the room [`Self::record`] leaves, so a turn
    /// whose events filled the record still records its end.
    fn record_turn_end(&mut self, event: SessionEvidenceEvent) {
        if self.events.len() < SESSION_EVIDENCE_EVENTS {
            self.events.push(event);
        } else {
            self.events_dropped = self.events_dropped.saturating_add(1);
        }
    }

    /// Fold one nanocode event. A payload that does not decode is recorded as a
    /// notice by its kind and folded no further: it can neither add usage nor
    /// name a model.
    pub(crate) fn fold(
        &mut self,
        event: &AgentEvent,
        secrets: &LiftedSecrets,
        progress: Option<&Arc<dyn SessionProgressSink>>,
    ) {
        // Every nanocode event is a lifecycle fact the transcript reads (a
        // model call's start, end or failure, a tool call or result, a limit,
        // a run error) — except the assistant's text deltas, the one stream.
        let observe = |kind: &'static str, text: Option<String>| {
            if let Some(sink) = progress {
                let class = if kind == "agent_message_chunk" {
                    ObservationClass::Stream
                } else {
                    ObservationClass::Milestone
                };
                sink.observe(SessionObservation { kind, text, class });
            }
        };
        match event.kind {
            AgentEventKind::AssistantDelta => {
                if let Ok(delta) = event.decode_payload::<AssistantDelta>() {
                    // What the stream may still turn into a lifted value is
                    // held back; a delta that releases nothing observes nothing.
                    let released = self.delta_scrub.push(secrets, &delta.text);
                    if !released.is_empty() {
                        observe("agent_message_chunk", Some(elide(&released)));
                    }
                }
            }
            AgentEventKind::ModelCallStarted => observe("model_call_started", None),
            AgentEventKind::ModelAttemptRetrying => {
                self.attempts_retried = self.attempts_retried.saturating_add(1);
            }
            AgentEventKind::ModelCallCompleted => {
                self.calls_completed = self.calls_completed.saturating_add(1);
                let Ok(completed) = event.decode_payload::<ModelCallCompleted>() else {
                    self.record(SessionEvidenceEvent::Notice {
                        method: SmolStr::new_static("model.call.completed"),
                    });
                    return;
                };
                if let Some(reported) = completed.usage.as_ref() {
                    let details = reported.input_tokens_details.as_ref();
                    let cached = details.map_or(0, |details| details.cached_tokens);
                    let written = details.map_or(0, |details| details.cache_write_tokens);
                    let call = TokenUsage {
                        // The reported `input_tokens` INCLUDES the cache read
                        // AND the cache write — nanocode's Claude backend sums
                        // the Messages API's three input classes into it, and
                        // OpenAI's prompt count holds both details — while
                        // kata's four classes are disjoint: `input` is the
                        // uncached part alone.
                        input: reported
                            .input_tokens
                            .saturating_sub(cached)
                            .saturating_sub(written),
                        output: reported.output_tokens,
                        cache_read: cached,
                        cache_write: written,
                    };
                    let sum = self.usage.get_or_insert_with(TokenUsage::default);
                    sum.input = sum.input.saturating_add(call.input);
                    sum.output = sum.output.saturating_add(call.output);
                    sum.cache_read = sum.cache_read.saturating_add(call.cache_read);
                    sum.cache_write = sum.cache_write.saturating_add(call.cache_write);
                }
                let model = secrets.bound_field(&completed.model);
                self.model = Some(model.clone());
                self.record(SessionEvidenceEvent::ModelCall {
                    model,
                    outcome: SmolStr::new_static("completed"),
                });
                observe("model_call_completed", None);
            }
            AgentEventKind::ModelCallFailed => {
                let Ok(failed) = event.decode_payload::<ModelCallFailed>() else {
                    return;
                };
                self.record(SessionEvidenceEvent::ModelCall {
                    model: secrets.bound_field(&failed.model),
                    outcome: SmolStr::new_static("failed"),
                });
                observe("model_call_failed", Some(secrets.bound(&failed.error)));
            }
            AgentEventKind::ToolCall => {
                let Ok(call) = event.decode_payload::<ToolCall>() else {
                    return;
                };
                self.record(SessionEvidenceEvent::ToolCall {
                    id: secrets.bound_field(&call.call_id),
                });
                observe("tool_call", Some(secrets.bound(&call.tool)));
            }
            AgentEventKind::ToolResult => {
                // Read as `ToolResultHead`, the two fields kata records: the
                // kinds' `result` shapes differ (the Responses kind's tool
                // output; the Messages kind's `{text}` or `{content_blocks}`),
                // and `refused_a_worker` reads the raw payload of either.
                if let Ok(result) = event.decode_payload::<ToolResultHead>() {
                    self.record(SessionEvidenceEvent::ToolResult {
                        id: secrets.bound_field(&result.call_id),
                        status: SmolStr::new_static(result.status.as_str()),
                    });
                    observe("tool_result", Some(secrets.bound(&result.call_id)));
                }
                if event
                    .decode_payload::<serde_json::Value>()
                    .ok()
                    .as_ref()
                    .is_some_and(refused_a_worker)
                {
                    self.record(SessionEvidenceEvent::CodeModeLimit {
                        which: SmolStr::new_static("workers"),
                    });
                    observe("code_mode_limit", Some("workers".to_owned()));
                }
            }
            AgentEventKind::ToolNotification => {
                let Ok(notification) = event.decode_payload::<ToolNotification>() else {
                    return;
                };
                if let Some(which) = guard_report(&notification.text) {
                    self.record(SessionEvidenceEvent::CodeModeLimit {
                        which: SmolStr::new_static(which),
                    });
                    observe("code_mode_limit", Some(which.to_owned()));
                }
                // The interpreter process's supervisor reports an end the
                // same way, just before the cell's error
                // (`kata_code_mode_host::Ended`).
                if let Some(ended) = kata_code_mode_host::Ended::from_report(&notification.text) {
                    let signal = match ended {
                        kata_code_mode_host::Ended::Signal(name) => Some(SmolStr::new(name)),
                        kata_code_mode_host::Ended::Exit(_) => None,
                    };
                    self.record(SessionEvidenceEvent::CodeModeInterpreterEnded {
                        signal: signal.clone(),
                    });
                    observe(
                        "code_mode_interpreter_ended",
                        Some(signal.map_or_else(|| "exit".to_owned(), |name| name.to_string())),
                    );
                }
            }
            AgentEventKind::RunError | AgentEventKind::RunFailed => {
                self.record(SessionEvidenceEvent::Notice {
                    method: SmolStr::new_static("run.error"),
                });
                let message = event
                    .decode_payload::<RunError>()
                    .map(|error| secrets.bound(&error.message))
                    .ok();
                observe("run_error", message);
            }
            _ => {}
        }
    }
}

/// The fields of a `tool.result` kata records, in either kind's payload: the
/// call's id and nanocode's status word. Nothing of the result is read here,
/// so the Responses kind's tool output and the Messages kind's `{text}` /
/// `{content_blocks}` decode alike (nanocode 8ec3b215: the codex backend's
/// `ToolResultEvent`, the claude backend's `tool.result` object).
#[derive(serde::Deserialize)]
struct ToolResultHead {
    call_id: String,
    status: ToolResultStatus,
}

/// nanocode's status words for a tool result: the codex backend's
/// `ToolStatus` (`completed`, `failed`, `cancelled`), and the claude backend's
/// `unknown`, for a call whose outcome its interruption left unknown. A
/// payload with another word records no `ToolResult`.
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ToolResultStatus {
    Completed,
    Failed,
    Cancelled,
    Unknown,
}

impl ToolResultStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

/// The Code Mode limit a guard's report names: `wall`, `output`, `memory` or
/// `stack`, or `None` for any other text.
///
/// Just before the error of a cell that failed on its wall, output, memory or
/// interpreter stack limit, a report of that limit is sent as a Code Mode
/// notification of its own (the heap's and the output's by the vendored
/// engine, `vendor/nanocode-code-mode-engine.patch`: `report_out_of_memory`,
/// `ExecutionState::queue`; the wall's and the stack's by the interpreter
/// process, `kata_code_mode_host`'s `interpreter`), and
/// nanocode emits every notification as a `tool.notification` event on both
/// kinds, whatever it then shows the model.
/// So the report reaches this fold however much text the cell emitted before
/// it: nanocode's truncation of the cell's visible result, which drops the
/// trailing `Script error:` past its budget, never touches the event. The
/// failed result's own text is not read for these limits, so one hit is one
/// record. A report is the whole text, exactly: `Code Mode cell exceeded its
/// <n> ms wall-time limit`, `Code Mode cell output exceeded its <n>-byte
/// limit`, `Code Mode cell exceeded its <n>-byte memory limit`, `Code Mode cell
/// exceeded its interpreter stack limit` (djs's stack limit is its own, a
/// slot count, so its report names no size), and `Code Mode cell exceeded its
/// <n>-byte native stack limit`, the supervisor's report of a native recursion
/// that overflowed the interpreter's cell thread (`thread_stack_bytes`) and so
/// ended the interpreter, sent just before its report of that end
/// (`kata_code_mode_host::native_stack_report`): both are `stack`.
///
/// What else reads as a report, stated: a cell whose own `notify` sends one of
/// those texts (recorded as a hit, though none happened), and a cell that
/// throws, uncaught, an error named and worded as djs's `RangeError: Maximum
/// call stack size exceeded` (the interpreter reads a failure off its first
/// line). What reads as none: a stack hit the cell catches and rethrows inside
/// an error of its own, which fails to the model as that error and is recorded
/// nowhere (`tests/code_mode_limits.rs`). A heap hit is never caught: djs ends
/// the cell, and the engine reports it. This is progress and evidence, never
/// authority. A cell that
/// yielded and failed on a limit while no `wait` observed it has its report
/// delivered when nanocode ends the turn's cells, which on a completed or
/// cancelled turn precedes the turn's outcome, so it is recorded then, told to
/// no model
/// (`a_yielded_cell_no_wait_observes_is_recorded_at_the_turn_end_and_told_to_no_one`).
/// Read from nanocode, not measured: a Responses-kind turn that fails with no
/// tool call in flight detaches its cells instead, and a report they deliver
/// after the outcome reaches no fold.
fn guard_report(text: &str) -> Option<&'static str> {
    let limit =
        |digits: &str| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit());
    if let Some(rest) = text.strip_prefix("Code Mode cell output exceeded its ") {
        return rest
            .strip_suffix("-byte limit")
            .is_some_and(limit)
            .then_some("output");
    }
    let rest = text.strip_prefix("Code Mode cell exceeded its ")?;
    if rest.strip_suffix(" ms wall-time limit").is_some_and(limit) {
        Some("wall")
    } else if rest.strip_suffix("-byte memory limit").is_some_and(limit) {
        Some("memory")
    } else if rest == "interpreter stack limit"
        || rest
            .strip_suffix("-byte native stack limit")
            .is_some_and(limit)
    {
        Some("stack")
    } else {
        None
    }
}

/// Whether a `tool.result` is the vendored guard's refusal of a worker past
/// the process's live-worker cap: a FAILED `exec` result whose last text is
/// the spawn's error, appended bare by nanocode (`this process already runs
/// <n> Code Mode workers, its limit: …`). No worker means no guard to report
/// it, so this is the one limit read off a result; a spawn happens only at
/// `exec`, so a `wait` result is never read for it, and a cell that never got
/// a worker emitted nothing before the refusal, which is the first text after
/// the result's header and so always within nanocode's visible budget. Read
/// in either kind's result shape (the Responses kind's tool output, the
/// Messages kind's `{text}` or `{content_blocks}`).
/// `code_mode_workers_through_adapter` drives the real guard, so a bump that
/// rewords the refusal is red there.
fn refused_a_worker(result: &serde_json::Value) -> bool {
    /// The last text of a tool output: on the Responses kind a bare string
    /// (`Text`) or the `text` of the last content item that has one
    /// (`Content`); on the Messages kind `{text}`, or the `text` of the last
    /// block of `{content_blocks}` that has one.
    fn last_text(value: &serde_json::Value) -> Option<&str> {
        match value {
            serde_json::Value::String(text) => Some(text),
            serde_json::Value::Array(items) => items.iter().rev().find_map(last_text),
            serde_json::Value::Object(item) => match item.get("content_blocks") {
                Some(blocks) => last_text(blocks),
                None => item.get("text").and_then(serde_json::Value::as_str),
            },
            _ => None,
        }
    }
    result["tool"] == "exec"
        && result["status"] == "failed"
        && last_text(&result["result"]).is_some_and(|last| {
            last.starts_with("this process already runs ")
                && last.contains(" Code Mode workers, its limit")
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use kata_agent::adapter::scope::{ObservationClass, SessionObservation, SessionProgressSink};
    use kata_types::redaction::LiftedSecrets;
    use nanocode_backend_codex::events::AgentEvent;
    use serde_json::json;

    use super::{Observed, guard_report, refused_a_worker};

    #[derive(Debug, Default)]
    struct Classes(Mutex<Vec<(&'static str, ObservationClass)>>);

    impl SessionProgressSink for Classes {
        fn observe(&self, observation: SessionObservation) {
            self.0
                .lock()
                .expect("classes lock")
                .push((observation.kind, observation.class));
        }
    }

    fn event(kind: &str, payload: serde_json::Value) -> AgentEvent {
        serde_json::from_value(json!({
            "protocol_version": 1,
            "request_id": "r",
            "seq": 0,
            "type": kind,
            "payload": payload,
        }))
        .expect("a nanocode event")
    }

    /// **The text delta is the one stream.** A model call's start and end, a
    /// tool call and its result are what a transcript counts calls by, so
    /// each is a milestone the emitter never coalesces; the assistant's delta
    /// is the only observation it may.
    #[test]
    fn only_the_assistant_delta_is_a_stream() {
        let classes = Arc::new(Classes::default());
        let sink: Arc<dyn SessionProgressSink> = classes.clone();
        let mut observed = Observed::default();
        for event in [
            event("model.call.started", json!({})),
            event(
                "assistant.delta",
                json!({"model_call_index": 0, "item_id": null, "phase": null, "text": "hi"}),
            ),
            event(
                "model.call.completed",
                json!({
                    "call_index": 0, "model": "m", "attempt": 0, "connection_generation": 0,
                    "status": "completed", "duration_ns": 1, "time_to_first_event_ns": 1,
                    "time_to_first_output_ns": null, "tool_calls": 1, "usage": null,
                }),
            ),
            event(
                "tool.call",
                json!({"call_id": "c1", "tool": "exec", "arguments": {}, "model_call_index": 0}),
            ),
        ] {
            observed.fold(&event, &LiftedSecrets::none(), Some(&sink));
        }
        assert_eq!(
            *classes.0.lock().expect("classes lock"),
            [
                ("model_call_started", ObservationClass::Milestone),
                ("agent_message_chunk", ObservationClass::Stream),
                ("model_call_completed", ObservationClass::Milestone),
                ("tool_call", ObservationClass::Milestone),
            ]
        );
    }

    fn failed_exec(text: &str) -> serde_json::Value {
        json!({
            "tool": "exec",
            "status": "failed",
            "result": [
                {"type": "input_text", "text": "Script failed"},
                {"type": "input_text", "text": text},
            ],
        })
    }

    /// **A guard report names its limit, and nothing else does.** Each of the
    /// five reports, as a whole text, is its limit (both stack reports,
    /// djs's call-stack limit's and the supervisor's of the cell thread's
    /// native stack, are `stack`); the same words with a
    /// prefix (as a failed cell's `Script error:`), a suffix, a number that is
    /// not one, the stack report in its old sized form, or an engine's own
    /// out-of-memory and stack messages are none.
    #[test]
    fn a_guard_report_names_its_limit_and_nothing_else_does() {
        for (text, which) in [
            (
                "Code Mode cell exceeded its 300000 ms wall-time limit",
                Some("wall"),
            ),
            (
                "Code Mode cell output exceeded its 8388608-byte limit",
                Some("output"),
            ),
            (
                "Code Mode cell exceeded its 268435456-byte memory limit",
                Some("memory"),
            ),
            (
                "Code Mode cell exceeded its interpreter stack limit",
                Some("stack"),
            ),
            (
                "Code Mode cell exceeded its 8388608-byte native stack limit",
                Some("stack"),
            ),
            (
                "Code Mode cell exceeded its 1048576-byte interpreter stack limit",
                None,
            ),
            ("Code Mode cell exceeded its native stack limit", None),
            ("Code Mode cell exceeded its stack limit", None),
            ("RangeError: Maximum call stack size exceeded", None),
            (
                "Script error:\nCode Mode cell exceeded its 300000 ms wall-time limit",
                None,
            ),
            (
                "Code Mode cell output exceeded its 8388608-byte limit.",
                None,
            ),
            ("Code Mode cell exceeded its ms wall-time limit", None),
            ("Code Mode cell exceeded its 3e5 ms wall-time limit", None),
            ("Code Mode cell exceeded its 256-MiB memory limit", None),
            ("InternalError: out of memory", None),
            (
                "this process already runs 8 Code Mode workers, its limit: end a running cell",
                None,
            ),
        ] {
            assert_eq!(guard_report(text), which, "{text}");
        }
        let native = kata_code_mode_host::native_stack_report(1 << 23);
        assert_eq!(
            native, "Code Mode cell exceeded its 8388608-byte native stack limit",
            "the supervisor's report is the text read above"
        );
    }

    /// **A worker refusal is read off a failed `exec` result's last text, and
    /// nothing else is.** The guard's live-worker refusal, appended bare as a
    /// spawn's error, is the cap's; the same text in a completed result, in a
    /// `wait`'s, in another tool's, behind `Script error:`, or not last is
    /// none. A guard report as a failed cell's `Script error:` is none too: the
    /// wall, output and memory limits are read off the guard's notification.
    #[test]
    fn a_worker_refusal_is_read_off_a_failed_exec_and_nothing_else_is() {
        const REFUSAL: &str = "this process already runs 8 Code Mode workers, its limit: end a \
                               running cell or wait for one to finish, then run this cell again";
        assert!(refused_a_worker(&failed_exec(REFUSAL)));
        assert!(refused_a_worker(&json!({
            "tool": "exec", "status": "failed", "result": REFUSAL,
        })));
        // The Messages kind's shapes.
        assert!(refused_a_worker(&json!({
            "tool": "exec", "status": "failed", "result": {"content_blocks": [
                {"type": "text", "text": "Script failed"},
                {"type": "text", "text": REFUSAL},
            ]},
        })));
        assert!(refused_a_worker(&json!({
            "tool": "exec", "status": "failed", "result": {"text": REFUSAL},
        })));
        let mut completed = failed_exec(REFUSAL);
        completed["status"] = json!("completed");
        let mut wait = failed_exec(REFUSAL);
        wait["tool"] = json!("wait");
        let mut other_tool = failed_exec(REFUSAL);
        other_tool["tool"] = json!("exec_command");
        let mut not_last = failed_exec(REFUSAL);
        not_last["result"]
            .as_array_mut()
            .expect("content items")
            .push(json!({"type": "input_text", "text": "after"}));
        for (label, result) in [
            ("completed", completed),
            ("wait", wait),
            ("another tool", other_tool),
            ("not last", not_last),
            (
                "behind Script error",
                failed_exec(&format!("Script error:\n{REFUSAL}")),
            ),
            (
                "a wall report as the script error",
                failed_exec("Script error:\nCode Mode cell exceeded its 300000 ms wall-time limit"),
            ),
            (
                "an out-of-memory script error",
                failed_exec("Script error:\nInternalError: out of memory"),
            ),
        ] {
            assert!(!refused_a_worker(&result), "{label}");
        }
    }

    /// **A limit is recorded once, off the guard's notification.** Folded in
    /// a turn's order, a failed `exec` result whose `Script error:` is the wall
    /// report records no limit, the guard's notification of the same report
    /// records `CodeModeLimit{wall}` and observes it once, and a notification
    /// a cell sent of any other text records nothing.
    ///
    /// **Would red if:** the fold read a result's script error as well (two
    /// records of one hit) or skipped `tool.notification`.
    #[test]
    fn a_limit_is_recorded_once_off_the_guards_notification() {
        use kata_types::agent::SessionEvidenceEvent;

        let observed_kinds = Arc::new(Observations::default());
        let sink: Arc<dyn SessionProgressSink> = observed_kinds.clone();
        let mut observed = Observed::default();
        let report = "Code Mode cell exceeded its 300000 ms wall-time limit";
        let mut result = failed_exec(&format!("Script error:\n{report}"));
        result["call_id"] = json!("c1");
        result["duration_ns"] = json!(1);
        result["started_after_ns"] = json!(null);
        result["structured_result"] = json!(null);
        result["metadata"] = json!(null);
        for event in [
            event(
                "tool.notification",
                json!({"call_id": "c1", "text": "a cell's own notice"}),
            ),
            event(
                "tool.notification",
                json!({"call_id": "c1", "text": report}),
            ),
            event("tool.result", result),
        ] {
            observed.fold(&event, &LiftedSecrets::none(), Some(&sink));
        }
        assert_eq!(
            observed.take_evidence().events,
            [
                SessionEvidenceEvent::CodeModeLimit {
                    which: "wall".into(),
                },
                SessionEvidenceEvent::ToolResult {
                    id: "c1".into(),
                    status: "failed".into(),
                },
            ]
        );
        assert_eq!(observed_kinds.limits(), ["wall"]);
    }

    /// **An interpreter process's end is recorded off its supervisor's
    /// report.** Folded in a turn's order, the supervisor's notification of an
    /// end by signal records `CodeModeInterpreterEnded{signal}` naming it, its
    /// report of an exit records one with no signal, and a notification that
    /// only starts like a report (a signal that is no name, trailing text)
    /// records nothing.
    ///
    /// **Would red if:** the fold skipped the supervisor's report, or read a
    /// text that is not a whole report as one.
    #[test]
    fn an_interpreter_end_is_recorded_off_its_supervisors_report() {
        use kata_types::agent::SessionEvidenceEvent;

        let observed_kinds = Arc::new(Observations::default());
        let sink: Arc<dyn SessionProgressSink> = observed_kinds.clone();
        let mut observed = Observed::default();
        for text in [
            "Code Mode's interpreter process ended by SIGSEGV",
            "Code Mode's interpreter process exited with status 101",
            "Code Mode's interpreter process ended by sigsegv",
            "Code Mode's interpreter process ended by SIGSEGV, said a cell",
            "Code Mode's interpreter process exited with status one",
        ] {
            observed.fold(
                &event("tool.notification", json!({"call_id": "c1", "text": text})),
                &LiftedSecrets::none(),
                Some(&sink),
            );
        }
        assert_eq!(
            observed.take_evidence().events,
            [
                SessionEvidenceEvent::CodeModeInterpreterEnded {
                    signal: Some("SIGSEGV".into()),
                },
                SessionEvidenceEvent::CodeModeInterpreterEnded { signal: None },
            ]
        );
        assert_eq!(observed_kinds.ended(), ["SIGSEGV", "exit"]);
    }

    /// **A worker refusal in the Messages kind's result shape is recorded.**
    /// That kind's `tool.result` carries its result as `{content_blocks}`; the
    /// fold records the result by its id and status, as on the Responses
    /// kind, and reads the refusal off the raw payload, recording
    /// `CodeModeLimit{workers}`.
    ///
    /// **Would red if:** the Messages shape's result went unrecorded, or the
    /// fold of a `tool.result` ended before the refusal was read.
    #[test]
    fn a_worker_refusal_in_the_messages_shape_is_recorded() {
        use kata_types::agent::SessionEvidenceEvent;

        let mut observed = Observed::default();
        observed.fold(
            &event(
                "tool.result",
                json!({
                    "call_id": "toolu_1", "tool": "exec", "status": "failed",
                    "duration_ns": 1, "started_after_ns": null, "structured_result": null,
                    "result": {"content_blocks": [
                        {"type": "text", "text": "Script failed"},
                        {"type": "text", "text": "this process already runs 2 Code Mode workers, its limit: end a running cell"},
                    ]},
                }),
            ),
            &LiftedSecrets::none(),
            None,
        );
        assert_eq!(
            observed.take_evidence().events,
            [
                SessionEvidenceEvent::ToolResult {
                    id: "toolu_1".into(),
                    status: "failed".into(),
                },
                SessionEvidenceEvent::CodeModeLimit {
                    which: "workers".into(),
                },
            ]
        );
    }

    /// **A `tool.result` is recorded under exactly nanocode's status words.**
    /// In the Messages kind's shape, `completed`, `failed`, `cancelled` and the
    /// claude backend's `unknown` (an interrupted call) each record a
    /// `ToolResult` under that word; a payload stating another word, or none,
    /// records nothing.
    ///
    /// **Would red if:** the fold recorded a status word nanocode never states,
    /// or dropped one it does.
    #[test]
    fn a_tool_result_is_recorded_under_nanocodes_status_words_only() {
        use kata_types::agent::SessionEvidenceEvent;

        let mut observed = Observed::default();
        for status in [
            json!("completed"),
            json!("failed"),
            json!("cancelled"),
            json!("unknown"),
            json!("running"),
            json!(null),
        ] {
            observed.fold(
                &event(
                    "tool.result",
                    json!({
                        "call_id": format!("toolu_{status}"), "tool": "exec", "status": status,
                        "duration_ns": 1, "started_after_ns": null,
                        "result": {"text": "a result"},
                    }),
                ),
                &LiftedSecrets::none(),
                None,
            );
        }
        assert_eq!(
            observed.take_evidence().events,
            ["completed", "failed", "cancelled", "unknown"].map(|status| {
                SessionEvidenceEvent::ToolResult {
                    id: format!("toolu_\"{status}\"").into(),
                    status: status.into(),
                }
            })
        );
    }

    /// Every observation's kind and text.
    #[derive(Debug, Default)]
    struct Observations(Mutex<Vec<(&'static str, Option<String>)>>);

    impl Observations {
        fn ended(&self) -> Vec<String> {
            self.0
                .lock()
                .expect("observations lock")
                .iter()
                .filter(|(kind, _)| *kind == "code_mode_interpreter_ended")
                .filter_map(|(_, text)| text.clone())
                .collect()
        }

        fn limits(&self) -> Vec<String> {
            self.0
                .lock()
                .expect("observations lock")
                .iter()
                .filter(|(kind, _)| *kind == "code_mode_limit")
                .filter_map(|(_, text)| text.clone())
                .collect()
        }
    }

    impl SessionProgressSink for Observations {
        fn observe(&self, observation: SessionObservation) {
            self.0
                .lock()
                .expect("observations lock")
                .push((observation.kind, observation.text));
        }
    }

    /// **A turn whose events filled the evidence record still records its
    /// end.** The record holds [`kata_types::agent::SESSION_EVIDENCE_EVENTS`]
    /// events; the turn's own events stop [`super::TURN_END_RECORDS`] short of
    /// it, counted as dropped past that, so the turn end's `TurnEnd` and
    /// `CodeModeWorkersLive` land in the record however many events came
    /// before them.
    ///
    /// **Would red if:** a turn end's record shared the turn's bound (watched:
    /// both dropped behind a full record).
    #[test]
    fn a_full_record_still_records_the_turn_end() {
        use kata_types::agent::{SESSION_EVIDENCE_EVENTS, SessionEvidenceEvent};

        let mut observed = super::Observed::default();
        let notices = SESSION_EVIDENCE_EVENTS + 10;
        for _ in 0..notices {
            observed.record(SessionEvidenceEvent::Notice {
                method: "run.error".into(),
            });
        }
        observed.turn_end("kill_all", "unconfirmed");
        observed.code_mode_workers_live(1);
        let evidence = observed.take_evidence();
        assert_eq!(evidence.events.len(), SESSION_EVIDENCE_EVENTS);
        assert_eq!(
            evidence.events[SESSION_EVIDENCE_EVENTS - 2..],
            [
                SessionEvidenceEvent::TurnEnd {
                    step: "kill_all".into(),
                    outcome: "unconfirmed".into(),
                },
                SessionEvidenceEvent::CodeModeWorkersLive { live: 1 },
            ]
        );
        assert_eq!(
            evidence.events_dropped,
            u32::try_from(notices - (SESSION_EVIDENCE_EVENTS - super::TURN_END_RECORDS))
                .expect("a small count")
        );
    }

    /// **`close` takes exactly the turn end's records.** What `close` reports
    /// (`CleanupReport::turn_end`) is the `TurnEnd` and `CodeModeWorkersLive`
    /// records still undrained, in order; every other event stays in the record
    /// for the evidence.
    ///
    /// **Would red if:** the take left a turn-end record behind or took a turn
    /// event with it.
    #[test]
    fn take_turn_end_takes_only_the_turn_ends_records() {
        use kata_types::agent::SessionEvidenceEvent;

        let mut observed = super::Observed::default();
        let notice = SessionEvidenceEvent::Notice {
            method: "run.error".into(),
        };
        observed.record(notice.clone());
        observed.turn_end("kill_all", "wire_broken");
        observed.record(notice.clone());
        observed.code_mode_workers_live(2);
        assert_eq!(
            observed.take_turn_end(),
            [
                SessionEvidenceEvent::TurnEnd {
                    step: "kill_all".into(),
                    outcome: "wire_broken".into(),
                },
                SessionEvidenceEvent::CodeModeWorkersLive { live: 2 },
            ]
        );
        assert_eq!(observed.take_evidence().events, [notice.clone(), notice]);
        assert!(observed.take_turn_end().is_empty());
    }

    /// The text of every `agent_message_chunk` the fold hands its sink.
    #[derive(Debug, Default)]
    struct Chunks(Mutex<Vec<String>>);

    impl SessionProgressSink for Chunks {
        fn observe(&self, observation: SessionObservation) {
            if observation.kind == "agent_message_chunk" {
                self.0
                    .lock()
                    .expect("chunks lock")
                    .push(observation.text.unwrap_or_default());
            }
        }
    }

    /// **A lifted value the provider splits across text deltas reaches no
    /// progress observation.** `before <value> after` is folded as assistant
    /// deltas cut at every byte through the value (two pieces) and at a spread
    /// of three-piece cuts. No chunk the sink receives carries a 4-byte window
    /// of the value, and the chunks, each unquoted, read back in order as
    /// exactly `before [redacted] after` — nothing dropped, nothing doubled.
    ///
    /// **Would red if:** the fold scrubbed each delta alone (a split value is in
    /// no single delta, so both halves pass), or dropped the text it held back.
    #[test]
    fn a_lifted_value_split_across_deltas_reaches_no_observation() {
        const VALUE: &str = "sk-fake-0123456789abcdef";
        let secrets = LiftedSecrets::new(vec![VALUE.to_owned()]);
        let stream = format!("before {VALUE} after");
        let start = "before ".len();
        let end = start + VALUE.len();
        let mut splits: Vec<Vec<usize>> = (start..=end).map(|at| vec![at]).collect();
        for first in (start..end).step_by(5) {
            for second in (first..=end).step_by(3) {
                splits.push(vec![first, second]);
            }
        }
        for cuts in splits {
            let chunks = Arc::new(Chunks::default());
            let sink: Arc<dyn SessionProgressSink> = chunks.clone();
            let mut observed = Observed::default();
            let mut from = 0;
            for to in cuts.iter().copied().chain([stream.len()]) {
                observed.fold(
                    &event(
                        "assistant.delta",
                        json!({
                            "model_call_index": 0, "item_id": null, "phase": null,
                            "text": &stream[from..to],
                        }),
                    ),
                    &secrets,
                    Some(&sink),
                );
                from = to;
            }
            let chunks = chunks.0.lock().expect("chunks lock").clone();
            for chunk in &chunks {
                for window in VALUE.as_bytes().windows(4) {
                    let window = std::str::from_utf8(window).expect("the value is ASCII");
                    assert!(
                        !chunk.contains(window),
                        "{cuts:?}: a chunk carries `{window}` of the value: {chunks:?}"
                    );
                }
            }
            let read_back: String = chunks
                .iter()
                .map(|chunk| {
                    chunk
                        .strip_prefix('`')
                        .and_then(|chunk| chunk.strip_suffix('`'))
                        .expect("a chunk is quoted whole")
                })
                .collect();
            assert_eq!(
                read_back, "before [redacted] after",
                "{cuts:?}: the chunks read back redacted, in order"
            );
        }
    }
}
