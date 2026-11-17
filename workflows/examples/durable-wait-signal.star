# durable-wait-signal — park a run until an external signal arrives, model-free.
#
# DEMONSTRATES the two ways a kata run WAITS on the outside world, durably:
#   * a BLOCKING human_request (`human_request(.., blocking=True, stage="decide",
#     timeout_ms=..)`) — the scoped stage is HELD until an operator answers the
#     question; the answer is rendered into the stage's command, then the stage
#     runs. `timeout_ms` is a self-heal deadline: if no answer arrives in time, the
#     run resumes using `default_assumption` as the effective answer, so a
#     forgotten signal can never wedge the run forever. The request is its own
#     durable INPUT WAIT (one main-side attempt, accepted once with the answer or
#     the default) and `decide`'s container starts only after it, with the answer
#     in its argv.
#   * an EXTERNAL INPUT CHANNEL (`channel("steering", expose_as="steering", ..)`)
#     — a durable side-channel an operator (or another system) appends to at any
#     time; its rows are rendered into stage prompts as `{{ external_inputs... }}`.
#
# Both survive an engine restart (the park + the channel contents are on the
# ledger), so this is a DURABLE wait on a signal, not a process-local timer.
#
# NOTE: `sleep(for_ms=..)` and `schedule(cron=..)` are the durable timer/cron
# primitives on the same surface and are wired end-to-end. This example focuses
# on human/channel signals; see the quickstart for authored sleep and schedule
# lifecycles (including schedule activation at node start).
#
# AGENTS / CONFIG
#   Shell stage -> no model/API budget. The wait needs an operator to answer the
#   blocking request (or the timeout to elapse).
#
# RUN
#   # Terminal 1, from an initialized project:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file:
#   kata check ./durable-wait-signal.star
#   kata run ./durable-wait-signal.star --submit
#   kata steer human-requests --execution-id <execution-id> --unanswered
#   kata steer answer-human-request <execution-id> proceed_q proceed
#   # Or wait 10 minutes for the default assumption to resume the run.
#
# EXPECTED
#   `decide` -> held until the blocking request is answered (or times out); then
#   -> Completed with `parsed.answer == "proceed"` (the answer above) and
#   `parsed.source == "operator"`; run -> succeeded. See
#   `durable-wait-timeout.star` for the unanswered path.

# A blocking `human_request` scoped to this stage holds it durably until an
# operator answers (or the self-heal timeout elapses). The stage renders the
# EFFECTIVE answer through `{{ human_requests.by_id.<id>.effective_answer }}`
# (and who gave it through `answer_source`: `operator` or `timeout_default`) — a
# model stage would render the same fields into its prompt. The answer is spliced
# into single quotes, so an answer containing `'` breaks this demo's shell quoting.
decide = stage(
    id = "decide",
    run = """
printf '{"decided":true,"answer":"%s","source":"%s"}\\n' '{{ human_requests.by_id.proceed_q.effective_answer }}' '{{ human_requests.by_id.proceed_q.answer_source }}'
""",
    agent = "shell",
    outputs = {"decided": "bool", "answer": "string", "source": "string"},
    progress_visibility = "summary",
)

workflow(
    "durable-wait-signal",
    description = "Durably park a run on an external signal: a blocking human_request + an input channel.",
    root = [decide],
    max_human_requests = 2,
    human_requests = [
        human_request(
            "proceed_q",
            stage = "decide",
            blocking = True,
            timeout_ms = 600000,
            priority = "high",
            question = "Proceed with the decision, or hold? Answer to unblock `decide`.",
            default_assumption = "proceed",
            context = "Blocking gate: the run parks here until you answer or the 10-minute timeout elapses.",
        ),
    ],
    max_external_input_channels = 2,
    external_input_channels = [
        channel(
            "steering",
            expose_as = "steering",
            max_items = 8,
            description = "Durable operator steering appended to this run at any time.",
            default_value = "No external steering was appended.",
        ),
    ],
)
