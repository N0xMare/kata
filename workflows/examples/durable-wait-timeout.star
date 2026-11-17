# durable-wait-timeout — a blocking human request nobody answers, model-free.
#
# The unanswered half of `durable-wait-signal.star`: `decide` is held on a BLOCKING
# `human_request` whose `timeout_ms` is three seconds. Nobody answers, so when the
# deadline passes the run resumes with the request's `default_assumption` as the
# effective answer, and `decide` renders it with `answer_source == "timeout_default"`.
#
# The request is a main-side INPUT WAIT (one `executor = 'main'` attempt in
# `awaiting_input`, its deadline anchored at the claim), and the deadline sweep
# accepts it `{"answer": "proceed-by-default", "source": "timeout_default"}` within
# one heartbeat interval after the deadline; `decide`'s container starts only after.
#
# RUN
#   kata serve --config ./.kata/kata.toml            # terminal 1
#   kata run ./durable-wait-timeout.star --submit     # terminal 2
#   kata steer human-requests --execution-id <execution-id>   # shows it waiting
#
# EXPECTED
#   `decide` -> Completed with `parsed.answer == "proceed-by-default"` and
#   `parsed.source == "timeout_default"`; run -> succeeded.

decide = stage(
    id = "decide",
    run = """
printf '{"answer":"%s","source":"%s"}\\n' '{{ human_requests.by_id.proceed_q.effective_answer }}' '{{ human_requests.by_id.proceed_q.answer_source }}'
""",
    agent = "shell",
    outputs = {"answer": "string", "source": "string"},
    progress_visibility = "summary",
)

workflow(
    "durable-wait-timeout",
    description = "A blocking human request nobody answers: the run resumes on its default after a short timeout.",
    root = [decide],
    max_human_requests = 1,
    human_requests = [
        human_request(
            "proceed_q",
            stage = "decide",
            blocking = True,
            timeout_ms = 3000,
            priority = "high",
            question = "Proceed? Leave unanswered to resume on the default after three seconds.",
            default_assumption = "proceed-by-default",
        ),
    ],
)
