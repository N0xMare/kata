# review-loop-smoke — worker/reviewer iteration live smoke
#
# Exercises the full worker/reviewer iteration runtime against real model
# agents. The `default` agent writes a tiny Rust function; the `reviewer` agent
# reviews it for correctness. If the reviewer says `refine`, the worker gets the
# feedback baked into `{{ review.feedback }}` and tries again. Loop exits on
# `approve`, `block`, or after 3 iterations (`on_exhaustion = fail`).
#
# Run with:
#   just api-submit-ref review-loop-smoke
# Monitor:
#   just api-execution <id>
# Each iteration is another attempt of `implement` and of `review`: iteration N
# is attempt ordinal N of each.
#
# Pre-reqs:
#   - an `[agents.default]` and an `[agents.reviewer]` block, each a nanocode agent
#     whose `credential` the worker can load (`kata login openai`, or an
#     `env:<VAR>` key). `kata init` writes both; `kata config check
#     --config <path>` prints what each label binds.


def _trim_leading_newline(text):
    # Keep naturally formatted triple-quoted prompts from gaining an unintended
    # leading newline.
    if text.startswith("\n"):
        return text[1:]
    return text


# Register stages in alphabetical id order (implement, review) so checked-IR
# emission stays deterministic.

implement = stage(
    id = "implement",
    agent = "default",
    sandbox = "iso",
    prompt = _trim_leading_newline("""
Write a Rust function with this exact signature:

    fn is_prime(n: u64) -> bool

Requirements:
- Return `false` for n = 0 and n = 1.
- Return `true` for n = 2.
- For n >= 3, use trial division up to and including floor(sqrt(n)).
- No external crates.
- No panics on any u64 input.

{% if review.iteration > 0 %}
This is iteration {{ review.iteration }}. A reviewer flagged issues with
the prior version:

    {{ review.feedback }}

Revise the implementation to address that feedback. Keep the signature
unchanged.
{% endif %}

Output ONLY the Rust source code for the function (signature + body).
No markdown fences, no explanation, no surrounding text.
"""),
)

review = stage(
    id = "review",
    agent = "reviewer",
    sandbox = "iso",
    depends_on = ["implement"],
    prompt = _trim_leading_newline("""
Review this Rust function for correctness:

---
{{ stages.implement.content }}
---

Verify each of these:
1. `is_prime(0)` returns `false`.
2. `is_prime(1)` returns `false`.
3. `is_prime(2)` returns `true`.
4. `is_prime(3)` returns `true`.
5. `is_prime(4)` returns `false`.
6. `is_prime(9)` returns `false`.
7. The loop bound correctly uses `sqrt(n)` or `i * i <= n`.
8. No overflow or panic on large n (e.g. `u64::MAX - 1`).

If ALL 8 checks pass, respond with exactly this JSON (single line, no markdown fence):
{"verdict": "approve", "feedback": "correct on all checks"}

If there's a specific fixable bug (one of the checks fails), respond with:
{"verdict": "refine", "feedback": "<one sentence naming the bug and the check it fails>"}

If the function doesn't compile, has wrong signature, or is fundamentally
not Rust, respond with:
{"verdict": "block", "feedback": "<reason>"}

Output ONLY the single-line JSON. Do not wrap in markdown fences. Do not
add commentary. Do not emit anything other than the JSON.
"""),
    outputs = {
        "verdict": "string",
        "feedback": "string",
    },
)

# `[[review_loops]]` worker_stage=implement / reviewer_stage=review /
# max_iterations=3 / on_max=fail lowers 1:1 onto the native loop() primitive.
loop(
    body = implement,
    gate = review,
    max_iterations = 3,
    on_exhaustion = "fail",
)

workflow(
    "review-loop-smoke",
    tags = ["smoke"],
    description = "Review-loop live smoke: `default` writes is_prime, `reviewer` reviews, loop iterates.",
    root = [implement],
    # A model/agent stage runs in a certified container. This pack passes SOURCE
    # TEXT between two model stages and touches no repository — `implement`
    # emits a function body, `review` emits a JSON verdict about that body — so
    # it is deliberately NOT `worktree_isolated` and `/work` is the empty
    # per-execution directory. That is the right answer here rather than a
    # shortfall: there is nothing for this smoke to read.
    #
    # Both stages share one profile because neither has more authority than
    # the other. Its `net` is the offline default: each agent's model is
    # reached from the worker under either spelling, and neither stage needs
    # the node's `[node] egress_allow`.
    sandbox_profiles = {
        "iso": sandbox_profile(
            workspace = "rw",
        ),
    },
)
