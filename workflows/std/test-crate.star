# test-crate — kata workflow stdlib
#
# Run `just test-crate <crate>` on the kata worker and emit a
# structured JSON report with pass/fail counts. It demonstrates
#   1. per-stage backend routing (`agent = "default"`),
#   2. minijinja templating (`{{ stages.X.parsed.field }}`),
#   3. structured stage outputs (`outputs=`).
#
# Downstream stages (in a derivative workflow built on top of this
# one — an "iterate-until-green" loop) can read typed fields like:
#
#     {{ stages.run_tests.parsed.passed }}
#     {{ stages.run_tests.parsed.failed }}
#     {{ stages.run_tests.parsed.failures }}
#
# Contract: because the stage declares an `outputs=` schema, the runner
# parses the agent's response as JSON and validates the declared
# field names against the parsed object. The agent MUST return ONLY a JSON
# object as its whole response — no prose, no code fence, no preamble.
# Unparseable content = stage validation failure = workflow abort. That is
# deliberate: the only way a downstream `parsed.*` access can be sound is if the
# upstream response is actually parseable.
#
# The crate under test is hardcoded to `kata-workflow`. Operators who need
# to test a different crate can write a one-line derivative workflow that
# changes the prompt's literal crate name.
#
# Run with:
#   kata run test-crate
#
# Pre-reqs on the operator machine:
#   - an `[agents.default]` block, a nanocode agent whose `credential` the worker
#     can load (`kata login openai`, or an `env:<VAR>` key). `kata init` writes
#     it; `kata config check --config <path>` prints what the label binds.
#   - the main MUST be running against the kata repo (so the execution's
#     candidate worktree carries the justfile and the crates this pack tests)
#
# ── WHERE THIS PACK RUNS ────────────────────────────────────────────────────
# A model stage runs in a sandbox, and `fs = workspace-*` binds the EXECUTION's
# workspace at `/work` — which, without `worktree_isolated`, is an empty
# per-execution directory. The pack would compile, run, find no justfile, and
# return its own `{"passed": 0, "failed": 0, "failures": [{"kind": "INFRA"}]}`
# shape: a GREEN workflow reporting a test suite it never ran.
#
# `worktree_isolated = True` is therefore load-bearing, not decoration — it is
# what puts a real checkout at `/work`. The cost is honest and it is a
# COLD one: a fresh candidate worktree has no `target/`, so the first
# `just test-crate kata-workflow` compiles the crate and its dependencies from
# scratch. That is why the stage below carries an explicit `timeout_ms` instead
# of the 300s platform default, which a cold build cannot meet.

# Single stage — runs the nextest-driven test suite for one crate and returns the
# parsed summary as JSON. Structured-output stages can emit exactly one JSON
# object as the whole response; anything else fails the validation guard in the
# runner.
run_tests = stage(
    id = "run_tests",
    agent = "default",
    sandbox = "build",
    # A cold candidate worktree compiles the crate under test and its
    # dependencies before a single test runs; the 300s platform default kills
    # that mid-build and the stage reports an INFRA failure for a suite that was
    # merely slow. One hour matches `kata-gate-fix-loop`.
    timeout_ms = 3600000,
    prompt = """Use the Bash tool to run exactly this command and capture all output
(both stdout and stderr):

    just test-crate kata-workflow

`just test-crate` is the kata-sanctioned way to run the test suite
for one crate — it wraps `cargo nextest run -p <crate>` with the
workspace slow-timeout profile. Never substitute `cargo test`, which
is banned workspace-wide; see AGENTS.md.

Once the command finishes, parse the nextest output and extract:

  - The crate name (pass through as "kata-workflow").
  - The `Summary` line. It looks like:
        Summary [  0.379s] 707 tests run: 707 passed, 0 skipped
    or on failure:
        Summary [  1.234s] 707 tests run: 706 passed, 1 failed, 0 skipped
    Extract `passed`, `failed` (0 if absent), `skipped`, and
    `elapsed_ms` from this line. `elapsed_ms` is the leading bracketed
    time converted from seconds to milliseconds and rounded to the
    nearest integer (e.g. `0.379s` -> 379).
  - Any failure lines of the form:
        FAIL [   0.123s] kata-workflow module::path::test_name
    For each, capture `{"name": "module::path::test_name", "kind": "FAIL"}`.
    If there were no failures, `failures` MUST be an empty JSON array `[]`,
    never omitted or `null`.

CRITICAL: Your ENTIRE response must be a single valid JSON object and
NOTHING ELSE. No leading prose, no trailing commentary, no Markdown
code fence, no explanation. The first character must be `{` and the
last character must be `}`. The shape is:

    {
      "crate": "kata-workflow",
      "passed": 707,
      "failed": 0,
      "skipped": 0,
      "elapsed_ms": 379,
      "failures": [
        {"name": "module::path::test_name", "kind": "FAIL"}
      ]
    }

Integer fields (`passed`, `failed`, `skipped`, `elapsed_ms`) must be
JSON numbers, not strings. If `just test-crate` fails to start at all
(missing `just`, missing crate, ...), still return valid JSON with
`"passed": 0`, `"failed": 0`, and a single entry in `"failures"`
whose `"name"` is the one-line error reason and whose `"kind"` is
`"INFRA"`. Do not apologize in prose — put everything in the JSON.
""",
    outputs = {
        "crate": "string",
        "passed": "u32",
        "failed": "u32",
        "skipped": "u32",
        "elapsed_ms": "u32",
        "failures": "json",
    },
)

workflow(
    "test-crate",
    description = "Run `just test-crate kata-workflow` and emit structured {passed, failed, failures} JSON.",
    root = [run_tests],
    # See the header: this is what puts a real checkout at `/work` instead
    # of an empty directory, and without it the contained stage would report a
    # vacuous INFRA result while the run went green.
    worktree_isolated = True,
    # `workspace-rw`, not `workspace-ro`. `just test-crate` wraps `cargo
    # nextest run -p <crate>`, which writes `target/` inside the worktree;
    # under `oci` that build tree alone would not fail a `workspace-ro` stage —
    # `target/` is untracked and `.gitignore`d, so adoption discards it rather
    # than refusing it — but any other change the run leaves in `/work` would.
    # The stage still must not edit source — that is the prompt's contract,
    # not the sandbox's.
    sandbox_profiles = {
        "build": sandbox_profile(
            workspace = "rw",
            net = "host",
            # The model runs `just test-crate` (→ cargo nextest) in the capsule —
            # name the programs so a node whose environment lacks them refuses
            # at CHECK rather than failing the stage at runtime.
            requires = ["just", "cargo"],
        ),
    },
)
