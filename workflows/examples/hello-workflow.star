# hello-workflow — the smallest possible kata workflow.
#
# DEMONSTRATES
#   * a single deterministic `agent = "shell"` stage,
#   * a flat `outputs = {..}` declaration (the stage prints one JSON object
#     whose fields match the declared output surface),
#   * the required `workflow("name", root=[..])` shape (POSITIONAL name,
#     `root=` — NOT `stages=`).
#
# AGENTS / CONFIG
#   No model backend and no `sandbox=` — `agent = "shell"` runs a plain
#   command CONFINED BY DEFAULT (a rootless capsule, a `workspace = "ro"`
#   view whose changes are refused at adoption — an untracked path
#   `.gitignore` ignores is discarded instead — no network, exactly
#   `sandbox_profile()`); there is no
#   `sandbox = "host"` opt-out — a stage authors a confined profile and
#   names the programs it needs in `requires = [..]`. No model is spawned,
#   so this loads, checks, and runs with zero model/API budget.
#
# RUN
#   # Terminal 1, from an initialized project:
#   kata serve --config ./.kata/kata.toml
#   # Terminal 2, from the directory containing this file:
#   kata check ./hello-workflow.star
#   kata run ./hello-workflow.star --wait --timeout-secs 60
#
# EXPECTED
#   stage `greet` -> Completed; run aggregate status -> succeeded; the parsed
#   output is {"greeting": "hello, kata", "ok": true}.

greet = stage(
    id = "greet",
    run = """
printf '{"greeting":"hello, kata","ok":true}\\n'
""",
    agent = "shell",
    outputs = {
        "greeting": "string",
        "ok": "bool",
    },
    progress_visibility = "summary",
)

workflow(
    "hello-workflow",
    description = "The minimal kata workflow: one deterministic shell stage.",
    root = [greet],
)
