# workspace-commit-smoke — "name + record the VCS commit as an Effect"
# live smoke.
#
# Proves the deterministic, replay-safe `commit` workspace-effect stage kind
# end to end on an installed main, model-free. Unlike park/promote (TERMINAL effects
# that tear the candidate worktree down), `commit` is NON-terminal: it finalizes
# the recorded candidate commit in place and leaves the worktree LIVE.
#
#   1. `dirty` (shell, confined by default): writes a file in the candidate worktree and
#      runs NO `git commit` — the stage's recorded apply puts the change into the
#      candidate commit, and the commit effect must finalize exactly that.
#   2. `commit` (agent="workspace_effect", op="commit", label="wave-commit"):
#      finalizes the recorded candidate via the execution's
#      ExecutionWorkspaceProvider, IN-PROCESS on the host and OUTSIDE any agent
#      sandbox (the determinism boundary: VCS is an Effect at a named boundary,
#      never shelled inside the agent sandbox). It records the
#      `{"operation": "commit", "ref_name": <candidate ref>,
#        "commit_sha": <new HEAD sha>}` envelope as the stage's Completed output.
#   3. `observe` (shell, confined by default): CHECKS the claim below against the
#      recorded envelope, the `workspace.*` namespace (recorded commits, read on
#      the host) and its own `/work`, and FAILS the run when a checked part does
#      not hold.
#
# THE CLAIM (the commit captures the uncommitted change):
#   1. `commit_sha` in the envelope == the recorded head `{{ workspace.head_sha }}`.
#   2. the recorded head's diff from the execution's BASE commit
#      (`{{ workspace.changed_files }}`) names `workspace-commit-smoke.txt`, and
#      commit_sha's tree holds the line `dirty` wrote to it: the commit's own diff
#      adds that line to that file (`{{ workspace.query(...) }}` over a jj
#      `diff_lines()` revset).
#   3. the worktree survives the non-terminal effect, file included.
#
# `observe` does NOT check that the head is exactly ONE commit over the base: the
# namespace exposes the head and its diff from the base, not the commit graph
# between them.
#
# ── WHY THE OBSERVE STAGE EXISTS ────────────────────────────────────
#
# A smoke that stops at the mutation it is smoke-testing can only prove the
# mutation RETURNED — never that it DID anything. The failure it guards is
# concrete: a `commit` effect that recorded a `commit_sha` whose tree lacks the
# stage's change would record an EMPTY diff — and a later promote would land
# that empty commit and tear down the candidate holding the real change.
#
# `observe` may depend on `commit` because the load-time validator keys effect
# terminality on the op (`WorkspaceEffectOp::terminal_reason`), and `commit` is
# not terminal; this pack is the shipped exercise of that edge.
#
# Idempotency: re-driving the `commit` stage (a resume, a sweep) converges on
# its recorded attempt — the claim is the double-spend guard — so it records
# the same commit and lands no second one.
#
# The `label` ("wave-commit") is descriptive metadata in the recorded directive,
# NOT part of any git ref.
#
# Run on a main — the commit lands in its `[vcs] jj_repo` repository
# (model-free: every stage is deterministic; `oci_main_live`'s live cell runs it):
#   (from the checkout root, with KATA_STDLIB_DIR=$PWD/workflows/std exported to the
#   main and the CLI: no install or checkout build resolves a rig without it)
#   kata run workspace-commit-smoke --wait
#   kata run show <exec-id>
#
# Inspect before running:
#   kata workflows inspect workspace-commit-smoke

load("kata/std.star", "workspace_write_stage", "effect_stage", "shell_json_stage")

dirty = workspace_write_stage(
    id = "dirty",
    reads = "whole-tree",
    run = """
LINE="workspace-commit smoke $(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s\\n' "$LINE" > workspace-commit-smoke.txt
# Intentionally do NOT git-commit: the candidate worktree stays DIRTY so the
# commit effect stage has real uncommitted changes to snapshot.
printf '{"status":"dirty","file":"workspace-commit-smoke.txt","line":"%s"}\\n' "$LINE"
""",
    outputs = {
        "status": "string",
        "file": "string",
        "line": "string",
    },
)

commit = effect_stage(
    id = "commit",
    op = "commit",
    label = "wave-commit",
    depends_on = ["dirty"],
)

# The `run` script is a minijinja template. `{{ stages.commit.content }}` is the
# commit effect's recorded envelope verbatim, and the `workspace.*` namespace is
# RECORDED state the runner renders IN-PROCESS on the host at dispatch — i.e.
# AFTER the commit effect ran: the recorded head, its diff from the execution's
# base commit, and a revset evaluated over the repository's commits. So this
# stage compares what the effect SAID against what the repository HOLDS, without
# shelling any VCS command itself. An effect that captured nothing fails part 2
# twice over: the base diff lacks the file and the head's diff lacks the line.
observe = shell_json_stage(
    id = "observe",
    reads = "whole-tree",
    depends_on = ["commit"],
    run = """

ENVELOPE='{{ stages.commit.content }}'
HEAD_SHA='{{ workspace.head_sha }}'
IN_BASE_DIFF='{% if "workspace-commit-smoke.txt" in workspace.changed_files %}yes{% else %}no{% endif %}'
LINE_IN_HEAD='{{ workspace.query(workspace.head_sha ~ ' & diff_lines(substring:"' ~ stages.dirty.parsed.line ~ '", "workspace-commit-smoke.txt")').commits | length }}'

fail() {
    printf 'workspace-commit-smoke: %s\\n' "$1" >&2
    exit 1
}

case "$ENVELOPE" in
    *'"operation":"commit"'*) ;;
    *) fail "the commit stage recorded no operation=commit envelope: $ENVELOPE" ;;
esac

SHA=$(printf '%s' "$ENVELOPE" | sed -n 's/.*"commit_sha":"\\([0-9a-f]*\\)".*/\\1/p')
[ -n "$SHA" ] || fail "the commit envelope carries no commit_sha: $ENVELOPE"

# CLAIM, part 1 — `commit_sha` in the envelope IS the recorded head afterwards,
# so the revset below, rooted at the head, reads commit_sha.
[ "$SHA" = "$HEAD_SHA" ] || \\
    fail "envelope commit_sha ($SHA) is not the recorded head ($HEAD_SHA)"

# CLAIM, part 2 — the dirty state
# was CAPTURED, not merely reported. An effect that snapshots nothing still
# publishes a success envelope, naming a commit that does not hold the change.
[ "$IN_BASE_DIFF" = "yes" ] || \\
    fail "the recorded head's diff from base does not name workspace-commit-smoke.txt — the uncommitted change was not captured (changed_files: {{ workspace.changed_files }})"
[ "$LINE_IN_HEAD" = "1" ] || \\
    fail "commit_sha $SHA does not add the dirty stage's line to workspace-commit-smoke.txt (diff_lines matched $LINE_IN_HEAD commits)"

# CLAIM, part 3 — `commit` is NON-TERMINAL: the worktree survives the effect,
# with the file still in it, which is the whole reason a stage may follow it.
[ -f workspace-commit-smoke.txt ] || \\
    fail "the candidate worktree no longer holds workspace-commit-smoke.txt"

printf '{"observed":"committed","commit_sha":"%s","worktree":"live"}\\n' "$SHA"
""",
    outputs = {
        "observed": "string",
        "commit_sha": "string",
        "worktree": "string",
    },
)

workflow(
    "workspace-commit-smoke",
    tags = ["smoke"],
    description = (
        "Commit-effect smoke: a shell stage leaves the candidate worktree dirty, " +
        "a deterministic workspace-effect commit stage snapshots it in place " +
        "(non-terminal; the worktree stays live), and a trailing observe stage " +
        "FAILS the run unless the recorded head is the sha the effect recorded " +
        "and that commit holds the file and the line the dirty stage wrote."
    ),
    root = [
        dirty,
        commit,
        observe,
    ],
    worktree_isolated = True,
)
