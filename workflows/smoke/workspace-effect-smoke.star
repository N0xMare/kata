# workspace-effect-smoke — factory-as-loop foundation live smoke.
#
# Proves the deterministic, replay-safe workspace-effect stage kind end to
# end on an installed main, model-free:
#
#   1. `change` (shell, confined by default): writes a file in the candidate worktree.
#      It shells NO git at all — see the identity note at the bottom.
#   2. `record` (agent="workspace_effect", op="commit"): finalizes the candidate
#      that change was recorded into THROUGH THE PROVIDER, so it has a HEAD to
#      park and kata authors it as the operator.
#   3. `park` (agent="workspace_effect", op="park", label="smoke"): performs an
#      in-execution park of the candidate workspace via the execution's
#      ExecutionWorkspaceProvider and records the `{operation, ref_name,
#      commit_sha}` envelope as the stage's Completed output. The git provider
#      creates the EXECUTION-SCOPED parked branch `refs/heads/parked/<exec-id>`
#      at the commit `record` made — never the empty change that commit left
#      above it — which then exists in the repo. (The `label` is
#      descriptive metadata in the directive, NOT part of the ref — this keeps
#      a crash-window re-dispatch reconcilable and same-label runs distinct.)
#
# This is a TERMINAL effect: park tears down the candidate worktree, so the
# linear pack ends right after it.
#
# Run on a main (model-free — both stages are deterministic):
#   (from the checkout root, with KATA_STDLIB_DIR=$PWD/workflows/std exported to the
#   main and the CLI: no install or checkout build resolves a rig without it)
#   kata run workspace-effect-smoke --wait
#   kata run show <exec-id>
#
# Inspect before running:
#   kata workflows inspect workspace-effect-smoke

load("kata/std.star", "workspace_write_stage", "effect_stage")

change = workspace_write_stage(
    id = "change",
    reads = "whole-tree",
    run = """
printf 'workspace-effect smoke %s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > workspace-effect-smoke.txt
printf '{"status":"written","file":"workspace-effect-smoke.txt"}\\n'
""",
    outputs = {
        "status": "string",
        "file": "string",
    },
)

# THE COMMIT IS AN EFFECT, NOT A SHELLED `git`.
#
# Not a line inside `change` such as:
#
#     git -c user.name=kata -c user.email=kata@local commit -q -m '...'
#
# — a FABRICATED identity, with no `commit.gpgsign=false` and no
# `core.hooksPath`, so on a host with a signing key the commit is signed with
# the OPERATOR'S key while attributed to `kata@local`: the host's identity
# discarded and the host's signing key inherited, backwards on both halves.
#
# `op = "commit"` is NON-TERMINAL (`WorkspaceEffectOp::terminal_reason` returns
# `None` for it), so a later stage may depend on it — the load-time refusal
# keys on the OP, not on membership in the effect map.
record = effect_stage(
    id = "record",
    op = "commit",
    depends_on = ["change"],
)

park = effect_stage(
    id = "park",
    op = "park",
    label = "smoke",
    depends_on = ["record"],
)

workflow(
    "workspace-effect-smoke",
    tags = ["smoke"],
    description = (
        "Factory-as-loop foundation smoke: a shell change, a deterministic " +
        "workspace-effect commit, then a workspace-effect park."
    ),
    root = [
        change,
        record,
        park,
    ],
    worktree_isolated = True,
)
