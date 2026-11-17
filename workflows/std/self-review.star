# self-review — kata workflow stdlib
#
# A workflow that reviews the most recent commit on this repo. Uses the
# "kata builds kata" pattern: the `default` agent summarises, the `reviewer`
# agent reviews. This workflow routes by agent AND threads upstream outputs
# through stage prompts via minijinja templating. The `review` stage reads
# `{{ stages.summarize.content }}` instead of re-running git.
#
# Run with:
#   kata run self-review
#
# Pre-reqs on the operator machine:
#   - an `[agents.default]` and an `[agents.reviewer]` block, each a nanocode agent
#     whose `credential` the worker can load (`kata login openai`, or an
#     `env:<VAR>` key). `kata init` writes both; `kata config check
#     --config <path>` prints what each label binds.
#   - working dir MUST be a git repo; the `ensure_git_repo` preflight stage
#     emits GIT_REPO_OK / NOT_A_GIT_REPO so operators know if downstream
#     stages are trustworthy.
#
# ── CONTAINED, AND HOW GIT WORKS IN THE CAPSULE ─────────────────────────────
#
# Three of the four stages exist only to run `git` — `ensure_git_repo` runs
# `git rev-parse --git-dir`, `summarize` runs `git show --stat HEAD` +
# `git log -1`, and `review` independently runs `git show HEAD` to read the diff
# it is judging — and every one of them is contained, so the pack compiles under
# the shipped default `[containment] require_contained_model_stages = true`.
# Agents edit files in an isolated worktree and only READ VCS state: the git
# history a capsule sees is a disposable view (`CapsuleGitView`), and every VCS
# write is a `workspace_effect` stage the runtime performs.
#
# TWO THINGS AN OPERATOR MUST KNOW, because they change what this pack does:
#
#  1. **History reaches the capsule as a git VIEW, not a bind.** A jj
#     SECONDARY execution workspace has no per-candidate git surface at all —
#     only a `.jj` pointer
#     (`crates/vcs/src/jj_tests.rs::secondary_execution_workspace_has_no_own_git_surface`)
#     — so under `oci` the `requires = ["git"]` profile below carries the run's
#     committed history into the capsule's `/work` as a disposable git view
#     (`smoke_shell_contained_stage_reads_git_history` is the live proof).
#
#  2. **Do not add a `cache_policy` to these stages.** The grant is stamped only
#     for a stage that is neither content-cache eligible nor authored
#     `cache_policy = "model_reuse"`, because git history is an ambient input no
#     cache key describes: the gitdir's path is stable across runs while its
#     content moves with every commit, and the workspace hash walks only the
#     candidate worktree. A stage may read git history, or have its result
#     reused. Never both. These stages leave `cache_policy` at its default, and
#     that is load-bearing rather than an omission.
#
# `workspace = "ro"` is deliberate: this pack only READS — the commit, its
# message, its diff. Nothing here edits the candidate, so nothing needs to write
# it, and a stage that may land no change is one fewer thing to reason about.


def _trim_leading_newline(text):
    # Keep naturally formatted triple-quoted prompts from gaining an unintended
    # leading newline.
    if text.startswith("\n"):
        return text[1:]
    return text


# Register stages in alphabetical id order (decide, ensure_git_repo, review,
# summarize) so checked-IR emission stays deterministic.

# Decision stage. Reads BOTH the summary and the review via templating, then
# emits a one-word verdict.
decide = stage(
    id = "decide",
    agent = "default",
    sandbox = "review",
    depends_on = ["review"],
    prompt = _trim_leading_newline("""
You have two upstream stages to consider.

Summary from `summarize`:
---
{{ stages.summarize.content }}
---

Review from `review` (produced by the separate `reviewer` agent):
---
{{ stages.review.content }}
---

Decide: SHIP, FIX, or REWRITE.

- SHIP  — the commit is ready to push as-is.
- FIX   — one or two small follow-up edits before pushing.
- REWRITE — the approach is wrong and needs a different commit.

Output ONLY one of those three words on the first line, then a
one-sentence justification on the second line. Base the decision on
the summary and review text above, not on re-reading the diff. If the
upstream outputs contain `NOT_A_GIT_REPO` or say git was unavailable,
output:

    ABORT: worker not in a git repository

and nothing else.
"""),
)

# Preflight diagnostic. Runs `git rev-parse --git-dir` on the worker and emits
# a crisp GIT_REPO_OK / NOT_A_GIT_REPO token in its stage output. Not a hard
# gate — operators reading the ledger see the literal token and know whether
# downstream stages are trustworthy.
ensure_git_repo = stage(
    id = "ensure_git_repo",
    agent = "default",
    sandbox = "review",
    prompt = _trim_leading_newline("""
Run the Bash tool:

    git rev-parse --git-dir 2>&1; echo "CWD=$(pwd)"

Then look at the output.

- If `git rev-parse --git-dir` printed a path (e.g. `.git` or a
  directory ending in `.git`), respond with exactly one line:
      GIT_REPO_OK
  and nothing else.

- If it printed an error like "fatal: not a git repository", respond
  with exactly these two lines and nothing else:
      NOT_A_GIT_REPO
      CWD=<the cwd line the shell printed>

Do not editorialize. Operators use the literal token to decide
whether the rest of this workflow's output is trustworthy.
"""),
)

# Review stage — routed to the `reviewer` agent. Reads the summary from the upstream
# `summarize` stage via the `{{ stages.<name>.content }}` template, then
# independently reads the diff and produces a review.
review = stage(
    id = "review",
    agent = "reviewer",
    sandbox = "review",
    depends_on = ["summarize"],
    prompt = _trim_leading_newline("""
Another agent produced the following summary of the most recent commit:

---
{{ stages.summarize.content }}
---

Now read the full diff with `git show HEAD` yourself and review it
against this checklist:

1. Correctness — does the code do what the summary and commit message
   claim it does? Cite file:line if you spot a mismatch.
2. Regression risk — could any existing behaviour break? Cite files.
3. Test coverage — is there a new test that pins the change? If not,
   propose ONE specific test: file, test name, and the assertion that
   must hold.
4. Comments & docs — any stale or misleading comments that should be
   updated alongside this change?
5. Security — does any input cross a trust boundary? Injection risk?
   Secret material now logged or persisted?

Return a short numbered review. Don't repeat the diff; just the
findings. Keep it under 400 words. If git is not available, say so
explicitly — do not fabricate a review.
"""),
)

# Summary stage. Reads the commit via git and produces a 3-5 sentence
# description of what changed, on the `default` agent.
summarize = stage(
    id = "summarize",
    agent = "default",
    sandbox = "review",
    depends_on = ["ensure_git_repo"],
    prompt = _trim_leading_newline("""
Run `git show --stat HEAD` and `git log -1 --pretty=full HEAD`, then
describe in 3-5 sentences what changed in the most recent commit and
the commit author's stated intent. If git is not available, say so
explicitly — do not fabricate a commit summary.
"""),
)

workflow(
    "self-review",
    description = "Review the most recent commit. `default` summarises + decides; `reviewer` reviews.",
    root = [ensure_git_repo],
    # LOAD-BEARING, not decoration. Without it `/work` is the canonical empty
    # tree a non-isolated execution is seeded with, and there is no candidate
    # repository for the git-history grant to resolve — every stage would
    # report NOT_A_GIT_REPO.
    worktree_isolated = True,
    sandbox_profiles = {
        # One profile for all four stages: they all only read. `net` is the
        # offline default: the harness reaches its model from the worker
        # under either spelling, and no stage needs the node's
        # `[node] egress_allow`. `workspace = "ro"` lands no change to the
        # candidate (a `/work` change a stage leaves fails it at adoption; an
        # untracked path `.gitignore` ignores is discarded), and
        # `requires = ["git"]` brings the run's disposable git view at `/work`.
        "review": sandbox_profile(
            # `ensure_git_repo` and the review stage shell `git` through the
            # model — declare it so a git-less node environment refuses at
            # CHECK, not mid-run.
            requires = ["git"],
        ),
    },
)
