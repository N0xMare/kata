# Changelog

All notable changes to kata are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and kata's versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Convention for future entries.** Each release gets a `## [x.y.z] - YYYY-MM-DD`
heading, newest first, above the older entries. Group changes under the
Keep-a-Changelog subheadings — `Added`, `Changed`, `Fixed`, `Deprecated`,
`Removed`, `Security` — and describe them in **user-facing language** (what an
operator or agent driving kata can now do). The version in the heading is the
single source of truth for a release and MUST match the workspace `Cargo.toml`
version and `kata --version`. Keep an `## [Unreleased]` section at the top
between releases to accumulate changes as they land.

## [Unreleased]

## [0.0.1] - 2026-11-17

The first release. kata is a prototype, built from
a source checkout. kata is a durable workflow engine for agentic software
work on Linux x86-64. You write a workflow in Starlark; kata checks the whole graph,
compiles it to a content-hashed execution program, and runs every shell command and
coding-agent turn inside a rootless OCI container on a pinned, seccomp-enabled youki,
with a durable record of what each stage did. kata is pre-1.0: interfaces,
configuration and on-disk formats may change between releases, and there is no
migration from one data directory format to the next.

This release went through kata's first L3 release review: an adversarial review, a
reconciliation of the protected-property ledger against a construct-to-cell map (every
gap it found is an acknowledged `unpinned` record), and a no-spend live differential.
The fixes made after that review went through a second, change-scoped pass: an
adversarial review of the changed code, the ledger entries it touches, the live
differential again, and mutation testing of the changed production code only. There
is no mutation verdict for the release as a whole.

### Added

- **A source install.** `cargo build --release --locked` in a checkout builds
  exactly the four shipped binaries — `kata`, `kata-worker`, `kata-provider-youki`
  and `kata-oci-hook` — on Rust 1.99 (rustup installs the release
  `rust-toolchain.toml` pins), and `just install` links `kata` and `kata-worker`
  into `~/.local/bin`. Run from that build, `kata host setup` provisions the provider
  binaries built beside `kata`, and builds the pinned youki (when absent) and the
  default capsule environment from the checkout's `nix/` with `nix-build`, streaming
  the build log; a re-run after a rebuild provisions the rebuilt provider binaries and
  updates the `.env` exports it wrote. Nix is a runtime requirement. `nix profile
  install` of the flake package is the alternative install.
- **Starlark workflows, checked before anything runs.** `stage()`, `parallel()`,
  `branch()`, `loop(body, gate)`, `topology(...)` role lists and dynamic fan-out,
  `subworkflow()`, `sleep()`, approval gates, blocking human requests, typed
  `outputs` with `validate_retries`, fallback agent panels (`agent = ["a", "b"]`),
  `cache_policy`, `memory_snapshot()` and workspace effects (`commit`, `promote`,
  `park`, `forge_export`). `kata check` compiles a workflow and runs the verifier
  without executing anything. Unknown `stage()` and `workflow()` keywords are reported
  together in one pass, with "did you mean" suggestions, and so are the verifier's
  findings. Many other refusals are not collected: such a refusal ends the check at the
  first error it finds, and the next is named once that one is fixed — for example the
  per-stage posture refusals (a stage's sandbox, an authored budget over a node
  ceiling, undeclared egress), a `produces` file under a read-only workspace, and a
  host-unconfined model stage under the installed policy. A template
  reads `{{ stages.<id>… }}` only from a stage it depends on: `kata check` refuses a
  `{{ … }}` read of any other stage (`output_reference_outside_dependency_closure`); a read the check cannot see (inside
  `{% … %}`, or a computed index) finds that stage absent on every schedule, because a
  template's `stages.*` holds only its dependency closure, never a sibling that
  happened to finish first. Run without a node, it names each node fact class it did not judge —
  `agents`, `ceilings`, `egress`, `environment`, exactly those it skipped — in one
  `not judged without a booted node:` line and as `deferred_node_facts` in JSON;
  `--config <kata.toml>` judges every class but `environment` (a stage's `requires`
  programs), and names that one when it skips it.
  `kata workflows schema` prints the DSL catalog, whose `enum_domains` list the accepted
  spellings of every closed string keyword — `cache_policy`, `exit_policy`,
  `on_exhaustion`, `progress_visibility`, the `memory_snapshot` kinds and statuses,
  `topology(mutation_policy=)`, `memory_writeback(scope=)`, `human_request(priority=)`,
  `cost_budget(mode)`, `sandbox_profile(net=, workspace=)`, `stage(op=)`,
  `schedule(on_missed=)` and the `containment`, `network` and `determinism` keys of
  `stage(execution_requirements={..})` — each the set its builtin accepts, matched
  exactly: `sandbox_profile(workspace=)` no longer trims, so `workspace = " rw"` is
  refused like any other unpublished spelling.
- **Typed agent output reaches the model as a schema.** On `nanocode_openai`, a
  stage's `produces = contract(..)` is also sent to the model as a strict JSON Schema
  (the Responses API's `text.format`), derived from the same contract kata validates
  the answer against; kata's validation and `validate_retries` still decide. Optional fields
  are sent as nullable, and a `null` on an optional `produces=` field now means the
  field is absent (it is removed from the parsed output) on every stage that declares a
  contract, shell stages included; a `null` workflow param is still checked against its
  type. Length and pattern bounds are not sent as schema keywords; kata still enforces
  them. Fields are sent in name order, not declaration order. A contract strict mode
  cannot state (past its size limits) is sent no schema.
  `nanocode_anthropic` has no schema channel and keeps the prompt path.
- **Invocation params in prompts and commands.** A workflow's declared
  `params={..}` are passed with `kata run --param NAME=VALUE` (or the REST, MCP and
  client faces), and every stage's `prompt=`/`run=` template reads them as
  `{{ params.<name> }}`. The `shquote` filter (`{{ params.task | shquote }}`) hands a
  value to a shell command as one quoted word. `kata check` refuses a read of a param
  the workflow does not declare (`param_unknown_in_template`) and any template that
  could render a `secret = True` param (`param_secret_in_template`).
- **A run's base is frozen at admission.** Every `worktree_isolated` run resolves its
  target before it is accepted — `kata run <pack> --target trunk`, the default — and
  forks `/work` from the commit it resolved, whatever trunk does afterwards, across a
  restart included. The run's git view names that branch at that commit and always
  carries the head's review range; it takes any file name Linux admits
  (`docs/a:b.md`, `?`, `*`, a trailing dot, `CON`) and refuses only git's own
  spellings of `.git`. `kata run show` prints the frozen target; landing
  refuses `target_trunk_renamed` when the node's trunk is no longer the branch the run
  froze (an operator promote answers it as a conflict: HTTP 409, op code `conflict`),
  and `target_trunk_raced` when a writer outside kata moved the trunk in jj's view
  during the landing (a conflict too, with nothing moved: re-issue the promote),
  a `promote`'s claim names that frozen branch as its `target` (what its approval gate
  shows), and a `promote` recovered after a crash is judged landed or not on that frozen
  branch, even when the repository's trunk answer has moved since;
  and a schedule's target is resolved at every fire, with a refused target
  recorded as the occurrence's firing instead of retried silently.
- **Templates read the run's frozen target.** An isolated workflow's `prompt=` and
  `run=` read `{{ target.head }}`, `target.branch`, `target.compare.merge_base`,
  `target.pr.title`, `target.changed_files`, `target.diff` and the rest of the target
  its run froze, the file list and the diff bounded (2,000 entries, 256 KiB) and
  flagged when cut. The diff writes each path exactly as `git diff` does, C-quoting a
  path that holds a control byte, DEL, a quote, a backslash or a non-ASCII byte, so a
  pull request's file names cannot forge diff headers; a file name that is not UTF-8,
  in a directory the change touches (the root included), fails the diff and the file list
  instead of rendering them. In a shell `run=`, a key whose text a PR author, the forge
  or a branch name chooses must end its expression with `| shquote`, written where the
  shell reads that quote as one word (not inside `"…"`, `'…'`, a backtick, a comment
  or a heredoc); `kata check` refuses any other read of it
  (`template_untrusted_in_run`), an unknown key
  (`target_unknown_in_template`) and a `target` read in a workflow that is not
  `worktree_isolated`. In a prompt, the `untrusted` filter
  (`{{ target.pr.body | untrusted }}`) starts every line of the text with `> `, any
  line break in it included, so a pull request's text cannot write a line of the
  prompt as kata; the `review` pack frames the title, description and changed paths
  this way.
- **A rendered command or prompt is bounded.** A shell stage whose rendered `run=`
  passes Linux's per-argument limit (131,071 bytes) and an agent stage whose rendered
  prompt passes 1 MiB — a validation retry's prompt included, feedback and all — fail
  `rendered_prompt_over_bound` at render, before the text is stored or dispatched.
- **A run can target a pull request.** `kata run <pack> --target pr:42` reads pull
  request 42 through `gh` and fetches its head and base branch into kata-owned refs
  before the run is accepted, within one 300 s bound: the run forks the pull request's
  head, its review baseline is the base branch, and it has no branch to land on, so a
  workflow that promotes or exports is refused `target_not_landable` before the forge
  is read; a read-only workflow is admitted. Its title and body are frozen cut to
  512 B and 8 KiB, and a template reads whether each was cut as
  `target.pr.title_truncated` and `target.pr.body_truncated` (shell-safe in a `run=`,
  like `target.diff_truncated`). A
  forge answer whose refs or url are malformed, a remote kata cannot tell, a failed
  fetch, a head that moved since the forge answered, or a head unrelated to its base is
  refused by name before anything is admitted.
- **The `change` pack.** `kata run change --param task=... --param
  test_command=...` plans the task, implements it in a fix loop that re-runs the
  test command and feeds its output tail back to the agent, parks for a human
  approval, and then commits the change, lands it on the local trunk and opens one
  pull request into that trunk, whatever it is called. A loop whose tests never pass
  parks its last candidate at `parked/<execution>`, and an edit made on disk while
  the run waits at the gate is refused at `commit` (`oci_candidate_disk_diverged`).
- **A pull request goes where the run was aimed.** `forge_export` takes no
  `remote=` or `base=`: the pull request's base is the trunk the run froze at
  admission, and the branch is pushed to the remote `git push` on that trunk would use
  (its `pushRemote`, else `remote.pushDefault`, else the remote it tracks), else the
  repository's only remote (`forge_remote_unresolved` when there is neither), resolved
  once when the export is claimed and used by its recovery after a crash too. The
  pull request opens in the repository that remote's URL names, never `gh`'s default,
  and `gh` must confirm it addresses that repository before anything is pushed
  (`forge_export_repository_unresolved`, `forge_export_repository_unaddressed`: an
  SSH host alias is refused, not translated). `kata
  check` refuses a `forge_export` with no `commit` or `promote` before it
  (`forge_export_without_commit`), and an export whose candidate a writable stage
  changed after the `commit`, with no `promote` landing the change, is refused at run
  time with nothing pushed (`forge_export_uncommitted_candidate`).
- **A pull request is opened once, even across a crash.** `forge_export` records its
  push and its pull request each as an intent before it sends it. The push goes only
  over the branch head kata read just before (a remote that does not answer that read
  fails the export with nothing pushed, `forge_export_remote_unread`; someone else's
  commit there is never pushed over, `forge_export_diverged`). An open pull request
  already on the branch into the run's base is adopted (one into another base is not
  the export's), and a forge that does not answer that lookup fails
  the export with nothing opened (`forge_export_forge_unread`); a pull request kata
  opens has a body ending with a hidden marker naming its intent. After a crash, or a
  push or create that failed, kata asks the remote and the forge which effects
  happened — a pull request closed meanwhile is adopted, not opened twice — and records
  an effect whose remote answers with a state it cannot tell about as
  `workspace_effect_unclassified`, never sending it again. A remote or forge that does
  not answer that question settles nothing: the export stays pending and kata asks
  again a minute later, recording it `workspace_effect_unclassified` only after ten
  unanswered asks; `kata run forge-reconcile <execution>` asks at once, say after
  `gh auth login`. Two cases read wrong and are
  stated in the operator guide: a branch moved back to (or deleted to) the head kata
  read after its push landed, and a closed pull request whose marker was deleted.
  The push sends the commit its intent recorded, by object id
  (`<commit>^{commit}:refs/heads/<branch>`), never what the local `kata/<execution>`
  branch holds when `git push` runs, and its receipt names that commit; it reads no
  replace ref or graft file and pushes no tag or submodule. The push's verdict is
  durable before the pull request is looked up, so a main killed during that lookup
  pushes once. A fork's pull request from a branch of the same name is never adopted.
- **Approval gates show what the run was asked to do.** `kata approvals` and `GET
  /api/v1/approvals` list each gate's frozen `target` and its run's non-secret
  `params` with their values; a secret param is never shown. A gated `forge_export`
  also names where the push goes: the remote its claim recorded (`forge_remote`) and
  the frozen branch the pull request opens into (`forge_base`).
- **The `review` pack.** `kata run review --target pr:42` (or no `--target`, for
  the trunk head against its parent) reviews the change in two agent turns over
  `/work` at the target head under `workspace = "ro"` (a turn that leaves a change
  there fails as `work_delta_out_of_scope`; an untracked path `.gitignore` ignores is
  discarded) — `find`, then `verify`, which re-checks every finding — and
  answers a typed review: a verdict (`approve`, `request_changes`, `comment`), a
  summary, and findings that each name a path, a line, a severity and a message.
  `kata run output <exec-id> verify` prints it. The pull request's title,
  description and file names reach the agent framed as untrusted text. Nothing is
  written to the repository, the remote or the forge.
- **A loop that runs out of iterations can still route.** Under
  `on_exhaustion = "accept"` the loop adopts its gate's last report, and a `route()`
  or `branch()` on that gate routes it: an implement → test loop whose test never
  passed reaches the route's `failed` arm (a `park`, say) instead of skipping every
  arm. When that last verdict's `review_quorum` was not met, the loop classified it
  `refine` whatever the gate's root said, so a route on the verdict field takes its
  `refine` arm and a route on any other field skips every arm. A loop whose bound
  tripped before its last iteration's gate reported routes nothing, because no
  report judged the candidate it ended on; when no stage downstream of the
  loop ran, the run's closeout parks that candidate at `parked/<execution>`. It and every exhaustion under `fail` or
  `escalate` skip every arm. A factory loop that exhausts on a refine
  verdict now runs that verdict's noop arm.
- **A run that could not park its candidate says why.** A run's closeout never
  parks over a `parked/<execution>` that already names another commit
  (`parked_ref_occupied`), nor a workspace whose working copy moved or whose disk
  carries foreign edits (`oci_candidate_diverged`, `oci_candidate_disk_diverged`).
  The refusal is recorded on the run: `kata run show` and `GET
  /api/v1/executions/<id>` serve it as `evidence.closeout_park_refusal`, and the
  closeout records no parked candidate. The recorded refusal stands: neither a
  restarted closeout nor a later default `park` adopts the `parked/<execution>`
  it names as the run's park.
- **A power loss does not tear what a run wrote into the repository.** Every
  repository write a recorded step depends on — target pins, a workspace's commits and
  checkout, a `/work` apply, a workspace effect, a park, a landing, a forge export's
  local branch — is on stable storage (`syncfs`) before the step is recorded, and kata's
  own `git` commands sync the loose objects and refs they write. At boot the main repairs
  what a power loss tore after the last sync (empty loose objects, torn keep refs, torn
  branches kata's export wrote last, torn target pins) and names at WARN, as
  `repository_torn`, a torn ref it will not rewrite — one the operator's git may have
  moved since jj recorded it. A commit, tree or file the repository lost is refused
  `repository_torn` where kata reads it, and a run's closeout records that refusal and
  closes out instead of exiting the main for "restart recovery" or tearing down the one
  copy of the files.
- **Opt-in spend limits: `time_bound`, `cost_bound` and `token_bound`.** No limit
  applies unless one is authored in `workflow(bounds = [..])` or `loop(bounds = [..])`
  (every stage keeps its 1 h default wall timeout). `time_bound` is the portable one,
  holding over every adapter and credential; CHECK refuses a `cost_bound` over an
  agent stage whose adapter kata cannot price
  (`cost_bound_unenforceable_unpriced_adapter`). `token_bound(n)` caps the tokens
  the stages recorded — input, output, cache read and cache write, summed — folded
  where the cost is, a child's included, and walks the run away past `n` exactly as a
  `cost_bound` does; a stage whose token count is unknown halts it closed
  (`token_metering_unavailable`).
  A `[[pricing.models]]` row bills prompt-cache writes through its
  `cache_write_multiplier` and cached reads through `cache_read_multiplier`, and a row
  must state both (one that omits either is refused at load rather than billing that
  class nothing). Every failed, cancelled or orphaned attempt that was
  dispatched records what it spent — the turn's reported usage, or `unavailable` when
  it is unknown, never `0` — and a hard cost bound fails closed on the unknown, so an
  agent attempt lost to a worker death, a deadline or a restart now walks such a run
  away even where its stage's failure would be tolerated (an advisory topology child).
  A turn its worker refuses with its answer unknown is charged the same way, naming its
  adapter and declared model, and a shell capsule's such refusal the authoritative `0`.
  A loop's bounds count every attempt its members ran — a structured-output retry's
  rejected turn and a failed attempt's charge included — and a loop `cost_bound` fails
  closed on a member of unknown cost; CHECK refuses an agent member or gate it covers
  whose spend kata cannot price (`cost_bound_unenforceable_unpriced_adapter`, an
  adapter with no billing backend; a priced kind serves no `subscription`, which
  `credential_mode_unsupported` refuses first). The std packs author `time_bound`s
  alone, the one bound every adapter and credential upholds: `kata-gate-fix-loop` drops
  its loop's `cost_bound(20.0)`, so it checks on every node it checked on before, and
  `kata-gate-fix-loop`, `kata-loop-lite`, `kata-work-item`, `kata-loop-plan-check-std`
  and the `std.software_factory.*` packs drop their `cost_budget("warn", ..)`s — a warn
  halts nothing and never fires under an unpriced adapter. The `kata/factory.star`
  helpers lose their `budget_usd` parameter with it. The `gold-loop` example drops
  its `cost_bound(5.0)` and halting `cost_budget` too: its one spending stage,
  `implement`, is bounded by its own 15-minute `timeout_ms`, and
  `just gold-loop-smoke` runs it on `nanocode_openai` under `OPENAI_API_KEY`.
  A workflow-scope bound counts
  every billed turn once, at its own frame — a loop member's, a topology root's and
  child's, a rejected structured-output turn's — and a run that walks away stops a
  pending loop at its next member, `Exhausted` under the loop's own `on_exhaustion`,
  releasing nothing behind its gate, and a pending `topology(..)` or dynamic fan-out at
  its next dispatch point: it starts no further member, waits for those it started, and
  fails naming the walk-away.
  A loop exhausted under `on_exhaustion = "fail"`, and a loop its gate blocks with no
  route on the gate, skips every stage behind its gate, as a walk-away skips its
  dependents, instead of releasing them on its failed candidate.
  A run walks away once, whatever stopped it — a bound, a halting `cost_budget`, a
  metering halt: its first trip records the one walk-away row, so a workflow
  `cost_budget("halt", ..)` that later stages cross again, or a second kind of halt,
  no longer adds rows, live or on resume; and every stage that finishes after it — one
  already running, a topology that settles, a loop that resolves — releases nothing.
  No stage starts after it either: a stage a completion before the trip released, one
  `max_concurrency` held back, and a plain stage's queued structured-output retry or
  fallback panel member no longer dispatch once the row is durable — the stage is
  skipped, or, at a retry seat, fails naming the walk-away.
  Before, only a bound the running total still exceeded kept a later stage's dependents
  from running, so a stage budget's or a metering halt's run went on releasing them.
  A workflow `time_bound` is measured at the instant kata recorded each stage terminal,
  not when the runner folds it: a run resumed after its bound passed no longer trips it
  at a stage that finished inside the bound — which skipped that stage's dependents
  though they had already run, and failed the resumed run with `cannot complete stage
  … in state Skipped` — and walks away at its next terminal instead.
- **Anthropic list prices.** A `nanocode_anthropic` turn under an `api_key`
  credential is priced from Anthropic's Claude 5 list prices (`claude-fable-5-1`,
  `claude-mythos-5-1`, `claude-opus-5-5`, `claude-sonnet-5-5`: input, output, cache
  read and the 5-minute cache write, dated `2026-11`); a `[[pricing.models]]` row
  with `backend = "anthropic"` overrides one.
- **One durable main.** `kata serve` runs the main: the one process that admits
  workflows, records every transition in SQLite, accepts at most one outcome per
  stage occurrence and recovers runs after a restart by replay. An attempt a crash
  may have left half-done settles PROVEN AMBIGUOUS and is never re-run automatically;
  a VCS effect the main performs is reconciled from the repository instead of
  re-issued. `kata service install` writes a systemd user unit for it.
  On restart, a capsule claim the previous main committed but never dispatched is
  dispatched, and a worker's failure report the previous main received but had not
  accepted settles the attempt with the worker's own verdict.
- **A provider flake does not fail a stage at once.** An agent turn whose model
  provider failed transiently (an overload, a rate limit, a server error, a dropped
  connection), once the harness's own retries are spent, is re-run on the same agent
  in a fresh container, twice — 30 s after the failure, then 120 s after the second,
  each wait measured from the failure's recorded instant, so a restarted main waits
  only what is left, and a cancel or a graceful stop does not wait it out — on every
  stage outside a `topology`, single-agent or panel, and on every capsule member of a
  `loop(..)`; a re-run whose wait would end past the run's `time_bound` is not run, and
  the stage fails at once naming the bound; a turn the provider refused (bad request, no credit, unknown
  model) is never run again on that agent: a fallback panel skips its later seats,
  and the stage fails naming the refusal when only refused agents remain.
- **API-key agents work under the installed service.** For every
  `[agents.<label>]` declaring `mode = "api_key", source = "env:<VAR>"`,
  `kata service install` copies `<VAR>` from the installing shell into the service's
  owner-only environment snapshot, and refuses while `<VAR>` is unset, set to a value
  that is not UTF-8 (said so, never read as unset), invalid, in the reserved `KATA_`
  namespace, or a name no worker delivers a credential through.
  Rotate a key by re-running `kata service install --config <path> --apply` with the
  service stopped. A main with no `supervised_node` transport starts no node, so its
  install copies none of these variables. A worker refuses an `env:<VAR>` key whose
  value is not UTF-8 `credential_unavailable` before the container, naming the
  variable and never the value, and `kata doctor`'s `credential_env` row fails one
  on every kind; any other variable that is not UTF-8 neither panics the worker nor
  reaches a message. A `.env` line never replaces a launch value, UTF-8 or not.
- **The installed service carries the provider declaration.** `kata service install`
  copies the three `KATA_EXTERNAL_*` keys `kata host setup` writes to the project
  `.env` into the service's owner-only environment snapshot, since the service never
  reads `.env`. A main with a `supervised_node` transport refuses to install while any
  of them is absent, naming the key; re-run the install after re-running `kata host setup`.
  A `KATA_EXTERNAL_*` key set to a value that is not UTF-8 is refused naming the key as
  not UTF-8, by the install and by every worker that reads it, never read as unset.
- **Every stage runs in a capsule.** A shell command or an agent turn runs in a
  rootless OCI container that sees only its declared Nix closure, its declared view
  of the workspace (`/work`), and the network it declares. `net = "host"` means the
  node's declared `[node] egress_allow` list of exact `host:port` entries, reached
  through a worker-owned proxy that checks every resolved address. A stage that
  authors no `net`, shell or agent, is `net = "offline"`, and so is an API agent run
  (`POST /api/v1/agents/run`) that omits `sandbox` or sends it empty: `sandbox: {}`
  is the omitted sandbox (`oci`, `workspace_ro`, `offline`), and a sandbox naming
  only some fields takes the omitted sandbox's value for the rest. Under
  `net = "offline"` a capsule reaches nothing, a shell stage's and an agent stage's
  alike: the embedded harness's model calls leave from the worker. Every face says
  which: `kata check --config` and `kata workflows inspect` print each stage's
  `capsule_network` (`offline` or `egress`, with its exact `host:port` list) — for an agent
  stage one row per agent it can run under, the primary then each fallback panel
  member — as do the workflow preflight in JSON and REST, the `check` and `observe`
  operations, an approval gate's capsule, and the execution record `kata run show`
  serves, which reads each declared capsule's own allowlist. A model stage's checked
  class never claims an offline network, so a model stage declaring
  `execution_requirements = {"network": "offline"}` is refused at check. A stage's `/work` changes come back as a recorded delta that the main
  applies, judged against the stage's `produces_files`; `reads = [...]` confines what
  the stage sees of `/work`, not the git view an agent stage (or a shell stage
  requiring `git`) carries, so it is no secrecy boundary for such a stage. An IPv6
  address in one of the well-known forms that carry an IPv4 one (v4-mapped,
  IPv4-translated, the well-known NAT64 prefix `64:ff9b::/96`, 6to4) is judged by the
  IPv4 rules; a network-specific NAT64 prefix or an ISATAP address is judged as IPv6
  only; and the other non-global IPv6 blocks are refused by name. An agent's
  scratch git repository is admitted before kata reads its commits as evidence: a
  pack in it (the agent ran `git gc` or `git repack`), a symlink or a special file
  refuses the turn's attempt, naming what it found.
- **Host preparation and certification.** `kata init` writes `.kata/kata.toml`,
  starter workflows (including the self-contained `std.hello`) and the `.gitignore`
  rules for kata's own roots. `kata host setup` checks the host step by step (Nix with
  its `nix-command` feature, cgroup v2 delegation, user namespaces, AppArmor), realises the pinned youki, installs its
  exact-path AppArmor profile through `sudo kata host apparmor-install` when it is
  missing or differs, provisions the container provider and finishes with
  `kata doctor`.
  `kata execution-provider certify oci` runs the full certification. A host that
  cannot prove containment is refused; there is no weaker fallback.
- **Credentials are references, never secrets in config.** An agent's `credential`
  names kata's own login (`kata_login`) or an environment variable (`env:<VAR>`);
  kata never reads another tool's login, and a config naming a host-login source
  or `[node] host_logins` is refused at load.
- **kata's own login, for the embedded agent harness.** `kata login openai` stores a
  ChatGPT login (through the device-code flow, or the browser flow, which prints the
  authorization URL, opens a browser unless `--no-browser` and waits for the callback
  on localhost:1455 or 1457; the next bullet says which it takes), or with
  `--api-key` an OpenAI API key read from stdin; `kata login anthropic --api-key`
  stores an Anthropic API key the same way. `kata login status` reports every stored
  login offline; `kata login status --check` also checks each with one authenticated
  read that spends nothing and fails on any that is not `ok`. `kata logout <provider>`
  removes a provider's login files (the issuer is not told), with any temporary copy
  a crashed write left and, for `openai`, the staging file a killed browser login
  left. The logins live owner-only under `~/.config/kata/logins/`; kata refreshes the
  ChatGPT login itself and never reads another tool's login in its
  place. An `[agents.<label>]` block declares one through `credential = { mode =
  "subscription" | "api_key", source = "kata_login" }` on a `nanocode_openai` or
  `nanocode_anthropic` agent (`nanocode_anthropic` under `subscription` is refused
  at check, `credential_mode_unsupported`: no Claude subscription login exists).
- **The embedded harness is kata's agent.** Both nanocode kinds run: a stage
  selecting `nanocode_openai` or `nanocode_anthropic` is admitted at check — the
  kind fixes its launch (the capsule's init is `kata-toolhost`) — and the worker runs nanocode's
  loop in its own process against the provider while every tool call runs in the
  capsule. Both kinds have run on a real model ("What has run on a real
  model", below).
  A `nanocode_anthropic` request does not present itself as Claude Code: its system
  prompt is nanocode's without the Claude Agent SDK identity line, so an API key whose
  credits refuse Claude Code traffic (`Your credit balance is too low`) runs it.
  `kata init` writes the embedded harness: `nanocode_openai` on kata's own ChatGPT
  login, model `gpt-6-luna` at `reasoning_effort = "medium"`, as `[agents.default]`
  and again under the role labels `reviewer` and `gate`, the only other model labels
  a shipped pack selects (a review stage and a loop or route gate), so no shipped pack
  selects a model label a fresh node lacks (agent-change's header-declared
  `change-agent` aside); a `net = "host"` pack still needs `[node] egress_allow`.
  nanocode is the only
  harness kata ships: the four vendor adapters are gone (`codex_app_server` and
  `generic_acp`, the counted round's two baselines, and `grok_acp` and `pi_rpc`).
  A block naming one with a credential this build parses is refused
  `adapter_unqualified` at check, by `kata config check` and by `kata doctor`,
  naming the nanocode kinds; a block in the vendor era's documented shape is
  refused at load, since a launch `argv` and an `egress_extra` are no fields of an
  agent block any more and a `[node] host_logins` key is no field of `[node]` (each
  an unknown field), and by the same doors as above on its host-login source
  (`source = "codex_login"` is `credential_undeclared`, naming the two admitted
  spellings). The vendor adapters'
  capsule floors went with them: an agent capsule records the 64-task and memory
  bounds a shell capsule does, and a node whose `capsule_process_count_ceiling` is
  under 64 refuses every capsule stage `capsule_budget_over_node_ceiling` at
  admission (`capsule_floor_over_node_ceiling` is gone, and `kata config check` no
  longer refuses a nanocode block for it). An agent turn carries no launch `argv` in its
  capsule. A
  nanocode `env:` key holding a control character no HTTP header carries (a key
  exported with its trailing newline) is refused `credential_unavailable` before the
  container, naming the variable. A nanocode block that declares no `credential`
  is refused `credential_undeclared` at check, at capsule assembly and by the worker
  before the container, naming its `kata login` (the harness has no other
  credential), and `kata doctor`'s `agent_backends` row fails it.
  `adapter_unqualified` now refuses exactly an adapter label that names no kind.
- **An agent block's label says what it is.** An `[agents.<label>]` block carries no
  `type`: every block is kata's embedded harness, its `adapter` naming the provider,
  and the reserved label `shell` is the shell route, an empty `[agents.shell]` (any
  key under it refuses the config at load, `shell_agent_block_keys`). A block that
  still carries `type` refuses the config at load, `agent_type_removed`, naming the
  block and telling you to delete the line. `kata init` writes no `type` line;
  `kata config check` and `kata doctor` list each block as `harness` or `shell`; a
  worker advertises the harness as `agent_backend=harness`. `POST /api/v1/agents/run`
  accepts the labels `kata init` declares — `default`, `reviewer` and `gate` — in place
  of `codex` and `claude_code`.
- **A provider failure names the provider's answer.** When the embedded harness's
  turn ends on its model provider's failure, kata reads the harness's own typed error:
  a 4xx answer it does not retry (no credit, an invalid key, an unknown model, a
  request too large; on the Responses WebSocket, the `error` event stating the status)
  is `refused`, and a failure it classes transient once its own retries are spent is
  `transient`. A ChatGPT plan's usage quota (`usage_limit_reached`) is `refused` on
  either Responses transport, its reason naming the quota, and
  `previous_response_not_found` is `transient`. Either settles PROVEN NOT PERFORMED, with the class and the provider's
  error type and message as the stage's failure, and a refused first request is
  charged nothing; it stays PROVEN AMBIGUOUS when a tool call ran in a stage with
  `net = "host"`. A failure in neither class stays PROVEN AMBIGUOUS, as before.
- **A cancelled turn's refusal says what the harness confirmed.** When an embedded
  harness turn ends cancelled, the stage's recorded reason says "the harness confirmed
  the cancel" only when nanocode answered the stop; a stop it left unconfirmed before
  the turn issued anything, and a stop kata never asked for, are each worded as what
  they are, never as a confirmed cancel. A turn's close now bounds the `SIGKILL` of the
  capsule's tool host and the wait for its exit by its close grace, as it bounds the
  steps before them: a kill whose delivery hangs, or a tool host that outlives it,
  ends the close as an unobservable teardown, never a confirmed one, instead of
  holding the close until the assignment's deadline.
- **The embedded harness's Code Mode runs outside kata's process.** The JavaScript a
  nanocode model writes and runs ("Code Mode") runs in an interpreter process of its
  own, which the process hosting the worker (always a `kata-worker`) starts from its
  own executable
  and confines: no inherited descriptor, an empty environment, killed with its
  parent, an address-space limit, no core file, and first in line for the kernel's
  out-of-memory killer. A crash of the interpreter (QuickJS 0.16.2 crashes on some
  out-of-memory paths a cell's own code reaches) ends only that interpreter: the
  cell fails to the model naming the signal, the turn's evidence records
  `code_mode_interpreter_ended`, and the next cell runs in a new interpreter. A turn's
  shutdown terminates the host of every cell nanocode still holds, killing and
  reaping its interpreter, so a cell inside a long native step ends with it, as long
  as the shutdown reaches that host within its 5 s grace; the turn's evidence then
  records the Code Mode workers still live (`code_mode_workers_live`). A cell's stored values stay in the hosting
  process and reach the interpreter one at a time, as the cell loads them; one cell's
  stored writes, tool-call input or tool result past 64 MiB fails that part by name.
  The interpreter's last confinement step is a seccomp allow-list of the system calls
  it was measured to make, on every thread: any other call (opening a file for
  writing, a socket, a signal to another process, `ptrace`, `execve`, a fork) ends the
  interpreter by `SIGSYS` before it runs, so a compromised interpreter can no longer
  signal the process hosting the worker or start a process of its own; it can still
  make that process allocate memory through what it sends (ADR-0001 states the
  residual). A host that
  cannot install the filter runs no Code Mode cell (each fails naming why), and `just
  host-check` names it. The interpreter's standard error no longer reaches the
  hosting process's: its last 64 KiB go into the error of a cell its end fails. A
  cell whose interpreter aborts tearing the cell down after it finished (as
  `Array.fromAsync` makes QuickJS do) no longer loses its result to that abort.
- **`kata login openai` works over SSH.** kata's own ChatGPT login takes the
  device-code flow (a URL and a one-time code to enter on any device; no port
  forward) when the session is remote (`SSH_CONNECTION` or `SSH_TTY` set) or has no
  graphical display, and the browser flow, which opens a browser, otherwise.
  `--device-code`, `--browser` and `--no-browser` choose a flow explicitly. Both
  flows store the same owner-only `~/.config/kata/logins/openai-chatgpt.json`; a
  device-code login that is refused, expires or is interrupted writes no file and
  keeps an earlier login.
- **Caching that never crosses a containment change.** `cache_policy =
  "content_cache"` adopts an earlier accepted capsule's result for equal inputs
  without running a container; `"model_reuse"` does the same for an agent turn,
  reporting zero spend, within `[runtime] model_reuse_max_age_secs` (7 days by
  default, `"unbounded"` to lift it). The reuse key includes the node's executor
  term — the rendered seccomp rules, the pinned youki's content hash, the bundle
  templates, the tool host's protocol and source, and the embedded harness: its
  nanocode rev, the Code Mode engine as kata runs it (the vendored engine, kata's
  patch and its interpreter process's source) and that interpreter's syscall
  filter, its limits, and the tool definitions and instructions it gives the model
  — so an upgrade that changes any of them misses every earlier result. A
  `kata-worker` states its executor term when it enrolls; a worker built from a
  different kata keeps taking work, but its results neither seed nor serve reuse, and
  a worker that states no term is refused.
- **Operating runs.** `kata run <workflow> --submit | --wait | --watch` (`--wait`
  exits non-zero for a failed run), `kata run list`, `kata run output`,
  `kata run cancel`, `kata approvals` and `kata run approve`, `kata steer`,
  `kata watch`, `kata events`, `kata timeline`, `kata diff`, `kata explain`,
  `kata report` and `kata usage` (spend, with an `Invoke` child's spend counted once,
  and a cancelled parent charged what its child had billed so far; it reads kata's ledger
  alone and calls no provider). `kata backup`, `kata restore` and
  `kata upgrade --dry-run` manage data directories. `--format json` returns a command's
  output as JSON: `kata check` (and `check --all`) as the versioned envelope carrying the
  `check` operation's response — the document the MCP `check` tool and REST
  `/ops/check` return — and every other command's own document bare, with no `op` tag
  claiming an operation it does not answer (consumers of `explain`, `report`, `doctor`
  and the rest read the document at the top level, not under `data`). A cancel counts
  a parked approval gate it settled as settled by the main, not as a stop asked of a
  worker. A `park` after a `commit` parks the committed commit, as `promote` and
  `forge_export` deliver it.
- **Four surfaces.** The `kata` CLI, an HTTP API with scoped ed25519 tokens, the Rust
  SDK, and an MCP server (`kata mcp`) derived from the API plus the closed list of
  workstation-local forms ADR 0004 admits (`author`, `check` of the caller's files, the
  DSL catalog resource); `kata skill install` installs a kata skill for a coding agent. The attached `kata
  mcp` serves every `check`/`run` form it advertises: a `.star` path and `check`
  with `all = true` are checked on the caller's machine, as `kata check` checks them;
  a path `run` reads the file there and submits its source; a library name is the
  main's to resolve. A workflow that does not compile is `usage` on every check face.
  `initialize` echoes a requested MCP protocol version only when it is `2025-06-18`,
  the revision `kata mcp` implements, and answers any other request with it.
  A path submitted to `kata run` or `kata factory run` that names no file is refused
  `not_found` (exit 3), and a file that is not `.star` `usage` (exit 2). `POST
  /api/v1/agents/run` runs a single agent turn for a label the main declares as
  `[agents.<label>]`, on any live worker with certified containment: an undeclared
  label is refused `400` (`adapter_undeclared`), and no placeable worker is a
  retriable `503`. `kata mcp` serves over stdio only, with no listening socket;
  through it a `run` gets a deadline its own wait sets, and a run whose reply was lost
  after it may have reached the main is answered not retryable, naming `list`, so an
  agent does not submit it twice. A refusal the main answers gives `kata run` and
  `kata run discharge-stop` its contract exit code: a missing, unverifiable or
  under-scoped API token (`401`/`403`) is `usage` (exit 2, not retryable), and a
  refused submission answers its class (`503` capacity, `409`/`412` conflict), not
  `500`. Approve and promote take no `decision_id`, and `POST /api/v1/agents/run`
  takes no `working_tree`: each request refuses an unknown field by name. Under a
  signed API token, a stop discharge's operator must be the token's `issued_for`.
- **The node is always a separate process.** The main hosts no worker. `kata init`
  writes `[[workers.transports]] type = "supervised_node"`: `kata serve` starts one
  `kata-worker` beside itself, publishes readiness only once it enrolled, and when it
  ends kills its cgroup subtree (when the main's cgroup is delegated), settles its
  attempts as any dead worker's (PROVEN AMBIGUOUS once a capsule was delivered), and
  starts a new one. A node that stops answering without ending is killed the same way
  when its heartbeat deadline passes, before its attempts settle, and replaced by a node
  that enrolls afresh; so is a node started again that has not enrolled 180 s after it
  started. The node never loads `.env` itself, and `workers.max_workers` keeps
  one slot for it that no `local_socket` daemon takes. A config naming the removed
  `in_process` transport is refused at load (`worker_transport_in_process_removed`),
  naming the two that exist, and `runtime.channel_buffer_size` is gone with it. `kata
  mcp` boots no engine: `--scratch`, `--config` and `--data-dir` are refused at parse.
- **Separate worker processes.** `kata-worker` daemons on the same host take capsules
  from the main over an authenticated local transport; capsules are placed only on a
  worker holding certified containment (`no_oci_worker_available` otherwise). A
  worker whose Hello carries a field outside the main's declared Hello vocabulary is
  rejected at the handshake. There is no cross-host worker: a `web_socket` transport is
  refused.
- **`kata doctor` lists a capsule attempt root kata could not remove.** Its
  `oci_attempt_roots_retained` row names an attempt root whose removal failed (an
  immutable entry, a mount point under it), with the recorded error, from the
  `<tag>.REMOVAL_FAILED` marker the worker leaves beside it in `attempts/`. Every worker
  start retries the removal and deletes the marker once it succeeds.
- **A capsule that declares egress carries every common proxy variable.** It gets eight:
  `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY`, each in both casings, since
  clients disagree on which they read (curl reads only the lowercase `http_proxy` for an
  `http://` URL). An `[agents.<label>] env` key and an `env:<VAR>` credential source may
  not name any of the eight, `PATH`, `HOME` or `XDG_RUNTIME_DIR`: a config naming one is
  refused by `kata config check` and at check (`capsule_agent_env_channel_owned` for a
  declared env key, `credential_undeclared` for a credential source).
- **A credential the provider echoes is redacted across chunks.** Under
  `progress_visibility = "full"`, a credential the model provider echoes split across two
  or more message chunks is redacted whole in the event stream: a chunk's text that could
  begin the credential is held until the next chunk shows it does not, and a credential
  the stream never finishes is never sent.
- **Overlapping credential values are redacted as one.** A credential's lifted values
  that overlap — one inside another, or two sharing bytes — are redacted as one
  `[redacted]`, in refusal reasons, evidence and the event stream, whatever order they
  were lifted in. A value that is part of the `[redacted]` marker itself (`]`, `d]`) is
  redacted like any other: earlier markers are left as written, and the event stream's
  last `]` is sent.
- **`kata events --exit-on` gives a contract exit however its stream ends.** It refuses
  `--status` beside it by name (usage, exit 2), since the `--exit-on` set is the wait's
  own status filter. A wait whose stream ends on an error item — the server's `event:
  error`, a lagged subscription, a malformed frame, a transport cut — exits 65, the code
  of a stream that closed before a match, with the cause on stderr. In the SDK,
  `wait_for_status_event` answers both as `SseClosedWithoutMatch`, whose `cause` carries
  the error item.
- **A promote of an unknown execution is `not_found`.** `kata run promote` (and `POST
  /api/v1/executions/<id>/promote`, the `promote` operation, the SDK's `promote`) of an id
  no execution was admitted under answers `not_found` — HTTP 404, CLI exit 3 — as observe
  and approve do; `conflict` (HTTP 412, exit 4) is kept for an execution in the wrong
  state.
- **Storage faults at boot are reported as storage.** Boot reports a failed read of the
  projection watermark or an execution's lifecycle row as a storage error carrying
  SQLite's message. A store-less node's failed memory snapshot is logged as a WARN line
  naming the reason.

### Security

- **kata's own `git` children run no hook from your configuration.** Neither from your
  repository's configuration nor from your global or system configuration: no
  hooks-directory script, no configured `hook.<name>.command` (git 2.56 runs those from
  any configuration, past `core.hooksPath`) and no `core.fsmonitor` command. `kata
  doctor`'s and `kata init`'s ignore probe and `kata run`'s uncommitted-edits check still
  read your repository's configuration, but run no fsmonitor command.
- **An `env:` credential never reaches youki.** It reaches neither `kata-provider-youki`
  nor any `youki`: the worker and the provider start each with an empty environment.
  The one youki container the worker runs at its start to certify the runtime, and the
  `systemctl --user kill` that stops it on a timeout, keep only `PATH` and
  `XDG_RUNTIME_DIR`, which they need to reach your user manager.

### Operator notes

- **A stage cannot make a nested user namespace.** The syscall fence every container
  carries — and the floor kata installs under the containment provider, which the
  container inherits — refuses `clone` with `CLONE_NEWUSER` (EPERM) and answers
  `clone3` with ENOSYS, so a libc falls back to `clone`, beside `unshare`. Without it, a
  stage could clone into a nested user namespace and hold capabilities there even on a
  host that restricts unprivileged user namespaces, because the container inherits the
  pinned youki's AppArmor `userns` grant. The fence also refuses `io_uring_setup`,
  `io_uring_enter`, `io_uring_register` and `userfaultfd` (EPERM): a tool that uses
  io_uring falls back as it does under Docker's default profile, and a tool that needs
  a user namespace of its own (rootless podman or buildah inside a stage) does not
  run.

- **What has run on a real model.** The counted round ran
  the `review` pack three times on a pull request with seeded defects and three times
  on one real third-party public pull request, and the `change` pack three times to a
  delivered pull request and once on its fix loop's refine cell, on each of three
  harnesses: `nanocode-openai` (the embedded harness on kata's own ChatGPT login) and
  the vendor baselines `codex-stock` and `claude-agent-acp` (`nanocode-openai` and
  `codex-stock` on `gpt-6-luna`, `claude-agent-acp` on `claude-sonnet-5-5`, all at
  `medium`). Its 30 run records, none void, are in `docs/evidence/runs/`, and the
  evidence page (`docs/evidence/README.md`) renders both parity verdicts from them:
  - OpenAI parity: not met — nanocode-openai passes fewer counted runs than codex-stock: E1 seeded-pr.
  - Anthropic parity: not met — fewer than 3 counted runs: nanocode-anthropic E1 seeded-pr; nanocode-anthropic E1 public-pr; nanocode-anthropic E2 pr.

  Every round here ran at a pre-release commit of kata's development history, which
  this repository does not carry; every record names its commit and tree, as the
  evidence page's Provenance rule states.

  At the counted round's commit the provider refused `nanocode_anthropic`'s one funded
  turn before any output (`HTTP 400 invalid_request_error: Your credit balance is too
  low`), which kata recorded as refused, PROVEN NOT PERFORMED, at an authoritative cost
  of 0. No turn of the 0.0.1 round (below) was refused.
  `claude-agent-acp`'s recorded tokens are its main
  loop's only, as ACP's `PromptResponse.usage` states them: they leave out the
  bridge's internal side calls and the session-title call after each answer, so its
  records undercount that baseline's use.

  The 0.0.1 round added 17 records:
  - E3's process column (the main or the worker killed at six points of `change`,
    among them a model call in flight) passed all six cases on both nanocode arms,
    `nanocode-openai` on kata's ChatGPT login and `nanocode-anthropic` on an API key;
    each arm's `P4` opened one pull request on the real fixture forge.
  - E3's host column (the whole VM killed), on `nanocode-anthropic` only: `P1-host`,
    `P3-host` and `P4-host` passed; `P2-host` is recorded as a FAIL from a test-rig
    defect. kata settled it PROVEN AMBIGUOUS ("the main restarted"; not
    re-delivered by its own reason, unchecked by the rig), but the rig's P2 oracle, shared with the process column, required
    "died", the worker-death wording, and stopped there. The rig was then fixed (it
    judges the settlement off the chain, takes each column's own wording and runs
    every P2 oracle), and the rerun round below re-ran `P2-host`.
  - E9 passed on a fresh Ubuntu 24.04 VM with `nanocode-anthropic`: every README
    install section exit 0, 726 s to the first run, and an E1 review whose seven
    non-recall oracles passed (seeded recall 3/3, recorded, not judged).

  `just live-nanocode`'s two `nanocode_anthropic` cells ran once in that round (no
  run record): A2 (the `agent-change` pack lands) passed; A1 (one real turn in a real
  capsule) failed on two rig defects, both since fixed and re-run below. It read
  the first accepted `implement` attempt, not the one kata settled on after its
  validation retry; and its prompt asked for "the JSON object the output schema asks
  for" when no schema reaches the model (`nanocode_anthropic` carries none, and the
  pack's flat `outputs` table sends none to any kind), where every prompt now states
  the answer's shape. The round's spend, read
  from its 21 executions in kata's databases: $0.211328 known at Anthropic's list
  price, plus six attempts kata could not meter, counted by the stop rule at $0.25
  each, for $1.711328; the OpenAI arm ran on the ChatGPT subscription.

  A rerun round on `nanocode-anthropic` re-ran those two
  rig-defect cells once each on the fixed rig, and added 2 records; the earlier FAIL
  records stay. `P2-host` passed on a fresh E9 VM: a model call open at the kill,
  settled PROVEN AMBIGUOUS ("the main restarted … NOT re-delivered"), every P2 oracle
  holding (one attempt, one claim, no acceptance, `/work` unchanged, nothing landed,
  pushed or opened, no container left); a `P1-host` run before it on the same VM
  passed too. `just live-nanocode`'s A1 and A2 on `nanocode_anthropic` both passed
  (no run record); A1 settled on its first attempt, with no validation retry, so the
  run did not exercise reading a retried attempt, which a host-free cell pins. Its
  spend, from its 4 executions: $0.053842 known at list price, plus two unmetered
  attempts at the stop rule's $0.25 each, for $0.553842.
  `nanocode-anthropic` still has no counted E1 or E2 parity run, and E2's `mismatch`
  case, the OpenAI arm's host column and an OpenAI E9 have not run. The kit programs
  that read those outcomes from outside kata (`e1-run.sh`, `e2-oracles.sh`,
  `ledger.py`, `score-e1.py`) are in `scripts/evidence-kit/`, as the bytes each E2
  record's `kit-sha256.txt` pins, and the round's E3 and E9 readers in its
  `round-0.0.1/`; E2's held-out oracles and gate stay private.
- **An owner-only refusal prints its fix.** When kata refuses to publish under a
  directory of yours that others can write (the main's address under
  `~/.local/state/kata`, `kata service install`'s unit and environment snapshot under
  `~/.config`, the installed main's discovery directory, `kata login`'s store), the
  refusal ends with the one command that fixes it, the path shell-quoted: `fix: chmod
  go-w <dir>`, `fix: chmod 700 <dir>` (`00700` when a set-ID bit is set), or `fix:
  chmod 600 <file>`. A directory another account owns is refused with the reason and
  no command. What kata refuses is unchanged.
- **Config is closed.** Every `kata.toml` section, a `kata-worker` daemon's own file
  and a Nix environment manifest refuse a key they do not declare, naming its dotted
  path (`unknown field`). `kata config check` reports the same refusal, and a hot
  reload that would apply it keeps the previous config. `kata host setup` refuses an
  undeclared `[node]` key before writing. A config that loads but declares an
  `[agents.*]` block the check refuses on config alone is not called invalid: `kata
  config check` prints its summary, then names every such block with its refusal and
  exits non-zero, because the stages selecting the block are what is refused.
- **The SDK's TLS trusts the host's certificate store.** The Rust SDK (`kata-client`),
  and so every CLI command that reaches the main, verifies TLS against the host's
  store — the system store, or `SSL_CERT_FILE` / `SSL_CERT_DIR` when set — as the
  embedded harness's clients do; it compiles in no root bundle. A host whose store
  yields no certificate is refused an SDK client (`HttpClientBuild`) before any
  request, for an `http://` API URL too.
- **A data directory is tied to its format.** This build writes `operational.db` at
  schema 49 (its checked programs at schema 11, its invocation envelopes at schema 3),
  the delivery event log `ledger_events.db` at schema 4, the worker membrane store
  `idempotency.db` at schema 2 and `memory.db` at schema 3; every capsule identity
  carries execution contract version 14. Boot refuses each of those files at another
  schema (`operational.db schema version <n> is not the clean runtime version 49; use a
  new empty data directory and preserve this directory offline`), `kata upgrade --apply`
  refuses a directory at another operational schema, and both refuse a directory holding
  a database file kata does not write (a top-level `*.db` or its
  `-wal`/`-shm`/`-journal` sidecar), naming each file; the recourse is a new, empty data
  directory, with the old one kept offline. Nothing in a refused directory is opened or
  deleted. An `operational.db` with no schema stamp is refused naming both things it can
  be, an interrupted first creation or an older or foreign file (`operational.db carries
  no schema stamp (version 0): …`), by `kata upgrade`, which can meet either, and at
  boot of a directory that holds its `main-identity.json`, where it is the second: kata
  writes the identity only after every store is created, so a directory whose first
  creation was interrupted has none and boot refuses it first (`has no clean-format main
  identity and contains preserved entry …`). `kata upgrade` refuses a
  data directory with no `operational.db` by name (`operational.db <path> does not
  exist`), and boot refuses a `cas.db` without its `cas/` tree as a missing authority
  asset (`clean engine restart is missing required authority asset(s): cas/`).
- **The gate's smoke rigs are not part of the install.** The 28 packs that exist to be
  driven by kata's own tests and smoke recipes — the 25 `*-smoke` packs,
  `hermetic-build-closure`, `local-worker-ping` and `params-conformance` — live in
  `workflows/smoke` beside the standard library, which keeps the 14 product packs. The
  flake package and `just package` do not carry them, and neither an installed `kata`
  nor a checkout build (the source install) lists or resolves them, so `kata workflows
  list` and `kata check --all` show the product. An explicit `KATA_STDLIB_DIR` naming
  a checkout's `workflows/std` adds its `smoke` sibling as the lowest-priority root,
  which never shadows a shipped name; `just workflows-check-all` checks both trees that
  way.
- **A pack's source text is its program.** A pack's source text, comments included, is
  part of its program: a comment edit gives it a new `program_hash` and
  `workflow_class`. The shipped packs select the
  agent labels `kata init` writes — `default`, `reviewer` and `gate` — and name the role,
  not a vendor, in their prompts and headers.
- **Backups are versioned.** Restore reads backup manifest version 2 (a data snapshot)
  and recovery manifest version 7 (a recoverable backup) only, and refuses a recovery
  artifact whose worker receipts name another `idempotency.db` schema.
- **A main and its containment provider come from one build.** They speak provider
  protocol 9 with certificate version 4. A provider at another protocol version is
  refused at the handshake by its number (`provider_protocol_too_old` or
  `provider_protocol_too_new`), and one at another certificate version as
  `provider_certificate_version_mismatch`. A refused provider is re-provisioned from the
  main's build: `kata host setup`, or `kata sandbox install-external-provider --name
  youki <dir>` and re-exporting `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS` as the address
  it prints.
- **iproute2 is a dependency, not part of the kata package.** The package declares
  the Nix store path of iproute2's `ip` in `share/kata/provider-members.toml`
  instead of copying the binary (a source build gets the same file from the
  checkout's `nix/share.nix`), and `kata host setup` copies it from there into the
  provider store. `--provider-source <dir>` holds only `kata-provider-youki`,
  `kata-oci-hook` and `toolhost/kata-toolhost` (a source that still holds `ip` is refused
  `provider_source_holds_ip`); `--provider-ip <path>` names another `ip`, which must
  resolve to a regular executable file under `/nix/store`. `kata sandbox
  install-external-provider` copies only the directory it is given, so provisioning the
  package's `share/kata/provider-source` with it yields an entry without `ip`, which
  refuses `Egress` capsules `provider_unresolved`: add the declared `ip` to a copy of
  that directory first.
- **The content store only grows.** kata has no content-store garbage collection:
  every object and blob file stays for the life of the data directory.
- **Exit status is judged.** A non-zero shell exit fails the stage by default
  (`exit_policy = "zero_success"`), as does a capture past its bound; a sibling stage
  that is still running is not cancelled when an ordinary stage fails.
- **`kata run` runs on the main only.** Workflows run on an installed main
  (`kata serve`, then `kata run <workflow> --submit|--wait|--watch`); there is no
  single-shot local runner.
- **A unix socket's 108-byte address limit no longer depends on the data directory's
  length.** Every unix socket kata binds or connects — the main's `local_socket`
  listener, a worker's connect to it, an `Egress` capsule's egress handoff socket under
  its attempt root — is addressed through a descriptor on the socket's directory, so a
  long project path no longer refuses every egress capsule `plan_refused`
  (measured live under a 200-byte `data_dir`; `PATH_MAX` still bounds every path under
  it). A socket's file name is limited to 82 bytes: a longer
  `local_socket` `path` or `home_node_endpoint` file name is refused at config load by
  `kata serve`, `kata doctor` and `kata-worker`, naming the limit and the path.
- **A capsule refused before its container says why.** An agent turn refused before
  its container was assigned (`plan_refused`, `provider_unresolved`,
  `materialization_refused` and the rest) records the refusing check's own words beside
  its label, so `kata run show`, `kata watch`/`--watch`, the API execution view and the
  stored record name the cause (a path, an error, a missing provider member), not only
  the label.
