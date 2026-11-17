# Protected properties and shipped constructs

- Governing decision: [ADR 0001](0001-replacement-architecture.md)
- Ledger: [`protected-properties.toml`](protected-properties.toml)
- Checker: `bin/kata-eval/tests/protected_property_ledger.rs`

This document states the properties kata's execution engine must preserve and the
execution constructs it ships, one engine: rootless OCI capsules on the pinned youki.
It is the source the protected-property ledger is checked against. Each property and
construct has a ledger entry naming the cells — real `#[test]` functions, host-free
and, where the claim is host-dependent, live — that pin it, beside every registered
operational crash boundary. The checker runs on every `just test` and refuses:

- a bullet under [Protected properties](#protected-properties) with no ledger property
  whose `statement` is that bullet verbatim, or a ledger property that is not a bullet;
- a row of the [construct table](#shipped-constructs) with no ledger construct, or a
  ledger construct the table does not name; and
- a ledger citation whose file, heading anchor or quoted text is missing.

The ledger's rule (an entry lands with the change that adds its property, construct or
crash boundary) and how a cell is added are in
[`docs/development/verification.md`](../development/verification.md#the-protected-property-ledger).

The acceptance oracle throughout is external observation: operational records,
filesystem and git results, real runtime enforcement and provider receipts — never an
adapter asking itself whether it worked. A skipped or unavailable capability is not a
pass.

## Protected properties

kata preserves:

- one authoritative main and main-authorized effects;
- checked-program admission and stable program/occurrence/effect identity;
- at most one accepted outcome per occurrence;
- a member's liveness judged from one snapshot of its occurrence and its attempts;
- authorization before dispatch or possible effect issuance;
- uncertainty after ambiguous issuance, never automatic reissue — save where an effect's
  observer settles it: a forge export's push intent left without a receipt is issued again
  when the remote reads not performed, so a push that landed and was then undone on the
  remote (the ABA residual) is sent twice;
- bytes-before-reference publication and coordinated retention of environment and Nix
  roots; CAS objects are never reclaimed;
- immutable action/environment binding before issuance;
- approval bound to exact action, inputs, environment, candidate, and effect scope;
- a derived surface that exposes a subset of its principal and never advertises what its
  principal lacks, save MCP's pinned workstation-local forms (ADR 0004);
- bounded ownership and cleanup of attempts, descendants, sessions, roots, and
  spools; and
- refusal, without a weaker fallback, when a required capability is absent.

Effects are settled per attempt. An attempt's terminal records what the main can prove
about it: a completed attempt is accepted at most once and replays; one PROVEN NOT
PERFORMED may be redone; one PROVEN AMBIGUOUS (or unclassified) is never re-run
automatically and is left to the operator. Trees the main lands are idempotent by
content, and a workspace effect is classified from the repository it changed rather
than performed again. Two doors refine the attempt: a `forge_export`'s push and its pull
request each carry an intent row, committed before the effect's first byte, with the
verdict its receipt or its observer writes (ADR 0002 as ADR 0003 amends it; "Workspace
effect" below). kata keeps no other per-effect record; ADR 0002
(`docs/architecture/0002-effect-permits.md`) proposes them for the other doors the main
performs.

A worker's death settles every attempt it holds, so the main declares it only on what it
observed. A worker whose connection closes is settled at once. A worker whose connection
stays open heartbeats every half `[workers] heartbeat_interval_ms`, at the cadence its
main binds into its enrollment, and is settled dead past `interval + heartbeat_grace_ms` of
observed silence — counted from its last heartbeat, or from when its main started reading
it — each sweep charging at most one interval of it, so a stall that holds up the main's
sweep is never charged to the worker as more than one interval; a stall that holds up only
the reading of a heartbeat while the sweep runs is charged in full, as that heartbeat's
delay. A live worker is never settled dead while each of its heartbeats is delayed by less
than `grace - interval / 2` on top of any stall of the sweep, or `grace + interval / 2` when
the sweep does not stall; a zero interval and a grace shorter than the interval are refused
at load. A worker silent past the deadline is found dead at the first sweep past it, one
interval late at most when the main's sweeps run on time, later by each stall of the sweep
beyond one interval; the settlement's durable writes follow that verdict. A dead worker is
settled again at every sweep until it heartbeats, so an attempt placed on it after its
verdict is settled at the next sweep, and a settlement that failed is retried there — until
its connection is gone and a sweep's settlement leaves no attempt on it, when the main
forgets it and judges it no more. Every
settlement a death causes records its leg, the observed silence against the deadline, and
what `/proc` said of the worker's process at that moment. A dead worker that is the main's
supervised node is killed first and reaped, with its whole cgroup subtree when the main's
cgroup is delegated (its own process alone when it is not); its settlements record the
kill, and a new node enrolls in its place, so a stopped node never resumes on its old
connection. A kill not reported done within 30 s counts as failed: the node's attempts
stay unsettled for the next sweep, and no other worker's death waits longer than that
behind it. A node started again that has not enrolled 180 s after it started has no
heartbeat to be judged by; it is killed the same way and replaced.

A *spool* is any attempt-scoped byte stream buffered to disk before it becomes a
retained artifact or is discarded. There is one: the capsule provider's captured stdout
and stderr under the attempt root (its `capture` directory). An agent adapter's stdio
runs over FIFOs and is not spooled, and terminal callbacks are refused. The spool has a
size bound, a cleanup cell, a crash-sweep cell and a decision to retain or discard it.

The *repository* is a second store a durable record names, so its writes are held to
bytes-before-reference too, against a power loss and not only a process death. A
provider call that writes it — the target pins, a workspace's commits and checkout, an
applied `/work` delta, a stale checkout's repair, a workspace effect's commit and ref, a
park, a landing or a revalidation park, a `forge_export`'s local branch, a workspace's
teardown, a pin's release and the boot's pin sweep and repair — answers only once those
writes are on stable storage (`JjBackend::durably`: `syncfs` over the filesystems holding
the repository's root and its git store, opened before the call writes anything so a
writeback error of any of its writes is reported), so an admission, an apply's
resolution, an effect's settlement or a closeout record never outlives a repository
write a power loss could take back. Every jj transaction kata publishes after writing
objects or refs into the git store — a snapshot's commit, a workspace's base, a
bookmark, a landing, a revalidation park, a forge export, a git import, a teardown's
removal (`commit_transaction`), and the `/work` apply's and the commit effect's own
publications — waits on a barrier over that store first, where gix writes them with no
sync, so jj's log never names an object a power loss emptied; a teardown's removal
therefore publishes behind the barrier before any workspace file is removed, and the
op-log GC syncs its new head before it deletes the operations it replaced. A failed
barrier refuses `repository_not_durable`, and nothing that depends on the write is
recorded. kata's own `git` children add `loose-object` and `reference` to git's
`core.fsync` (`GIT_EXECUTION_OVERRIDES`). Each of these barriers is pinned at the syscall
boundary (`just repository-barrier-live`) and was watched red with it removed. Excepted,
stated: jj-lib's own operations inside one call kata cannot barrier from — a new
workspace's `add workspace` operation, which writes its `.jj/repo` pointer (kata syncs
the workspace's filesystem as the call returns), and an adoption's two `init`
operations — so a power loss inside that call can leave a registered workspace whose
pointer or first `@` is torn — the recovered `Admitting` execution's census then refuses
its admission and closes it out, and a read of that `@` refuses `repository_torn`; a
terminal workspace's removal and reap, which leave nothing a record depends on (one a
power loss takes back is reclaimed by the next boot's reap); and a push, whose durable
half is the remote's. What a power loss tears after the last barrier, the boot
repairs before anything else reads the repository (`JjBackend::repair_torn_repository`):
an EMPTY loose object is removed, since git and gix skip writing an object whose file
exists; a torn `refs/jj/keep/<id>` is rewritten at `<id>` when the store holds it, else
deleted; a torn branch is rewritten at the commit jj's view records for it only when
jj's export is its evidenced last writer — a kata branch (`parked/`, `exec-`, `kata/`),
or one whose newest reflog entry is jj's export of that commit (trunk after a kata
landing) — and a kata branch jj never recorded is deleted; any other torn branch, and
every torn remote-tracking ref or tag, is left and named at WARN as `repository_torn`,
never rewritten at a record the operator's git may have moved past. The boot's
target-pin sweep deletes an unowned execution's pins, torn or not, and rewrites an owned
execution's torn pin at its recorded target, or deletes it naming `target_head_absent`
when the store lost that commit too; the sweep, like a release, deletes every pin it
deletes in one ref transaction, so the repository-wide `packed-refs` is rewritten at
most once per call. A commit the repository's view names that its store does not hold
or cannot decode — a disk that lost a barriered write, or the window above — is refused
`repository_torn` where kata reads it as a workspace's `@` or a commit to park
(`JjBackend::named_commit`), and so is a candidate whose parent commit, tree or blob the
store lost under an intact commit, before a park, a landing, a workspace effect or the
closeout reads it through the working copy (`require_intact_content`); the closeout
records that refusal and closes the run out with its workspace standing, where before it
answered an internal error that kept the run `Terminalizing` and exited the main (a lost
tree), or parked a commit the store could not serve and tore down the one copy of its
bytes (a lost blob). Residuals, stated: a loose object a power loss left non-empty but
undecodable (a filesystem that zero-fills) is not removed, so a later write of it is
skipped and its read refuses; an object older than the candidate's parents is not read
before a park; a torn ref left unrepaired stays torn until the operator repairs it, and
jj's next import of git's refs (a new workspace's) fails on it; a branch whose reflog
lost the operator's newest entry together with the ref, and whose entry before it is
jj's export of jj's recorded commit, is rewritten at that commit; a `packed-refs`
rewrite inside a release, a sweep or a repair that a power loss cuts before the call's
sync can come back empty on a filesystem that does not protect a rename over an
existing file (ext4's default `auto_da_alloc` does; xfs and ext4 mounted
`noauto_da_alloc` do not), losing every packed ref with it; and an owned execution whose
pins a power loss removed outright is not re-pinned. Measured cost: one `syncfs` per
barrier — 0.15 ms with nothing dirty, about 3 ms after a jj-sized write, and the time to
flush every dirty page of the filesystem when other writers share it (66 ms for 256 MiB
of one writer's data on this project's NVMe; 0.4 s for the first sync on the shared
build box at load 15 with 0.8 GB dirty, the next ones 0.4 ms); and one walk of the
candidate's tree per park, landing or workspace effect — 5–14 ms over this project's own
2,017-file tree in a debug build, beside the 57–61 ms the same call's working-copy status
takes.

## Shipped constructs

Every construct below runs on the one engine. The rows after Reads confinement name the
authoring forms, the operator, API, MCP and SDK surfaces and the node verbs that reach it,
and the recovery mechanisms it rests on; each row's ledger entry states its guarantee. A
newly shipped construct adds its row here and its ledger entry in the same commit; the
checker refuses a row without an entry and an entry without a row.

<!-- oci-constructs:begin -->
| Construct | Authored as | Runs as | Ledger entry |
|---|---|---|---|
| Shell stage | a `shell` stage | `Execute { executor: Command }`, one capsule | `shell-stage` |
| Join | `parallel()` | `Join`, main-resolved | `join` |
| Select | `branch()` | program-level `Select`, main-resolved | `select` |
| Durable timer | `sleep()` | `Wait(For \| Until)`, main-resolved | `timer` |
| Approval gate | `approval = True` | a gate on the stage's own capsule attempt | `approval-gate` |
| Input wait | a blocking human request | program-level `Wait(Input)`, main-resolved | `input-wait` |
| Subworkflow | `subworkflow()` | `Invoke`, a linked child execution | `subworkflow-invoke` |
| Content cache | `cache_policy = "content_cache"` | `CapsuleReuse`, main-resolved | `content-cache` |
| Model reuse | `cache_policy = "model_reuse"` on an agent stage | `CapsuleReuse` over the agent capsule — the source's response and recorded `/work` delta adopted, zero spend | `model-reuse` |
| Exit status | `exit_policy` | the main's capture and exit judgement | `exit-status` |
| Cancel | `kata run cancel` | the cancel latch and terminal publication | `cancel` |
| Workspace effect | `stage(agent = "workspace_effect", op = …)` | `MainOperation::WorkspaceEffect`, main-resolved | `workspace-effect` |
| `/work` apply | a capsule stage's recorded delta | `MainOperation::WorkApply` at `#apply/<stage>`, main-resolved | `work-apply` |
| `/work` scope | `produces_files = [...]` | whole-delta refusal at main-side adoption | `work-delta-scope` |
| Capsule egress | a capsule's declared `CapsuleNetwork::Egress` — authored as `net = "host"` over `[node] egress_allow`, shell or agent stage alike | `createContainer` hooks + worker-owned `CONNECT` proxy on the handed listener | `capsule-egress` |
| Node-declared egress | `net = "host"` on the stage's profile + `[node] egress_allow` | `CapsuleNetwork::Egress` over the node's installed set at assembly; an empty set refused `egress_undeclared` at CHECK | `node-egress` |
| Agent capsule network | `net` on an agent stage's profile + the node's `egress_allow` | the capsule's network by the shell stage's rule: `egress_allow` under `host`, `Offline` under `offline`; named on every face as a `CapsuleNetworkPosture`, per panel member at check | `agent-capsule-network` |
| Scratch `/work` | `sandbox_profile(workspace = "scratch")` | the canonical empty tree mapped `ReadWriteScratch`; the delta recorded `scratch_delta_*` as evidence, never applied | `scratch-workspace` |
| Memory snapshot | `memory_snapshot()` | `MainOperation::MemorySnapshot`, main-resolved | `memory-snapshot` |
| Agent turn | `stage(agent = "<label>")` + the node's `[agents.<label>] adapter`/`credential` | `CapsuleProcess::Agent` — the embedded nanocode harness runs the turn in the worker, every tool call in the capsule's tool host | `agent-turn` |
| Execution target | `kata run --target` (REST/MCP `target`); `trunk` when omitted, or `pr:<N>` | an `ExecutionTarget` resolved and pinned BEFORE acceptance, frozen in the invocation (envelope schema 3) and bound by the admission digest; the fork, the git view, recovery, the landing check, the `promote` effect's claim and reconcile and the `target.*` template namespace read it | `execution-target` |
| Agent `/work` git view | implicit with an agent stage — no authored form | the `execution_git_views` row → `Capsule.git_view` → the worker's `/git-history` + `/git` mounts and the `/work/.git` gitfile | `git-view` |
| Tool host | implicit with an agent stage of a nanocode kind (`adapter = "nanocode_openai"` or `"nanocode_anthropic"`) — no authored form; the kind fixes the launch, so an agent block has no `argv` or `egress_extra` to declare (the config load refuses either as an unknown field), and `kata config check`, CHECK and assembly refuse an `env.HOME` (`capsule_agent_env_channel_owned`) | the capsule's init is `kata-toolhost`, bound read-only at `/.kata` from the provider entry's `toolhost/`; every tool call a toolhost frame over the worker-owned FIFOs, run as its child inside the capsule | `tool-host` |
| Review loop | `loop(body = …, gate = …)` | `ExpandBounded` — one `#op/` main attempt driving member capsules at `expand.child(iteration).child(member)` | `expansion` |
| Stage progress | `progress_visibility = "off"\|"summary"\|"full"` | `WorkerMessage::CapsuleProgress` — agent adapters' scrubbed session events or the command spool's bounded stdout/stderr tail, rate/byte/queue-bounded with drops counted, projected through the attempt row onto the shared `progress` event | `capsule-progress` |
| Static topology | a stage's declared `topology(...)` role list | one `ExpandBounded` at the stage's own coordinate — member 0 the root attempt, each declared child a capsule at `path.child(m)` stage-named `<base>#child-<role>` — and the stage settles with the authored fan-in and review quorum; every member maps its OWN `/work` branch of the stage's head (forked at one point, like a `parallel()` branch) and the settle merges the branches in its resolving transaction, a contested path failing the stage `work_fanin_conflict` | `static-topology` |
| Loop topology | a static `topology(...)` stage as a `loop(..)` body member or gate | a nested `ExpandBounded` seated per iteration at `loop.child(N).child(m)`, members one level below; the loop reads its settled fan-in envelope as the member's; a GATE topology's unmet quorum is the iteration's `refine` | `loop-topology` |
| Dynamic fanout | a `topology(..., dynamic_fanout = True)` stage | `ExpandBounded` at the stage's coordinate, template = the root; the root's `child_invocation_requests` mint members `path.child(n)` at runtime, each a capsule on its own `/work` branch, merged at the settle, `owned_paths` held over the recorded deltas | `dynamic-fanout` |
| Validation retry | `outputs = {...}` + `validate_retries` on a capsule stage | a capsule occurrence at the chain seat `[i].child(k)` — the loop member's and topology root's seats too — the invalid attempt's outcome accepted and its `/work` delta applied before the retry mints, authorized by the chain's validation ordinal | `validation-retry` |
| Failure retry | a fallback `agent = [a, b]` panel; a transient model provider failure on any plain stage or `loop(..)` capsule member | the chain's next seat, on the member the chain's walk names: the same agent, twice, each re-run after its backoff (30 s, then 120 s, from the failed frame's recorded instant), for a transient provider failure, else at once the panel's next member whose agent the provider has not refused on the chain, `n − 1` advances in all; PROVEN AMBIGUOUS / UNCLASSIFIED / an operator's stop never retry; a failure-retry policy (a fallback panel) on an expansion member refused at CHECK | `failure-retry` |
| Environment requires | `sandbox_profile(requires = [...])` | `environment_requirement_unmet` at CHECK, `capsule_requirement_not_in_environment` before dispatch, folded into the stage identity; `requires = ["git"]` maps the recorded git view on an isolated run | `environment-requires` |
| Reads confinement | `stage(reads = [...])` | a `CapsuleWorkView` on the capsule; `materialize_tree` writes only the covered members, uncovered base members read back UNCHANGED in the delta | `reads-confinement` |
| Unhonoured-knob refusals | `stage(allowed_tools=, required_capabilities=)`; `sandbox_profile(secrets=, toolchain=, rootfs=, image=)` | each knob the capsule route cannot honour refused by name at CHECK, never accepted, hashed and dropped | `check-unhonoured-knob-refusals` |
| Routing sugar | `route()`, `when()`, `branch_if()` | lowered to the `BranchRoute` the equivalent `branch()` lowers to; a discriminant of the wrong arity refused at load | `routing-sugar` |
| Contract typing | `contract()`, `field()`, `enum()`, `variant()`, `list_of()` and the constrained primitives | a closed JSON Schema object per contract, its limits the validator's own | `contract-typing` |
| Workflow params | `workflow(params = {...})`; `subworkflow(params = {...})` | typed `WorkflowParamSpec`s in canonical order, resolved and validated at admission; a secret is never readable by a template | `workflow-params` |
| Sequence | `sequence(a, b, c, ...)` | exactly the edges `a->b`, `b->c`, never duplicated beside an authored `depends_on` | `sequence` |
| Workflow max concurrency | `workflow(max_concurrency = N)` | `program.max_concurrency`, folded into the program hash; at most N stages in flight | `workflow-max-concurrency` |
| Worktree isolation | `workflow(worktree_isolated = True)` | the isolated-workspace flag on the program summary; a `workspace_effect` stage or a `target.*` read without it refused at CHECK | `worktree-isolated` |
| Model hint | `stage(model_hint = "<model>")` | the assembled turn's model, overriding the node's `[agents.<label>] model`, folded into the stage contract hash | `model-hint` |
| Locked sandbox profile | `sandbox_profile(locked = True)` | `SandboxProfile::locked`, lowered and hashed; nothing reads it after lowering | `sandbox-profile-locked` |
| Workflow pattern | `workflow(workflow_pattern = workflow_pattern(...))` | `program.workflow_pattern`; an escape hatch draws a verifier warning | `workflow-pattern` |
| Validation criterion | `workflow(validation_criteria = [validation_criterion(...)])` | a criterion bound to its declared proof stage, whose validation evidence it records | `validation-criterion` |
| Authoring surface closure | any builtin or keyword the DSL catalog does not declare | refused at load naming the identifier | `authoring-surface-closure` |
| Schedule | `schedule(id, submit, every_ms = N` or `cron = ..., on_missed = ...)` | an immutable program pinned at install, fired from a durable cursor once per due occurrence | `schedule` |
| Advisory human request | `human_request(..., blocking = False)` | execution evidence with its default assumption active; nothing parks | `human-request-advisory` |
| External-input channel | `workflow(external_input_channels = [channel(...)])` | bounded, idempotent appends exposed to the consuming stage under `external_inputs.<expose_as>` | `external-input-channel` |
| Steer verbs | `kata steer human-requests`, `answer-human-request`, `external-inputs`, `append-external-input` | the REST doors for human requests and external inputs, driven from the CLI | `steer-verbs` |
| Memory selector | `workflow(memory_selectors = [memory_selector(...)])` | a checked selector whose objects, within the execution's scope window, render under its alias | `memory-selector` |
| Memory writeback | `workflow(memory_writebacks = [memory_writeback(...)])` | the producer stage's drafts landed in the node's memory store at the declared tier | `memory-writeback` |
| Capsule capture bounds | `stage(work_delta_bytes = N, work_delta_entries = M)`; `[node] work_delta_*_ceiling`; the output and result bounds | hashed `CapsuleBudgets` the worker enforces before publishing and the main re-checks at adoption | `capsule-capture-bounds` |
| Capsule memory bound | `sandbox_profile(image = {"memory_mb": N})`; `[node] capsule_memory_bytes_ceiling` | the capsule's recorded `memory_bytes`, enforced as its cgroup `memory.max` with no swap | `capsule-memory-bound` |
| Capsule containment | no authored form: every capsule | one rendered `config.json`: a rootless user namespace, no capabilities, the stage seccomp deny-list, an empty network namespace and a leaf cgroup | `capsule-containment` |
| Operator park | `kata run park <exec> [--ref <label>]`; REST `POST /api/v1/executions/{id}/park` | the standing candidate published at `parked/<label>` and the workspace torn down; an occupied ref refused `parked_ref_occupied` | `operator-park` |
| Forge reconcile | `kata run forge-reconcile <exec>`; operation `forge_reconcile` | the open forge intent's observer asked at once, counted like any other ask | `forge-reconcile` |
| Nanocode adapter | `[agents.<label>] adapter = "nanocode_openai"` or `"nanocode_anthropic"` | nanocode's loop in the worker, every tool call a tool-host frame, refusing before any model call what it cannot serve | `nanocode-adapter` |
| Harness credential | `[agents.<label>] credential`; `kata login`, `kata logout` | `kata_login` or `env:<VAR>` resolved into the harness's in-process carrier, never the capsule; kata's own login stored owner-only | `harness-credential` |
| Code Mode | implicit with every nanocode agent stage: the model's `exec`/`wait` cells | each cell in a confined interpreter process, a child of the worker, under kata's fixed `CODE_MODE_LIMITS` | `code-mode` |
| Bounds walk-away | `workflow(bounds = [...], cost_budget = ...)`; a stage's `cost_budget`; a metering halt | one durable walk-away row, after which no stage starts and no later terminal releases its dependents | `bounds-walk-away` |
| Discharge stop | operation `discharge_stop`; `kata run discharge-stop` | an attributed, durable, non-overwritable operator assertion that clears the parking latch and nothing else | `discharge-stop` |
| Backup and restore | `kata backup [--recoverable]`; `kata restore` | manifest versions 2 and 7 only, every member verified before any activation, never a partial target | `backup-restore` |
| Recovery capture | `kata backup --recoverable` | every authoritative store exported under one exclusive hold; nothing published on failure | `recovery-capture` |
| Operation contract | no authored form: `kata_op_contract::Operation` | a closed set of 11 operations, one request and one response schema each, answered in the versioned envelope | `op-contract` |
| Operation errors and exit codes | no authored form: every failed operation and every `kata` exit | six typed codes with a total, stable exit mapping; network and capacity retryable | `op-error-exit-contract` |
| REST operations route | `POST /api/v1/ops/{operation}` | every operation through the one shared dispatch, answered 200 with its envelope | `rest-ops-anchor` |
| API route scope | `[api.auth] type = "signed_token"`; `kata api-token mint --scope ...` | a scope required per matched route template, unclassified routes failing closed to Admin | `api-route-scope` |
| MCP face | `kata mcp [--connect <url>] [--no-engine]` | a JSON-RPC 2.0 server attached to the installed main, proxying to `/ops` and serving ADR 0004's workstation-local forms at the caller | `mcp-face` |
| CLI JSON face | `kata --format json <command>` | an envelope for `kata check` only, every other command's own document bare | `cli-format-json-face` |
| SDK operation methods | `kata_client::KataClient` | one public method per fronted operation, spelled with the contract's word | `sdk-operation-methods` |
| Skill install | `kata skill install --host claude-code` or `codex` | an additive `.mcp.json` merge and the installed `SKILL.md`; `codex` prints the steps and writes nothing | `skill-install` |
| Shared dispatch | the request bodies of author, check, run, observe and list on any face | the shared dispatch's per-operation semantics, the workstation-local forms refused `usage` | `op-dispatch-node-operations` |
| Service install | `kata service install`, `start`, `stop`, `restart`, `status`, `logs`, `uninstall` | one systemd-user unit running the one foreground installed main through `__service-exec` | `node-verb-service` |
| Upgrade | `kata upgrade [--dry-run or --apply]` | a report of what boot would refuse on a data directory, never a migration | `node-verb-upgrade` |
| Repair nucleus | `kata repair-nucleus [--apply]` | the operational projection rebuilt from its chain, never the reverse | `node-verb-repair-nucleus` |
| Host setup | `kata host setup`; `kata host apparmor-install` | the host checks, the pinned youki, the provider store and the node's oci declarations, finished by `kata doctor` | `node-verb-host-setup` |
| Doctor | `kata doctor [--online]` | one pass, warn or fail row per readiness check, without booting a node | `node-verb-doctor` |
| Config check | `kata config check --config <path>` | the TOML parse, `KataConfig::validate` and the CHECK's config-only judgement of every harness agent block | `node-verb-config-check` |
| API token mint | `kata api-token mint --scope ...` | an ed25519-signed bearer whose scope is bound into the signature | `node-verb-api-token` |
| Execution provider | `kata execution-provider list`, `inspect`, `certify` | the closed provider world, its containment posture and the one rootless-OCI certification | `node-verb-execution-provider` |
| External provider install | `kata sandbox install-external-provider` | the provider directory copied, hashed and sealed into the by-hash store | `node-verb-sandbox-install-external-provider` |
| Capsule materialization | no authored form: every capsule stage's input mappings | verified CAS bytes written into the attempt root, never through a planted symlink, within member and manifest ceilings | `capsule-materialization` |
| Promotion gate | `stage(agent = "workspace_effect", op = "promote")`; `kata run promote`; `validation_criterion(required = True)` | a landing only of the candidate tree its passing required validation stamped | `promotion-gate` |
| Closeout park | no authored form: the closeout of every `worktree_isolated` run | the candidate parked under `parked/<exec>`, a refusal recorded as closeout evidence before the terminal lifecycle | `closeout-park` |
| Transition chain | no authored form: every durable state change | the retained chain as authority, every projection row its pure fold, replayed at recovery | `transition-chain-authority` |
| Durable schema refusal | no authored form: a data directory at another schema or format | refused by version with the new-empty-directory recourse, before any store open or lock mutation | `durable-schema-refusal` |
| Recovery import | `kata restore` of a v7 artifact | the import door: identity published last, behind a durable quarantine | `recovery-import` |
| Strict input | no authored form: config files, CLI flags, wire frames, the data directory's file set | unrecognised input refused by name, never defaulted | `strict-input` |
| CLI attachment | no authored form: every attached CLI command and the default `kata mcp` | a verified attachment to the installed main through its published descriptor | `cli-attachment` |
| Operator read surface | `kata status`, `run show`, `events` and the other read verbs and routes | answers from the node's durable state, mutating nothing | `operator-read-surface` |
| Factory controller | `kata factory apply`, `finalize` and the other factory verbs | a claimed controller application committed once, behind Approve scope | `factory-controller` |
| Offline verbs | `kata build`, `workflows`, `evidence`, `version --compare` | answered without a node, each printing its own document | `offline-verbs` |
| Memory store surface | `kata memory get`, `propose`, `snapshot`, `import-inbox` | reads and proposals over the node's `/memory` routes | `memory-store-surface` |
| Direct agent run | `POST /api/v1/agents/run`; `GET /api/v1/agents` | its own invocation kind, lowered to a checked single-stage program under the confined default | `agent-run-api` |
| Graph well-formedness | `stage(id=, depends_on=)`; `workflow(root=)` | unique, unreserved stage ids, declared edges and root, and no cycle, before hashing | `graph-well-formedness` |
| Stage output reference | `{{ stages.<producer>.parsed }}`, `.content` | checked at load against the producer's outputs and the consumer's dependency closure | `stage-output-reference` |
| Evaluator hermeticity | `load(...)` in a pack | whitelisted roots only, no graph or schedule from a loaded module, a budgeted evaluation, every module's bytes in program identity | `evaluator-hermeticity` |
| Pack resolution | `kata run <name>`; `workflow_ref`; `subworkflow(pack =)` | a name resolved through the ordered workflow roots, the resolved bytes the ones admitted | `pack-resolution` |
<!-- oci-constructs:end -->

## How each construct runs

The paragraphs below state each construct's mechanism and the refusals that bound it.
The ledger cites them; the cells it names are the proof.

### Shell stage

A shell stage compiles to the authoritative typed operation with a stable occurrence;
it binds immutable source inputs and a proven Nix environment; the main issues an
attempt to a subordinate worker; the worker runs it in rootless youki on the
Nix-prepared rootfs, under kata's syscall fence — which refuses every door to a nested
user namespace (`unshare`, and `clone` with `CLONE_NEWUSER`, EPERM; `clone3`, ENOSYS, so
a libc falls back to `clone`) beside kernel administration, `io_uring` and
`userfaultfd`, and kills a call through a foreign ABI (an i386 `int 0x80`), measured in
the capsule by the adversarial A1' row; bounded output is collected as a portable
artifact, validated, and exactly one outcome is accepted by the durable authority. An
interruption at authorization, dispatch, process completion, artifact publication or
acceptance either continues from durable facts or retains explicit uncertainty — it never
duplicates an acceptance or an effect issuance.

A run walks away once. Its first trip — a workflow bound's, a halting `cost_budget`'s, a
metering halt's — records the execution's one walk-away row, and no later trip records
another, on the live run or a resumed one. Every stage terminal the fold applies after the
walk-away, in chain order, releases nothing: a stage already running finishes and keeps its
outcome, and its dependents are skipped. And no stage starts after it: once the row is
durable the ready-advance skips every stage it would dispatch next — one a completion
before the trip released, one the `max_concurrency` throttle held, whatever its operation —
with every stage behind it, while a `loop(..)` or `topology(..)` stage still claims and
stops at its first dispatch point. The one exception is a capsule attempt a main that died
left claimed and never dispatched: the restarted run's boot
(`Dispatcher::dispatch_claims_left_undispatched`) dispatches it whether or not the row is
on the chain, and consults no walk-away.

### Join

The join is `OperationalDb::resolve_join`: one transaction that claims and accepts one
main attempt with `{"joined": [<input occurrence id hex>]}` in input order, only while
every input occurrence is accepted under the writer lock (`join_input_unaccepted`,
nothing written) — no capsule or command row. Each `parallel()` branch's `/work`
delta is computed off the barrier's one frozen fork base and fanned in at the join; a
path two branches both changed is the recorded terminal verdict `work_fanin_conflict`,
which moves no head.

### Select

A route's decision is the accepted outcome of its `Select` occurrence, claimed and
resolved in one transaction (`MainOperation::Select`) with a `SelectRecord` computed by
the pure `execution_program::select::select_decision`. Skipped stages are not
occurrences: a join downstream of a not-taken arm is never minted. The resolver reads an
accepted `Select` back and refuses `select_decision_diverged` when the recomputed
decision disagrees; a verdict that decides nothing resolves the select `failed` and
fails the run. Its attempt's stage id is the program-operation coordinate `#op/<path>`,
and a `#op/` attempt takes no `max_concurrency` slot.

### Durable timer

The CHECK admits `sleep()` and refuses only an unrepresentable deadline
(`durable_sleep_unrepresentable`). `WorkflowRunner::park_timer` claims one main attempt
in `awaiting_timer` with the deadline written in the claim's transaction, so no clock
read at a resume or boot can re-anchor it and no sleep is a failure retry; a resumed
runner's re-submission converges on it. `Dispatcher::sweep_due_waits` accepts each due
timer once, on every deadline sweep tick and once when startup recovery opens; the wake
comes up to one heartbeat interval after the deadline.

### Approval gate

The approval gate is a gate on the stage's own capsule attempt: `authorize_attempt`
derives it from the checked stage and returns `Authorization::Parked`, the capsule
published and declared and its attempt claimed `awaiting_approval` in the claim's
transaction, no worker chosen and nothing dispatched; `dispatch_claimed_attempt_in_tx`
refuses an undecided one (`approval_decision_required`). The one door out,
`OperationalDb::decide_capsule_approval`, is one writer transaction that re-reads its
premise and records a write-once `approval_decided` transition carrying the verdict, the
principal the API transport proved and the capsule id. Approve then dispatches at a
placement chosen in the same transaction; reject records `failed` PROVEN NOT PERFORMED;
a repeat answers `Already…`; the opposite verdict is refused `approval_already_decided`.

### Input wait

A blocking human request is its own program-level input wait: each request with
`blocking` and a target stage lowers to `Wait(Input{request})`, and
`hold_for_blocking_inputs` claims one main attempt per unaccepted request at
`#op/<path>` parked `awaiting_input`, holding the target. Its acceptance releases the
target and a cancel fails it. The accepted `InputWaitRecord` is what the target renders
from, so the answer is in the capsule's argv and identity. The answer door
`OperationalDb::resolve_input_wait` is one transaction; a second answer is refused
`input_request_already_resolved` naming the winner.

### Subworkflow invoke

The child program is bound at the parent's CHECK, stored once by hash, and runs as a
separate, linked execution. One acceptance commit, `OperationalDb::invoke_child_execution`,
claims the parent's main attempt parked `awaiting_child_completion` and admits the child
in the same writer transaction, so a crash leaves neither or both. Resolution is the
child's terminal publication: the transaction that publishes the child's terminal finds
the parent attempt parked on it and resolves it — `completed` with the child's outputs,
`failed` for a failed or timed-out child, `cancelled` for a cancelled one — each carrying
the child's invocation summary over every call the child billed.

### Content cache

The content cache runs on the capsule route: a capsule stage whose every
container-observable input equals an earlier accepted capsule's is not run, and its
occurrence is claimed and accepted by a main attempt (`MainOperation::CapsuleReuse`)
with the earlier result. The key is `Capsule::reuse_key` over the whole capsule except
its id and occurrence — prepared action, environment, platform, mappings (so the walked
`/work` tree), argv and every budget — plus the node's executor term.

The executor term (`kata_types::execution_platform::ExecutorTerm`) is derived at boot
from the rendered seccomp rules, the pinned youki's content hash, the bundle templates
rendered for a fixed command, agent and toolhost reference capsule, the tool host's
protocol and source digest, and the embedded harness's identity (its pinned nanocode
rev, the digest of the Code Mode engine as kata runs it — the vendored engine, kata's
patch to it and kata's interpreter host —, the digest of the interpreter's syscall
filter as compiled, Code Mode limits, host tool definitions and the instructions kata
gives it), so a kata upgrade that changes any of them misses every earlier result. It is one node-wide
term: a change to a property only one kind of capsule uses misses every capsule once.
It is a key parameter,
never a capsule field: no capsule id, occurrence or platform moves with it, and a
stage-cache store carrying none serves and records no hint. Every accepted capsule
outcome is stamped with the executor term of the worker that produced it, and a worker
states its term when it enrolls (a worker stating none is refused). The reuse door
misses `SourceExecutorTermDiffers` for a source stamped with another term or with none,
writing nothing, so a worker built from a different kata keeps taking work but its
results neither seed nor serve reuse.

The lookup is a hint in the rebuildable `stage_cache.db`; it is consulted after the
capsule is assembled and before `/work` is published, a worker is selected or the
attempt is authorized, so a hit publishes no `/work`, declares no capsule and writes no
command row. A reuse re-judges its source's accepted outcome against the
adopting stage's exit policy and misses on a failure (`SourceOutcomeFailsStage`).

### Model reuse

An agent stage authoring `cache_policy = "model_reuse"` compiles and consults the same
capsule reuse cache as `content_cache`: the agent capsule's reuse key folds the rendered
prompt, adapter, model and credential reference beside the shared inputs, and a hit is
the same `OperationalDb::reuse_accepted_capsule_result` door — the occurrence accepted
main-side with `reused_from`, nothing dispatched, the source's response, `agent` band
and recorded `/work` delta adopted verbatim. The adopted `token_usage` is rewritten to
`StageUsage::unbilled()`: a hit makes no provider call, and the source's spend was
charged to the source's execution already. A non-agent stage authoring `model_reuse` is
refused at CHECK, because a command capsule makes no model request.

The memoised-spend bound is enforced at the model-reuse consult: a source occurrence
accepted longer ago than `[runtime] model_reuse_max_age_secs` is not adopted and the
stage runs its own turn. The bound is read off the source's own `accepted_at_ms`, never
the hint's `recorded_at_ms`; absent or `0` means 7 days, `"unbounded"` lifts it, and a
malformed value is refused at load. Nothing is deleted, and `content_cache` is
unbounded.

### Exit status

A capsule's exit status and capture are judged at the main, before any byte of its
result is read, by `ShellExitPolicy::judge_provider_completion`: first
`judge_provider_capture` (no exit policy exempts a capture past its bound), then
`judge_exit`, with a reported-no-status mapped to `SIGNALLED_EXIT_CODE`. The provider
reports no status, rather than its runtime client's own `255`, when that client failed
without finishing its own delete — its container directory still present, or not
confirmed absent, at the reap (`kata-provider-youki`'s `client_exit`). The judgement
reads the execution's durable program, cross-checked against the occurrence's
`program_hash`. A failing capsule is recorded `failed` (`cancelled` under a standing
stop), PERFORMED BUT FAILED, its result not adopted and its occurrence accepting
nothing. A worker whose capsule start checkpoint cannot be sent launches nothing.

### Cancel

`kata run cancel` reaches `WorkflowExecutor::cancel`, which first latches the
execution's own terminal intent `cancelled` with the operator's reason
(`OperationalDb::latch_execution_cancel`), then resolves parked timers and input waits
`cancelled` main-side, settles parked gates `cancelled` (no stop request is written for a
gate; the response counts it with the waits in `main_side_settled`, never in
`assignments_asked_to_stop`), asks every running capsule to stop, fenced, and walks every child a live `Invoke` waits on, transitively, latching
each child's terminal intent first — so a child with no work placed at that instant is
stopped too, not only asked. While the latch stands, `record_transition` refuses every
attempt claim, worker or main (`claim_after_terminal_intent`).

### Workspace effect

`workspace_effect` ops (park, promote, commit, forge export) run at the main as typed,
authorized, op-log-tagged effects: the attempt is claimed, the tagged jj operation is
performed in the main process, and the outcome is resolved, with per-op recovery
classified from repository facts rather than re-performed. The main-side crash
boundaries `after_workspace_effect_*` are registered, armed and pinned. The windows inside
the verbs are kata-vcs test arms, not registered boundaries
(`KATA_WORKSPACE_EFFECT_CRASH_ARM`): `before_jj_publish` in every verb, `commit`'s
`between_write_and_publish` and `after_jj_publish_before_return`,
`after_jj_publish_before_teardown` in `park` and a landed `promote`,
`after_landing_park_before_teardown` in a `promote` whose landing
parked, and, between the three steps of
every teardown (`JjBackend::remove_workspace_tagged`: the working-copy commit's removal
from the view, the workspace store's `forget`, the directory's removal),
`after_wc_removal_before_forget` and `after_forget_before_remove_dir`; their cells are filed
under the nearest registered boundary. Every leg that answers a performed `park`, or a
`promote` whose landing reached the trunk, from repository facts — the sweep and the
perform's reconcile-first alike — finishes the teardown before it resolves
(`Dispatcher::finish_owed_teardown`), so that recovered effect leaves no execution
workspace standing. That includes a teardown a crash interrupted partway: a directory
whose working-copy commit the view no longer names is no live workspace
(`lookup_workspace`), so recovery neither repairs nor classifies its `@`, and the
teardown, idempotent step by step, finishes it — a directory left half-removed included.
When the sweep cannot classify a pending effect at all — the workspace lookup or the op's
classify returns an error, a typed one included (the frozen branch gone after a rename) —
it records the attempt failed under
`workspace_effect_unclassified` naming that error (`Dispatcher::resolve_unclassified_effect`),
a record that claims neither that the effect ran nor that it did not, never re-driven and
nothing torn down, rather than fail the run before the fold. Boot recovery asks first: for
a run whose workspace is gone, `WorkflowExecutor::missing_workspace_proof` classifies its
pending `park`/`promote` through `Dispatcher::workspace_teardown`, and an error there
refuses the restart naming it, recording nothing — the attempt stays pending until a
restart can read the facts (a workspace lookup that errs refuses the same way). The
classify reads refs and the view and never the working copy, so the stale-checkout repair
runs after it, only
before a step that uses the working copy (the `Committed` arm, the re-perform, the export's
push), and its error propagates as theirs do: a working copy that cannot be loaded never
hides the ref that answers a published `park` or `promote`. A `promote` whose landing parked the rebased delivered commit for
revalidation is answered the same way: a `parked/<exec-id>` proven to be that landing's
own rebase (`JjBackend::own_revalidation_park`: one parent on the frozen branch that the
delivered commit does not descend from, itself off that branch, the ladder's description,
the recomputed rebase's tree), with the workspace gone or its `@` still the recorded
candidate, classifies `LandingParked`, and after the teardown the attempt is recorded
failed with the verb's own refusal; that park under a moved `@` is `Diverged` (the
candidate moved), and any other commit there is an outside write, `Diverged` — both move
nothing. A conflict park leaves the delivered commit itself at `parked/<exec-id>`, the
shape a `park` effect of the same execution also writes (whether the two can be pending
at once is not settled), so recovery does not read it: the live workspace classifies `NotPerformed` and the
verb lands again on the frozen branch as it then stands. The park is judged on the frozen
branch even after the host's trunk answer moved or was renamed, and the legacy
`promote_workspace` refuses its revalidation park with the same function's text
(`revalidation_park_refusal`). No park writes over a `parked/<…>` naming another commit
than the settled candidate it would write (`refuse_occupied_parked_ref`): a failed or
completed run's closeout park (`park_workspace_recorded`) refuses `parked_ref_occupied`
as the closeout's answer, so the ref and the workspace stand and the run closes out
unparked. An operator park of a standing workspace (`park_workspace`, which
`park_candidate` re-runs rather than adopt the default ref while the workspace stands)
refuses the same name. A ref already at that commit is adopted — the check is commit
equality, not authorship — and the park completes. Every named closeout park refusal
(`parked_ref_occupied`, `oci_candidate_diverged`, `oci_candidate_disk_diverged`, and
`repository_torn` for a workspace whose `@`, or a parent, tree or blob of it, the store
lost) is
recorded on the execution (`ExecutionEvidence::closeout_park_refusal`, one claimed row)
BEFORE the terminal lifecycle is published. A failed append keeps the run
`Terminalizing`, and the next boot's repair asks the unchanged park again and records
it. A recorded refusal is the closeout's answer for good (`recorded_closeout_park_refusal`):
a repair after a crash that followed the record does not ask the park again
(`park_candidate_at_closeout`), and the `parked/<exec>` it names is never adopted as the
run's park — not by the execution read (`recover_auto_parked_candidate_evidence`), not
by the Terminalizing repair once the workspace is gone, and not by the operator's
default park once the terminal reaper removed the workspace (`park_candidate` refuses
`parked_ref_occupied` unless the execution's own parked-candidate evidence binds that ref
and commit). The operator park's own refusal is its synchronous answer and is not
recorded. After a `commit`, `park` parks, `promote` lands
and `forge_export` pushes the commit it finalized, never the empty working-copy commit it
leaves above it, while all three still fence on that recorded candidate. CHECK refuses a
`forge_export` with no `commit` or `promote` among its transitive ancestors
(`forge_export_without_commit`, `parser::validate`). A
`forge_export` whose delivered commit, after a `commit` ran, is neither the head row's
`committed_commit_id` nor a commit a completed `promote` of the execution landed
(`landed_promote_commits`) — a writable stage changed the candidate and no boundary
recorded the change — is refused `forge_export_uncommitted_candidate` on every drive that issues the push
(`Dispatcher::refuse_uncommitted_export`, called from `ExportDrive::push`), before the
remote is read or anything is pushed — a drive that resumes on an open intent answers
that intent and does not ask it; `commit → shell(rw) → promote → forge_export` exports the commit its
promote landed. The PR's base is the frozen target's landable branch, read off the
immutable invocation on every leg (never a pack literal or a default; an invocation with
none is `target_not_landable`). The push remote is inherited from the repository for
that branch (`forge_export_remote`: git's push remote for it — `branch.<branch>.pushRemote`,
else `remote.pushDefault`, else `branch.<branch>.remote` — else the only remote, else
`forge_remote_unresolved`, both refused before the claim) and RECORDED on the claim
(`WorkspaceEffectSpec::forge_remote`): every drive of the export — the live claim, an
approved gate, a recovery after a crash — pushes to and reads back that remote, never one
re-read from git config after the claim. A drive that issues the push first writes
`kata/<exec>` through `write_workspace_effect_forge_ref` (one that resumes at an observer
or at the pull request writes nothing locally), which first asks one helper
(`JjBackend::refuse_unexportable`), whose refused set is: a live workspace whose disk is
dirty (`oci_candidate_disk_diverged`) or whose `@` is not the recorded candidate
(`oci_candidate_diverged`), a delivered commit whose tree is conflicted
(`forge_export_conflicted_commit`), and one whose author or committer is an identity kata
will not publish (`publishable_author`). Each is a typed refusal recorded as the attempt's
failure, with nothing written or pushed; a workspace that is no longer live (a landed
promote removed it) fences nothing. A `forge_export` issues its two wire effects — the
push of `kata/<exec>` and the pull request from it — each under an intent row
(`forge_intents`, `OperationalDb::record_forge_intent`), committed after every step that
can fail without issuing it and before the effect's first byte, its verdict written once
by the effect's receipt or its observer (`Dispatcher::drive_forge_export`); a push's
PERFORMED verdict, its receipt or its observer's, commits on its own
(`OperationalDb::settle_forge_intent`) before the pull request's lookup, so a main killed
inside that lookup pushes once and records no NOT PERFORMED verdict. The push's
intent follows a read of the remote's head (`forge_remote_head`) whose answer is the
push's lease (`--force-with-lease=refs/heads/<branch>:<lease>`), and the push writes the
intent's commit to `<branch>` and nothing else. Its source, `<commit>^{commit}`, is a full hex
id of the repository's own object format (read by gix; any other string is refused before git
runs), which git resolves as that object under every one of its name rules and never through a
local ref — not `kata/<exec>`, nor `<id>`, `refs/<id>`, `refs/tags/<id>`, `refs/heads/<id>`,
`refs/remotes/<id>` or `refs/remotes/<id>/HEAD`, the last four of which a bare `<commit>`
source would send. The push runs with replace objects off (`GIT_NO_REPLACE_OBJECTS=1`, no
inherited `GIT_REPLACE_REF_BASE`), so a `refs/replace/<id>` substitutes nothing, with no
graft file read (`GIT_GRAFT_FILE=/dev/null`, so `.git/info/grafts` is not), so the pack
carries only the objects the commit reaches, and with
`--no-follow-tags --recurse-submodules=no`, so `push.followTags` sends no tag and
`push.recurseSubmodules=only` cannot skip the branch under an exit 0. A write from outside
kata in that closed set — a ref shadowing the id, a replace ref, a graft, those two keys —
changes neither what is pushed (the commit, and on a remote that held nothing, exactly the
objects it reaches) nor the receipt's `pushed` commit, and a commit the local repository lacks fails the
push with nothing sent: a read that fails records
no intent and fails the export PROVEN NOT PERFORMED (`forge_export_remote_unread`), and a
head that is neither absent, the delivered commit, nor the commit this execution last
pushed there — its newest push intent to that remote's branch recorded performed
(`last_performed_forge_push`); an older push of the same execution does not count — is
refused `forge_export_diverged` with no intent. Every `Forge` call of the export is bound to
the repository the push remote's URL names (`forge_export_repository`), which the forge must
confirm it addresses before the push (`Forge::confirm_repository`): a URL that names none
(`forge_export_repository_unresolved`) or one the forge does not confirm
(`forge_export_repository_unaddressed`) is refused with no intent and nothing pushed. The pull request's intent follows a lookup of
an open pull request from the head into the export's base (`Forge::find_open_pr`; one into
another base is not the export's): one found is adopted and the export
completes with no pull-request intent (adopting sends nothing), and a lookup that fails records
no intent and fails the export PROVEN NOT PERFORMED (`forge_export_forge_unread`).
Otherwise the intent commits, its coordinates end the body as a marker
(`<!-- kata-forge-intent: <attempt>/<index> -->`), and
`Forge::create_pull_request` only creates. A
drive reads the attempt's intents first: none means nothing was issued and the export runs
from the start; an intent with no verdict asks its observer, and nothing is issued again
under it. The push's observer is the remote ref: PERFORMED at the intent's commit, NOT
PERFORMED only while the ref holds the lease (absent, when the lease is absence), and
any other head UNCLASSIFIED at once — recorded failed `workspace_effect_unclassified` and
never pushed again. The pull request's observer is a pull request on the head carrying
the marker — the whole comment, so one intent's marker never matches another's — in any
state (`Forge::find_marked_pull_request`): found — open, closed or merged — it is
adopted, PERFORMED; none, NOT PERFORMED; a listing at its bound or past the bytes a `gh`
command may print on stdout (`MarkedPullRequest::BeyondBound`), UNCLASSIFIED at once — a
failed `gh`, however much it prints on stderr, is a read not answered. A read the
remote or forge does not answer settles nothing (owner decision #15): it is counted on
the intent (`forge_intents.unanswered_reads`), the attempt stays `pending`, the sweep
asks again once `FORGE_OBSERVER_ASK_SPACING` (60 s) has passed since the last unanswered
read and no sooner, and the read that brings the count to `FORGE_OBSERVER_UNANSWERED_BOUND` (10)
settles the intent UNCLASSIFIED; a drive that finds the count already there settles it
without asking. `kata run forge-reconcile` (`Dispatcher::reconcile_forge_exports`) asks
at once, its read counted like any other, and refuses an execution with no pending
export (`forge_reconcile_nothing_pending`); `WorkflowExecutor::reconcile_forge_exports`
refuses first an execution whose lifecycle is not `Running`. A command that returned an error records it
on its intent (`forge_intents.command_error`) before the observer is asked; a NOT
PERFORMED verdict on such an intent, from any ask, fails the export with that error,
proven not performed, and on an intent no command answered (a crash left it) issues the
effect again under a fresh intent. Residuals, stated: a ref back on the lease after
kata's push landed and before its PERFORMED verdict commits — a crash between the push
and its receipt, then a move before the observer's first answered read — by any path,
moved back or deleted when kata found it absent, reads NOT PERFORMED, and the push is
issued again (M0 finding F9; unanswered reads keep that window open); a push the remote refused because the branch
moved between the read and the push reads UNCLASSIFIED while the branch holds that other
head (NOT PERFORMED only if it is back on the lease by the observer's answered read,
which fails the export with the command's error); and a pull
request whose marker was deleted and that is no longer open yields a second pull
request. The observers assume the crashed main's `git push` or `gh` child died with it,
as the shipped service unit makes it (`KillMode=control-group` kills the main's group
before `Restart=on-failure`); a child that outlives its main can land after the restarted
main's observer read NOT PERFORMED. A command killed at `FORGE_COMMAND_TIMEOUT` is observed
at once, so a forge still applying it records NOT PERFORMED for an effect that then lands
— a wrong record, never a second effect, since that verdict after a failed command issues
nothing again. The push's receipt commits whether or not the attempt is still drivable,
so a cancel after the push returned leaves it recorded PERFORMED; any push intent still
open when the attempt is settled stays open — one a crash left between the push's intent
and its receipt, or one whose command failed and whose observer has not yet answered —
the record of an effect that may have been issued.

No hook from the repository's or the operator's configuration runs inside kata's own `git`
children (`GIT_EXECUTION_OVERRIDES`): `core.hooksPath=/dev/null` empties the hooks
directory, `hook.<event>.enabled=false` for every event githooks(5) of git 2.56 lists stops
configured `hook.<name>.command` hooks, which `core.hooksPath` does not reach, and
`core.fsmonitor=false` is in the set too (no cell observes an fsmonitor in these
children: none of the operations the hooks cell drives reads the index). `kata doctor`'s
and `kata init`'s `git check-ignore` and `kata run`'s uncommitted-edits `git status`, which
inherit the repository's configuration on purpose, pass `core.fsmonitor=false` alone (the
only hook either command runs, measured on git 2.56; a cell watches each one's fsmonitor
not run). `kata version --compare`'s `git rev-parse HEAD` and the identity probe's `git var
GIT_AUTHOR_IDENT` (`observe_identity_at`) pass no override: neither runs a hook (measured on
git 2.56, under a configured hook on every event and an fsmonitor). A recovery remote's
`git` runs in a repository kata initialized with no template; its two `git config` reads
(`reacquire_recovery_repository`) inherit the operator's global and system configuration to
find the credential helper, its username and `useHttpPath` settings and `core.sshCommand`,
which the fetch then carries as `-c` settings; every other recovery `git` runs under no
global or system configuration. Not refused: an event a later git
adds (a cell reads the host git's githooks(5) and fails on one the set lacks), and the
hooks a local remote's own receive-pack runs, which a forge on another machine would run
too.

### `/work` apply

A completed capsule stage's recorded delta is applied at the main as a typed
`MainOperation::WorkApply` attempt at `#apply/<stage>` — claimed, its effect published,
and the `execution_work_tree_heads` row advanced inside the resolving transaction, with
the stage's dependents gated until that acceptance. An isolated root head applies
through jj (refused `work_apply_candidate_diverged` when `@` moved); a non-isolated root
and every `parallel()` branch head advance CAS-only. The crash windows
`after_work_apply_claimed_before_apply` and `after_work_apply_published_before_resolve`
are recovered by classification, never by re-applying; at
`after_work_apply_acceptance_before_successor_release` the acceptance and the head
advance have committed and the successor's gate reads no pending apply, so it is
released on the next advance. Inside the jj apply, the test-only arms of
`KATA_WORK_APPLY_CRASH_ARM` — `before_jj_publish`, `between_write_and_publish` and
`after_publish_before_checkout` — split its write, its publish and its checkout. A delta
whose base is no longer the head it was claimed against is refused
`work_delta_base_stale`.

### `/work` scope

A capsule stage's `/work` writes return through the typed `WorkApply` main effect with
its `produces_files` scope enforced at adoption: an out-of-scope delta is refused WHOLE
with its paths named, never partially applied, the stage failed and its cost charged
(`work_delta_out_of_scope`, PERFORMED BUT FAILED). Under `workspace = "ro"` the scope
is empty by posture and this door is its whole enforcement: the capsule maps `/work`
read-write (`spec_for_as` refuses a read-only `/work`), so a write succeeds while the
stage runs and adoption refuses any non-empty delta by the same name, nothing of it
applied. The delta is the worker's census (`kata_worker::work_delta`, its excluded set
stated there): a change to a tracked path, or to an untracked path the post-run tree's
`.gitignore` files do not ignore. An untracked ignored path (a build's `target/`) is not
in it, so under either posture it is discarded, neither refused nor applied. The
post-run `.gitignore` files include the ones the stage wrote, so a stage can make a new
path ignored itself — an untracked `.gitignore` that is itself ignored, by its own
patterns (`*`) or by any other applicable `.gitignore` (a base `.*`), leaves the delta
with every new path its patterns match — and that path is discarded rather than
refused: a residual, stated exactly
in the census module. A
`.gitattributes` carrying a
conversion (`filter=`, `ident`, `working-tree-encoding`, `eol=crlf`) is refused
`work_delta_unsupported_repository` by the same census parser admission uses. A delta
path with a VCS-internal component (`.git` or `.jj`, at any depth) is refused
`work_delta_reserved_path` by the worker's capture, the adoption judge and the jj apply
boundary alike: jj's checkout refuses such a path, so a tree naming it would wedge every
checkout of the workspace.

### Capsule egress

Two `createContainer` hooks are rendered into the bundle ONLY for `Egress`: one raises
the guest's loopback interface, and the other binds the proxy listener inside the
container's network namespace and hands the listening fd to the worker over
`SCM_RIGHTS` before it exits. The worker adopts that fd as its `EgressProxy`'s accept
socket, so the guest's proxy endpoint is the worker's own listener projected into the
namespace — there is no in-container acceptor. The handoff socket lives under the
attempt root, so both ends address it as `/proc/self/fd/<fd>/handoff.sock` through a
descriptor on its directory, and no data-directory length can push it past the kernel's
108-byte `sun_path` (a socket's file name, at most 82 bytes, is the one bound kept). The
proxy matches exact `host:port` entries; it resolves an allowlisted name itself,
classifies every resolved address (loopback, unspecified, link-local, private, CGNAT,
multicast, reserved and the v4-mapped forms that would launder them are
`egress_address_refused`) and connects only to the checked addresses, with no second
resolution. Its refusals are attempt evidence.
The hook binary's sha256 is pinned into the plan and verified before launch.

### Node-declared egress

`net = "host"` is an egress declaration the node answers: `[node] egress_allow` states
exact `host:port` authorities, every entry parsed at config load through
`EgressAuthority::from_authority_str` (a misspelled entry refuses the boot, naming
`node.egress_allow` and the entry), and boot installs the parsed set. Capsule assembly
turns a stage's `net = "host"`, shell or agent, into `CapsuleNetwork::Egress` over
exactly the installed set. A stage that authors no `sandbox=`, shell
or model, materializes `net = "offline"` (`materialize_sandbox`), so it reaches the node's
set only by authoring `net = "host"`. `net = "offline"` is the spelling for no
NODE egress — a capsule under it is `Offline`, shell or agent alike — so a `net = "host"`
stage on a node whose set is empty is refused at CHECK
`egress_undeclared` naming the stage, and `Capsule::new` refuses an empty `Egress`
`capsule_egress_allowlist_empty`. The allowlist folds into the capsule id.

### Agent capsule network

An agent stage's `net` governs its capsule's reach exactly as a shell stage's does: `net =
"host"` is `Egress` over the node's `egress_allow`, `net = "offline"` is `Offline`, minted
by the one rule `capsule_rules::capsule_network_for`. The embedded harness's model calls
leave from the process hosting the worker, never from its capsule, and its block has no
`egress_extra` (the config load refuses one as an unknown field). Every face names what the capsule gets as a `CapsuleNetworkPosture` —
`offline` or `egress` with its exact authorities: `kata check`'s and `GET
/workflows/{name}`'s per-stage preflight and the `check` operation (the allowlist rule
assembly mints from, over the installed node — one row per agent the stage can run under,
the primary then every fallback panel member), the execution record `kata run show` and
`GET /executions/{id}` serve and the `observe` operation (each declared capsule's own
bytes), and an approval gate's capsule. A model stage that authors no `sandbox=` — and an
API agent run that omits `sandbox` — materializes `net = "offline"`, as a shell stage
does, so its capsule reaches none of the node's `egress_allow`. The five example packs
whose model stages authored `net = "host"` (`code-review-loop`, `gate-fix-loop`,
`gold-loop`, `parallel-tickets`, `software-factory-slice`) author no `net`, so theirs are
too.
The frozen class never claims an `Offline` network for a
model stage: its network axis is `Unrestricted` under either `net`, so a model stage
declaring `execution_requirements = {"network": "offline"}` is refused at CHECK under
every `net`.

### Scratch `/work`

`sandbox_profile(workspace = "scratch")` is a capsule `/work`: the canonical empty tree
mapped `GuestAccess::ReadWriteScratch`, the one artifact that role may name
(`work_tree_not_role_bound` answers any other), mounted writable by the bundle while the
scratch tag is refused on any other guest path. The delta it records is
`scratch_delta_*` evidence, adopted with `WorkDeltaDisposition::Scratch` and never
scheduled onto the durable head.

### Memory snapshot

`memory_snapshot()` is a typed main-resolved stage: the marker rides `StageDefinition` →
`ExecutionProgramStage` → `RuntimeOperation::MemorySnapshot` →
`MainOperation::MemorySnapshot`, and it resolves through
`claim_and_resolve_main_attempt` against the node's memory store — no process, worker,
capsule, sandbox or loopback API. The accepted output is the serialized snapshot
envelope; a store-less node resolves the recorded failure
`memory_snapshot_store_unavailable`, logged as a failure (a `warn` line naming the reason,
never the accepted resolution's line). An accepted occurrence converges on its recorded
resolution without re-reading the store; a failed resolution is retried at the next
presentation and mints a further attempt.

### Agent turn

Assembly's agent arm mints `CapsuleProcess::Agent` over the submit-published Private
prompt blob, with the stage's authored model. The worker resolves the prompt before
launch, resolves the node's declared credential (`kata_login` or `env:<VAR>`) into an
in-process carrier the harness holds — never the capsule — starts the capsule with
`kata-toolhost` as its init, drives the turn under the capsule's armed wall-clock
deadline, confines every tool call to `/work` and `/out`, prompts once and settles the
turn. A refusal before the provider accepts is PROVEN NOT PERFORMED; past acceptance the
container is killed and contained first, and the outcome is PROVEN NOT PERFORMED only on
a confirmed empty cgroup, PROVEN AMBIGUOUS otherwise. A completion publishes the
response as a Private blob, `/out`, the `/work` delta and the session's evidence record.
kata reads no other tool's login; its own login (`kata_login`, below) is the one kata
refreshes: nanocode, in the worker's process, rotates its refresh token
(`kata_agent_nanocode::credential::load`). An `env:` key is also in the worker's own
process environment, where the operator exported it, and in none of the processes that
run the capsule: `kata-provider-youki` and every `youki` the worker or the provider runs
start with an empty environment, except the certification's throwaway `youki run` at the
worker's start, which `systemd-run` execs with the worker's `PATH` and `XDG_RUNTIME_DIR`
(and its own `INVOCATION_ID`); the `systemctl --user kill` that certification's watchdog
runs on a timeout keeps the same two and nothing else. Neither name can carry a key: an
`env:` source naming `PATH` or `XDG_RUNTIME_DIR` is refused, and so is a declared
`[agents.<label>] env` key naming either (`capsule_agent_env_channel_owned`).

A stage's `produces=` contract also reaches the model as a strict structured-output
schema on a kind whose protocol carries one (nanocode's OpenAI `text.format`): assembly renders it from the stage's
`output_schema`, the schema the runner validates against, onto the turn spec, where it
folds into the capsule id. A contract strict mode cannot state is sent no schema, never
part of one, and a kind with no channel is never sent one — `Capsule::new` refuses the
pairing and its adapter refuses the prompt. kata's validation of the answer is unchanged
and stays the only judge; a `null` on an optional field is that field absent.

The embedded nanocode harness's two kinds qualify: a stage declaring either is admitted
at check (`nanocode_anthropic` under `subscription` is refused
`credential_mode_unsupported`, no Claude subscription login existing in this build), the
worker's production registry serves its adapter (`kata-agent-nanocode`) for both, and
`kata init` declares `nanocode_openai` as the default agent. Its cells are on this
construct: it runs nanocode's loop in the
worker and every tool call as a frame to the capsule's tool host, refuses before any
model call a tool set that is not exactly the tool host's, marks the issuance watermark
on each model request, carries its credential (an `env:` key, or kata's own login,
`kata_login`, read only from the owner's logins directory the binary names, and
refreshed under that file's lock so two holders rotate it once) to the adapter in the
worker's process and never into the capsule, and ends every turn before its outcome: a `KillAll` confirmed
within a 5 s grace, else (a broken wire, or no confirmation in time) the tool host's
stdin closed, on which the tool host kills its processes itself without the outcome
waiting for it. That fallback, and only it (a confirmed kill records nothing), is
recorded as `TurnEnd`, and reaches the durable record in the session evidence a
completed turn's report carries (`AgentTurnReport::session_evidence`), and otherwise
in the refusal's reason (`kill_all: unconfirmed` or `wire_broken`): a refused,
cancelled, provider-failed or ambiguous turn, or a completed one whose teardown or
publication is refused, carries no evidence. A record names that session evidence only
when the main adopts the turn's result: a completed turn whose result the main then
refuses (its `/work` delta out of scope, say) fails with the main's own reason, and its
session evidence stays a content-store object no record names. A turn the model PROVIDER failed, on a
turn nobody asked to stop, is classified from nanocode's own typed error, never from
whether bytes left: a 4xx error answer nanocode does not retry — an HTTP error response,
or on the Responses WebSocket an `error` event stating a 4xx status — is a refusal
(`refused`), and a failure nanocode classes transient (an overload, a rate limit, a
5xx, a timeout, a dropped stream, a refused connect, or an error event of one of those
kinds inside a response stream), reached once its own retries are spent, is
`transient`. Two codes the provider's answer names are classified by name before
nanocode's retry advice is read: a ChatGPT plan's usage quota (`usage_limit_reached`)
is `refused` on either Responses transport, an HTTPS 429, a WebSocket `error` event
with or without a status, or a `response.failed` event carrying it, its reason naming
the quota; and `previous_response_not_found`
is `transient`, since a fresh attempt chains to no stored response. The worker settles either PROVEN NOT PERFORMED with the class and the
provider's own error type and message as the reason, unless a tool call ran in a
capsule that can reach the network (`net = "host"`), or the teardown could not confirm
the container's subtree empty, which stays PROVEN AMBIGUOUS. A refusal of the turn's
one request, sent once, is charged the authoritative `0`; otherwise the charge is the
usage the completed calls reported, or `Unavailable` when none did. Every other failure
after a request left (an error event stating no HTTP status that nanocode does not
retry and that names neither code, a `response.failed` among them; a 5xx nanocode does
not retry; a malformed
response), a provider failure on a turn kata asked to stop, and every break of the
tool-host wire stays PROVEN AMBIGUOUS, and a dead worker or main settles its attempt
PROVEN AMBIGUOUS as before. When the worker's deadline dropped `prompt`, `close`
runs the turn end after the evidence was drained and reports what that run records
(`CleanupReport::turn_end`, in-process), which the worker folds into the refusal's
reason the same way; nothing is recorded when a panic unwound `prompt` (the session's
`Drop` ends the turn without waiting on anything). The turn's end then runs nanocode's
shutdown within a second 5 s grace (abandoned when it does not finish), which
terminates the host of every Code Mode cell it still holds. Every cell runs in an
interpreter process (below), and terminating its host kills that process and reaps it
before the terminate returns, so a cell inside one long native step, which no
interrupt reaches, ends with it: through the worker, a failed turn whose detached cell
spins or runs a long default-comparator sort leaves no interpreter process behind and
names no live worker (MEASURED). That no cell outlives its turn's outcome still rests
on the shutdown reaching every host within its grace, so the record stays: once the
shutdown returns or its grace expires, the turn's evidence records the Code Mode
workers still live in the process (`CodeModeWorkersLive`, read off the vendored
engine's live-worker counter, which counts a worker until its interpreter process is
reaped; process-wide and so never below what the turn left running), and the worker
publishes it with a completed turn's evidence or names a nonzero count in a refused
turn's reason (`code_mode_workers_live`); the evidence keeps room for the turn end's
records however many events precede them. A turn the worker abandons past its stop
grace has its turn end run by `close`, after the evidence is drained: `close` reports
the count with its `TurnEnd`, and the worker names a nonzero one in the refusal's
reason.
The worker installs kata's Code Mode limits once, when it builds its adapter registry,
and with them the engine's worker backend that runs every cell in an interpreter
PROCESS (one per cell, as nanocode spawns a host per cell): a confined child of the
process hosting the worker (a `kata-worker`, never the main: the node `kata serve`
supervises, or a daemon), that process's own executable re-executed, holding
descriptors 0 to 2 and an environment of an empty `TZ` alone, with a parent-death
SIGKILL, an address-space limit, no core file, not dumpable, first in line for the
OOM killer, and last a seccomp allow-list of the system calls it was measured to make,
on every thread under no-new-privs. No cell runs in the hosting process: an interpreter
that cannot start fails its cell, naming why, and one that cannot install its filter
cannot start. The cell runs in djs, nanocode's own engine; the interpreter sets the
cell's heap and its output limit on it (the engine, as kata patches it, charges each
event as the cell makes it, so a flood ends at the limit before anything queues past
it) and enforces the wall itself, and the supervisor counts the live interpreters. Through the adapter, a cell that allocates
past the heap limit, spins in JavaScript past the wall limit or needs an interpreter
past the process's live-interpreter cap fails to the model and the turn goes on, and a
cell after an ended host runs on a new one. A wall, output, heap or live-interpreter-cap
hit is recorded in its evidence (`CodeModeLimit`) whatever the model was shown, whether
the failure reaches the model in the cell's `exec` result or, for a cell that yielded
first, in a later `wait` on it, and so is a stack hit whose failure reaches the cell's
end with djs's own `RangeError` on its first line. Every heap hit a cell's own code
makes is reported: djs ends it uncatchably, and the engine (as kata patches it) sends
the report. Each report is a harness notification of its own, which the harness emits
as an event the adapter reads; the live-interpreter-cap refusal is the refused cell's
whole result. A stack hit the cell catches and rethrows inside an error of its own
fails to the model as that error and is not recorded, and a cell's own notification
of a report's text is recorded as a hit (MEASURED). A heap too small for the engine's
bootstrap (under about 360 KiB) fails every cell with no report; kata's is 256 MiB.
Every cell runs in a host of its own, in an interpreter process of its own, so
nothing an earlier cell left in its interpreter is reachable from it (cells share only
what they `store`). The operations under which QuickJS ended its process on an
exhausted heap (`Function.prototype.bind`, `eval` of a class, `Array.fromAsync`) fail
the cell on its heap under djs, at every headroom of the same sweep, and end no
interpreter (MEASURED, behind the interpreter process). An interpreter that ends while
its cell runs, which no cell is known to cause under djs (pinned by killing one from
outside, as the OOM killer would), ends only itself: its cell fails to the model with
the supervisor's report of the end (`Code Mode's interpreter process ended by
SIGKILL`, read off its reap, which no core dump holds: a probe child on a host piping
its core dumps to apport is reaped 0.3 ms after its `abort()` not dumpable, and
dumpable 1.1 s after it alone and 9.2 s beside 8 other dumps, past a 1 s wall and its
grace, MEASURED), which the turn's evidence records as `CodeModeInterpreterEnded`, and
the next cell runs in a new interpreter, with the whole heap; one that ends after its
cell's `Done` ends no cell and is recorded nowhere (pinned through the adapter on both
kinds and live through a `kata-worker` daemon, read alive off `/proc` with its stage
completed in the raw ledger).
The supervisor treats what the interpreter sends as untrusted: a frame over 64 MiB, an
event of no running cell (a frame between cells), a journal event, a `Held` no `Hold`
asked for, output past the cell's limit and its one report (every content item charged
its payload, images included), a `Load` while no cell runs or with two answers still
being written to it, or a cell past its wall by 5 s gets the interpreter killed and its
cell failed; it writes to the interpreter from a thread of the interpreter's own, so an
interpreter that stops reading delays neither the wall's kill nor `terminate` (pinned:
with a write to it blocked, the kill within 2 s past the wall and grace, `terminate`
within 2 s), and ending one shuts the socket down, so none of its threads outlives it. A cell's stored
values cross one at a time as it loads them, so a session storing more than a frame
holds still runs every later cell (pinned at 120 MB); a cell whose own stored writes or
tool-call input exceed a frame fails naming it, and a tool result past it fails that
tool call by name. The interpreter's standard error is a socket the supervisor drains,
keeping its last 64 KiB and counting what it drops, and none of it reaches the hosting
process's standard error or log: a cell its interpreter's end fails, or that could not
start, carries it in its error, labelled as written since that interpreter started, as
it may be an earlier cell's (pinned with a 200 KiB flood and a last line, and with an
earlier cell's line).
The syscall filter refuses, by ending the interpreter with SIGSYS before the call runs,
every system call outside its list and every listed one on arguments its rule does not
admit (a descriptor other than 0 to 2, a signal to another process, a `prctl` other than
naming a thread, a `clone` that is not a thread of its own in its own namespaces, a clock
other than the system's and its own CPU clocks), and every call of a foreign
architecture or the x32 range; of the listed calls `clone3` answers ENOSYS and a
read-only close-on-exec `openat` EACCES (glibc's malloc and assertion paths open /proc
files that way and carry on without them), and neither runs. So a compromised
interpreter (code execution through an engine defect) opens, creates and
executes nothing, makes no socket, process or namespace, and signals, traces and reads
no other process: each of an open for writing, a socket, a SIGKILL to its parent,
`ptrace`, `process_vm_readv`, `execve`, `fork`, a raw `clone` of a process, a thread
cloned into a new network namespace and a read of its parent's CPU clock ends it by
SIGSYS, read off its wait status, with the file and the parent untouched; every listed
call runs and the kernel reports every thread filtered; 27 sampled denied calls end it;
and the process hosting a compromised interpreter that tries to kill it lives (pinned
through the supervisor). An honest cell whose interpreter is stopped and continued runs
on: the kernel resumes a timed wait that a stop or a cgroup freeze interrupted through
`restart_syscall`, which the list admits (pinned with a cell waiting on its tool while
its interpreter is stopped and continued; MEASURED as well across a cgroup freeze and
thaw). What it does NOT refuse, pinned or stated as a residual: the
listed calls (`sched_getaffinity` tells it whether a process id exists and its CPU
mask), its own CPU until the wall's kill and its memory up to its limits, and frames up
to 64 MiB, whose limit bounds bytes, not their decode in the hosting process: up to 88
times a frame's length for an array of one-key objects (5.6 GiB from 64 MiB), 71 for
nested arrays, 16 for an array of zeros, once for a string (MEASURED, serde_json
1.0.149), whether the supervisor then admits the frame or kills its sender. The
supervisor of each interpreter holds at most six decoded frames at once (four queued,
one its reader waits to queue, one it handles), but the harness holds every admitted
tool-call input until its call ends, and a cell's tool calls are bounded only by its
event count (32,768 at kata's limits). So a compromised interpreter can still make the
hosting process allocate with no practical bound, and so can an HONEST cell that passes
large inputs to many tool calls at once, as it could when the engine's worker thread ran
in the hosting process (MEASURED: ten concurrent calls on one array of four million zeros
grow the hosting process by about 1.26 GB through the interpreter process and 1.33 GB on
the in-thread worker). That is the memory residual of the boundary, and it is not
bounded. The harness cuts the result it shows the model
to a 12,000-token budget that counts the result's
header and error with the cell's text, which cuts or drops a failed cell's trailing
error once that text fills it (an output hit by a text flood, always). The guard's
report still reaches the model on the OpenAI Responses kind, as an output of its own,
unless the harness compacts the turn's history before the model's next request, which
rewrites the newest outputs, the report first; on the Anthropic Messages kind it is the
same cut result's last text block, dropped once the text before it fills the budget, so
there such a hit fails to the model without its reason (MEASURED; pinned on both
kinds). A hit in a cell that yielded and that no `wait` observes is told to no model,
and is recorded when the harness ends the turn's cells, before a completed turn's
outcome (measured on both kinds).

### Execution target

An isolated run's `/work` forks from a target resolved ONCE, before acceptance, and
frozen into its invocation. The face parses the spelling with the one parser
(`TargetSpec::parse`); the executor refuses a target the program cannot carry
(`refuse_target_spec` — a `pr:<N>` spec on a program holding a `promote` or a
`forge_export` is `target_not_landable` before the forge is read), then —
outside the admission permit, so a slow repository holds no shutdown drain — the
provider resolves it and pins what it resolved under `refs/kata/targets/<id>/`
(`head`, and `compare` when there is a baseline); the invocation carries the frozen
`ExecutionTarget`, which the admission digest binds and the structural check
(`check_invocation_target`) re-runs on every recovered and child invocation. The
default `trunk` target is resolved and frozen for EVERY isolated run, so a trunk that
moves after acceptance — across a crash before the workspace exists included — never
changes a run's base: workspace creation, the `/work` head (`work_tree_base_not_the_target`),
the git view, recovery, the landing check (`target_trunk_renamed`, on the `promote`
effect and the operator promote alike; a trunk a writer outside kata moves in jj's view (to any
commit, a rewind included)
between the ladder's read and its fast-forward is refused `target_trunk_raced`, with
nothing moved, and an operator promote answers both as a conflict), the `promote`
effect's claim (its recorded
`target`, which the approval gate shows) and its reconcile (its classify judges the frozen
branch, on the sweep and the perform's reconcile-first alike, whatever the repository's
trunk answer is by then) all read the frozen value. The pins keep the
frozen commits reachable through a force-moved trunk and `git gc`; resolution answers
only once they are durable, so an acceptance never outlives them across a power loss.
They are released as a step of the terminal cleanup obligation (a failed release keeps
it pending), released at once when a submission is refused after resolution, and
collected at boot for any execution that no longer owns them — a refusal or a crash
between resolution and acceptance (`after_target_pinned_before_acceptance`). Release and
the boot sweep delete a pin a power loss tore like an intact one, and the sweep rewrites
an owned execution's torn pin at its recorded target (`TargetPinClaim`). A schedule pins no target: each
fire resolves its own, and a refused one is recorded as the occurrence's firing. A
`pr:<N>` target is read through the forge and fetched within ONE 300 s bound, still
outside the permit: every field of the forge's answer is validated before any is used
(the author's head name is never composed into a refspec or the fetch's argv), the remote is the one
whose configured URL is the forge's repository, the fetch writes `head` and `compare`
and no other ref, and a head that moved since the forge answered
(`target_pr_head_raced`) or a refusal after the fetch deletes what it pinned. A store
with no git backend has nothing to pin a commit in (`target_requires_git_backend`).

Templates read the same frozen value. The runner takes the target from the admitted
invocation — on the submit path and on recovery — and every render binds it as the
`target.*` namespace (`target_reads::TargetReads`); `changed_files` and `diff` are read
through the provider from the frozen merge base and head (`recorded_commit_diff`,
`recorded_commit_text_diff`) when a template first reads them, capped at 2,000 entries
and 256 KiB and flagged when cut. A pull request's title and body are cut at
resolution to 512 B and 8 KiB at a character boundary, and the invocation freezes
`title_truncated` / `body_truncated` beside them — stored, because an uncut text
within three bytes of its bound looks like a cut one — which `target.pr` renders (the
shipped `review` pack notes a cut text and its URL after the untrusted frame). The
`untrusted` template filter starts every line of its value with `> ` and writes each
line boundary in it (LF, CRLF, CR, VT, FF, FS, GS, RS, NEL, LS, PS) as LF and `> `, so
the value begins no line of the prompt; the shipped `review` pack renders the title,
the body and every changed path that way, so the frame's end line and kata's notes
cannot be written by the author (nothing makes a pack use the filter: a pack that
renders third-party text bare has no such frame). The structural check refuses a flag set on a text more than three bytes short of its bound,
which no cut leaves (`target_fields_inconsistent`).
Because a PR author, the forge or a branch name
chooses most of that text, CHECK refuses a shell `run=` that reads any key but the
40-hex ids, the kind, the PR number and the four flags outside a trailing `| shquote`,
or inside one emitted where the shell does not read the quote as one word — inside a
quote, backtick, `${…}`, comment or heredoc body, after `\` or `$`
(`template_untrusted_in_run`: an AST walk over every branch carrying a POSIX lexer's
positions, `shell_position`) — a key the namespace does not answer, and a `target`
read in a non-isolated workflow. A command that re-parses a word as shell (`sh -c`,
`eval`) is not checked. `target.diff` writes every path it renders exactly as `git diff`
does under `core.quotePath=true` — C-quoted when it holds a control byte, `"`, `\` or a
non-ASCII byte, a spaced `---`/`+++` name ending in a tab — so a path the PR author
chose cannot write a line git would not. A name that is not UTF-8 is refused, not
rendered: when a directory that differs between the two commits (the root, whenever
anything changed) holds one, `target.diff` and `target.changed_files` fail the render
that reads them. A re-render reads the same frozen commits;
`target.diff`'s hunk boundaries are the build's jj-lib line diff's.
Every render — a target's or not — is bounded before it is stored: a shell command at the
per-argument `execve` limit, an agent prompt at 1 MiB (`rendered_prompt_over_bound`),
and an agent's validation-retry prompt again once its feedback is appended.

### Agent `/work` git view

An agent capsule's `/work` is a real, writable, DISPOSABLE git repository with real
reachable history — the host `.git` is never bound. Admission
(`publish_execution_git_view`) reads the workspace's committed base and checks it is
the head the execution's FROZEN target names, takes the view's branch ref off that
target (trunk's name at the head, or a pull request's base branch at its compare
base; an unborn trunk's target names no branch, and its empty-root base is refused
`git_view_base_commit_absent` before any view exists — kata does not invent a branch)
rather than resolving trunk again, resolves the repository's identity, and
streams into CAS a git-history artifact holding only objects reachable from the base
within `history_depth`, plus the target's review range down to its merge base whatever
the depth. It refuses an absent base, a base that is not the target's, a missing
identity, or an artifact over the byte ceiling by name at admission, never inside the
container. The `execution_git_views` row records it; the capsule carries it as
`Capsule.git_view`; the worker mounts the history read-only at `/git-history` and
assembles a writable `/git` scratch that the `/work/.git` gitfile names. Agent commits
stay scratch, bounded in the session evidence, and are never adopted; the host store is
never mutated.

### Tool host

A nanocode agent capsule's init is `kata-toolhost`, a static executable: a rootless
runtime cannot exec a second process into a running container, so every tool process the
model runs is the toolhost's child. The kind fixes the launch — the agent turn encodes no
argv and the bundle execs `/.kata/kata-toolhost` — and the bundle binds the provider entry's `toolhost/` directory
read-only at `/.kata`, which `toolhost_dir` admits only as exactly one regular file its
owner may execute. `/.kata` is no `GuestPath` root, so no capsule mapping can name it;
the bundle renders `HOME=/tmp` and no credential. The toolhost states its protocol version
and source digest in a `Hello` before anything else, a self-report that catches a
mismatched build and not a dishonest one; `Hello::check` classifies a mismatch
`toolhost_mismatch`. The worker's toolhost client reads no frame before that `Hello`
and refuses a mismatch before sending its first frame, and it treats every `Error` the
toolhost sends as a protocol break, the null-id one naming a session whose `Stdin` was
refused included. It runs each `Exec` as a session in a process group of its own, streams its
output and ends it with one `Exited` after both pipes close and the process is reaped; a
session whose process stops reading its stdin queues at most four 64 KiB chunks, and a
`Stdin` past them is answered `Error` and dropped, so the worker's writes cannot grow the
toolhost's memory. Its file verbs move at most 4 MiB and answer the kernel's errno, EROFS
on `/.kata` and the store. `KillAll` kills every descendant — one that left its group
included — and answers `Done` only once none is left; it walks `/proc` on a backoff
and gives up after 3 s with one still listed (a zombie its tracer never waited on, a
process in an uninterruptible sleep) or a session's `Exited` not queued (a worker that
stopped reading stdout cannot hold the kill past its deadline). Given up, it answers
`Error` with the request's id, never `Done` or `Bye`, as the last frame it writes, waits
at most 1 s for that frame to reach stdout, and exits 2, which as the capsule's init
makes the kernel kill what is left: once a kill begins, the exit comes within about 4 s
whether or not the worker reads. Only the end of stdin, `Shutdown` and a broken stdout
end it, each after the same kill, or a kill that gives up: it handles no signal but
SIGCHLD (it restores the SIGSEGV and SIGBUS handlers Rust's runtime installs to the
default), so every other signal from inside the capsule is dropped by the kernel, and a
SIGCHLD a capsule process sends only triggers a reaping pass; and it is not dumpable, so a
capsule process can list its descriptors but open none of them. A tool process holds
only its own three pipes: every descriptor the toolhost opens is close-on-exec, and one
it inherited is marked so before it starts anything. It is one thread, its blocking pool
capped at two.

### Review loop

A `loop(body, gate, ...)` lowers to one program-level `ExpandBounded`. The expansion
claims one `pending` main attempt at its own `#op/<path>` coordinate carrying the whole
durable spec; iteration `N`'s member `M` dispatches as an ordinary capsule attempt at
`expand_path.child(N).child(M)`, and its `/work` delta applies through the shared
`#apply/<stage>` door. A loop's own `cost_bound` and `token_bound` trip closed on a member
of unknown cost or tokens, and CHECK refuses an agent member or gate its `cost_bound` covers
whose spend kata cannot price (`cost_bound_unenforceable_*`), as at workflow scope. The
bound decision resolves once: `Approved` or `Blocked` at the
classifying iteration — a `Blocked` no route on the gate routes fails the worker and skips
every stage behind the gate — or `Exhausted` under the authored `on_exhaustion` — `fail`
records the bound as the run's failure and skips every stage behind the gate, `accept` adopts the last
iteration's member outcomes, and
`escalate` parks the expansion's own attempt on the shared approval door. Under `accept`
a `route`/`branch` on the gate routes the gate's last classified report as it routes a
completion — except that a last verdict whose `review_quorum` was unmet was classified
`refine`, so a route on the loop's verdict field reads the refine tag and a route on any
other field skips every arm. The rewrite is the route's alone: its `Select` record names
the refine tag, while the gate's completed output (the run's outputs, `{{ stages.<gate> }}`
and `run show`) keeps the root's own report. CHECK refuses the one shape whose verdict-field route could
not take that tag, `loop_accept_quorum_route_needs_refine_tag`: exactly a review-quorum
gate of an `accept` loop with a route on the loop's verdict field whose arms (equal to the
field's tags) lack the loop's refine tag; recovery judges it again, so an execution of
that shape admitted by an earlier build fails its recovery batch closed
(`DurabilityFailed`), naming the stage. A walk-away the RUN records while the loop is
pending (a workflow bound, a halting `cost_budget`, a metering halt) dispatches no further
member: the loop resolves `Exhausted` under its own `on_exhaustion` at its next member, under
every `on_exhaustion` nothing behind it then runs (the dependents of its gate and of every
member, and every arm of a route on the gate, are skipped) — as nothing does behind a loop
whose record applies after the walk-away whatever it decided — and every member frame — a completion, a rejected structured-output turn, a failure terminal —
was charged to the workflow scope at its own fold. Under `fail` and `escalate`, and under
an `accept` whose per-loop bound tripped, or whose run walked away, before its last
iteration's gate classified (no report judged the candidate the loop ended on), every arm
of it is skipped — and when no stage downstream
of the loop minted an attempt, that unjudged candidate is the workspace the run ends with
and the completed run's closeout parks it at `parked/<exec>`, never leaving it as a
promotable workspace; a crash between that park and its evidence is reconciled from the
ref by the Terminalizing repair before it publishes `Completed`. A resumed
runner re-derives the expansion from durable occurrences, and a record disagreeing with
the recompute is refused `expansion_decision_diverged`.

### Stage progress

A running capsule streams progress to the main, honouring
`progress_visibility = off|summary|full`. The authored setting rides the capsule
assignment the authorization writes, never the capsule's identity, and `off` builds no
emitter at all. Agent capsules stream their adapters' observed session events, every
provider-influenced string scrubbed by the same pass the evidence record uses — the
assistant's text deltas as one rolling stream (`RollingScrub`: a lifted value split
across deltas is replaced whole, the held tail decided on the raw text — the earliest
unfinished value head, at most the longest value less one byte, a run of overlapping
occurrences it cuts into placeheld at once and only its bytes past the tail kept raw, so
the held text stays bounded however long a run of repeated values grows — and
overlapping values redacted as one run, so the deltas read back as the whole stream's
scrub), every other observed string alone; command
capsules tail the provider's stdout and stderr spools under the attempt root. The wire
arm is `WorkerMessage::CapsuleProgress`, bounded on every axis — a stream observation
(a text delta, a spool line) once per kind per window, superseding only its own kind and
sent when the window ends; a lifecycle milestone (a model call's start or end, a tool
call, a turn boundary) never coalesced and sent at once in observation order, the held
stream frames ahead of it, and a new window opened — a window lasts 250 ms or until the
next milestone, so a stream kind's frames number one per 250 ms plus one per milestone;
4 KiB per preview; 64 KiB of stream and 64 KiB of milestone preview per attempt, charged
at send; drops counted, and an attempt that finishes with any refused ends on one
accounting frame the drain sends past the queue — and the main projects it
through the attempt's own durable row onto the shared `progress` event. Progress is
informational only: never identity, never authority.

### Static topology

A static `topology` role list lowers to `ExpandBounded` at the stage's own coordinate:
member 0 is the root attempt, each declared child a capsule at `path.child(m)` named
`<base>#child-<role>`, and the accepted expansion settles the stage with the authored
fan-in and review quorum. Every member maps its own `/work` branch of the stage's head,
forked at one point, and the settle merges the branches in its resolving transaction; a
contested path fails the stage `work_fanin_conflict`. Each member's billed frame is
charged to the workflow scope at its own fold, a child under the stage's name; the
settled fan-in, which restates the children's cost, is not charged again. A topology that
settles after the run walked away releases nothing, and a pending topology dispatches
nothing once the run walked away: at its next dispatch point — its root or its children —
it waits for the members it already started and resolves failed naming the walk-away row,
its dependents skipped.

### Loop topology

A static `topology` is admitted as a `loop(..)` member or gate: it fans out every
iteration, gate included, as a nested `ExpandBounded` seated at the loop member's
coordinate, and the loop reads its settled fan-in envelope as the member's. An unmet
quorum on the gate is the iteration's `refine` (the quorum's reason appended to
`{{ review.feedback }}`) rather than a failure. A walk-away stops a member topology at its
next dispatch point as it stops a stage's; its failure is the loop's member death, which
aborts the loop. Loops refuse by name
`dynamic_fanout_in_loop_unsupported`, `loop_gate_quorum_needs_default_verdicts` (a
quorum gate under a custom `gate_verdict`) and `loop_member_not_a_capsule_under_oci` (a
member or gate that lowers to a `Wait`, an `Invoke` or a `Join`).

### Dynamic fanout

A `dynamic_fanout` stage lowers to `ExpandBounded` at its own coordinate whose checked
template is the root alone. The root's accepted output names the children, validated by
`dynamic_child_requests` against the checked plan and minted at `path.child(n)` under
`<base>#child-<role>-<label>`, each on its own `/work` branch merged at the settle, with
the `owned_paths` scope held over the members' recorded deltas. A child that requests
children is refused `dynamic_fanout_nested`. A walk-away stops a pending dynamic fanout at
its next dispatch point — its root or the children its root requested — as it stops a
static topology.

### Validation retry

An accepted-but-invalid structured output (`outputs = {...}` with `validate_retries`)
retries as a capsule at the chain seat `[i].child(k)` — at a loop member's or topology
root's seat too. The invalid attempt's accepted outcome stands and its `/work` delta is
applied before the retry mints; the retry is authorized by the chain's validation
ordinal, and an agent stage's retry prompt carries the validation feedback. A spent
budget fails the stage in the validator's phrasing. Once the run has walked away a plain
stage's queued retry is never dispatched: the stage fails naming the walk-away row — except
a retry a main that died left claimed and never dispatched, which the restarted run's boot
dispatches (see the walk-away paragraph above).

### Failure retry

A failed attempt whose durable classification is PERFORMED BUT FAILED or PROVEN NOT
PERFORMED is re-run at the chain's next seat, on the member the chain's walk names
(`PanelWalk`), re-derived from the chain's durable occurrences. It is never re-run for
PROVEN AMBIGUOUS or UNCLASSIFIED. The classification is the typed `verdict` the
attempt's terminal transition records — the worker's report, or the main's own
settlement — and a terminal recording none is unclassified, whatever its reason says. An agent turn whose model provider failed TRANSIENTLY
(the worker records the class `transient` beside the PROVEN NOT PERFORMED verdict) is
re-run on the same agent, twice per chain (`TRANSIENT_PROVIDER_RERUNS`), on any plain
stage, single-agent or panel, outside the panel's budget, each re-run due after its
backoff (`TRANSIENT_PROVIDER_RERUN_BACKOFF_MS`: 30 s before the first, 120 s before the
second), measured from the instant the chain recorded the failed seat's terminal frame —
never from a clock a resume reads, so a main that restarts mid-wait re-derives the same
due instant by replay and waits only what is left of it. A queued re-run not yet due is
no row: a graceful shutdown detaches a run whose only open work is one, and the replay
re-derives it. Once the execution latches its outcome (an operator's cancel among them) a
queued re-run is due at once, so its claim is refused (`claim_after_terminal_intent`) and
the run ends then, not at the backoff's end; a re-run whose due instant is past the run's
`time_bound` is not queued at all — it could only reach its terminal past the bound — and
the stage fails at once naming the bound. Every other seat is due at once. Every other retryable
failure, and a transient one past those re-runs, falls back to the stage's fallback
panel's next member whose agent label the model provider has not refused on this chain; a
panel of `n` members is a budget of `n - 1` fallbacks, and a single-agent stage has none.
An agent turn whose provider REFUSED its request (`refused`) adds its agent label to the
chain's refused set, so the agent is never run again on the chain, at any later seat: the
walk skips its later panel members, and the stage fails naming the refusal when only
refused agents remain. The retry's prompt is re-rendered from durable
inputs, never replayed from the failed attempt's bytes, so a resume renders the
identical prompt. Every panel member is judged by the agent-declaration door at CHECK. A
loop member or topology stage carrying a failure-retry policy is refused at CHECK
`expansion_failure_retries_unsupported_under_oci`. A `loop(..)` member's capsule re-runs a
transient provider failure under the same rule, through the loop's own seat walk
(`derive_expansion`): the same agent, twice per member chain, each re-run due after the same
backoff from its failed seat's terminal frame, at the member seat's `child(k)` with the same
prompt, under the plain stage's verdict rule (`failure_is_retryable`; a seat settled
`cancelled` is never re-run either) — a seat the derive reaches before it is due is
`Backoff`, so a restart re-derives it too, a graceful shutdown detaches a run whose only open
work is that loop (`expansion_waits_out_a_backoff`), and once the execution latches its
outcome the derive dispatches it at once, its claim refused. A re-run due past the run's
`time_bound` is not run: the member fails, naming the bound; a loop's own `time_bound` is
judged at the member's acceptance, as before. The refused set, stated: a `topology` stage's root and children, a static topology
serving as a loop member among them, do not re-run one — the topology's fan-in names each
member by its first seat's occurrence (`topology_fan_in`), so a member accepted on a re-run
seat would need the fan-in to land that seat's `/work` instead. An attempt the main could not send is
settled PROVEN NOT PERFORMED and never re-sent. Once the run has walked away a queued seat
is never dispatched: the stage fails naming the walk-away row — except a seat a main that
died left claimed and never dispatched, which the restarted run's boot dispatches (see the
walk-away paragraph above).

### Environment requires

`requires` is judged at CHECK against the node's bound environment
(`environment_requirement_unmet`, over the `PATH` program set boot installs) and again
before every dispatch (`capsule_requirement_not_in_environment`, over the manifest's
`path_prepend` through the same probe `argv[0]` is resolved by). `requires` is a hashed
`SandboxProfile` field. Requiring `git` gives the stage the run's disposable git view on
a `worktree_isolated` run; a non-isolated execution records no git view, so
`requires = ["git"]` there enforces the program alone.

### Reads confinement

A confinable stage's `reads = [...]` mints a `CapsuleWorkView` on its capsule, hashed
into the capsule id, minted only when the closure is non-empty (`reads = "whole-tree"`
maps the whole head), and refused `work_view_requires_work` on a capsule with no `/work`
mapping. The include list is the reads plus `produces_files` on a writable workspace,
and the reads alone on `workspace = "ro"`. `materialize_tree` writes into `/work` only
the manifest members the view covers, plus every declared member's enclosing
directories, while `/git-history` and the `/work/.git` gitfile land unfiltered. A base
member the view did not cover reads back UNCHANGED in the delta, never as a `Delete`, so
a confined stage cannot erase the head by hiding it.
