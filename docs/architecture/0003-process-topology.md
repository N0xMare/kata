# ADR 0003: Process topology — control plane, gateway, effects worker, nodes

- Status: Proposed — after 0.0.1
- Date: 2026-11-03
- Scope: the processes kata runs, what each holds and refuses, the links between them,
  how they are built and installed, and where kata records the intent of an effect it
  cannot take back. "Stages" names each implementation stage a passage cites.
- Amends, on acceptance: ADR 0001, ADR 0002 and `AGENTS.md` ("What this amends"), each
  passage in the stage that makes it true.

## Context

kata runs workflows unattended: a run outlives the terminal that started it and, on a
crash, the process that ran it, so the control plane is an always-on server and execution
can span machines.

Today the main, `kata serve`, holds the durable authority (operational SQLite, the content
store, the jj repository and its uid's forge credentials) and hosts no worker: its default
`supervised_node` transport starts one `kata-worker` beside it, the node, which loads
kata's own login and runs the agent loop, the provider streams and the Code Mode
interpreter (S1's first step; `in_process`, which ran them inside the main, is refused by
name). `local_socket` admits further `kata-worker` daemons. Every worker runs at the main's
uid, sharing its data directory by path and one symmetric secret. Each consequence is a
stated residual or a check wider than its mechanism: a defect that model output reaches
ends the node and every attempt it hosts, never the main (CM1 and CM2 confine only the
interpreter within it); a node that stalls without ending is judged dead by its heartbeat,
or before it enrolls by its 180 s enrollment budget, and the main kills it (with its cgroup
subtree when the main's cgroup is delegated) before its attempts settle and starts a new
one, which enrolls afresh, while a `local_socket` daemon judged dead is settled and left
running; the login lives wherever the worker runs, though a rotating refresh token
tolerates one refresher; issuance survives only if the worker does (`IssuanceMarkLayer`),
usage is a worker claim, and bounds act only at stage terminals; a cut-off worker keeps
spending, and a main restart settles every live attempt AMBIGUOUS
(`settle_capsule_attempts_after_restart`; `cancelled` under a standing stop) but one
whose worker's failure report the previous main had retained, which it records as
reported when that adjudication succeeds within `RETAINED_FAILURE_BUDGET` and otherwise
also settles AMBIGUOUS; deployment facts are process globals, the
server resolves `load()` against its own working directory, and no versioned network
protocol exists.

ADR 0001 keeps remote workers experimental until enrollment, fencing, restart, partition
and two-host tests pass; this ADR names the topology they qualify. Its facts were read
at a pre-release kata revision and nanocode `2ac77424`, and restated as wave 1 (M0, X1a,
A1, S1-a, E1) landed. The load-bearing ones: nanocode takes credential-free authentication and a
caller-supplied transport on all three protocols (`gateway_managed`, `host_transport`,
`ChatGateway::send_host`, `ClaudeClient::with_transport`), and every capsule already has
its own provider process.

## Effects: which ones need an intent record

| Class | Effects | Record | After a crash |
| --- | --- | --- | --- |
| **Idempotent by content** | a content-store object; a `/work` delta applied by content; a jj operation tagged with its attempt | the transition chain, with the row | redo, or classify from the repository |
| **Not idempotent, observable** | a push (the remote ref); opening a pull request (the pull request on kata's head); a comment carrying kata's marker | intent before the first byte, receipt after | the observer decides; nothing is redone without its verdict |
| **Not idempotent, unobservable** | a model request (`store = false` keeps nothing) | intent (a mark) before the first byte, terminal after | unknown, charged as unknown, never re-issued; only a new attempt may run again, and only if no request delivered output (§5) |

A push looks idempotent and is not: CI and webhooks act on the first one. No comment door
ships without its marker and observer (ADR 0002, decision 4).

kata writes an intent as late as possible: after every step that can fail without
issuing, immediately before the first byte. After a crash, no intent means PROVEN NOT
PERFORMED, an intent with a receipt the recorded outcome, and an intent alone is ambiguous
unless an observer can say; no protocol removes that interval, so kata keeps it short and
per effect, records it as unknown (never zero), and never re-issues it. A model request's
intent is a mark in the gateway's own journal, adopted before any verdict depends on it
(§5); a push's or pull request's is a `forge_intents` row in `operational.db`, keyed
`(attempt, effect index)` beside its execution and stage, committed just before `git push`
or `gh` is spawned (by the main today, by the effects worker from X1).

**E1** (landed) puts the forge export behind intents. **A remote read comes first**
(`ExecutionWorkspaceProvider::forge_remote_head`): a read that fails records no intent and
fails the export PROVEN NOT PERFORMED (`forge_export_remote_unread`); a head that is
neither absent, the export's commit, nor the commit this execution last pushed there is
someone else's, refused `forge_export_diverged`; any other head is the push's lease
(`--force-with-lease`). The push writes the intent's commit and nothing else: its source
is `<commit>^{commit}`, a full hex id of the repository's own object format, which git
reads as that object under every one of its name rules and never as a local ref (the
local branch, or one spelled as the id); replace objects are off; no graft file is read
(`GIT_GRAFT_FILE=/dev/null`), so a graft adds no parent's objects to the pack; and
`push.followTags` and `push.recurseSubmodules` are overridden (`kata_vcs::jj`
`forge_export`'s narrowing states each). **A lookup comes before the pull request too**
(`Forge::find_open_pr`, M0's `LookupPR`, like every `Forge` call of the export bound to
the repository the push remote's configured URL names,
`ExecutionWorkspaceProvider::forge_export_repository`, which `Forge::confirm_repository`
confirms the forge addresses before the push, or the export is refused
`forge_export_repository_unaddressed` with nothing pushed): an open pull request already on the head into
the export's base is adopted under no intent (one into another base, or from a fork's
branch of the same name, is not the export's, which opens its own), and a lookup that
fails, or lists its bound of pull requests without the export's, records no intent and
fails the export PROVEN NOT PERFORMED (`forge_export_forge_unread`). **Each push and pull request**
then gets its intent, and its verdict (`performed`, `not_performed`, `unclassified`) is
written once, by its receipt or its observer; nothing is issued again under an intent
without one. **The push's observer is the remote ref** (M0 F9): PERFORMED when the ref
holds the intent's commit, NOT PERFORMED only while it still holds the lease, and any
other head, a state that contradicts both, UNCLASSIFIED at once, which fails the export
`workspace_effect_unclassified` and pushes nothing again. **The pull request's observer**
is the intent's id, a marker in the body (`<!-- kata-forge-intent: <attempt>/<index> -->`),
found in any state, open, closed or merged (`Forge::find_marked_pull_request`); a listing
that reaches its bound, or the bytes a forge read may print, is a state that answers
neither way, UNCLASSIFIED at once, never "none" and never an unanswered read (M0
`BeyondBoundSettlesAtOnce`). **An observer read the remote does not
answer settles nothing** (owner decision #15; M0 `NoUnclassifiedBeforeTheBound`): the
intent stays open and the attempt pending, each unanswered read counted on the intent;
the sweep asks again no sooner than 60 s after the last, and the tenth unanswered read
settles it UNCLASSIFIED (`NoAskPastTheBound`). `kata run forge-reconcile <execution>` asks
at once, outside that spacing, and counts like any other ask. A push or create whose own
command failed records that error on its intent before its observer is asked, so a NOT
PERFORMED from any later ask fails the export rather than issuing the effect again.
A push's PERFORMED verdict, its receipt or its observer's, commits before the pull
request's lookup, so a main that dies there has lost no answered read.
Residuals, stated: a branch back on the leased head by any path after kata's push landed
and before its PERFORMED verdict commits (a crash before the receipt, then a move before
the observer's first answered read), deleted included when kata found it absent, reads
NOT PERFORMED, and the push is sent again (ABA; a remote that does not
answer keeps that window open through the re-asks); a push the remote refused because the branch moved
between the read and the push reads UNCLASSIFIED while the branch holds that other head
(NOT PERFORMED only if it is back on the lease by the observer's answered read, which
fails the export); a pull request whose
marker was deleted and that is no longer open is opened again; a crash between the push
and its receipt, the attempt then cancelled before the observer answered, leaves the push
intent open; and the observers assume a crashed main's
`git push` or `gh` died with it, as the installed unit's `KillMode=control-group` makes
it, and read at once after a command's timeout. The claim
(`claim_workspace_effect_attempt`) stays the double-spend guard.

## Decision (proposed)

### 1. Services, and the rule they serve

kata handles three kinds of thing: **the workflow authority** (operational SQLite and the
content store); **credentials** (whatever authorizes a model request, such as kata's
login or an `env:<VAR>` key, or a VCS effect, such as a host account's git and forge
credentials); and **model-driven execution** (an agent loop; evaluating model- or
agent-influenced code: Code Mode, submitted Starlark, templates; a model-requested
command; decoding model-influenced bytes with C or without a cap).

**The rule:** no kata process holds the authority together with any credential or with
model-driven execution, and no process that holds a credential runs model-driven
execution. Closed-set, size-capped, pure-Rust decoding is data handling, stated and not
refused. Two transitional cases are named, each with the stage that ends it. *The node*
loads kata's login beside the embedded loop until S3, runs that loop until S4, and runs at
kata-control's uid until C1, so until then it can open what that uid owns. *kata-control*
holds the jj repository and its uid's forge credentials until X1, and compiles submitted
Starlark and renders templates in its own process until A3.

**Why separate processes on one server.** Each service is its own process, unit and uid,
which buys five things one process cannot. *Crash domain:* a panic, abort or OOM kill ends
one service, so a provider-stream defect in the gateway does not stop scheduling.
*Address space:* a memory-disclosure defect or core dump cannot expose another service's
secrets; kata-control's memory never holds a token. *Per-uid file ownership:* the kernel,
not kata, refuses the node uid the login store, the gateway uid `operational.db`, and
kata-control the forge credentials, each from the stage that ends its transitional case.
*Per-unit limits:* memory, task and CPU limits per unit, the OOM killer choosing inside
one. *Independent restarts:* restarting the gateway or a node leaves the authority
running, and a kata-control restart under 15 s kills no capsule (§4). Every link uses one
authenticator over a Unix socket or TCP (§3): moving a service is configuration.

| Service | Binary | Where | Holds | Never holds or runs |
| --- | --- | --- | --- | --- |
| CLI | `kata` | any machine, macOS included | an API token; pinned deployment keys | durable state, credentials, runtime crates |
| Control plane | `kata-control` | one always-on Linux server | the authority: API, admission, scheduling, settlement, recovery, intent rows, slice escrow; the admission registry | a provider connection; any credential (from X1); model-driven execution (from A3); it links no nanocode or `rquickjs-sys`, and from X1 no jj-lib or gix |
| Gateway | `kata-gateway` | the control plane's server | kata's login; the `env:` keys its unit inherits; its mark journal | the authority, model-driven execution, nanocode, QuickJS, a C decompressor |
| Effects worker | `kata-effects` | the control plane's server; one instance, while VCS work is pending | the repository; its own host account's git and forge credentials | the authority, a model credential, model-driven execution (its evaluation child holds nothing) |
| Node | `kata-node` | each Linux execution machine | youki, cgroups, attempt roots, a content cache, its key | any credential (from S3), model-driven execution (from S4), the authority's files (from C1), VCS state |
| Capsule members | `kata-toolhost`, `kata-harness` | inside a capsule | nothing durable | any credential, any listener |

A manifest test per binary refuses, from `cargo tree`, every crate its row excludes; the
dependency graph shares no code with the runtime it judges.

**Confined children** re-execute their parent's binary under a sentinel, dispatched by one
crate function every binary calls first, with an empty environment, descriptors 0–2 and
one pipe, parent-death SIGKILL, an address-space limit, no core dumps, `oom_score_adj`
1000, and a seccomp allowlist compiled by kata's own `sandbox_seccomp` (CM2) that kills
on any other call. The **evaluation child** of `kata-effects` compiles one submitted
program or renders one template and exits, under minijinja's `fuel`, a CPU-time limit and
a wall kill. No child is shared: that limit is per process, and kata-control's
`rederive_program_hash` proves only that the returned IR matches its own hash, not that it
compiles the bundle. Its allowlist, pinned exactly in X1, admits only reads and writes
on inherited descriptors, memory management, futex, clocks, randomness, signal return and
exit: it opens, executes, traces, reads another process's memory and connects to nothing,
so no file its uid owns (forge credentials included) and no network. The **Code Mode
child** (CM1, CM2) is the harness binary's: `kata-node`, from S4 `kata-harness`.

**Gateway.** One per deployment, the only holder of kata's login and of the embedded
harness's API keys, so each rotating refresh token has one refresher. It accepts
connections only from kata-control and admitted nodes, exposes no operator API, and its
refusals hold against a compromised node or capsule, not against a compromised control
plane, which grants every slice; even then no credential byte leaves it but upstream.

**Effects worker.** The one process that touches the repository and the forge. It serves
`ExecutionWorkspaceProvider` (40 methods) and `Forge` (5) to kata-control as a closed
request set: applying capsule work deltas by content; park, promote, land and the merge
queue as jj operations tagged with their attempt; materializing `/work` and `/git-history`
(§7); each push and pull request, only under an intent row kata-control committed; and the
evaluation child. Both traits already live in `kata-effects-contract` apart from their jj
and `gh` implementations, and that crate's linked closure holds no jj-lib, gix or gix-pack
(X1a). Its git and forge credentials are its host account's (`gh` login, SSH keys,
credential helper), the host's answer, never copied. The service manager starts ONE
instance when kata-control connects to its socket (`Accept=no`, `User=kata-effects`); it
serves every connection, serializes landings as the main does (`landing_mutex` and its
`flock`), and exits a minute after its last connection: it runs only while VCS work does.

### 2. One writer per durable fact

| Fact | Writer | Store |
| --- | --- | --- |
| executions, attempts, transitions, schedules, bundles, facts, incarnations; forge intents and receipts; slice escrow; adopted marks; memory, events, stage cache | kata-control | its SQLite stores |
| content objects and roots | kata-control; others upload and never write a row | `cas.db`, `cas/` |
| slices as received; marks and their terminals | gateway | `<gateway data>/gateway.db` |
| kata's login; the admission mirror (sequence, admitted keys, revocations) | gateway | `<gateway identity>/` |
| repository and operation log | effects worker | the jj repository |
| admission: keys, scopes, revocations, join-token hashes | kata-control | `<control identity>/admission.db` |
| a service's key and pinned keys | that service | `<service identity>/` |
| intake journal, attempt roots, provider store, Nix roots, cache | that node | `<node data>/` |

**Identity outlives the data directory.** Every durable change replaces a service's data
directory with a new, empty one; its identity directory (key, pinned keys, admission
registry or mirror, login store) survives under its own `IDENTITY_FORMAT` stamp, refused
by name when older (recourse: re-enroll, log in again). **Data generations.** Each data
directory carries a random generation id, minted at creation and at every restore, and
carried in `Hello`, `Welcome`, `Resume`, slices and marks. A peer that sees a new
generation drops every counter and intake journal it kept for the old one; the gateway
closes every slice of an older control generation. A restore is a boot: it settles every
attempt open in the restored store AMBIGUOUS once `W` from boot has passed (§4), and holds
every execution open at the backup's point for the operator (§10). **Revocations do not
roll back:** the gateway mirrors `admission.db`'s monotonic sequence and every revocation,
and answers an older registry `admission_rolled_back` with that mirror, which a restored
kata-control commits before it makes any admission write, a join included, or accepts any
`Hello`: a join first would carry the restored sequence past the mirror's, which would
then look no newer, and a mirrored revocation would be lost (M0 F6). A revocation is
reported done only once the mirror holds it (§3). A restore with no mirror to adopt (a new
machine, a lost gateway identity) drops every admitted node key, so every node joins
again; the drop is an `admission.db` write like any other, so it advances the sequence.

No service opens another's directories. Operational SQLite and the content store remain
the sole workflow authority (trust boundary 2, amended): the gateway's journal is the
model door's intent record, adopted before any verdict depends on it; a node's intake
journal is evidence about its own crash windows.

### 3. Links and authentication

Every link between kata's processes is mutual TLS 1.3 with Ed25519 raw public keys (RFC
7250, rustls 0.23.46 on ring), each side pinned by exact key, no certificate authority;
over a Unix socket the receiver also checks `SO_PEERCRED`. The node dials kata-control
(one session stream, one stream per content transfer) and the gateway (one h2 stream per
model request or WebSocket session); the gateway dials kata-control (slices, marks,
revocations, the login relay, admitted keys); kata-control dials the effects worker's
activation socket, and the worker, while serving, dials kata-control's content protocol
(`Put`s of materializations, `Get`s of deltas); the node speaks to its providers over
stdio and to capsules over tool host protocol 3. The CLI and the SDK keep today's HTTPS
API with ed25519-signed tokens; a remote API listener needs an operator-declared X.509
pair (for example `tailscale cert`) or is refused `server_tls_undeclared`. Process keys,
minted at first start, are owner-only, never exported, never a host's or operator's.

**Enrollment.** `kata node token create <name> --slots N` (Admin) mints a single-use
token, valid 15 minutes, carrying kata-control's key, the gateway's key and endpoint, and
a 256-bit secret stored only as its blake3 hash. `kata-node join <token>` makes the node
key, connects pinning kata-control, presents the secret once, and is recorded; admitted
keys go to the gateway. The gateway and the effects worker register the same way, by
role; a new gateway key revokes the old one at once, its slices lost (§5).
`local-worker.secret` is deleted.

**Revocation.** `kata node revoke <name>` commits `revoked` first, and reports it done
only once the gateway's mirror holds it, else committed and not yet mirrored (M0 F4). From
the commit the handshake refuses the key (`node_revoked`); from the mirror's receipt the
gateway refuses the node's requests and cuts its streams. Until that receipt, while the
gateway's session with kata-control is down, the node can still spend on its open slices,
up to their grants and deadlines. Its attempts settle as a silent node's do (§4): settling
at the revocation would precede an empty subtree and could start a re-run beside the
original.

### 4. Node session

**Hello.** A node that starts, or whose lease expired, empties its kata cgroup subtree,
confirms it empty from outside, and opens a new incarnation with `Hello` (identity,
generation, release, schemas, executor term, containment report, capabilities, prior
intake journal). It is refused by name for an unknown or revoked key, another release,
schema or term, a subtree not clean, or containment not certified (a SKIP is a FAILURE);
capacity, environments and cache are placement filters (§11). kata-control commits the
incarnation, the settlement of the node's earlier attempts that marks do not judge, and
its realizations in one transaction, and only then answers `Welcome{incarnation,
control_incarnation, generation, lease_ttl_ms}`. An attempt judged by marks settles after
`Welcome`, when its slice closes or at `G` (§5), so a down gateway never delays `Welcome`.

**Intake journal.** The node fsyncs `Accepted(attempt, lease_epoch)` before acknowledging
a dispatch, and `Started` before creating the container. A still-open attempt of an
earlier incarnation settles:

| Intake | Verdict |
| --- | --- |
| absent, or `Accepted` without `Started` | PROVEN NOT PERFORMED |
| `Started`, embedded harness, from S3 | by its marks (§5) |
| `Started`, otherwise (the embedded harness too before S3) | PROVEN AMBIGUOUS |

The journal is believed at node trust: a lying node can turn an attempt it ran into NOT
PERFORMED and cause a re-run, which gives it nothing it lacked; marks are the gateway's.
**A node that never returns** is settled from kata-control's own records once `t_recv +
L·(1+ρ) + K + slack` passes with no `Hello` or `Resume`: a dispatch with no frame written
is NOT PERFORMED; a written one is decided by marks for the embedded harness and is
AMBIGUOUS otherwise, as is any fact a restart lost. A `Hello` from a new node generation
settles the old one's attempts by this rule, never by the intake table. Verdicts only
move forward; a late journal is evidence.

**Lease.** The node renews a node-wide lease every `T_renew` = 5 s, on `CLOCK_BOOTTIME`.
It records `t_send` per renewal; on the grant its lease runs to `D = t_send + L`, `L` =
20 s. The kill does not depend on the node process. `AssignStage` carries `lease_until`
(the current `D`), and the provider refuses an assignment without one or past it before
`youki run`; each later grant sends `SupervisorFrame::LeaseUntil{D}`; the provider's
50 ms loop (`WATCH_INTERVAL`) compares `CLOCK_BOOTTIME` with `D` and writes `1` to the
capsule's `cgroup.kill`. A stopped, crashed or partitioned node writes no further `D`, no
capsule process can signal its provider, and the node answers a dead provider with
`kill_and_contain`.

kata-control records `t_recv` per granted renewal (its own `CLOCK_BOOTTIME`, in memory)
and settles a silent node's attempts only after `t_recv + L·(1+ρ) + K + slack`: `ρ` = 10⁻³
bounds the drift, and `K` is the worse of the two kill paths, the provider's (from `D` to
an empty subtree under a capsule saturating its CPU and `pids.max`) and the node's
`kill_and_contain` of a capsule whose provider died just before `D` (M0 F1), each
measured, and pinned below the slack. Since `t_send ≤ t_recv`, the subtree is empty before
settlement whatever the clocks' offset, against a node that stops, stalls, crashes or is
partitioned, and a provider that dies under a live node.

**The double faults**, a dead provider under a stalled node and under a crashed one (M0
F7), have no kill at `D`. The node unit is the backstop. Its stop, for a crashed node,
signals the node's whole control group with `SIGKILL` (`KillMode=control-group`,
`KillSignal=SIGKILL`), which a capsule's PID-namespace init cannot ignore; L2b owes the
measured probe that this stop empties the capsules' subtree, and how fast, beside `K`'s.
Its watchdog, for a stalled one: `WatchdogSec=10s`, `NotifyAccess=main`,
`WatchdogSignal=SIGKILL`, `WATCHDOG=1` sent on every lease-loop iteration, renewed or not,
so a kata-control outage never fires it. `__service-exec` clears its environment
(`command.env_clear()`), so it carries `NOTIFY_SOCKET` and `WATCHDOG_USEC` as typed
handoff fields, never from the operator's environment file. Under `KillMode=control-group`
the bound is `WatchdogSec` plus the group kill, measured, not claimed inside the order: a
capsule's PID-namespace init (`kata-toolhost`, whose one handler is `SIGCHLD`) ignores the
default `SIGABRT` from an ancestor namespace until `TimeoutAbortSec` (30 s today). Without
a service manager neither backstop exists, and the capsule runs on.

**Suspend.** Supported nodes are always-on servers. One that suspends anyway thaws in no
fixed order, so its capsules (a `net = "host"` one's network included) can run for an
unmeasured window after settlement, every model request and result refused. Both of
`capsule_timing`'s exceptions close: the node side moves to `CLOCK_BOOTTIME`, and
kata-control anchors the capsule wall as `(boot_id, CLOCK_BOOTTIME)` of its own host.

**Resume and restart.** A node whose session drops while its lease is valid keeps its
capsules and sends `Resume{incarnation, generation, held, intake}`, accepted unless
kata-control already settled that incarnation or an older control generation welcomed it,
as after a restore, so a capsule an older generation started is granted nothing more
(`lease_lapsed`: kill, sweep, `Hello`). A restarted kata-control, a restored one included,
keeps no lease state on disk and waits `W` = `L·(1+ρ) + K + slack` from boot for each
node's `Resume` before it settles. A last grant is at most `T_renew` old:

| kata-control down | Running capsules | Model requests |
| --- | --- | --- |
| under 15 s | none killed | none refused: the gateway serves from its slices and queues marks; only a bounded request needing a refill waits |
| 15–20 s | killed where the lease runs out first | served while the capsule lives |
| over 20 s | all killed; settled by intake at `Hello` | none: no capsule is left |

Boot-to-ready is measured and pinned below 10 s. The attempt × lease × incarnation ×
intake × slice × mark machine, restore and the forge intents are a checked model (M0,
`docs/architecture/models/0003`, run by `just model-check-0003` nightly in L2) before
`Resume` or slices are built (ADR 0002, decision 5). It refuted this ADR's draft in eight
places, each corrected where its rule is stated and named by its finding (F1 to F7, F9).
It also answers the plan's question about the ingress fence's NULL-placement exemption
(F8): the exemption does not survive placement-in-dispatch, since once the placement
commits in the dispatch transaction, keeping it lets any admitted node's frame through at
a parked attempt's epoch, and `fence-placement-in-dispatch` passes without it, so L2b
removes it. Its passes also rest on three sentences the draft left unstated, now stated: a
no-mirror restore's key drop advances the sequence (§2), a restore is a boot (§2), and
`Resume` across a restore is refused (above).

**Fencing.** Every frame carries `AttemptFence{protocol_version, lease_epoch, node_id,
incarnation}`, echoed, never minted, by the node, and each connection is bound to its
authenticated node and incarnation. `fence_inbound_attempt_frame` keeps its order and
adds `StaleIncarnation` after `WrongWorker`; a node refuses a control frame from an older
incarnation of the same generation (`StaleControlPlane`). A returning partitioned node is
fenced at four layers: execution (its capsules died at `D`), spend (from S3: no
credential; slices revoked before settlement, an unclosed one freezing its scopes, §5),
results (stale incarnation) and bytes (content-addressed). CPU work and a `net = "host"`
capsule's traffic run until `D`.

### 5. Model egress: gateway, slices, marks

**Protocols.** Exactly what nanocode speaks: OpenAI Responses over WebSocket and
HTTPS/SSE, with an API key or the ChatGPT login; Anthropic Messages with an API key; and
OpenAI-compatible Chat Completions to OpenRouter only (nanocode's `ChatGateway`), with an
API key and any model id (`Model::Custom`), enabled only after a probe shows nanocode's
chat path running kata's tools and Code Mode on non-OpenAI models; until then an agent on
it is refused at check. Each upstream URL is a constant per (protocol, login mode). Left
to a later Cloudflare decision: `ChatGateway`'s Workers AI and nanocode's
`ResponsesGateway` (OpenRouter, Vercel AI Gateway, Cloudflare's two gateways), since
Cloudflare's URLs name an operator account (`WORKERS_AI_API_BASE_URL`) and each needs the
chat probe's evidence. Testing uses the ChatGPT subscription and an Anthropic API key.

**Relay.** Harness host transport, tool host, node, then one h2 stream per request to the
gateway (until S4 the harness runs in the node). The node stamps the attempt's identity
from its assignment and drops any the capsule sent; the capsule has no listener.

**Slices.** kata-control is never on the request path. In the dispatch transaction of an
embedded-harness attempt it grants a slice (attempt, lease epoch, node, incarnation,
generation, models, login mode, deadline, bounded scopes, grant) and sends the assignment
only after the gateway has journaled it. A grant exists only inside a token- or
cost-bounded scope: kata-control debits it from each enclosing scope's remaining bound in
that transaction (escrow; a cost grant at the models' prices). The gateway asks for a
refill when a grant runs low, drawn only from the undebited remainder; unspent grant
returns to its scopes when the slice closes.

**Marks.** After the upstream connection is ready and before the first upstream byte, the
gateway checks each request against its slice, and only if every check passes commits a
mark in `gateway.db` (one local transaction and fsync) and forwards:

| Check | Refused as |
| --- | --- |
| the slice exists, belongs to the authenticated node at its incarnation, and is open | `attempt_fenced` |
| the node is not revoked | `node_revoked` |
| model, credential, login mode and endpoint are the slice's and the protocol's | `model_undeclared`, `login_mode_mismatch`, `endpoint_outside_protocol` |
| the slice's deadline has not passed | `deadline_passed` |
| the grant is not spent (a spent grant waits for a refill while its scopes keep an undebited remainder or a sibling holds unspent grant), and no mark in its scopes is `Unknown` | `bound_exhausted` (only when neither remains), `bound_unprovable_after_unknown_usage` |
| no enclosing scope's known usage, summed over every slice of that scope, has reached the grants escrowed to it: one slice's own grant is not enough once a sibling overshot (M0 F2) | `bound_exhausted` |

Each `response.create` is its own mark, and an unknown client message ends the stream.
Each mark ends in exactly one terminal, `Completed{usage}`, `Rejected`, `NotForwarded` or
`Unknown{reason, delivered}`, and records `delivered`: whether any model output went
toward the node. An event the gateway cannot classify counts as output. `Rejected` holds
only HTTPS statuses that promise no processing and the not-billed pre-output codes
nanocode itself names (`transport/api_error.rs`); a transient server code promises
nothing, so it and every other pre-output failure are `Unknown{delivered = false}`: the
same effect verdict, an unknown charge. S3 pins the closed non-output and `Rejected` sets
per protocol. A 401 refreshes the login and re-issues under a new mark; nothing that may
have been processed is re-issued, by the gateway or by the harness: kata's host transport
and the gateway hand every `Unknown` back to the harness as not retryable
(`x-should-retry: false`) on both backends, so nanocode's own retry layers (Responses: 5
tries by default; Messages: 5, or 3 without tools, fixed in the backend) send each request
once per mark (M0 F3).

**Adoption.** The gateway ships marks and terminals asynchronously, idempotent by
`(generation, mark sequence)`; kata-control commits them in batches, off every request
path. Before settling an embedded-harness attempt for any reason, kata-control sends
`SliceRevoke`; the gateway stops admitting marks on the slice, cuts its open streams
(`Unknown{cut}`), and answers `SliceClosed` with every mark and terminal. Settlement waits
for the closed slice. If the gateway cannot answer within `G` (default 60 s), an attempt
whose node reported an outcome settles with that outcome and one that marks must judge
settles PROVEN AMBIGUOUS, each with an unknown charge; a later answer is evidence. Such a
slice is *unclosed*, and every slice a lost gateway journal held is *lost*; kata-control
counts either as an `Unknown` in each enclosing bounded scope, granting there no refill
and no new slice, which covers unknowns the gateway never journaled. It resends
`SliceRevoke` first on every connection of that gateway generation until `SliceClosed`
arrives; a new generation holds no old slice and refuses requests on one. Exception,
stated: until the gateway closes an unclosed slice, a node that still reaches it can
spend on that slice up to its grant and deadline; under `time_bound` alone, its deadline.

| Marks of the closed slice | Effect verdict |
| --- | --- |
| none delivered | PROVEN NOT PERFORMED: no output reached the harness, so no tool call was issued; the retry chain may run the stage again as a new attempt with new marks, every unknown charge counted (under `time_bound` alone only the chain's length bounds that spend) |
| some delivered, with an outcome the node reported | that outcome |
| some delivered, otherwise | PROVEN AMBIGUOUS, never re-run |

The charge is the `Completed` usage plus unknown for each `Unknown` mark, never zero.
`IssuanceMarkLayer` and the tool-frame issuance mark are deleted. If kata-control is down,
marks queue and only refills wait. A gateway restart turns its open marks into
`Unknown{gateway_lost, delivered = true}` and keeps its slices. A lost downstream cuts the
upstream at once. A down gateway holds every embedded-harness dispatch, leaves running
turns without model access (a stream in flight cut, a new request failing at the node),
and holds their settlement up to `G`, then settles as above. A mark costs one fsync on
the gateway's journal: p99 ≤ 10 ms to forward, measured in S3; a miss adds group commit.

**Bounds.** `time_bound`, the default, is upheld by the provider's kill at the capsule
wall and the gateway's cut and refusal at the slice deadline. `token_bound` and
`cost_bound` are opt-in. The claim, exactly: no request is forwarded in a bounded scope
once its grants are spent by known usage or any mark in it is `Unknown`, except on an
unclosed slice within its escrowed grant (above); overshoot is at most the usage of
requests in flight at the crossing (exact because the gateway checks the scope's summed
usage, not only each slice's grant). An `Unknown` closes both bounds of every enclosing
scope for the run (today `loop_bounds_trip` lets an uncounted member trip only a token
bound); a sibling's unspent grant returns only when it closes.

**Metering.** Usage is read from the wire (Responses `response.completed.usage`; Messages
`message_start` and `message_delta`; Chat Completions the usage trailer with OpenRouter's
cost); harness-reported usage is evidence only. Prices move to kata-control, keyed on
protocol and model. On subscription logins `cost_bound` stays refused, and `token_bound`
until a live capture shows usage on responses-lite.

**Credentials.** The gateway forwards only allowlisted client headers, drops and records
any authentication header the client sent, injects the credential, and never writes a
credential byte toward a node. **`kata_login`** moves from `~/.config/kata/logins` into
the gateway's identity directory with today's owner-only checks. `kata login openai` runs
the device-code flow only, relayed by the API to the gateway, so neither the CLI nor
kata-control sees a token byte; a rotated refresh token is committed before use (a death
in between burns the login, stated). A stored API key is entered with `kata-gateway login
<provider> --api-key` on the gateway's host; the CLI form is refused by name.
**`env:<VAR>`**, the host's answer, is read only by the gateway, only for names some
agent declares, from the environment file its installation copied. Deleted: the browser
loopback flow, the cross-process login lock, every node-side credential load, and (V0)
the vendor harnesses with their credential lifts, consent and refresh paths.

### 6. Capsule: tool host and harness

`kata-toolhost` stays the capsule's first process, static musl and pure Rust. For an
embedded-harness capsule it spawns `/.kata/kata-harness` over a `CLOEXEC` socketpair, with
an empty environment and non-dumpable; tool processes are its children, never hold its
descriptor, and cannot trace it. The harness holds no credential; a tool process can kill
it, ending only its own turn (stated). Protocol 3 adds an opaque `Harness(bytes)` relay.
Code Mode is the harness's own child (CM1 moved whole, CM2 under the capsule's deny-list);
one harness process is one turn, so no second vendored nanocode crate is needed. It counts
against `memory.max` and `pids.max`; static musl, built only by Nix, its C set exact
(`rquickjs-sys`, `ring`, `zstd-sys`); the term's `agent_harness` becomes `harness`.

### 7. Content and VCS

**Content protocol**, one h2 stream per transfer. `Get` serves only objects in the read
set of a live attempt of the requester, verified by recomputation. `Put` is accepted only
for a live attempt the requester holds (or a materialization kata-control asked the
effects worker for), counted against that attempt's output, result and work-delta
budgets, refused before a byte lands past them, and receipted only after blake3, fsync
and the row commit. A result names only receipted objects. An orphan stays; a compromised
node can grow the store by at most one attempt's budgets per attempt. The node cache is
bounded and never evicts a live read set. One server uses the same protocol.

**VCS** lives entirely in the effects worker: the jj repository and its operation log;
park, promote, land, the merge queue, `/work` apply and forge export. Capsules receive
`/work` and `/git-history` as content, so no repository mirror exists. The repository is
a clone with a declared upstream, landing is a push, and a target is only state it can
fetch (trunk, a pushed ref, `pr:N`); anything else is refused `target_not_on_server`.

### 8. Authoring

**`kata-program`**, depending on `kata-types` only, holds the DSL, Starlark evaluation,
the loader abstraction, the checked program and its lowering, preflight, policy,
templates, loops, `workflows test`, the schema catalog, the bundle codec and the pure
capsule-network rule; `kata-workflow` becomes the runtime. A non-`Default`
`DeploymentFacts` value replaces the `node_profile` and `containment_policy` statics,
served at `GET /api/v1/deployment/facts` with a digest admission records. `kata check
--against <name|url|file>` judges, through the functions admission runs, the node fact
classes a node-less check reports as not judged (P3: agents with their credentials,
ceilings, egress and environments), and floors and pricing beside them; without it those
classes stay reported deferred, and `--config <kata.toml>` judges all but environments (a
stage's `requires`). Containment is no such class: the `oci`
door refuses every process stage a host-unconfined profile derives, with or without a
node. A bundle is a canonical manifest of every loaded file by hash, the frozen pack roots
and the compiler digest; kata-control has it recompiled in the evaluation child through an
in-memory loader, never accepts a client's IR, refuses a disagreement by name, and keeps
the bytes in the content store. Server-side resolution (`WorkflowLibrary::default_roots`)
is deleted: named refs, MCP, the API and schedules resolve only published bundles. The
Rust SDK takes the CLI's path (`KataClient` publishes and runs by digest; `run_starlark`
sends one file; a `load()` needs a published bundle).

### 9. Versions and upgrades

Every service and capsule member embeds one release digest (blake3 over the sources,
`Cargo.lock` and the youki pin), stated at `Hello` and every registration with the schema
stamps and the executor term. A mismatch is refused by name, naming the older side; no
negotiation window, since every durable change already forces a new data directory.
Upgrade: `kata-control drain`; stop; install; start kata-control, the gateway, then the
nodes. Identity directories carry keys, admission and kata's login across it.

### 10. Deployment

**Build.** The Nix flake builds every binary and the static capsule members (today
`packages.kata` and the static-musl `kataToolhost`; `kata-harness` from S4), as per-role
packages: the CLI; the server (`kata-control`, `kata-gateway`, `kata-effects`); the node
(`kata-node`, the provider and capsule members). No Terraform: the machines exist, and
installing kata on them is configuration, not provisioning.

**Install.** Two paths install one unit text. The product path is self-installing
binaries: `kata-control install` creates its directories and installs and starts the
server's units under host users the operator created (kata refuses with the user named,
never creating one); `kata-node join <token>` enrolls and installs the node's unit; each
copies its declared environment into its owner-only environment file, as `kata service
install` (deleted) does today. The owner's fleet uses numtide system-manager (declarative
units on non-NixOS hosts such as Ubuntu with Nix): the flake exports a module whose unit
files the binaries render at build time, a flake check refusing any difference; no secret
enters the store.

Units: `kata-control` and `kata-gateway`, always on; `kata-effects.socket` (`Accept=no`)
and its one service, on demand; `kata-node`, with `KillMode=control-group`, `Delegate=yes`
and the watchdog (§4). No service parents another; cells start the same binaries, a
test-owned acceptor standing in for socket activation. The system profile, the qualified
one, runs four host users on the server (`kata-control`, `kata-gateway`, `kata-effects`,
`kata-node`) and `kata-node` alone elsewhere; from C1 a capsule escape lands at the node's
uid, which owns no other service's files (before C1, at kata-control's: §1). The per-user
profile runs them at one uid: separation is process-level only, a stated residual, and
`/proc` cells pin that no node or capsule process loads a credential.

**Network.** Tailscale is the network, never the authenticator: kata-control and the
gateway listen on the server's tailnet address, nodes dial out to them, the CLI and
phones reach the API over the tailnet, and every link keeps kata's own mutual TLS. API
exposure is tailnet-only by deployment: kata refuses a wildcard bind
(`listener_wildcard`) and does not claim to verify that an address is a tailnet's.

**Availability.** No high availability: the control plane is restarted by its unit and
recovered by replay. **Backup**, a snapshot, not continuous (decision 9): kata-control,
under its own uid, snapshots its stores and `admission.db` (public keys, scopes,
revocations, token hashes) every 5 minutes into a local spool it owns, and links each new
content object there as it lands (new objects only, by hash). A host-owned unit, under its
own host user and the host's credential (on the fleet, an SSH key for a gmknuc-k11-1
account no node uid reads), ships the spool off-host; kata-control holds no credential. No
backup holds a private key or credential: a copied login would sit on another host, and
restoring its rotated refresh token would burn it. **Restore** mints a generation (on a
new machine, new keys: every node re-joins, kata's login is created again), adopts the
gateway's mirror (§2), and holds every execution open at the backup's point, and every
schedule catch-up for a slot due after it, as `progress_after_backup_unknown`: work
started after the backup may have pushed, spent or run, so none is dispatched until the
operator resumes or cancels it. A restored kata-control also holds every dispatch, a
resumed execution's and a schedule catch-up's included, until `W` from boot (§4): a
capsule the older generation started runs until its lease kills it, and the stage run
again beside it would run twice (M0 F5). The gateway's journal is not kept; the repository
returns from its upstream, unpushed parked state lost (stated).

### 11. Placement

Occupancy is read from durable rows. Filters, in order: the node active (not cordoned or
draining); containment certified (`CAPSULE_PLACEMENT`, fail-closed); budgets fitting a
slot and the read set the cache; the environment realized, by that node, or realizable
in the start deadline; a free slot, least loaded first. Drain waits for settlement.

## Consequences

Once S4, A3 and X1 have landed, no defect that model output reaches sits in a process
holding the authority or any credential; until then, §1's two transitional cases hold.

**What improves.** Issuance is durable per request before the first byte. Effect
ambiguity shrinks to the requests that delivered output, spend ambiguity to the requests
in flight. A partitioned node's capsules die at the lease deadline without its help. A
kata-control restart under 15 s settles nothing and refuses no model request. Forge
effects carry an intent behind a remote read. Metering comes from the wire, bounds act
per request, and from X1 kata-control holds no credential.

**Costs, stated.** Settling an embedded-harness attempt waits for its slice to close. A
down gateway holds that dispatch and cuts running turns off from every model; past `G`
their attempts settle with a reported outcome or AMBIGUOUS, at an unknown charge, scopes
frozen, and a node still reaching the gateway can spend on their slices until they close.
A spent grant waits for a refill or a sibling's close; one `Unknown` closes both bounds of
its scopes. A crashed or revoked node's attempts settle after about 25 s; while the
gateway's session with kata-control is down, a revoked node can still spend on its open
slices, up to their grants and deadlines, until the gateway's mirror receives the
revocation (M0 F4). The double faults, a dead provider under a stalled or a crashed node
(M0 F7), are bounded only by the node unit: its watchdog for the stalled node, its stop's
group `SIGKILL` for the crashed one; without a service manager the capsule runs on. A
suspended node is unsupported. Every protocol change is a drain; every VCS operation
crosses a process boundary. The ChatGPT login is device-code only; an `env:` key is a
copy. The harness's memory counts against stage budgets. On one server the content
protocol copies bytes shared on disk today. The per-user profile separates by process
only. Losing the server loses up to 5 minutes of store state and holds every execution
then open for the operator; a new machine also loses every enrollment and kata's login.

**What stays the same.** A capsule is never delivered twice; neither an ambiguous attempt
nor an execution open at a restored backup's point is re-run automatically; bytes come
before references; containment refuses rather than falls back; VCS has one writer. Remote
nodes stay experimental until the two-machine cells pass.

## Acceptance and non-goals

Every property above lands with a cell that reads its outcome from outside kata (a mock
provider's log, a second read-only handle, `/proc`, `cgroup.procs`, `cargo tree`), watched
red first, in namespaces on one kernel in L1 and on two machines in L2; the stage that
lands a property names its cell. Not goals: control-plane high availability; intermittent
nodes (the future ADR); execution on macOS or phones; exactly-once inside a capsule; a
wire-compatibility window; any path that carries a model credential through the API.

## Alternatives considered

- **Marks as control-plane rows** (the earlier draft): every model request on the
  authority's writer, refusals past a restart's hold bound, boot-window machinery.
- **The gateway inside kata-control, or one per node:** credentials and stream parsing in
  the process whose death costs every run; N refreshers of one token.
- **VCS credentials in kata-control:** the authority would hold one. **The effects worker
  under a subordinate uid** (kata-control owns the range and can map it; no host account
  holds the forge login), **per connection** (two repository writers) **or per operation**
  (a start and a repository load each): decision 1.
- **Compiling or rendering in kata-control, or under fuel only:** evaluation in the
  authority; fuel bounds steps, not one step's allocation (`'x' * n`).
- **`kata login --api-key` sealed to the gateway's key** (holds only against an honest
  control plane unless the CLI pins that key out of band); **an `Unknown` mark charged at
  a ceiling** (a Responses request carries no mandatory output cap); **systemd's watchdog
  as the lease** (it counts `CLOCK_MONOTONIC` and exists only under a service manager).
- **Terraform** (nothing to provision); **one multi-call binary** (linkage unprovable from
  the graph); **a parser child in the gateway** (no body is compressed, every parser is
  capped Rust); **a `/proc/<pid>/maps` check** (a statically linked QuickJS is never
  mapped by name) **or an executable-bytes check** (it sees only what LTO kept; S1's
  dependency-graph cell is stricter); **a loopback URL into the capsule, HTTPS-only
  Responses, draining after downstream loss, a client's IR, a repository mirror,
  `in_process`**.

## What this amends

**ADR 0001.** *Product and authority:* the main becomes kata-control, workers become
nodes with registration, incarnation and lease, local issuance state becomes the intake
journal, and "effects execute only from an authorization durably issued by main" covers
forge intents and marks under a granted slice. *Initial profiles:* §1's services on Linux
x86-64; remote experimental until the two-machine cells pass; macOS CLI-only. *Agent
execution:* the loop runs in the capsule, its model connections leave through the
gateway, the vendor paragraphs go. *Trust boundaries:* 1, kata's login and `env:` keys
only at the gateway, VCS credentials only in the effects worker's account; 2, the gateway
journal adopted before any verdict, forge intents as rows; 3, the content protocol,
leases expiring at the provider; 4, the harness in the capsule; 6, intent before exposure
per model request and forge effect; 7, node keys, join tokens, revocation, the intake
journal at node trust.

**ADR 0002** (Proposed). *Decision 1:* an embedded-harness model request becomes a door
kata gates and records. *Decision 2:* holds for push, pull request and comment; a model
mark is the named exception, minted by the gateway, never re-issued. *Decision 3:* a wire
effect's record splits into intent and receipt; a model request's intent is written at the
door, by the gateway, and adopted before any verdict depends on it, slices escrowing its
bounds. *Decision 4:* model requests have no observer; a push's is the remote ref; a pull
request's matches kata's marker in any state. *Which doors first:* push and pull request
(E1, landed: ADR 0002 states its decisions 1 to 4 so in place), marks separately (S3).

**`AGENTS.md`.**

1. Opening paragraph: "resolve in the main" becomes the control plane; a stage's process
   runs as a capsule on a node.
2. Parallel work: "the installed main" becomes the installed deployment.
3. Surfaces: the four principal surfaces stand, the CLI and the Rust SDK both submitting
   published bundles; the role binaries' commands are host administration, not a
   principal surface; the skill derives from `kata` alone.
4. Hermetic: "Effects are named at a boundary and recorded. An idempotent effect may be
   redone. A non-idempotent one (a model request, push, pull request or comment) has its
   intent recorded immediately before its first byte and is never redone automatically
   under that intent: an observable one waits for its observer's verdict; a model request
   is never re-issued, though a stage none of whose model requests delivered output may
   run again as a new attempt, every unknown charge counted. None is shelled from inside
   an agent sandbox."
5. Credentials: kata's login is "created only by an explicit `kata login` (or
   `kata-gateway login --api-key` on the gateway's host), stored in the gateway's
   owner-only login store, refreshed only by the gateway, never present on a node or in a
   capsule"; `env:` keys are the host's answer, copied into the gateway's environment
   file; VCS credentials are the effects worker's host account's.
6. Gate layers: "A live cell leaves L1 for L2 only when it is timer- or load-bound, or
   needs a second real machine, AND a twin pins its logic: host-free for a timer or load
   bound; for a second machine, a single-host twin in network and time namespaces that
   `gate-containment` runs and that fails rather than skips. A second machine that does
   not answer makes its tier a named SKIP, not a red: it blocks no push, and its twins
   still run in L1. A capability SKIP stays a FAILURE inside containment."
   `gate_exclusion` enforces it through typed `NightlyCell` fields (R).
7. OS: the CLI is the one artifact built for macOS, unqualified.

**Also:** `protected-properties.md` and `.toml`, the operator guide, `nanocode.md`, the
SDK's rustdoc, and the rustdocs each stage names.

## Stages

The passages above name the stage that makes each true. Three have landed ahead of the
0.0.1 tag: CM1 confines Code Mode's interpreter in a re-executed child, CM2 gives that
child its syscall allowlist through `sandbox_seccomp`, and P3 makes a node-less check name
each node fact class it did not judge. M0, E1, A1 and the first steps of S1 and X1 have
landed since, as the table marks; the rest follow:

| Stage | What lands |
| --- | --- |
| M0 | the checked model of §4's and §5's machines, of restore and of E1's intents, before `Resume` or slices are built (landed: `docs/architecture/models/0003`) |
| V0 | the vendor adapters deleted, after the counted round and before S2's session and S3's gateway (D-d) |
| S1 | the node always a separate daemon: `in_process` deleted (landed: `kata serve` supervises its node, a `kata-worker`); `kata-control` and `kata-node` their own binaries and units |
| S2 | the node session on one server: §3's links, enrollment and revocation; §4's lease, intake journal, `Resume` and fencing; §9's release check; §11's placement |
| S3 | the gateway: §5's marks, slices, relay, metering and credentials |
| E1 | forge intents and the remote read before each ("Effects"; landed) |
| C1 | §7's content protocol; the node under its own host user |
| X1 | the effects worker (§1, §7): the repository and the forge credentials leave kata-control (X1a landed: the provider and forge traits in `kata-effects-contract`) |
| A1–A4 | §8: the `kata-program` crate (A1, landed); deployment facts and `--against` (A2); bundles and the confined evaluation child (A3); a CLI-only `kata` (A4) |
| R | §10: remote server nodes, deployment, backup and restore, and the two-machine cells |
| S4 | §6: the harness in the capsule |

## Future ADR: intermittent nodes

Laptops, VM guests and any machine that sleeps, freezes or leaves are out of this ADR. A
later ADR owns them: an availability class; freezing capsules on session loss; guests
whose `CLOCK_BOOTTIME` stops while paused; the suspend window, measured; placing only
offline work outside bounded scopes; and a LOST WITHOUT EXTERNAL EFFECT verdict. It builds
on the lease, the provider-owned kill, the intake journal and the slices.

## Decisions

**Decided (2026-11-03).** D-a: the boundaries now, gmknuc-k11-1 as node 2, intermittent
nodes to the future ADR. D-b: the gateway's own journal and per-attempt slices (§5). D-c:
three services and three uids on one server, separable by configuration (§1). D-d:
nanocode only, the vendor adapters deleted after the counted round (V0). D-e: the flake,
self-installing binaries and system-manager, join tokens, Tailscale under kata's mutual
TLS, no HA, backup (§10). D-f: namespace cells in L1, two-machine cells nightly, an
unreachable node 2 a named SKIP that blocks no push (`AGENTS.md` item 6). D-g: CM2 through
`sandbox_seccomp`. Earlier: a separate gateway process; multi-binary; no `in_process`.

**The questions this ADR raised, decided by the owner the same day.** The unknowns left
are probes inside the stages, first nanocode's chat path (decision 4); none changes the
topology.

1. **The effects worker runs as one socket-activated instance under its own host user**,
   exiting after an idle minute; X1 measures its start. Only this process touches the
   repository and the forge login, so a scheduler bug cannot reach them. Not chosen: a
   child under a subordinate uid or at kata-control's uid, which separate weakly or not at
   all, and a fourth always-on service, which isolates alike (`git` and `gh` read the
   account's files either way) but runs while no VCS work does.
2. **Programs and templates run in a confined evaluation child**, one per program or
   render, reusing the Code Mode child's re-exec entry and confinement (CM1, CM2), not in
   kata-control under fuel only. Agents can write or influence workflow code and
   templates; a child that opens no file, starts no program and reaches no network keeps a
   hostile one from the database and every credential.
3. **Model budgets reach the gateway as slices**: escrowed grants; an `Unknown` closing
   its scopes; after `G` = 60 s without `SliceClosed`, a reported outcome kept at an
   unknown charge, AMBIGUOUS only where marks must judge (§5). Model calls never wait on
   the control plane, and a gateway outage freezes budgets without turning finished work
   into operator work.
4. **Chat Completions is enabled through OpenRouter only, after a probe** on an OpenRouter
   key with a small cap the owner supplies when that work opens. It opens models such as
   GLM and Kimi once the probe shows nanocode's tools and Code Mode work on them; until
   then an agent on it is refused at check. Workers AI waits for the Cloudflare decision.
5. **E1 and its ADR 0002 amendment are adopted.** kata reads the remote and records "about
   to push" first, so after a crash it knows whether the push or pull request happened
   without asking the operator. A remote reachable at the read and not at the push leaves
   the intent open for its observer's bounded re-ask, and ends `unclassified` only if the
   remote stays silent through it. Refined in "Effects", which states every residual E1
   leaves.
6. **Lease expiry is the provider-owned kill, backed by the watchdog**
   (`WatchdogSignal=SIGKILL`, a ping on every lease-loop pass), not the watchdog as the
   lease. Each capsule's own supervisor kills it when the lease runs out, even if the node
   froze or was cut off, so a re-run elsewhere is safe. The watchdog covers the rare
   double failure in about 10 s and never fires on a kata-control outage. Refined in §4,
   which names both double faults (M0 F7) and what bounds each.
7. **Identity directories and data generations are adopted**, a restore adopting the
   gateway's revocation mirror before any `Hello` (with none, dropping every node key).
   Nodes need not re-enroll after each upgrade, and a node revoked after a backup stays
   revoked after its restore. Refined in §2, which holds every admission write, a join
   included, until the mirror is adopted (M0 F6).
8. **Stored API keys live only on the gateway's host, and the ChatGPT login is by device
   code only**, not a CLI `--api-key` sealed to the gateway's key. Keys never cross the
   CLI or the control plane; the costs are no browser-redirect login and a shell on the
   server to enter a key.
9. **The control plane is backed up by snapshot** (§10): its stores every 5 minutes and
   each new content object as it lands, into its own spool, shipped by a host unit with
   the host's credential. Shipping the stores' WAL continuously was the alternative, and
   the larger change. A restore holds every execution open at the backup's point for the
   operator rather than repeat pushes or spend.
10. **kata refuses wildcard binds and claims no tailnet check.** kata cannot reliably
    prove an address is a tailnet's, so it listens only where the operator says; its own
    mutual TLS stays the gatekeeper.
11. **P3 lands before the 0.0.1 tag.** A node-less check judged against defaults and could
    pass a workflow the real node refuses; with P3 it names each node fact class it did
    not judge.
12. **Model spend: the ChatGPT subscription and the Anthropic API key first, each when its
    stage reaches it; OpenRouter later.** S3's ChatGPT-subscription and Anthropic API-key
    turns prove injection and metering on real providers, and S4 repeats both inside the
    capsule; the chat probe spends a small, capped amount on OpenRouter.
13. **Work is sized by the repository areas it changes, its diff, its complexity and the
    agents that build and check it, never by time.** This is the owner's answer to the
    effort question, in place of an estimate.
14. **This ADR is committed as "Proposed — after 0.0.1".** It records the direction
    without changing code or delaying the tag.
