# ADR 0001: Architecture

- Status: Accepted
- Date: 2026-09-19
- Amended: 2026-10-30
- Scope: kata's architecture

## Context

Kata's own value is checked Starlark workflows, a durable transition authority,
evidence and effect discipline, and candidate promotion. Mechanisms that maintained
substrates supply better — package realization, OCI execution, agent protocols — are
delegated to them, without weakening the semantic, durability, or containment
contract.

## Decision

### Product and authority

Kata has no backwards-compatibility obligation before 1.0: obsolete APIs, schemas,
and implementations are removed rather than wrapped. Durable retained data still
requires an explicit migration, refusal, or disposal decision, and uncertain effects
may not be silently reissued.

There is one authoritative main. It alone admits programs, advances occurrences,
accepts outcomes, authorizes effects, and owns durable recovery. Workers are
subordinate: they prepare and execute bounded capsules and return observations.
Workers may retain bounded local issuance/deduplication state but cannot advance a
workflow. Effects execute only from an authorization durably issued by main,
including effects implemented at main itself.

Starlark remains the authoring surface and lowers to a versioned, content-hashed,
checked program. Runtime semantics use explicit operations (execute, wait, invoke,
select/join, and bounded expansion), logical occurrences, physical attempts, and
separate effect records. At most one outcome is accepted per occurrence. Placement
and retries do not change logical identity; changed inputs, environment, command,
permissions, or platform change the prepared action identity.

### Initial profiles

The initial qualified platform target is **Linux x86-64**. A profile is supported
only after its named qualification gates pass; until then this is a target, not a
claim of present support.

The initial supported production profile is:

- one operator-run main with local subordinate workers, each a separate `kata-worker`
  process — the node `kata serve` starts and supervises, or a daemon the operator
  starts; the main hosts no worker;
- Linux x86-64;
- Nix-managed software, with immutable closures bound before execution;
- rootless OCI execution through the **Youki executable**;
- OCI Runtime Specification configuration represented with `oci-spec` Rust schema
  tooling;
- an initially Nix-prepared root filesystem; and
- refusal before issuance when required rootless OCI, kernel, cgroup, filesystem,
  network, or resource containment cannot be installed. There is no host-process or
  weaker-sandbox fallback.

Rootless OCI through the pinned youki is the ONE execution engine in the tree; there is
no second engine to select or fall back to.

Nix is mandatory for the managed software profile. It owns package realization,
closure transport, store verification mechanisms, and collection. Kata owns which
exact closure was authorized, its binding and evidence, retention intent, privacy
classification, and crash-safe coordination with Nix roots. Ordinary actions do not
receive a Nix daemon socket or mutable store authority. Private or irreproducible
artifacts remain in Kata's artifact plane.

Experimental profiles are not production fallbacks:

- **Microsandbox through its Rust SDK** is the first microVM experiment. It must
  satisfy the same capsule, artifact, uncertainty, and acceptance contracts before
  qualification.
- Remote subordinate workers remain experimental until portable artifacts,
  authenticated enrollment, scoped secrets, fencing, restart, partition, and
  two-host tests pass.
- Other OS/architecture combinations, including Linux ARM64 and macOS, are
  unqualified. A Linux guest on macOS is not native Darwin support. macOS and Linux
  ARM64 support are deferred.

Nix build delegation is an experimental, explicitly admitted subset; arbitrary
commands are never inferred to be derivations.

### Agent execution

The admitted agent set is nanocode, embedded in the worker as kata's agent harness
for the OpenAI Responses and Anthropic Messages APIs, pinned by source revision, as
two kinds (`nanocode_openai`, `nanocode_anthropic`) — the one harness kata ships and
`kata init`'s agent. No vendor CLI runs in a capsule, and kata reads no other tool's
login: a harness is served by an API key from the worker's environment or by kata's
own login.

Each adapter declares what its protocol offers, measured, in its module doc and in
the adapter qualification matrix, and refuses by name a request it cannot serve. Agent
processes, sessions, callbacks, terminals, files, and stdio are worker-owned and
attempt-scoped. Protocol disconnect after possible model or
tool issuance remains ambiguous; usage unknown is not recorded as zero. A turn of the
embedded harness that its model provider failed with a typed answer — a 4xx error answer
the harness does not retry, or a failure it classes transient once its own retries are
spent — is a known failure, not a disconnect: it is settled not performed, with the
provider's class and reason, unless a tool call ran in a capsule that can reach the
network. A transient failure is re-run on the same agent a fixed number of times, and a
refused agent is never run again on the stage's retry chain.

The embedded harness's model calls leave from the process hosting the worker, never
from its capsule, so an agent stage's `net` governs its capsule exactly as a shell
stage's does: a stage that authors no `net`, shell or agent — an API agent run omitting
`sandbox` included — is `offline`, and it reaches the node's declared egress only by
authoring `net = "host"`. An agent block has no `egress_extra` to declare. The execution record
and an approval gate read an agent capsule's network off the declared capsule's own
allowlist; the check surfaces predict that network, per agent the stage can run under
(primary and each fallback panel member), from the same rule assembly mints from, over
the installed node's facts. The checked program claims no offline network for any
agent stage: its turn talks to its model provider.

A stage's typed output contract is validated by kata, never by a vendor: the turn's
answer is checked against the stage's `produces=` schema and retried within
`validate_retries`. Where an adapter's protocol carries a strict structured-output
schema, the same contract is also sent to the model as one, rendered from the schema
kata validates against and carried in the capsule's identity; it is an aid to the
model, not a second judge. A contract the strict dialect cannot state is sent no
schema, never part of one.

The embedded harness runs its agent loop in the process that hosts the worker, a
`kata-worker` node and never the main, so a defect model output reaches ends that node
and the main settles its attempts. Its model connections leave from that process, never
from the capsule, and its credential stays there. An
agent capsule of the embedded harness is offline unless its stage declares network
access: it opens no endpoint of the harness's provider, and the node can name no extra
one for it. It has no tools of its own that act
on a host. Every tool the model can call does one of three things: it forwards a
process-execution or file-access call to kata's tool host, which executes it inside
the capsule; it changes only the turn's own state; or it is Code Mode, an embedded
interpreter whose only effects are calls to the other two. The worker builds the
harness with the capsule's execution environment, and before any model call it
checks that the harness's host tool set is exactly the tool host's; a harness whose
tool set differs is refused. Whatever ends a turn, before its outcome is recorded
the worker asks the tool host to kill every process it started for the turn and
waits a bounded grace for the confirmation. Over a broken tool-host connection, or
when the confirmation does not arrive within the grace, it closes the tool host's
input instead, on which the tool host kills them itself; the outcome does not wait
for that. Only that fallback is recorded, never a confirmed kill: in the evidence a
completed turn publishes with its result, and otherwise in the turn's refusal reason,
since the worker publishes no evidence for a turn that did not complete. A turn end
the worker forces after its deadline drops the harness's turn call runs when the
worker closes the session, after it took the evidence; the session reports what that
run records with its close, and the refusal's reason names it the same way. A turn end
a panic runs records nothing. The
worker then shuts the harness down within a second bounded grace, abandoning a
shutdown that does not finish within it; the shutdown terminates the host of every
Code Mode evaluation it holds, and terminating a host kills its interpreter process
(below) and reaps it, so an evaluation inside one long native step, which no
interrupt reaches, ends with it. That no Code Mode evaluation outlives its turn's
recorded outcome still rests on the shutdown reaching every host within its grace,
so once the shutdown returns or its grace expires, the worker counts the Code Mode
interpreters still live in the process, each until its interpreter process is
reaped, and records the count with the outcome: in the turn's evidence when it
completed, and in its refusal's reason otherwise when the count is nonzero. The
count is process-wide, so it is never below what the turn left running. A turn the
worker abandons past its stop grace has its harness shut down when the session
closes, after its evidence is taken; the close reports that count, and the refusal's
reason names it when it is nonzero. Kata's attempt settlement is the only
durability authority for a turn; the harness keeps no state across attempts.

Model-authored code that the harness evaluates ("Code Mode") runs in an embedded
JavaScript interpreter, in an interpreter process of its own: a child of the process
that hosts the worker, started from that process's own executable for each Code Mode
host the harness spawns, and confined before it takes an evaluation (descriptors 0 to
2 only, an empty environment, a parent-death kill, an address-space limit, no core
file, not dumpable, first in line for the kernel's out-of-memory killer, and last a
syscall filter: trust boundary 4). No evaluation runs in the hosting process: an
interpreter that cannot start, or cannot install its filter, fails its evaluation,
naming why. The interpreter has no filesystem, process or network binding;
its only effects are calls to the harness's other tools, which its host forwards.
Once per process, before any harness is built, the worker installs a heap limit, an
interpreter stack limit, a per-evaluation wall-time limit and a per-evaluation bound
on what an evaluation emits, which charges every event it causes a fixed cost beside
its text and so bounds the number of events as well as their bytes (a tool call's
input is not charged). Exceeding one ends that evaluation with an error, and the
turn continues, except where the interpreter mishandles its own exhausted heap
(below). The harness shows the model an evaluation's result cut to a
fixed budget, which counts the result's header and error with the evaluation's
text and so cuts or drops that error once that text nearly fills it, so the
patched interpreter also sends its own report of a limit hit it can tell as a
harness notification, which the worker records in the turn's evidence whatever
the model was shown. It tells a wall-time or output hit from its own budget, and
a heap or stack hit from the interpreter's own error or, for a heap hit the
interpreter could not even report, from the heap it left exhausted; a hit the
evaluation catches and rethrows inside an error of its own, and a heap hit that
reaches the evaluation's end only as a bare thrown `null` once its heap was
released, are reported as that error and recorded nowhere. The OpenAI Responses
harness hands the model each notification outside the cut result, so there the
report reaches it unless the harness first compacts the turn's history, which
rewrites the newest outputs, the report first; the Anthropic Messages harness
appends it to the cut result, so there an evaluation whose text fills the budget
fails to the model without its reason. The wall-time limit
interrupts running JavaScript at its next interrupt check and stops the evaluation's
job queue before its next job, so one long native step (a built-in sort of millions
of elements) runs to its end first. Every evaluation runs in an interpreter
instance of its own, dropped with everything the evaluation left in it (its queued
jobs included) when the evaluation ends, so no evaluation's heap, globals or jobs
reach the next; and the heap limit applies only once an evaluation's context is
prepared, because the interpreter's own context creation is not safe against it. If an
interpreter process ends, Code Mode does not: the next evaluation starts a new one. The
harness starts an interpreter for every evaluation that begins while another still
runs, so the worker also caps the interpreters live in the process at once, and an
evaluation that would need one past the cap ends with that refusal as its whole
result, which reaches the model and the evidence on both harnesses. These limits bound the interpreters, at most that many each under the heap
limit and the address-space limit, not the hosting process: copies the harness makes
outside the interpreter are not bounded by them. A memory-safety defect in the
interpreter, or a native stack overflow its stack limit does not prevent, ends only
the interpreter process. The interpreter's handling of an exhausted heap has such
defects on paths an evaluation's own code reaches, an allocation that fails there
ending it by a fault or by one of the interpreter's own assertions; those measured are
stated and pinned, not bounded. An evaluation whose interpreter ends while it runs
fails with the hosting process's report of that end, which the turn's evidence
records, and the next evaluation starts a new interpreter; one whose interpreter ends
after its result ends no evaluation, because the interpreter drops an evaluation's
instance, where such an end happens, only once it has sent the evaluation's result.
What an interpreter writes to its standard error reaches the hosting process, never its
log: the last fixed number of bytes are kept per interpreter and carried in the error
of an evaluation its end fails. The hosting process reads what an interpreter
sends as untrusted input: bounded in size per message, admitted only for the
evaluation it runs, its output (every content item's payload) charged against that
evaluation's output bound, and an interpreter that breaks any of that, or outlives its
evaluation's wall by a fixed grace, is killed; the hosting process never waits on an
interpreter, so one that stops reading delays neither that kill nor a termination. An
evaluation's stored values stay in the hosting process and cross to the interpreter
one at a time, as the evaluation loads them, so what a session stores is bounded by no
message; an evaluation whose own stored values, tool-call input or tool result exceed
one message fails that part by name. The message bound is on bytes, not on what
decoding a message takes in the hosting process: a message of many small JSON elements
decodes to tens of times its size there (measured up to 88 times), and the harness holds
every tool call's input until the call ends, with an evaluation's tool calls bounded only
by its event count. So the hosting process's memory is bounded neither against an
interpreter that sends many such messages nor against an honest evaluation that passes
large inputs to many tool calls at once, whose inputs decode there as they did when the
evaluation ran in that process.

Native adapters are allowed only for the named contracts above, not as an unbounded
plugin surface.

### Trust boundaries

1. **Author/operator to main:** main accepts only checked programs and explicit
   approvals. Operator identity, trunk, credentials, and toolchains are inherited or
   refused, never guessed. The one credential kata holds itself is the embedded
   harness's login: created only by an explicit operator login, stored in kata's
   own owner-only file, refreshed by kata, and never shared with or read from
   another tool. Without that file the turn refuses and names the login command.
2. **Main durability boundary:** operational SQLite and authoritative artifact roots
   are the sole workflow authority. Bytes are preserved before durable references;
   history reads and caches do not recreate execution authority. The repository is held
   to the same rule: a write a durable record or a jj operation will name is on stable
   storage first (a `syncfs` barrier over the repository's filesystems), and what a power
   loss tears after the last barrier is re-derived from a durable record or refused by
   name, never read as authority.
3. **Main to worker:** the boundary is an immutable, versioned capsule containing
   identities, guest paths, budgets, permissions, and artifact/environment
   references—not main-host paths. Leases fence acceptance but cannot undo issued
   work.
4. **Worker to runtime/agent:** Youki or an experimental VM receives only the
   capsule's mounts and capabilities. A capsule's root filesystem holds its bound
   environment, its mappings, the runtime-owned mounts and, for a nanocode agent
   capsule, the tool host: one static executable that is the capsule's first
   process, bound read-only at a fixed guest directory from kata's
   content-addressed provider store and never addressable by a capsule mapping. The
   tool host states its protocol version and source digest before its first tool
   call, and the worker refuses a mismatch before sending one. That statement
   catches a mismatched build, not a dishonest one: the bytes are trusted as the
   provider store entry is. The tool host acts only on its input stream and a
   shutdown request. The one signal it handles is SIGCHLD, which a capsule process
   can send and whose only effect is a pass that reaps the tool host's exited
   children; every other signal from inside the capsule is dropped by the kernel.
   Capsule processes cannot open its descriptors.
   Agent callbacks, tool calls and child processes remain inside this boundary.
   Missing enforcement refuses. The one model-authored code that runs outside a
   capsule is the embedded harness's Code Mode, in an interpreter process the
   worker's hosting process starts and confines: its every end ends only it, and what
   it sends is untrusted input. Its last confinement step is a syscall filter, an
   allow-list of the calls the interpreter was measured to make, installed on every
   thread under no-new-privileges before it takes an evaluation: any other call, or a
   listed one on arguments its rule does not admit, ends the interpreter before it
   runs. So code execution inside it (through a defect of the interpreter) opens,
   creates and executes no file, makes no socket, process or namespace, signals, traces
   and reads the memory or CPU time of no other process (the hosting process included),
   and reads and writes only its three descriptors: its message socket, the null device
   and its standard error. Two listed calls are answered without running: a thread-creation
   call whose flags the filter cannot read, and a read-only open of the kind the C
   library makes on two honest paths. The refused set is exact against the
   interpreter's list in `kata_code_mode_host` and the kernel-level cells that run each
   listed call and each sampled refused one in a confined interpreter. What it still
   does, stated: the listed calls (one tells whether a process id exists), its own CPU
   until the wall's kill and memory up to its limits, and messages to the hosting
   process up to the message bound, whose decoding there the boundary does not bound
   (above).
5. **Preparation and storage:** Nix/store/cache trust is distinct from Kata's
   acceptance and private-artifact trust. A store path or metadata query is not by
   itself byte verification.
6. **External effects:** authorization is recorded before a capability capable of
   issuance is exposed. A crash without a conclusive receipt settles the attempt
   PROVEN AMBIGUOUS, which is never re-run automatically and is left to the operator.
   Settlement is per attempt, except for a `forge_export`'s push and pull request:
   each is recorded as an intent before its first byte and a receipt with its result,
   and an intent a crash left without a receipt is decided by its observer, PERFORMED
   or NOT PERFORMED, or left unclassified (ADR 0002 decisions 3 and 4, as ADR 0003's
   stage E1 implements them). Per-effect permits for every other effect are proposed
   in ADR 0002.
7. **Remote workers:** authentication proves peer identity, not general authority.
   Enrollment grants only declared placement, data, secret, and effect scopes.

### Repository and documentation shape

Tracked documentation has three classes:

- `docs/architecture/`: accepted decisions and the protected properties;
- `docs/product/`: user/operator product contracts; and
- `docs/development/`: contributor procedures and implementation guidance.

Untracked research is not documentation and cannot be an authority. Accepted
conclusions are restated concisely in the tracked class they govern.

Reusable Rust libraries live under `crates/`. Root `bin/` contains applications and
their assembly only. Packaging products are emitted under `target/dist/`; source
packaging logic may live elsewhere but must not treat generated output as source.

## Consequences

Kata owns workflow meaning, durable authorization and acceptance, evidence,
candidate policy, and cross-system reconciliation. It does not own a package
manager, OCI runtime, VMM, general agent protocol, or multi-main system. Upstream
adoption removes duplicate mechanisms only after boundary tests establish the
required properties. One baseline per required capability keeps the certification
matrix bounded.

No current implementation, containment property, platform profile, provider, or
agent is certified by this decision alone.
