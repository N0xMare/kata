# nanocode in kata

kata embeds [nanocode](https://github.com/nanocodexyz/nanocode) as a library
(`crates/agent-nanocode`). nanocode publishes no releases kata can pin, so kata pins
one upstream commit and tracks nanocode's `master` by moving that pin deliberately.

## What kata takes from nanocode

- **Four direct git dependencies** in the workspace `Cargo.toml`:
  `nanocode-backend-codex`, `nanocode-backend-claude`,
  `nanocode-process-contracts` and `nanocode-sync` (the stream trait of an HTTP
  layer's response body, which kata's wire implements), all at one `rev`. `NANOCODE_REV` in
  `crates/agent-nanocode/src/lib.rs` names the same commit.
  `crates/agent-nanocode/tests/nanocode_seam.rs` refuses a `Cargo.lock` that
  resolves any nanocode package to another commit, and a host tool set that moved.
- **The Anthropic kind's system prompt, less two blocks.** kata builds the Claude
  agent without system blocks of its own, so nanocode selects its default blocks for
  the turn's model (`instructions::default_system_blocks`, crate-private at
  `8ec3b215`: for most models it drops the Opus 5.5 paragraph that closes its upstream
  block, for the models its `TOTAL_TOKENS_REMINDER_MODELS` names it appends a
  total-tokens reminder, and for those its `bash-first.json` names, `claude-opus-5-5`
  and `claude-fable-5-1`, it appends a Bash-first steer opening "While bypass
  permissions mode is active:" after the Code Mode instructions a code-only agent
  gets). The Messages client's HTTP layer, `MessagesMark` in
  `crates/agent-nanocode/src/adapter/session.rs`, then sends every request without
  two of those blocks, each removed only when its whole text matches
  (`without_claude_code_blocks`): the Claude Agent SDK identity line that opens them
  (`subscription_wire::IDENTITY`), and the bypass-mode steer (`BYPASS_STEERS`, kata's
  copy of the two `bash-first.json` steers, since the file is crate-private). kata is
  not the Agent SDK, and an API key's credits may refuse a request that says it is:
  measured on 2026-11-12, that one line turns a key's 200 into a 400 `Your credit
  balance is too low`, as does the `claude-code-20250219` beta, which nanocode sends
  only on its subscription wire. The steer describes Claude Code's bypass permission
  mode, which a kata capsule does not have. The edit re-serializes the body (the
  same JSON, its members' order aside) and leaves a subscription request, whose
  billing line comes first, untouched. `nanocode_qualification`'s
  `each_anthropic_model_gets_its_own_system_blocks_less_the_identity_and_the_bypass_steer`
  reads the request bodies the mock receives for `claude-sonnet-4-6`,
  `claude-opus-5-5` and `claude-fable-5-1` and pins each model's own blocks and the
  absence of both; the unit cell
  `the_wire_edit_removes_the_identity_and_the_bypass_steer_and_nothing_else` pins
  that the edit removes those blocks alone; `an_api_key_anthropic_request_carries_no_claude_code_mark`
  reds on the identity line, the `claude-code-20250219` beta or a `metadata.user_id`
  naming an account in the request the mock receives. Since `8ec3b215` nanocode
  sends every API-key request `x-claude-code-session-id` and a `metadata.user_id`
  naming only the session (upstream records this as what stock Claude Code sends on
  an API key); the cell pins both to the session's id, and whether a key's credits
  refuse them is not measured. `harness_identity` folds the blocks kata removes;
  the blocks themselves follow `nanocode_rev` and the stage's model. The upstream
  block keeps other Claude Code product text a kata capsule does not match (its
  terminal display, its user-selected permission mode and hooks, clickable
  `file_path:line_number`, the Claude Code surfaces line, a fixed total-tokens
  reminder); kata removes no part of a block, so these stay, listed for review.
- **One vendored crate**, `vendor/nanocode-code-mode-engine`: nanocode's
  `crates/runtime/code-mode-engine`, the host that runs Code Mode cells in djs,
  nanocode's own JavaScript engine (`crates/patches/djs` upstream, which kata
  takes as a git dependency like the rest).
- **A platform for nanocode.** nanocode no longer runs on tokio: it spawns each
  agent's driver, and reads its clocks, timers and randomness, through
  `nanocode_platform`, which needs an installed host or its own executor's
  context. Before it builds an agent, the adapter installs kata's tokio runtime
  as that host, once per process (`adapter::platform`): the driver is a task of
  the runtime that drives the turn, and nanocode's sockets keep their own
  reactor, which works under any executor.
  The workspace `[patch."https://github.com/nanocodexyz/nanocode"]` entry builds every
  dependency on that crate from this copy, so it is part of a fresh clone and
  `cargo build --locked` needs nothing kata does not already fetch.

## The vendored engine

The copy exists so kata can carry a patch to it in-tree. It is a function of three
inputs, and nothing else:

1. **The upstream copy.** Every file under `crates/runtime/code-mode-engine` at the
   pinned rev, and the repository's `LICENSE-MIT` and `LICENSE-APACHE`. It is read
   from git objects, so no checkout state or `.gitattributes` rule can change a byte.
2. **Its `Cargo.toml`, resolved.** Each `workspace = true` field takes its value from
   nanocode's root `Cargo.toml` at that rev. A sibling path dependency becomes a
   `git` + `rev` dependency on the same repository and rev, so it is the same
   package the rest of nanocode resolves to. The `[lints]` table is nanocode's own.
   The crate is in the workspace `exclude` list, so kata never lints or tests it
   as one of its own, and `just fmt` runs `cargo fmt` without `--all`, which would
   also format the members' path dependencies, so kata never formats it either.
3. **`vendor/nanocode-code-mode-engine.patch`, applied.** This is kata's whole delta
   (`git apply -p1`). An empty file means no delta.

`just nanocode-vendor-check` (`scripts/nanocode-vendor.py check`) derives that tree
and compares it with `vendor/nanocode-code-mode-engine`. It refuses, naming each
one:

- a changed, missing or extra file, a changed executable bit, or a symlink;
- a patch file that does not apply;
- direct nanocode pins that disagree or are not on the nanocode repository;
- a `[patch]` entry that does not route the crate to `vendor/`.

It fetches the upstream objects once into `~/.cache/kata/nanocode.git` (under
`$XDG_CACHE_HOME` when that is set). When it cannot fetch them it refuses: a check
that cannot look does not pass. `just verify` routes `vendor/**` to it, and
`dev-loop-check` runs it and its `--self-test`, so the commit tier checks it too.
It does not read `Cargo.lock`. That cargo actually builds the copy, and no
unpatched git copy of the crate, is `nanocode_seam.rs`'s
`nanocode_rev_matches_the_lockfile`.

**To change the delta**, edit the files under `vendor/nanocode-code-mode-engine`,
then run `python3 -B scripts/nanocode-vendor.py record`. It rewrites the patch
file as the diff from the upstream copy to the tree. Commit both. Never edit the
patch file by hand to change the tree. `python3 -B scripts/nanocode-vendor.py
vendor` re-derives the tree from the patch file, which undoes an edit you have not
recorded.

A change to the delta moves the executor term. `crates/agent-nanocode/build.rs`
hashes every file of `vendor/nanocode-code-mode-engine`, the patch file and the
manifest and `src/` of kata's interpreter host (`crates/code-mode-host`) into
`CODE_MODE_ENGINE_DIGEST`, and `kata_code_mode_host::syscall_filter_digest` digests
the interpreter's syscall filter as compiled; `harness_identity` folds both into the
`agent_harness` property, so kata-worker's
`the_node_term_is_pinned_and_carries_no_version_string` turns red and the literal is
re-pinned in a commit of its own, as after a bump (below). Every capsule reuse key on
every node misses once, so no capsule result from the old engine serves a turn on the
new one.

## The kata delta: Code Mode's seams

nanocode's Code Mode runs a cell's JavaScript in djs, nanocode's own engine
(`crates/patches/djs`), through `EmbeddedHost`: a host that runs the cell in
slices of djs fuel on whatever task polls its `read_event`, with timers from
nanocode's platform (`nanocode_platform::sleep`). On native targets djs keeps
its arena's bounds checks (djs-core forbids `unsafe` code without its
`unsafe-heap` feature, which djs-embed turns on for WebAssembly only). Upstream
caps a cell's heap at half the memory the process has free when its first cell
starts (`MemAvailable`, or the cgroup's headroom, `memory.rs`), so the cap is the
machine's, and sets no wall, output or worker limit; nanocode spawns a fresh host
for every cell on native targets (`run_cell_actor`). kata keeps the engine out of
the process hosting the worker (below), and the patch adds only the seams that
needs:

- `set_worker_backend(..)` (`src/backend.rs`), process-wide and once only. Once a
  backend is installed, every `EmbeddedHost::spawn` hands the backend that host's
  ends (`WorkerEnds`: the commands the host sends, `HostCommand`, in order; the
  sender of the events it reads, `Events`; the failure it returns once that sender
  is gone, `startup`; and `Stopped`, which `terminate` awaits), and every method of
  the host (`start_cell`, `read_event`, `send_tool_result`, `hold`, `release`,
  `terminate`) goes to the backend: the host runs no cell itself. A spawn the
  backend refuses fails with the backend's text. Without a backend, every host is
  upstream's. Under a backend, `take_stored` returns nothing: a cell's writes reach
  the host with its terminal event, so a cell its host terminated keeps none. This
  DIVERGES from upstream at `8ec3b215`, which keeps a terminated cell's writes
  (`CellTerminal::Terminated { stored }`, filled from `take_stored`); at `2ac77424`
  nanocode kept none either. kata keeps its behaviour on purpose: no work of a cell
  outlives the cell, and a write the cell made before kata killed it (its wall, a
  turn's end) is part of that work. A model that reads such a value finds it absent
  under kata. Pinned by `code_mode_limits`'s
  `a_cell_its_host_terminated_keeps_none_of_its_writes` (kata's backend: nothing
  kept) and its twin `code_mode_unlimited`'s
  `upstreams_host_keeps_a_terminated_cells_writes` (upstream's host, the same cell:
  the write kept), which reds when upstream stops keeping it and this divergence is
  gone.
- `set_stored_loader(..)`: what answers a cell's `load` of a key the stored values
  its `start_cell` was given lack. kata's interpreter process starts every cell
  with none and loads each key from its parent as the cell asks (below).
- `CellTools::encoded` and `CellTools::from_encoded`: a cell's encoded tool catalog
  (definitions, descriptions, schemas), so it crosses to the interpreter process.
- `set_output_limit(..)`: what a cell may emit and what each event costs it
  (kata's `wire::Event::charge_of`). The engine charges each event as the cell
  makes it, inside the step that makes it, before it queues it: the event that
  takes the cell past the limit is never queued, nor is any after it, the script
  is stopped as its `exit` stops it, and the cell ends with `Code Mode cell
  output exceeded its <n>-byte limit` as a `Notify` of its own and an `Error` of
  the same text, keeping none of its writes. Charged where the interpreter reads
  an event instead, a step (200,000 fuel, whose host calls cost the same fuel
  whatever their payload) queues every event it makes first: a loop notifying
  one 1 MiB string queued gigabytes and the interpreter died on `RLIMIT_AS`
  before its first event was read (MEASURED; `code_mode_limits.rs`'s
  `a_flood_of_large_chunks_ends_at_the_output_limit_before_the_interpreter_grows`).
- The heap's report. Just before the `Error` of a cell djs ended on its heap cap
  (`Script stopped: the cell ran out of memory.`, which no script can catch: djs
  runs with `fatal_out_of_memory`), the engine sends `Code Mode cell exceeded its
  <n>-byte memory limit` as a `Notify` of its own, `<n>` being the cap
  (`cell_memory`). Every heap hit a cell's own code makes is reported: the hit
  is never a JavaScript exception, and one in a call the engine makes between
  two steps (handing the cell a tool's result or failure, a reply) ends the
  cell the same way (`EmbeddedHost::fail`; before kata's patch it failed the
  host with `embedded Code Mode execution failed: out of memory` and no
  report). A heap too small for the engine's bootstrap
  (under about 360 KiB) fails every cell with the bootstrap's own `out of memory`
  and no report.
- `platform`: the engine's re-export of `nanocode_platform`, so kata can install
  its own platform host (the interpreter process's, below, and the adapter's,
  `adapter::platform`) without a fourth direct nanocode dependency.

Everything else kata enforces is kata's own code (`crates/code-mode-host`), not
the engine's. kata's values are `CODE_MODE_LIMITS` in
`crates/agent-nanocode/src/lib.rs`; `CodeModeLimits` names them:

- `memory_bytes`, 256 MiB: the interpreter process sets it on the engine
  (`set_cell_memory`) before its first cell, so a cell's heap does not depend on
  the machine. djs keeps a script's call stack in that heap (its own slot limit,
  `ExecOptions::max_stack`, throws a catchable `RangeError: Maximum call stack size
  exceeded`), so the heap bounds the stack too; kata has no separate interpreter
  stack limit since nanocode left QuickJS.
- `thread_stack_bytes`, 8 MiB: the stack of the interpreter's thread that runs its
  cells, rather than the inherited `RLIMIT_STACK`. djs runs a script's frames on
  its heap; what this stack holds is the native frames of djs's builtins and the
  engine (MEASURED need: `code_mode_stack_through_adapter.rs`).
- `cell_wall`, 300 s: the interpreter ends a cell running, waiting on a tool or a
  timer, or held, once the wall has passed since its `Start`, between two of the
  engine's slices, with the report `Code Mode cell exceeded its <n> ms wall-time
  limit` and an `Error` of the same text. One long native step (a split or join of
  hundreds of megabytes) returns no slice; the supervisor kills its interpreter
  `WALL_GRACE` (5 s) past the wall. Time between cells is not charged.
- `cell_emitted_bytes`, 8 MiB: each notification, content item, tool call and
  yield is charged `CELL_EVENT_BYTES` (256) beside its payload (a notification its
  text, a content item every string in it but its `type`; a tool call's input is
  not charged), so a cell sends at most `cell_emitted_bytes / 256` events and at
  most `cell_emitted_bytes` of payload (`wire::Event::charge_of`). The engine joins a
  cell's texts into one item of up to 64 KiB before it sends them. The interpreter
  installs the limit on the engine (`set_output_limit`, above), which charges each
  event as the cell makes it: the event that would cross the cap is never queued;
  the cell ends with the report `Code Mode cell output exceeded its <n>-byte
  limit` and an `Error` of it.
- `live_workers`, 8: hosts live in the process at once, each counted from its spawn
  until its interpreter process is reaped (`kata_code_mode_host::live_workers`). A
  spawn past it fails (`this process already runs <n> Code Mode workers, its
  limit: ...`), which nanocode fails the cell with. Each host has an interpreter
  process of its own under `memory_bytes` and an address-space limit, so this
  bounds the interpreter heap the process can hold at `live_workers` x
  `memory_bytes` (2 GiB), and the interpreters' memory at `live_workers` x
  `address_space_limit` (about 10 GiB; below). The cap is the process's: one attempt's running cells
  can leave another's next cell without a host until one ends.
- The stack's report: a cell whose `Error`'s first line ends with `RangeError:
  Maximum call stack size exceeded` gets `Code Mode cell exceeded its interpreter
  stack limit` just before it. A script that throws that error itself, uncaught,
  reads the same; a stack hit the cell catches and rethrows inside an error of its
  own is reported as that error, with no report.

`install_code_mode_limits` installs them through `kata_code_mode_host::install`,
and the worker calls it once at start, when it builds its production adapter
registry (`kata_worker::adapter_registry::production`), before any agent is
built. A Code Mode host spawned in a process that never called it runs its cells
in that process, under upstream's machine-derived heap cap and no other limit.

**Held time counts against `cell_wall`.** nanocode can hold a running cell
(`EmbeddedHost::hold`, then `release`) to journal it and replay it on another
host. A held cell keeps its process and its memory, and its timers keep their
deadlines; the interpreter's wall runs on through a hold (read, not pinned: no
cell can reach a hold). nanocode holds only journaled cells, and kata gives
nanocode no cell journals (`Tools::cell_journals`), so nanocode never holds a
cell in kata's process today, and the supervisor refuses a journaled cell
(`adapter::seam::tests::kata_installs_no_code_mode_cell_journals` turns red on a
tool set that carries them).

What the limits bound is the interpreters, not the hosting process: at most
`live_workers` interpreter processes, each under `memory_bytes` and an address-space
limit. The heap bounds what a cell's JavaScript allocates in djs; djs's native
builtins allocate outside it (MEASURED: `normalize` of 40 million characters
completes at a 608 MiB resident peak under the 256 MiB heap, and of 80 million
fails an allocation on `RLIMIT_AS`), so the real bound on one interpreter's
memory is `address_space_limit`, 1,288 MiB under kata's limits, and on the
process's interpreters together `live_workers` times it, about 10 GiB. A native
allocation past it ends that interpreter by SIGABRT (`memory allocation of <n>
bytes failed`), its cell failing with the supervisor's report of the end, not a
limit's: the address space is no limit of `CodeModeLimits`, and an allocation
that fails there is not told apart from one the host refused
(`interpreter_process.rs`'s
`a_native_allocation_past_the_address_space_ends_only_its_interpreter`).
Rust-side copies of a cell's `stored` values and of events already sent are
outside the djs heap; the session's stored values stay in the hosting process, and
an interpreter holds only the values its cell loaded.

## The interpreter process (`crates/code-mode-host`)

`install_code_mode_limits` installs kata's limits through
`kata_code_mode_host::install`, which installs a backend behind the engine's
worker seam: every Code Mode host nanocode spawns (one per cell) becomes a
supervisor thread in the process hosting the worker — always a `kata-worker` node, never the main:
the node `kata serve` supervises (`type = "supervised_node"`) or a daemon the
operator starts (`local_socket`) — and, for its cells, an interpreter PROCESS. Nothing
runs a cell in the hosting process; there is no fallback.

- The interpreter is the hosting process's own executable, re-executed from
  `/proc/self/exe` with `INTERPRETER_ARGS`: the same build by construction, no
  store member. `kata-worker` dispatches to it first thing in `main`
  (`run_if_interpreter`); `kata` hosts no worker and has no entry. A test binary whose cells run behind the backend
  carries `kata_code_mode_host::interpreter_entry!()`, a test named for those
  arguments (they are a libtest invocation of exactly it, plus a filter no test
  is named). Its protocol runs on a socket that is its descriptor 0: each frame a
  big-endian `u32` length and JSON (`wire.rs`), at most `FRAME_CAP` (64 MiB);
  its standard output is `/dev/null` and its standard error a socket of its own,
  which the supervisor drains (below). A program with no entry (libtest selecting no test, or a `main`
  that never dispatches) exits 0 before `Ready`, and its cell fails naming the
  entry it lacks. Every test binary that runs nanocode's Code Mode cells after
  `install_code_mode_limits` (directly, or through
  `kata_worker::adapter_registry::production`) needs the entry. A test binary
  that reaches the production registry only through another crate's code
  (`kata_worker::capsule_route`) and runs a nanocode turn needs it too, and
  gate_exclusion's `every_test_binary_that_installs_kata_code_mode_invokes_the_interpreter_entry`
  does not see it.
- A cell's `Start` carries its source and tools, not its stored values: the
  engine's stored-value loader in the interpreter (`set_stored_loader`, part of
  kata's patch) asks the supervisor for each key the cell loads and the cell's
  JavaScript waits for the answer, so what a session has stored is bounded by no
  frame. The first `load` of a key in a cell costs that round trip; the
  interpreter keeps the cell's answers, up to 16 MiB of keys and values, so a
  key loaded again costs none, and empties them at the next `Start`. Each frame
  is still at most
  `FRAME_CAP`: a cell whose source and tools exceed it fails before it runs; a
  tool result past it fails that tool call in the cell, naming the frame; a cell
  whose stored writes, error or tool-call input exceed it fails naming the frame
  (the interpreter sends that `Error` in the event's place, keeping none of the
  cell's writes), and the next cell runs. A tool call's input crosses as its
  JSON text and is parsed into a value alone, under serde_json's 128-level
  recursion limit, the one the engine parsed it under (arrays nested 127 deep
  pass, 128 fail the call in the cell with the engine's `invalid tool input`):
  nested in the frame it sat three levels down, and inputs the engine admitted
  got the interpreter killed as a malformed frame.
- It confines itself before it answers anything: it closes every descriptor
  above 2, arms a parent-death SIGKILL and checks its parent is the one that
  started it, sets `oom_score_adj` 1000, `RLIMIT_AS` (`memory_bytes` + the
  thread stack + 1 GiB, 1,288 MiB under kata's limits; MEASURED `VmPeak` at a
  full 256 MiB djs heap: 474 to 486 MiB),
  `RLIMIT_CORE` 0 and not dumpable, and last installs its syscall filter
  (`syscall_filter.rs`, below) on every thread. Its environment holds only an
  empty `TZ`, which the parent sets after clearing the rest: the engine reads a
  cell's time zone at its start, and an empty `TZ` is UTC to it, with no zone
  file opened or stat'ed (the filter refuses both) and no host's zone told to a
  cell; an interpreter without it refuses before `Ready`. A step that fails ends
  it before `Ready`, so the cell fails naming why: a host whose kernel, or an
  enclosing seccomp profile, refuses the filter runs no cell (`could not confine
  itself: seccomp(2) refused its syscall filter (...)`).
- It installs its own platform host on the engine (`platform::install`): the
  clocks, timers on its cell thread's runtime and the kernel's randomness, so no
  engine timer starts nanocode's own reactor (an epoll instance, an eventfd and a
  thread, which the filter refuses).
- It runs the engine's own host (no backend installed there) on a thread of
  `thread_stack_bytes`, under a current-thread tokio runtime that waits on the
  host's events, its parent's frames and the cell's wall at once; it enforces the
  wall and the stack report there (above), and the engine the output limit it
  installed. It runs ONE host per
  cell: after each terminal event it terminates that host, starts the next and
  answers `Ready`, so nothing of a cell (a timer, a queued job, a value) reaches
  the next. Since nanocode spawns a host per cell, one interpreter process runs
  one cell in practice; a host given a second cell runs it after `Ready`.
- The supervisor starts an interpreter lazily, when a cell needs one; waits for
  its `Ready` (30 s); and treats everything it sends as untrusted: an event is
  admitted only for the cell it started, and charged as the engine charges it
  (or less: a notification its text, a content item every string in it but its
  `type`, each event `CELL_EVENT_BYTES`); a frame over the cap, an event of no
  running cell, a journal event, a `Held` no `Hold` asked for, output past
  `cell_emitted_bytes` and one report, a `Ready` unasked, a `Load` while
  no cell runs or while two answers to it are still being written (the engine
  asks again only once it has read the last answer), or a cell past its wall by
  `WALL_GRACE` (5 s) gets the interpreter killed (SIGKILL) and reaped. An
  interpreter's refusal reaches its cell cut to 4096 characters. The supervisor
  never waits on the interpreter: what it sends goes through a writer thread of
  that interpreter's, so one that stops reading delays neither its cell's wall
  nor `terminate`; ending an interpreter shuts the supervisor's end of the
  socket down, which ends that writer and the reader even while a process the
  interpreter started holds the other end. A cell whose interpreter
  ends while it runs fails with a `Notify` of the supervisor's report of the end
  (`Code Mode's interpreter process ended by SIGKILL`, or `... exited with status
  <n>`), recorded by the adapter as `CodeModeInterpreterEnded`, then an `Error`
  naming it (and why kata killed it); a wall kill reports the wall as the
  interpreter words it (`CodeModeLimit{wall}`). The report names the signal because the
  interpreter is not dumpable, so no core dump holds its reap: MEASURED with a
  probe child on a host whose `core_pattern` pipes to apport, from `abort()` to
  its parent's reap, 0.3 ms not dumpable, and dumpable 1.1 s alone and 9.2 s
  beside 8 other dumps, long enough to outlive a 1 s wall and `WALL_GRACE` and
  be reported as a wall kill; the hostile interpreter `hostile_interpreter`
  tests against is not dumpable for the same reason. An interpreter that ends
  between cells ends no cell and is recorded nowhere. A cell journaled by nanocode is refused (kata
  installs none). `terminate` and a dropped host kill the interpreter and reap it
  before the host stops counting as live, so a cell inside a native step does
  not outlive its turn's shutdown.
- Its standard error is a socket the supervisor drains on a thread of its own
  (`code-mode-err`), keeping the interpreter's last `STDERR_CAP` (64 KiB) bytes
  and counting what it drops; nothing of it reaches the hosting process's
  standard error or log. A cell the interpreter's end fails, or that could not
  start, carries it in its error after the report (`...; its standard error
  since it started: ...`, or `..., its last 65536 bytes (<n> before them
  dropped): ...`): an interpreter runs its host's cells one after another (one
  cell, as nanocode spawns hosts), so what it kept may be an earlier cell's.
  That is how a panic or glibc assertion line reaches the model and the
  transcript, cut with the rest of the result. Ending an interpreter shuts the supervisor's end down once it
  is reaped, so the drain ends once it has read what was written before.
- Its syscall filter (`crates/code-mode-host/src/syscall_filter.rs`, compiled by
  kata's own `kata_types::sandbox_seccomp::allow_list_program`, no seccomp crate)
  is an allow-list of the calls the interpreter was MEASURED to make after its
  confinement (strace of every interpreter process, threads included, across
  kata-code-mode-host's and kata-agent-nanocode's interpreter suites and a shipped
  `kata` driven by hand), each listed with its reason: read/write/close on
  descriptors 0 to 2 and writev on 2 (glibc's fatal report); the memory calls;
  futex; `clone` of a thread only (`CLONE_THREAD` set and no `CLONE_NEW*`
  flag), `clone3` answered ENOSYS so glibc falls back to it; each thread's rseq, robust list, name (`prctl(PR_SET_NAME)`
  only), affinity read, gettid, sigaltstack and getrandom; exit and exit_group;
  the signal calls and `tgkill` of its own pid only (abort's raise, with getpid);
  `restart_syscall`, through which the kernel resumes a timed futex wait (the
  engine's wait for a tool result, a timer or a hold) once a stopped or frozen
  interpreter continues, and which resumes only that listed call; the clock
  reads the vDSO falls back to, on the system's clocks and its own CPU clocks
  only (a negative clock id is another process's CPU clock); sched_yield; and `openat` with exactly
  `O_RDONLY|O_CLOEXEC` answered EACCES (glibc's malloc reads
  `/proc/sys/vm/overcommit_memory` the first time a thread arena shrinks, and
  `__assert_fail` reads `/proc/self/maps` before an assertion line; the engine
  reads `/proc/meminfo` and the cgroup's files for its default heap cap, which
  kata overrides, and std the cgroup's CPU quota; all carry on without them).
  djs needed no change to the list: strace of `interpreter_process`'s
  interpreters past their confinement saw only listed calls. Everything else, a
  listed call on other arguments, a foreign arch and the x32 range end the interpreter by SIGSYS
  (`SECCOMP_RET_KILL_PROCESS`), so code execution inside it (through an engine
  defect) opens, creates and executes nothing, makes no socket,
  process or namespace, and signals, traces and reads no other process, its
  memory or CPU clock: the
  process hosting it survives its `kill` (`tests::a_compromised_interpreter_cannot_kill_its_parent`).
  It is x86-64's: on another target the interpreter refuses before `Ready`.
  MEASURED, release, with nanocode's djs engine at `8ec3b215` (200 interpreters
  of 50 trivial cells each, the probe in the interpreter): compiling and
  installing it takes 243 µs (p50 280 µs, p99 338 µs), and a cell costs 665 µs to
  672 µs against 552 µs to 555 µs with the install removed (three runs each), a
  new interpreter's first cell 3.99 ms to 4.16 ms against 3.83 ms to 3.93 ms
  (with QuickJS at `2ac77424`: 141 µs, and 1.135 ms against 1.119 ms a cell).
- Not refused, stated: the listed calls on the arguments they admit
  (`sched_getaffinity` tells whether a process id exists); its own CPU until the
  wall's kill and memory up to its limits; and frames up to `FRAME_CAP`, which
  bounds bytes on the wire, not what decoding one takes in the hosting process.
  A frame's JSON values decode there to up to 88 times its length (MEASURED,
  serde_json 1.0.149, 64 MiB frames: an array of one-key objects 5.6 GiB, nested
  arrays 4.5 GiB, an array of zeros 1 GiB, a string 64 MiB). Each interpreter's
  supervisor holds at most six decoded frames at once (four queued, one its
  reader waits to queue, one it handles); the harness holds every admitted
  tool-call input until its call ends, and a cell's tool calls are bounded only
  by its event count (`cell_emitted_bytes / CELL_EVENT_BYTES`, 32,768), so the
  hosting process's memory is bounded neither against a compromised interpreter
  nor against an honest cell that passes large inputs to many tool calls at
  once, whose inputs decode in the hosting process as they did on the engine's
  in-thread worker (MEASURED: ten concurrent calls on one array of four million
  zeros, about 1.26 GB through the interpreter process, 1.33 GB in-thread). `FRAME_CAP`
  stays 64 MiB: one content item of the cell's whole 8 MiB output, JSON-escaped
  at worst six bytes to one, must fit, and a cell's stored writes cross in one
  `Done`. MEASURED across kata-agent-nanocode's and kata-code-mode-host's suites
  and the worker's `agent_turn_capsule`, past the cells that test the cap: a
  `Start` reached 8.5 KB, a content item 100 KB, a notification 4 KB.

`crates/code-mode-host/tests/` drives the supervisor through the engine's host:
`interpreter_process.rs` (cells in one child, which the kernel charges a spinning
cell's CPU to, not this process; a
terminate that kills a native step and reaps it; the count held until the reap; a
parent killed by SIGKILL leaving no interpreter, the interpreter stopped so only
its parent-death signal can end it; the kernel's account of its limits, OOM score
and dumpability; programs that cannot start or end before `Ready`; a session
storing 120 MB, more than a frame, whose later cells all run and load; a cell
waiting on its tool whose interpreter is stopped and continued, which completes
(the kernel's `restart_syscall` admitted); a key
loaded again not asked for again, and what the interpreter keeps of the answers
bounded; a cell's
stored writes and a tool result past a frame, each failing by name; image items
up to the engine's own limit admitted) and `hostile_interpreter.rs` (an
interpreter written by hand breaking each rule above, and one that stops
reading, leaves a process of its own holding its socket, refuses with a MiB
of text, or floods its standard error). `syscall_filter.rs`'s own cells run an
adversary confined as every interpreter is, driven by hand, and read the
kernel's wait status: each escape (an open for writing, a socket, a kill of
its parent, ptrace, process_vm_readv, execve, fork, a raw clone, a thread
cloned into a new namespace, a read of its parent's CPU clock) ends it by
SIGSYS; every listed call runs and every thread reads `Seccomp: 2`; 27 sampled
denied calls end it. The shipped `kata-worker` runs a cell as an interpreter
(`pidfile_tests/code_mode_interpreter.rs`).

Through the adapter, against the mock provider and the toolhost double,
`crates/agent-nanocode/tests/code_mode_through_adapter.rs` runs under kata's own
limits, installed by `install_code_mode_limits`. A model-written cell that
allocates 384 MiB fails, the next request tells the model "Script failed" with
the engine's `Script stopped: the cell ran out of memory.`, the model's next cell
runs in an interpreter process of its own (the first one reaped when its host
dropped) and the turn completes, with this process's peak resident memory far
under the heap the cell filled. A cell the model terminated is followed by a cell
on a newly spawned host, in another interpreter process, and the terminated one's
interpreter is reaped. `code_mode_wall_through_adapter.rs` installs kata's limits
with a 2 s wall. A spinning cell fails to the model with exactly the wall's error
and report, ended by the interpreter between two slices, not by the supervisor's
kill (no `CodeModeInterpreterEnded`); the model's next cell runs and the turn goes
on. Its second cell spins and yields after 200 ms, as a cell under kata's 300 s
wall and nanocode's default yield (30 s on the Responses kind, 10 s on the
Messages kind) does; the model's `wait` on it then receives the wall failure.
`code_mode_workers_through_adapter.rs` installs kata's limits with a cap of two
hosts. The model starts three cells that spin and yield: the third fails to the
model naming the cap, the turn goes on, and while the model then waits on the
first cell the kernel lists exactly the two spinning cells' interpreter
processes. `code_mode_output_through_adapter.rs` runs under kata's own limits: a
cell flooding image content items fails at the 8 MiB output limit, the last text
of its result is `Code Mode cell output exceeded its 8388608-byte limit`, the next
cell runs in an interpreter of its own and the turn goes on.
`code_mode_interpreter_through_adapter.rs`: a bind flood (which ended QuickJS by
SIGSEGV) is a heap hit on both kinds under djs, recorded once and ending no
interpreter; and a cell whose interpreter is killed from outside while it waits
(SIGKILL, as the kernel's OOM killer would, since an interpreter runs at
`oom_score_adj` 1000; a cell can also end one itself by SIGABRT, a native
recursion past its stack or a native allocation past its address space, both
pinned in `kata-code-mode-host`'s `interpreter_process.rs`) fails to the model with the supervisor's report `Code Mode's
interpreter process ended by SIGKILL`, the evidence records exactly
`CodeModeInterpreterEnded{SIGKILL}`, the next cell runs and the turn completes, on
both kinds. These binaries install kata's limits through kata's installer, so
each carries the interpreter entry.

What the model is told of a cell is nanocode's VISIBLE output of it, which the two
backends cut differently. On the Responses kind Code Mode bounds a cell's items
to its own 10,000-token budget (`CODE_MODE_OUTPUT_TOKENS` in the codex backend's
builtin tools), the result's header (`Script failed`, its wall time and
`Output:`) outside it; when every item is text it joins the cell's text and its
`Script error:` into one item and keeps its head and tail (`Warning: truncated
output (original token count: <n>)`, then the head, `…<n> tokens truncated…` and
the tail), so a failed cell's error survives at the tail however much text came
before it; a result with other items keeps them in order and drops the text past
the budget (`[omitted <n> text items ...]`). On the Messages kind the claude
backend keeps the result's text blocks in order up to a 12,000-token budget that
counts the header (4 UTF-16 units a token, each block rounded up),
middle-truncates the block that crosses it and drops the rest (`[<n> more text
blocks omitted]`): once the header and the cell's text fill it, a failed cell's
error is cut past its reason or dropped, and the cell's result says `Script
failed` without the reason. A cell whose own text fits the budget can lose its
report there all the same: 47,900 bytes of text (11,975 tokens) and the header
leave the error its reason only at its tail and drop the report on the Messages
kind, while the Responses kind tells both
(`a_cell_text_under_the_budget_keeps_the_reason_and_on_messages_loses_the_report`).
The report closes that gap where nanocode lets it. nanocode delivers a Code Mode
notification differently on the two backends. The codex backend hands the model
each one as an output of its own for the call, after the result, truncated on
its own budget, so the report reaches the model on the Responses kind unless
nanocode compacts the turn's history before the model's next request: once the
history reaches its auto-compact threshold (90% of the model's context window for
the gpt-6 models), its compaction request rewrites tool outputs from the newest
back, the call's last output, the report, first, to `Output exceeded the
available model context and was truncated` until the history fits 95% of the
window, and the model then reads the compaction's item in place of them. A cell's
own outputs can do that alone: a notification flood inside kata's 8 MiB output
limit is ~1.8M tokens
(`on_the_responses_kind_a_compaction_rewrites_the_report_and_the_record_stays`;
the claude backend's compaction is not measured). The claude backend appends each
notification to the same `tool_result` as one more text block, after the error,
which the same truncation drops: on the Messages kind the report reaches the
model only while the header, the cell's text and its error leave it room in the
budget. Past that a hit is told to the model as a bare `Script failed` and `[2
more text blocks omitted]`: a MEASURED residual, which the claude cells below
pin. Moving the report out of that result would change nanocode, which kata does
not patch (the 2026-10-29 decision).

The record does not depend on what the model is told. On both backends nanocode
emits every notification as a `tool.notification` event, and the adapter records
a report's limit off it as `CodeModeLimit` (`wall`, `output`, `memory` or
`stack`; `adapter::events::guard_report`), once per hit: the failed result's own
text is not read for these limits. The adapter reads any notification whose
whole text is a report's, so a cell's own `notify` of one is recorded as a hit
though none happened (progress and evidence, never authority). A hit nothing
reports (above) is recorded nowhere. Every tool call's result is recorded as
`ToolResult`, by its id and nanocode's status word, on both kinds: the adapter
reads only those two fields of a `tool.result`, so the claude backend's `{text}`
/ `{content_blocks}` result decodes as the codex backend's tool output does
(`adapter::events::ToolResultHead`). The live-worker cap has no cell to report it
(a refused cell never had a host), so its refusal, which nanocode appends bare to
the `exec` result as the cell's only text and so always inside the budget, is
recorded as `CodeModeLimit{workers}` off that result
(`adapter::events::refused_a_worker`), in either backend's result shape. A cell
that yielded and failed on a limit while no `wait` observed it is told to no
model, but nanocode delivers its report when it ends the turn's cells, before a
completed or cancelled turn's outcome, so the evidence records it then; a
Responses-kind turn that fails with no tool call in flight detaches its cells
instead (read from nanocode, not measured), and a report they deliver after the
outcome reaches no record. The adapter-level cells drive the real limits and
assert the record, so a bump that rewords a report or the live-worker refusal is
red there:

- `code_mode_output_through_adapter.rs`, under kata's limits: a text flood past
  the output limit (its flood reached nanocode as exactly the whole texts the
  limit accepts, read off nanocode's original-token count), a heap hit after one
  60,000-byte text beside the same allocation after a 600-byte text, and a stack
  hit after the long text; on the Responses kind each error survives at the tail
  of the truncated text and each report reaches the model as an output of its
  own, on the Messages kind each past-budget error and report are dropped from
  the result; every hit is recorded once on both. Also: a heap hit inside a
  `try`/`catch`, which no catch holds, told with the engine's error and report
  and recorded on both kinds; a heap hit after 47,900 bytes of text (above); and
  a notification flood whose compaction rewrites the report on the Responses
  kind, recorded all the same.
- `code_mode_wall_through_adapter.rs`: a wall hit after a 70,000-byte text, told
  on the Responses kind and untold on the Messages kind, recorded on both; a
  yielded cell's wall hit, whose report reaches the model with the `wait` that
  observed it; and a yielded cell's wall hit no `wait` observes, recorded at the
  turn's end on both kinds and told to no one.
- `code_mode_workers_through_adapter.rs`: the refusal on both kinds.
- `code_mode_stack_through_adapter.rs`: the stack hit's report and record.

The worker publishes the record with a completed turn's evidence:
`crates/worker/tests/agent_turn_capsule.rs` reads a past-budget heap hit's
`CodeModeLimit{memory}` back off the CAS for each kind, and, for a turn whose
cells flood the heap twice with cells after each flood, the two
`CodeModeLimit{memory}` of a completed capsule whose later cells all ran; a
child of that binary runs the same turn and exits 0
(`a_worker_turn_whose_cells_hit_the_heap_ends_no_process`).

`crates/agent-nanocode/tests/code_mode_limits.rs` drives the engine's host
directly, behind kata's interpreter process under small limits (a 16 MiB heap,
a 2 s wall, 1 MiB of output, two hosts), and reads what a cell cost from outside
it (the events, the wall clock, the interpreter's `/proc/<pid>/status` and CPU
ticks). Its cells: a heap hit fails with the engine's error and report and the
next cell, in the same interpreter, allocates 14 MiB; a spinning cell and a
microtask that requeues itself each end at the wall with exactly its report,
ended by the interpreter, not the supervisor; a cell waiting on a timer and one
on a promise nothing settles end at the wall; idle time before a cell's `Start`
is not charged; an output flood ends at the cap, the last whole byte the cap
admits is admitted and the next refused, and every kind of event is charged
(MEASURED, a 1 MiB cap: 15 content items of 64 KiB, 4096 yields, 4080 one-byte
notifications, 4096 unanswered tool calls); a recursion past djs's stack limit
gets the stack report (131,068 levels under a 16 MiB heap); only real limit hits
are reported (a thrown error worded as a report is not; a forged stack error,
thrown uncaught, is: the stated residual), and a heap hit inside a `try` still
ends the cell and is reported; a third host under a cap of two is refused until
one ends; and the installer takes one set of limits per process. The cells that
pinned QuickJS's own failures are gone with it: the prototype leak that let a
later cell read an earlier one's globals, context creation under the limit, the
bare-`null` heap hit and the exhausted-heap heuristic, and the job drain (djs's
jobs live in the instance a cell's `start_cell` replaces). A held cell is
unreachable through nanocode, which holds only journaled cells, and kata's
supervisor refuses those; no cell pins the wall through a hold. Read, not
reachable today: a `Hold` sent before an interpreter answers `Ready` reaches it
ahead of the cell's `Start`, and the cell is not held.

`code_mode_context_failure.rs` runs trivial cells in child processes under one
byte and every 8 KiB up to 512 KiB of `memory_bytes`: every child exits 0, and
each cell runs or fails with the engine's own `failed to compile the embedded
Code Mode bootstrap: out of memory` (MEASURED: 352 KiB fails, 360 KiB runs), with
no report, every cell of a child in one interpreter. `code_mode_unlimited.rs`
checks the behaviour when no backend is installed: upstream's host runs a 64 MiB
allocation in the test process itself, and no interpreter is listed.
`code_mode_out_of_memory_defects.rs` sweeps the headroom a cell leaves before an
operation, every 8 bytes up to 16 KiB under a 4 MiB heap, behind kata's
interpreter process, for the operations that met QuickJS's out-of-memory defects
(`Function.prototype.bind`, `eval` of a class, `Array.fromAsync`) and a control:
each runs at some headrooms and fails on the heap, with the engine's error and
report, at the others, and no interpreter ends (MEASURED: ran / failed on the
heap 1911/138 control, 1933/116 `bind`, 1528/521 `eval`, 1842/207
`Array.fromAsync`). Each is its own binary because the installer is process-wide.

`code_mode_stack_through_adapter.rs` measures the thread stack's headroom over
what a cell can push onto it, through the adapter. Under kata's limits a cell
recurses through `sort`'s comparator until djs throws `RangeError: Maximum call
stack size exceeded`, catches it, then recurses through a host call (each level is
`setTimeout`, whose delay coercion calls the cell's `valueOf` back) until it
throws again. The model is told that error and the stack report, which the
evidence records as `CodeModeLimit{stack}`; its next cell runs and the turn
completes (MEASURED depths: 20,972 levels through `sort`, 15,419 through
`setTimeout`). Children of the test binary then run twelve recursion shapes
under shrunk cell-thread stacks: djs runs a script's frames on its heap, so
`sort`, `setTimeout`, plain recursion, `Proxy` traps, `bind`, a prototype chain
and `JSON.parse` complete on 64 KiB, and the native recursion of djs's own parsers
and builtins (nested source, regular-expression groups, `JSON.stringify`,
`String`, a linked-list collection) sets the need, each bounded by djs. Not every
native recursion is: `instanceof` against a chain of bound functions recurses
natively once per link (MEASURED: 20,000 links complete; 100,000 overflow the
8 MiB stack), so a cell can overflow any thread stack. The overflow ends the
interpreter by SIGABRT (Rust's `thread 'code-mode-cell' (<tid>) has overflowed
its stack`), and the supervisor, reading that line off the interpreter's
standard error, sends `Code Mode cell exceeded its <n>-byte native stack limit`
before its report of the end: the evidence records `CodeModeLimit{stack}` and
`CodeModeInterpreterEnded{SIGABRT}` (`interpreter_process.rs`'s
`a_native_recursion_past_the_thread_stack_ends_only_its_interpreter_and_is_reported`).
The line is the interpreter's own text, so a compromised interpreter can write
it, as it can any report. A search
finds the smallest stack every shape completes on: MEASURED, 372 KiB (368 KiB
overflows, on regular-expression groups at djs's 211-group bound); kata's 8 MiB
is 22 times it, and the cell is red if `thread_stack_bytes` drops below twice the
need. At 64 KiB the overflowing shapes end their interpreter by SIGABRT (Rust's
`thread 'code-mode-cell' has overflowed its stack`) and the child itself exits 0.

## A turn the provider failed

When nanocode ends a turn nobody asked to stop on its model provider's failure, after
a request left, kata classifies it from nanocode's own typed error, never from whether a
request body left (`kata_agent_nanocode::adapter::session::provider_failed`, nanocode
`8ec3b215`):

- **transient** when nanocode's `BackendFailure::retryable` says so: the Messages
  client's `ClaudeError::is_transient` (HTTP 408, 409, 429 and 5xx unless the
  provider sent `x-should-retry: false`; the overloaded, rate-limit, API and timeout
  stream errors; a stream that ended early; a transport failure it calls transient,
  a refused connect among them) and the Responses client's
  `ResponsesError::retry_advice` (the same statuses unless the body names a terminal
  code, a premature close, a transport or timeout failure, an overload, rate-limit or
  server error event). It has been retried, within kata's attempt budget below.
- **the call's last real failure** when kata's wire ended the call
  (`kata_agent_nanocode::adapter::wire`): the provider's own failure of the call's
  last attempt, classified by these same rules, never kata's refusal.

### kata's wire: the attempt budget, the waits, the meter

kata, not the harness, is the retry authority (the runner re-runs a transient stage
and walks a fallback panel), and it bounds nanocode's retrying where it can measure
it: on the wire, below nanocode's own retry logic, on every model request of both
kinds, without any of nanocode's retry knobs (`adapter/wire.rs`). On the Responses
kind kata rebuilds nanocode's standard service (`Retry::into_inner`) as nanocode's own
retry policy over kata's `ResponsesWire`, so every attempt, its retries, its 429-to-529
patience and its stream re-sends after a cut included, reaches kata with its typed
result on either transport; on the Messages kind the client's HTTP layer
(`MessagesMark`) sees every request and response. Upstream at `8ec3b215`, unbounded,
the Messages client makes eleven attempts (about 180 s for a dropped connection or a
500), both clients wait out a 429, 502, 503, 504 or 529 for up to 600 s (MEASURED,
every attempt answered 503: the Messages client 22 requests in 578 s, the Responses
client 49 in 605 s), and the Responses client re-sends a failed stream five more
times beyond its attempts, a 5xx the provider marked `x-should-retry: false` among
them. Under the wire:

- A call may fail **five attempts in a row** (`ATTEMPTS`, kata's and nanocode's own at
  `2ac77424`); the next request is refused before it leaves, unsent and not
  retryable, which ends the call on either client. So is a re-send of a request the
  provider answered `x-should-retry: false` (ADR 0003's finding F3) and of one whose
  answer kata classes the provider's refusal (a WebSocket `error` event stating a 4xx,
  a plan's `usage_limit_reached` 429): nanocode would re-send each. The count is the
  turn's failed attempts since one last completed, so a new call after a failure
  nanocode does not re-send counts on: tighter than per call, never looser.
- The call ends on the provider's **last real failure**: on the Responses kind the
  retry policy makes no further attempt and nanocode's retry layer hands that
  attempt's own typed error back at once; on the Messages kind the wire refuses the
  next request, and the session classifies the turn by the failure the wire recorded,
  rebuilt as nanocode's own `ClaudeError` from the status, headers and body (or the
  transport failure, the error event, the stream that ended before `message_stop`)
  the wire saw, through `provider_failure` — the class that failure has without kata.
- Every wait is capped at kata's `2ac77424` backoff, 1.1 s × 2ⁿ (`wait_cap`): on the
  Responses kind the retry policy's wait is cut there; on the Messages kind a
  `retry-after` past it, or one kata cannot read, is removed from the error answer
  before nanocode reads it, so nanocode waits its own backoff. MEASURED at
  `8ec3b215`, every attempt answered 503, a 429 asking 120 s, or cut mid-body: five
  requests, the Responses turn over in 16.3 s to 16.5 s, the Messages turn in 17.4 s
  (`nanocode_qualification`'s `a_call_answered_503_every_time_ends_on_the_attempt_budget`,
  `a_429_asking_two_minutes_is_waited_at_most_the_wires_cap`,
  `a_call_cut_mid_response_every_time_ends_on_the_attempt_budget`; a 500 marked
  `x-should-retry: false` is sent once on either kind,
  `a_5xx_marked_not_to_retry_is_sent_once`). The Messages kind pays one more wait than
  at `2ac77424`: nanocode waits its backoff after the last allowed attempt (8 s, up
  to 25% over) before the request kata refuses.
- What it costs, stated: kata's rebuilt Responses retry policy carries no
  WebSocket-to-HTTPS fallback (nanocode's `with_standard_transport_fallback` is
  crate-private), so a WebSocket the provider refuses fails the call
  (`a_refused_websocket_connect_is_marked_conservatively`), and the runner re-runs a
  transient stage.
- Every attempt is **metered on the wire**, never read off nanocode's events: a
  completed attempt is charged the usage its response states (a Responses `usage`; a
  Messages stream's `message_start` and `message_delta` usage through its
  `message_stop`); an attempt the provider refused with a 4xx answer (or a WebSocket
  `error` event stating a 4xx), or that never left, nothing; every other attempt — a
  5xx, a stream cut or ended early, a transport failure after the request left, a
  completed response that states no usage — UNKNOWN, which makes the turn's charge
  unknown, a COMPLETED turn's usage (`None`) as much as a failed one's
  (`nanocode_qualification`'s `a_completed_turn_with_a_cut_attempt_is_charged_unknown`).

- **by name**, before nanocode's retry advice is read, for two codes the answer
  names in `error.type` or `error.code`: `usage_limit_reached` (a ChatGPT plan's
  usage quota) is **refused** on either Responses transport — an HTTPS 429, which
  nanocode reads as retryable, a WebSocket `error` event with or without a
  `status`, or a `response.failed` stream event carrying the error object in its
  `response.error`, which nanocode also reads as retryable — its reason naming the
  quota, since the plan's limit resets on its own schedule;
  `previous_response_not_found` is **transient**, since a fresh attempt chains to no
  stored response. None of these wire shapes has been measured against the real
  provider; the mock's shapes follow the Responses API's documented error object, and
  an answer that names neither code falls to the rules below.
- **refused** when the error is a 4xx error answer that is not retryable: the
  Messages client's `ClaudeError::Http`, the Responses client's `HttpRejected` or
  `HandshakeRejected`, or its `Api` error event of type `error` stating a 4xx
  `status` — the Responses WebSocket's spelling of an HTTP error response, and so the
  production transport's answer to a request the provider refuses. The reason is the
  status and the answer's `error.type` (and `code`) and `error.message`, scrubbed of
  the turn's lifted values and bounded.

Anything else after a request left — an error event that states no HTTP status, is
not retryable and names neither code above (a `response.failed` event among them), a
5xx nanocode does not retry, a
context-window or image refusal nanocode reshaped from its status, a malformed
response — stays `Ambiguous`, as does every break of the tool-host wire and a provider
failure on a turn kata asked to stop. A Responses HTTPS response the connection cut
mid-body is no longer among them: at `8ec3b215` nanocode reports it as a retryable
transport failure and re-sends the call (above), so a cut kata's attempt budget ends
on is **transient** (MEASURED, 1 + 5 requests; at `2ac77424` it was an undecodable
body with no retry advice, `Ambiguous`). The turn's charge is the wire's meter
(above): known only when no attempt can have billed unseen
(`kata_agent_nanocode::adapter::wire::Wire::failed_turn_charge`;
`nanocode_qualification`'s `a_failed_turn_with_a_resent_attempt_is_charged_unknown`).
The outcome
is `TurnOutcome::ProviderFailed`, which also states whether a tool call left the
harness during the turn and what the turn is charged; the worker settles it
(`kata_worker::agent_turn`, and the protected-properties `agent-turn` construct).
`nanocode_qualification`'s `a_provider_refusal_fails_the_turn_with_the_providers_reason`,
`a_websocket_error_event_with_a_4xx_status_is_the_providers_refusal`,
`a_plan_usage_limit_is_refused_on_both_transports_naming_the_quota`,
`a_plan_usage_limit_in_a_response_failed_event_is_refused_naming_the_quota`,
`a_previous_response_not_found_is_transient_on_both_transports`,
`a_transient_failure_past_the_attempt_budget_is_classed_transient`,
`a_server_error_the_harness_does_not_retry_stays_ambiguous`,
`a_model_connection_dropped_mid_response_is_a_transient_failure` and the
`a_refused_*_connect_is_marked_conservatively` cells pin this classification on both
kinds against the mock provider; `agent_change_live`'s
`a_provider_failing_its_response_mid_turn_settles_proven_ambiguous_live` pins an
Ambiguous turn's settlement on a real node: a `response.failed` event naming the
terminal `insufficient_quota`, after the turn's command ran, settles PROVEN AMBIGUOUS
and is never re-run; its twin
`a_provider_cutting_its_response_mid_turn_is_re_run_then_falls_back_live` pins the
mid-body cut's settlement on a real node: PROVEN NOT PERFORMED, `transient`, charged
`unavailable`, re-run twice on the same agent and then on the fallback panel's next
member, which completes (MEASURED at `8ec3b215` under kata's wire: 197.8 s, the
runner's 30 s and 120 s re-run backoffs and the wire's backoff among it).

## Bumping nanocode

`just nanocode-bump <rev>` moves kata to another nanocode commit. `<rev>` is a
commit sha, or a branch or tag the remote resolves, such as `master`. It runs these
steps in order and stops at the first failure:

1. `scripts/nanocode-vendor.py bump` rewrites the four direct pins in `Cargo.toml`
   and `NANOCODE_REV`. It then re-derives `vendor/nanocode-code-mode-engine` at the
   new rev and re-applies the patch. If the patch no longer applies, it fails
   loudly with `git apply`'s error and leaves the tree as the pristine upstream
   copy. Port the delta by hand (the old patch file still holds it), run
   `python3 -B scripts/nanocode-vendor.py record`, and re-run the recipe.
2. `cargo metadata` re-resolves the lock. Every nanocode package moves to the new
   rev, along with whatever the new rev needs, and no other entry moves. It does
   not use `cargo update -p`, which also re-picks among duplicate versions of
   unrelated crates.
3. `scripts/nanocode-vendor.py flake-hash` rewrites `flake.nix`'s `nanocodeHash`:
   `nix hash path` over the rev's `git archive`, which is how `fetchgit` stores
   it. For a rev with submodules, or a `.gitattributes` attribute that can change
   archived bytes, it refuses instead and names the recompute step: set
   `nanocodeHash` to `lib.fakeHash`, run `nix build .#kata`, and paste the hash it
   reports as `got:`.

   The Nix build vendors nanocode apart from every other dependency, and needs
   nothing else from a bump. nanocode's crates read files outside their own
   directories (djs-core `include_str!`s `../../../../builtins/gen/*.js`, and its
   build script walks `../djs-libm/src`), so they build only inside nanocode's
   tree, as they do in cargo's git checkout. `flake.nix` splits the lock: every
   non-nanocode package goes through importCargoLock, and the nanocode packages
   become a second cargo directory source, the whole tree at the locked rev with
   each package an entry linked to its directory in it
   (`nix/nanocode-vendor-dir.py`). Every derivation that builds with
   `kataCargoVendor` copies that source into its build directory with the links
   kept (`postUnpack = nanocodeVendorUnpack`). The split also means a nanocode
   package can share a name and version with a crates.io one (nanocode's own
   `unicode-normalization` 0.1.25) without colliding in importCargoLock's
   one directory.
4. `just nanocode-vendor-check`, then `just build-toolhost`, then `cargo nextest run
   -p kata-agent-nanocode`. The toolhost build comes first because the package's
   `toolhost_backpressure` cells exec `target/debug/kata-toolhost` and refuse a
   stale one `toolhost_mismatch`. The run includes the seam pins (`nanocode_seam`)
   and the Code Mode limit cells. A moved host tool set is red here by design, with
   one `host tool-set drift:` line per moved backend naming the tools added and
   missing: update `HOST_SET_CODEX` / `HOST_SET_CLAUDE` only after deciding how kata
   serves the new tool. A moved model-facing tool list is red the same way, in
   `the_model_facing_tool_list_is_the_pinned_set` and its Anthropic twin, against
   `tests/fixtures/{codex,claude}_model_tools.json`. `nanocode_qualification`'s
   `a_stop_with_the_connect_in_flight_reads_the_watermark_crossed` is a MEASUREMENT
   of nanocode's connect/attempt ordering (the `Generation` attempt is called
   before the WebSocket handshake answers), not a kata guarantee, so a bump that
   calls it only once connected turns the cell red by design. Re-measure the new
   ordering, then re-word the cell's doc, its ledger pins and D1 §2.3 to it; never
   weaken the cell to pass.

The recipe does not finish the bump. After it:

- Run `nix build .#kata`, which checks the `nanocodeHash` step 3 wrote, and
  `just deny`. Re-read every `deny.toml` entry whose reason names nanocode: an
  ignore forced by nanocode's old requirements comes out once the new rev lifts
  it.
- `git grep` the old rev. Each hit is a fact read or measured at that rev (a doc
  comment, a cell's MEASURED note, a ledger pin): re-check it at the new rev, then
  move it there or rewrite it.
- Read upstream's diff since the old pin for what kata depends on: the host traits
  the seam implements, the Code Mode crates, auth and token refresh, the Responses
  and Messages request shapes, the tool definitions and the model ids kata's
  evidence runs name.
- Re-check, at the new rev, the nanocode facts kata's docs state but no cell pins:
  - the ChatGPT early-refresh window, five minutes at `8ec3b215` (unchanged since `2ac77424`)
    (`REFRESH_EARLY_MILLIS` in nanocode's
    `crates/backends/codex/client/src/auth/subscription.rs`, `REFRESH_EARLY_SECONDS`
    in `auth/chatgpt.rs`). kata keeps no copy of it
    (`kata_agent_nanocode::credential::load_chatgpt`), but the operator guide's
    `kata_login` paragraph states it; a bump that moves it re-words that sentence.
  - the ChatGPT browser login's callback ports, `localhost:1455` then `1457` at
    `8ec3b215` (unchanged since `2ac77424`) (`CALLBACK_PORTS` in `auth/chatgpt.rs`), and its five-minute wait for
    the callback (`LOGIN_TIMEOUT`, same file). The operator guide's `kata login`
    table, the CHANGELOG, `kata login openai --help` and its browser prompt
    (`bin/kata/src/cli/login.rs`) state both; a bump that moves either re-words them.
- Re-check, at the new rev, the error types the provider-failure classification
  reads (above): `NanocodeError::Response`, `BackendFailure::{retryable, as_any}`,
  `ClaudeError::{Http, is_transient}`, `ResponseError::responses_error` and
  `ResponsesError::{HttpRejected, HandshakeRejected, Api, retry_advice}` (the
  WebSocket `error` event's `status` field among them), and what kata's wire stands
  on (`adapter/wire.rs`): `DefaultResponsesService` as `Retry<ResponsesRetryPolicy,
  ResponsesService>` with `Retry::into_inner`, `ResponsesRetryPolicy::default`, the
  `ResponsesServiceResponse` parts it rebuilds, `ClaudeError::{Http, Transport,
  StreamError, IncompleteStream}` it rebuilds from the wire, and the clients'
  backoff it leaves within `wait_cap` (the Messages client's 500 ms doubling; the
  Responses client's 1 s doubling). A variant that moved fails the build; a
  classification or a budget that moved reds the cells named above, which are then
  re-measured, never weakened.
- Re-check, at the new rev, the private `ChatGptSubscription` state fields kata
  reads out of nanocode's store, `credential.{refresh_token, account_id,
  expires_at}`: `kata_agent_nanocode::credential::login_state` reads all three for
  the offline status `kata login status` and `kata doctor` report, and
  `FileStore::stored_refresh_token`, the refresh's supersede check, reads
  `credential.refresh_token`. A rename fails closed: the status reads signed out,
  and the supersede check never matches the presented token, so every refresh is
  answered `kata_refresh_superseded` and none reaches the issuer (a token past its
  expiry then refuses the turn). `the_offline_status_reads_the_state_nanocode_wrote`
  (`crates/agent-nanocode/src/credential.rs`) reds on a rename; run it at the new
  rev.
- Re-read nanocode's per-model system blocks when
  `each_anthropic_model_gets_its_own_system_blocks_less_the_identity_and_the_bypass_steer`
  is red, and the default blocks for a new Claude Code or Agent SDK identity line:
  the qualification cell refuses the two nanocode names at `8ec3b215` (unchanged
  since `2ac77424`), not one upstream adds later, and the wire edit removes only the
  identity that opens the blocks and the bypass-mode steers whose text it holds
  (`the_wire_edit_removes_the_identity_and_the_bypass_steer_and_nothing_else` reds
  when either moves; re-copy `BYPASS_STEERS` from `prompts/bash-first.json`).
- Re-read how nanocode presents the host tools to the model: since `8ec3b215` the
  Responses kind sends them inside a `functions` namespace, which
  `the_model_facing_tool_list_is_the_pinned_set` flattens and pins
  (`"namespaces": ["functions"]` in `codex_model_tools.json`).
- Re-pin the executor term. `agent_harness` carries `NANOCODE_REV` and the
  vendored engine's digest (`kata_agent_nanocode::harness_identity`), so every bump
  moves the node's term,
  and kata-worker's `the_node_term_is_pinned_and_carries_no_version_string` turns
  red; the recipe does not run it. Confirm that `agent_harness` is the only one of
  the seven properties that moved: no cell does this, so add a throwaway
  `#[cfg(test)]` cell to `crates/worker/src/executor_term.rs` that writes each
  entry of `node_properties()` (name, length, sha256 of the bytes) to a file
  outside the tree, run it at the old pin (Cargo.toml, Cargo.lock,
  `crates/agent-nanocode/src/lib.rs` and the vendored engine restored from the
  base revision, then restored back with `sha256sum -c`) and at the new one, and
  compare the two files outside kata. Only `agent_harness` should differ, and its
  JSON only in `nanocode_rev` and `code_mode_engine_digest` (the re-vendored copy)
  unless upstream moved a tool definition, a limit or the Claude system blocks
  (`claude.instructions.system_blocks`).
  Delete the throwaway cell, then re-pin the literal in a commit of its own after
  the bump. Every capsule reuse key on every node misses once.

Review the diff and commit the bump as one change, followed by the re-pin. Bump
deliberately: now, before each evidence round (which records the nanocode rev), and
before a release.

## The nightly drift report

Between bumps, the L2 nightly reports what a bump to nanocode's `master` would meet
([verification.md](verification.md), "The nanocode drift step"). It runs part of
the recipe against `master`'s head in a scratch copy of the revision outside the
checkout: step 1 (`scripts/nanocode-vendor.py bump`, re-vendoring with the patch),
step 2 (the lock re-resolution), and of step 4 only the `nanocode_seam`,
`nanocode_qualification`, `nanocode_thread_backend` and `code_mode_*` binaries of
kata-agent-nanocode. It does not
run step 3 (`flake-hash`), the vendor check, the package's other binaries (such as
`toolhost_backpressure`) or kata-worker's executor term cell, which every bump turns
red, so a green drift report still leaves the steps after the recipe owed. It changes
nothing in the checkout. It runs `master`'s
unreviewed code on the nightly's host, in a narrowed environment that is not a sandbox
(verification.md states what it does and does not keep from that code). The nightly report's "nanocode drift" section names
`master`'s rev and the revision's pin, whether the patch applies, the lock, build
and test results, and the host tool-set drift. A moved host tool set shows as one
`host tool-set drift:` line per backend, naming the tools nanocode added and the
pinned ones it no longer registers. The step never makes the nightly red: a patch
that no longer applies, or a red cell, is the notice to port the delta or decide how
kata serves a new tool before the next deliberate bump, not a regression on `main`.
