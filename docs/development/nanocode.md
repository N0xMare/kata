# nanocode in kata

kata embeds [nanocode](https://github.com/gakonst/nanocode) as a library
(`crates/agent-nanocode`). nanocode publishes no releases kata can pin, so kata pins
one upstream commit and tracks nanocode's `master` by moving that pin deliberately.

## What kata takes from nanocode

- **Three direct git dependencies** in the workspace `Cargo.toml`:
  `nanocode-backend-codex`, `nanocode-backend-claude` and
  `nanocode-process-contracts`, all at one `rev`. `NANOCODE_REV` in
  `crates/agent-nanocode/src/lib.rs` names the same commit.
  `crates/agent-nanocode/tests/nanocode_seam.rs` refuses a `Cargo.lock` that
  resolves any nanocode package to another commit, and a host tool set that moved.
- **The Anthropic kind's system prompt, less one line.** kata builds the Claude
  agent with its own system blocks (`claude_system_blocks` in
  `crates/agent-nanocode/src/adapter/session.rs`): nanocode's default blocks
  (`nanocode_backend_claude::upstream::system_blocks`) without the Claude Agent SDK
  identity line that opens them (`subscription_wire::IDENTITY`), then the Code Mode
  instructions a code-only agent gets. kata is not the Agent SDK, and an API key's
  credits may refuse a request that says it is: measured on 2026-11-12, that one
  line turns a key's 200 into a 400 `Your credit balance is too low`, as does the
  `claude-code-20250219` beta, which nanocode sends only on its subscription wire.
  The subscription wire puts the identity back after its billing line whatever the
  blocks hold, so a subscription request is unchanged. nanocode exports no handle
  to the Code Mode text, so kata holds a copy,
  `crates/agent-nanocode/src/adapter/claude_code_mode.md` (nanocode's
  `crates/backends/claude/prompts/code_mode.md`). The unit cell
  `claude_system_blocks_are_nanocodes_defaults_less_the_agent_sdk_identity` reads
  both prompts off the wire nanocode serializes and reds when the copy, or the
  identity's place, moves; `nanocode_qualification`'s
  `an_api_key_anthropic_request_carries_no_claude_code_mark` reds on any Claude Code
  mark in the request the mock receives. `harness_identity` folds the blocks.
- **One vendored crate**, `vendor/nanocode-code-mode-engine`: nanocode's
  `crates/runtime/code-mode-engine`, the QuickJS worker that runs Code Mode cells.
  The workspace `[patch."https://github.com/gakonst/nanocode"]` entry builds every
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

## The kata delta: Code Mode resource limits

Upstream's native worker sets no memory, stack or time limit on QuickJS and sends a
cell's output through an unbounded channel. When a context cannot be built or a
cell's execution errors, its thread ends. The cell then fails with "Script failed"
and the engine's "host ended before a result", not the cause, and nanocode's Code
Mode drops that worker and spawns a fresh one for the next cell. The patch adds an
opt-in guard, and it keeps the worker alive so the failed cell carries its own
cause:

- `NativeLimits { memory_bytes, max_stack_bytes, thread_stack_bytes, cell_wall,
  cell_emitted_bytes, live_workers }` and `set_native_limits(..)`. The setter is process-wide
  and once only: the same limits again are accepted, and different ones are
  refused with the installed limits returned. A worker reads the limits when it is
  spawned. A worker spawned with none installed bounds nothing: no memory, stack,
  wall or output limit. The failure handling below (a cell's own `Error`, the
  kept thread, a runtime of its own for every cell) and the job drain's stop on
  an interrupt apply with or without limits.
- `live_workers()` reads the count the `live_workers` limit caps, kept with or
  without limits installed: every worker in the process from its spawn until its
  thread ends, idle ones included, or, for a worker an installed backend started,
  until that backend drops the worker's `LiveWorker`. kata's turn end reads it once
  nanocode's shutdown returns or its grace expires, and records it in the turn's
  evidence (`CodeModeWorkersLive`), so a worker still live after the shutdown is
  counted. Behind kata's backend, which kills and reaps a terminated host's
  interpreter process before it releases the count, a turn's own cells are never
  among them (below); the count is process-wide, so another session's cell inside
  a native step is (`nanocode_qualification.rs`, which runs under kata's limits
  as the worker installs them,
  `a_code_mode_cell_in_a_native_step_past_the_shutdown_is_recorded_live`).
- `set_worker_backend(..)`: the seam kata's interpreter process sits behind
  (`crates/code-mode-host`, below). Once installed (process-wide, once only), every
  `EmbeddedHost::spawn` hands its worker's ends (`WorkerEnds`: the commands the host
  sends, the sender of the events it reads, its startup failure, the signal
  `terminate` awaits, its `LiveWorker`) to the backend instead of starting a worker
  thread. `HostCommand` and `StartExecution` are public for it. Nothing else of the
  engine changes: without a backend, every worker is the thread below.
- `set_cell_ended(..)`: what a native worker calls, on its thread, with a cell's id
  once the cell's terminal event is sent and before it drops the runtime the cell
  ran in (where `Array.fromAsync`'s leak trips `JS_FreeRuntime`'s assertion).
  Without it the worker drops the runtime at once, as before; kata's interpreter
  process installs one that waits until it has written that event to its parent.
- Every cell runs in a QuickJS runtime of its own: the worker builds one, with
  the bootstrap's loader, the rejection tracker, `max_stack_bytes` and its
  interrupt, prepares the cell's context in it, and drops it, with everything the
  cell left in it, when the cell ends; the next cell's runtime is built then. The
  worker thread is kept. `memory_bytes` is set on the runtime only once its
  cell's context is prepared, just before the cell starts, because QuickJS's
  context creation is not safe against the limit (below). A limit below what the
  runtime then holds (its context and bootstrap: about 200 KiB, MEASURED) fails
  every cell on the memory limit (`code_mode_context_failure.rs`).
  `thread_stack_bytes` sizes the worker thread. The
  setter does not check that it exceeds `max_stack_bytes` with headroom: if it
  does not, deep recursion overflows the native stack and aborts the process the
  thread runs in (behind kata's backend, the interpreter process) instead of
  failing the cell. kata's headroom is measured, not assumed (below).
- `cell_wall` is armed when a cell starts and disarmed when it ends, so preparing
  the next context between cells is never charged. Running JavaScript past the
  deadline is interrupted at its next interrupt check, and the job drain stops
  before its next job (below). A cell waiting on a tool result or a timer ends
  there too, and so does a held one (below). One long native step (a built-in
  sort of millions of elements) runs to its end before the interrupt lands.
- `cell_emitted_bytes` caps what one cell emits. Every event a cell causes is
  charged a fixed `CELL_EVENT_BYTES` (256) beside its payload: a notification, a
  yield, a tool call, a content item, and each text event (the `text` that opens
  a buffered run pays the event; one that joins the run pays its separator). So
  a cell sends at most `cell_emitted_bytes / 256` events and at most
  `cell_emitted_bytes` of payload. A tool call's input is not charged: only
  `memory_bytes` bounds it, while the interpreter builds it. The call that
  crosses the cap throws and emits nothing, the cell fails, and an interrupt
  ends JavaScript that catches the throw and carries on
  (`every_event_a_cell_emits_is_charged_and_the_next_cell_runs`: an empty-text,
  a yield, a one-byte-notify and an unanswered-tool-call flood each end at the
  cap). What each event then costs inside nanocode (its channel slot and update
  structures) is nanocode's; the charge bounds how many there are, not that
  cost.
- A limit hit, a context that cannot be built and an execution error each end the
  cell with an `Error` event, which the model reads (a context that cannot be
  built: `code_mode_context_failure.rs`,
  `a_context_that_cannot_be_prepared_fails_each_cell_and_the_worker_answers_the_next`).
  The worker then runs the next cell in a fresh runtime, whatever the cell before
  it did (`code_mode_limits.rs`,
  `every_cell_after_a_heap_hit_runs_with_the_whole_heap` and its child twin
  `heap_hits_end_no_process`; through the adapter,
  `the_cells_after_heap_hits_run_with_half_the_heap_on_both_kinds`), and that
  cell starts with the free heap every cell after the process's first starts
  with, within 64 bytes: all of `memory_bytes` but what its own runtime and
  prepared context hold (`every_cell_after_the_process_first_starts_with_the_same_free_heap`;
  the process's first cell has 5 KiB more, MEASURED). Except where QuickJS
  mishandles the exhausted heap itself (the next bullet). A runtime
  outlives a garbage collection in two ways one cell could otherwise pass on to
  the next, and the job queue below is the third:
  - rquickjs 0.14 keeps, for a runtime's whole life, the prototype of the first
    Rust function made in it (`Opaque::get_or_insert_prototype`, which
    `RustFunction::prototype` fills with that context's `Function.prototype`), a
    counted reference to its context that QuickJS's cycle collector cannot see.
    While one runtime ran every cell, the first cell's context, its globals and
    whatever a later cell stored through the `Function` constructor every later
    cell's native functions inherit (`clearTimeout.__proto__.constructor`)
    stayed allocated: MEASURED, a later cell read the first cell's globals
    through it (`no_cell_reaches_the_globals_of_an_earlier_cell`), and a first
    cell that filled the heap left every later cell an exhausted one.
  - QuickJS 0.16.2 (rquickjs-sys 0.14) creates a context unsafely against the
    memory limit: `JS_NewContextRaw` links the new context into the runtime's
    garbage list (`add_gc_object`) and, when its `class_proto` allocation then
    fails, frees it (`js_free_rt`) without unlinking it (`remove_gc_object`); the
    runtime's next collection walks the freed block and aborts the process
    (`gc_decref`'s `JS_GC_MARK(p) == 0` assertion, or `mark_children`'s `abort`,
    or a SIGSEGV), and a creation that fails deeper leaves its half-built context
    allocated, so the next attempt fails there. rquickjs-sys keeps C assertions
    unless its `disable-assertions` feature is on, which nothing in kata's tree
    enables. MEASURED before this design: after a heap hit in a worker's first
    cell the next cell failed with `failed to create a fresh embedded QuickJS
    context: Allocation failed while creating object`, every later one too
    through the adapter, and at the engine the cell after it aborted the
    process. A lane probe that unlinked the context in a copy of QuickJS ended
    every abort of a context-creation sweep; kata does not patch QuickJS, it
    creates no context under a limit.
- RESIDUAL, contained: QuickJS 0.16.2 mishandles an exhausted heap on paths a
  cell's own code reaches, and there an allocation past `memory_bytes` ends the
  process QuickJS runs in, not the cell. Behind kata's backend that process is the
  cell's interpreter process, never the node (nor the main, which hosts no
  worker). MEASURED (gdb
  on the dead process), each pinned at every headroom of a sweep through the
  interpreter process (`code_mode_out_of_memory_defects.rs`,
  `quickjs_out_of_memory_defects_end_only_the_interpreter_process`):
  - `Function.prototype.bind`: `js_function_bind` frees the bound function whose
    `bf` record it could not allocate, and `js_bound_function_finalizer` reads
    the record through its NULL pointer (SIGSEGV);
  - `eval` compiling a class: the compiler's `resolve_scope_var` faults
    (`resolve_variables` ← `js_create_function` ← `__JS_EvalInternal`; SIGSEGV);
  - `Array.fromAsync`: an allocation failure leaks an object, the cell completes,
    and dropping its runtime trips `JS_FreeRuntime`'s assertion that its last
    collection freed every object (`list_empty(&rt->gc_obj_list)`; SIGABRT). One
    runtime per cell makes every such leak abort as its cell ends; before it,
    this one aborted too, when the runtime was replaced for the job it left
    queued.

  A heap flood a model writes reaches them by chance: through the adapter under
  kata's limits, `const fns = []; for (;;) fns.push(Math.max.bind(null,
  fns.length));` ends its interpreter process on `nanocode_anthropic` (before the
  interpreter left the hosting process it ended that process, 4 of 4 runs), and
  fails on the memory limit on `nanocode_openai`, whose heap layout differs
  (`code_mode_interpreter_through_adapter.rs`). The three are the measured ones,
  not a bound: a sweep of sixty operations, each run at every 32 bytes of
  headroom up to 24 KiB, found them. The engine cannot keep a cell off these
  paths (any allocation may be the one that meets the limit), and kata neither
  patches QuickJS nor disables its assertions: the interpreter process contains
  them instead (below).
- Just before the `Error` of a cell that failed on a limit the guard can tell, the
  worker sends the guard's report of that limit as a `Notify` event of its own:
  `Code Mode cell exceeded its <n> ms wall-time limit`, `Code Mode cell output
  exceeded its <n>-byte limit`, `Code Mode cell exceeded its <n>-byte memory
  limit`, or `Code Mode cell exceeded its <n>-byte interpreter stack limit`. The
  wall and output reports come from the guard's own budget, never from the
  failure's text, so a script that THROWS one is not reported (one that sends one
  with `notify` is a notification like any other, which the adapter reads as a
  report: below). The memory and stack reports of a failure the bootstrap reports
  are read off its first line, which must END with QuickJS's `InternalError: out
  of memory` (an allocation past `memory_bytes`) or `RangeError: Maximum call
  stack size exceeded` (a recursion past `max_stack_bytes`); a script that throws
  an error with that name and message itself reads the same. When QuickJS cannot
  allocate even its own out-of-memory error it throws a bare `null`, and when the
  bootstrap, which needs the heap too, then cannot report the failure, the engine
  sees the cell's run rejected: the guard reads the heap of a cell that failed
  that way (outside the bootstrap's report), and a heap within 64 KiB of
  `memory_bytes` (`EXHAUSTED_HEAP_HEADROOM`; MEASURED: within 4 KiB for every such
  hit, under 16 MiB and 256 MiB; far from it for a run rejected otherwise) names
  the memory limit, as the cell's error and as its report. What the guard cannot
  tell, MEASURED and pinned
  (`only_a_failure_quickjs_names_or_an_exhausted_heap_is_read_as_a_limit`): a hit
  the cell catches and rethrows inside an error of its own (the bootstrap writes
  the `cause` below the first line), and a heap hit QuickJS throws as a bare
  `null` inside a function whose frame releases the heap before the bootstrap
  reports it as `Uncaught null` (or, from an async function nothing awaits,
  `Unhandled promise rejection: null`), which a cell's own `throw null` reads
  the same as, or whose `null` rejects the cell's run before the bootstrap can
  report it, once the heap was released (a flood of rejected promises:
  `embedded QuickJS execution rejected: Exception generated by quickjs:
  Null"null"`). Each fails to the model as that error, without a report. A cell that
  catches either error and ends cleanly is not reported. Without limits nothing
  is reported. The guard sends its report as a notification, not as more of the
  cell's output, because nanocode delivers a notification as an element of its
  own beside the cell's result, which its truncation of the result does not reach
  on the Responses kind (the paragraph on what the model is told, below).
- The job drain stops between two jobs once the worker's interrupt is raised (a
  limit hit, or a `terminate` or a drop of the host). The interrupt ends the job
  that is running, but a job that queues its successor before it spins would
  otherwise keep the drain going for ever: past the wall, and past `terminate`,
  which waits for the thread with no bound of its own
  (`code_mode_limits.rs`,
  `a_self_requeueing_microtask_ends_at_the_wall_and_the_next_cell_runs`, and
  `code_mode_unlimited.rs`, `terminate_ends_a_self_requeueing_microtask`, where
  no wall exists). The jobs it leaves queued go with the runtime (below). This
  stops JavaScript at its next interrupt poll or between jobs; a long native
  step, such as one sort of millions of elements with the default comparator,
  polls no interrupt and runs to its end first.
- No job outlives the cell that queued it. QuickJS queues promise jobs on the
  runtime, not on a context, and a queued job keeps its context alive. A cell
  that fails before its queue is drained (the wall interrupting a timer callback,
  say) would leave a job that the next context's preparation runs, with no wall
  armed and under the failed cell's id. QuickJS has no call that empties the
  queue; the cell's runtime, its queue included, is dropped when the cell ends,
  and after a context that could not be built (`code_mode_limits.rs`,
  `a_failed_cells_queued_job_never_runs_after_it`).

- `live_workers` caps the workers live in the process at once, idle ones
  included; a worker counts from its spawn until its thread ends.
  `EmbeddedHost::spawn` past the cap fails, and nanocode fails the cell that
  needed the worker to the model with that message. Each worker has its own
  runtime under `memory_bytes`, and nanocode spawns a worker for any cell that
  starts while another of the session's cells still runs (a yielded cell runs on
  until its wall), so only this cap bounds how many runtimes, and so how much
  interpreter heap, the process holds: `live_workers` x `memory_bytes`
  (`a_worker_past_the_live_limit_is_refused_until_one_ends`).

**Held time counts against `cell_wall`.** nanocode can hold a running cell
(`EmbeddedHost::hold`, then `release`) to journal it and replay it on another
host. Upstream's engine then blocks the cell's thread until the release, with no
bound of its own. A held cell keeps its thread, its runtime and its memory, and
its timers keep their deadlines: on release, every timer that came due while it
was held fires at once, and a cell replayed elsewhere re-plans each timer from
the wall-clock time it was set. A hold therefore does not stop the cell's clock,
and the guard does not stop the wall: a cell held past its deadline ends there
with the wall error (`code_mode_limits.rs`,
`a_held_cell_ends_at_the_wall_and_the_next_cell_runs`). A cell replayed on
another host is a new start there, under a wall of its own. kata gives nanocode
no cell journals (`Tools::cell_journals`), so nanocode never holds a cell in
kata's process today; the decision governs the engine, not a path kata takes
(`adapter::seam::tests::kata_installs_no_code_mode_cell_journals` turns red on a
tool set that carries them).

What the limits bound is the interpreters, not the hosting process: at most
`live_workers` interpreter processes, each under `memory_bytes` and an address-space
limit. Rust-side copies of a cell's `stored` values and of events already sent are
outside the QuickJS allocator; the session's stored values stay in the hosting
process, and an interpreter holds only the one value a `load` is reading.

## The interpreter process (`crates/code-mode-host`)

`install_code_mode_limits` installs kata's limits through
`kata_code_mode_host::install`, which also installs a backend behind the engine's
worker seam: every Code Mode worker nanocode spawns becomes a supervisor thread in
the process hosting the worker — always a `kata-worker` node, never the main:
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
  frame. The first `load` of a key in a cell costs that round trip (MEASURED,
  release: 48 µs, against 1.1 µs on the engine's thread); the interpreter keeps
  the cell's answers, up to 16 MiB of keys and values, so a key loaded again
  costs what it does on the thread (0.6 µs), and empties them at the next
  `Start`. Each frame is still at most
  `FRAME_CAP`: a cell whose source and tools exceed it fails before it runs; a
  tool result past it fails that tool call in the cell, naming the frame; a cell
  whose stored writes, error or tool-call input exceed it fails naming the frame
  (the interpreter sends that `Error` in the event's place, keeping none of the
  cell's writes), and the next cell runs.
- It confines itself before it answers anything: it closes every descriptor
  above 2, arms a parent-death SIGKILL and checks its parent is the one that
  started it, sets `oom_score_adj` 1000, `RLIMIT_AS` (`memory_bytes` + the
  thread stack + 1 GiB; MEASURED `VmPeak` at a full 256 MiB heap: 467 to 492
  MiB), `RLIMIT_CORE` 0 and not dumpable, and last installs its syscall filter
  (`syscall_filter.rs`, below) on every thread. Its environment is empty (the
  parent clears it). A step that fails ends it before `Ready`, so the cell fails
  naming why: a host whose kernel, or an enclosing seccomp profile, refuses the
  filter runs no cell (`could not confine itself: seccomp(2) refused its syscall
  filter (...)`).
- It runs ONE engine worker (the thread above) per cell: after each terminal
  event it terminates that worker, waiting for its thread to finish, starts the
  next and answers `Ready`. The worker drops the cell's runtime on its own
  thread right after it sends the terminal event, while the interpreter's main
  loop is still writing that event, so the interpreter's `set_cell_ended` hook
  holds that drop until the event is written. So a QuickJS abort in a cell's
  teardown (`Array.fromAsync`) happens after its `Done` reached the supervisor and
  before the supervisor sends the next cell, which then starts a new interpreter;
  it is charged to neither cell. MEASURED without the hook: with the terminal
  frame written 1 ms late, all 338 aborts of the out-of-memory sweep's
  `Array.fromAsync` row took their cell's `Done`; with no delay, 2 runs of 8 lost
  one once the syscall filter (below) had shortened glibc's abort path.
- The supervisor starts an interpreter lazily, when a cell needs one; waits for
  its `Ready` (30 s); and treats everything it sends as untrusted: an event is
  admitted only for the cell it started, and charged as the engine charges it
  (or less: a notification its text, a content item every string in it but its
  `type`, each event `CELL_EVENT_BYTES`); a frame over the cap, an event of no
  running cell, a journal event, a `Held` no `Hold` asked for, output past
  `cell_emitted_bytes` and one guard report, a `Ready` unasked, a `Load` while
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
  (`Code Mode's interpreter process ended by SIGSEGV`, or `... exited with status
  <n>`), recorded by the adapter as `CodeModeInterpreterEnded`, then an `Error`
  naming it (and why kata killed it); a wall kill reports the wall as the engine
  words it (`CodeModeLimit{wall}`). The report names the signal because the
  interpreter is not dumpable, so no core dump holds its reap: MEASURED with a
  probe child on a host whose `core_pattern` pipes to apport, from `abort()` to
  its parent's reap, 0.3 ms not dumpable, and dumpable 1.1 s alone and 9.2 s
  beside 8 other dumps, long enough to outlive a 1 s wall and `WALL_GRACE` and
  be reported as a wall kill; the hostile interpreter `hostile_interpreter`
  tests against is not dumpable for the same reason. An interpreter that ends
  between cells ends no cell and is recorded nowhere. A cell journaled by nanocode is refused (kata
  installs none). `terminate` and a dropped host kill the interpreter and reap it
  before the worker stops counting as live, so a cell inside a native step does
  not outlive its turn's shutdown.
- Its standard error is a socket the supervisor drains on a thread of its own
  (`code-mode-err`), keeping the interpreter's last `STDERR_CAP` (64 KiB) bytes
  and counting what it drops; nothing of it reaches the hosting process's
  standard error or log. A cell the interpreter's end fails, or that could not
  start, carries it in its error after the report (`...; its standard error
  since it started: ...`, or `..., its last 65536 bytes (<n> before them
  dropped): ...`): one interpreter runs its host's cells one after another, so
  what it kept may be an earlier cell's. That is how a QuickJS or glibc
  assertion line reaches the model and the transcript, cut with the rest of the
  result. Ending an interpreter shuts the supervisor's end down once it
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
  `__assert_fail` reads `/proc/self/maps` before QuickJS's assertion line; both
  carry on without them). Everything else, a listed call on other arguments, a
  foreign arch and the x32 range end the interpreter by SIGSYS
  (`SECCOMP_RET_KILL_PROCESS`), so code execution inside it (through a QuickJS
  memory-safety defect) opens, creates and executes nothing, makes no socket,
  process or namespace, and signals, traces and reads no other process, its
  memory or CPU clock: the
  process hosting it survives its `kill` (`tests::a_compromised_interpreter_cannot_kill_its_parent`).
  It is x86-64's: on another target the interpreter refuses before `Ready`.
  MEASURED, release: compiling and installing it takes 141 µs (p99 303 µs), and
  a cell costs 1.135 ms against 1.119 ms with no filter (a new interpreter's
  first cell 4.96 ms against 4.90).
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
`interpreter_process.rs` (cells in one child and no QuickJS thread here; a
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

kata's values are `CODE_MODE_LIMITS` in `crates/agent-nanocode/src/lib.rs`: 256 MiB,
1 MiB, 8 MiB, 300 s, 8 MiB and 8 workers, so the process holds at most 2 GiB of
interpreter heap and 64 MiB of worker thread stack. The worker cap is the
process's, so concurrent attempts share it: one attempt's running cells can leave
another's next cell without a worker until one ends. `install_code_mode_limits` there installs them, and
the worker calls it once at start, when it builds its production adapter registry
(`kata_worker::adapter_registry::production`), before any agent is built. A Code
Mode worker spawned in a process that never called it is unlimited.

Through the adapter, against the mock provider and the toolhost double,
`crates/agent-nanocode/tests/code_mode_through_adapter.rs` runs under kata's own
limits, installed by that installer. A model-written cell that allocates 384 MiB
fails, the next request tells the model "Script failed" with the out-of-memory
error, the model's next cell runs in the same interpreter process, and the turn
completes. The out-of-memory hit reaches the cell as a JavaScript exception, so
that host is kept with or without the kata delta. A cell whose host ended, because the model terminated it, is
followed by a cell that runs on a newly spawned host, in another interpreter
process: nanocode's Code Mode spawns one for the next cell, so an ended host does
not end Code Mode for the turn.
`code_mode_wall_through_adapter.rs` installs kata's limits with a 2 s wall. A
spinning cell fails to the model naming the wall limit, the model's next cell
runs in the same interpreter process, and the turn goes on. A wall hit is the
engine's failed-cell end, not a JavaScript exception, so this is the cell that
proves, through the adapter, that the kata delta keeps the host after a
limit hit. Its second cell spins and yields after 200 ms, as a cell under
kata's 300 s wall and nanocode's 10 s default yield does; the model's `wait` on
it then receives the wall failure. `code_mode_workers_through_adapter.rs` installs kata's limits with a
cap of two workers. The model starts three cells that spin and yield: the third
fails to the model naming the cap, the turn goes on, and while the model then
waits on the first cell the kernel lists exactly the two spinning cells'
interpreter processes. `code_mode_output_through_adapter.rs` runs under kata's own limits: a
cell flooding image content items fails at the 8 MiB output limit, the last text
of its result is the guard's `Code Mode cell output exceeded its 8388608-byte
limit`, the next cell runs in the same interpreter process, and the turn goes on.
`code_mode_interpreter_through_adapter.rs` runs a bind flood between text cells on
both kinds: on `nanocode_anthropic` each flood ends its interpreter by SIGSEGV,
the model is told so, the text cell after it runs and the turn completes, with one
`CodeModeInterpreterEnded{SIGSEGV}` per flood in the evidence. These binaries
install kata's limits through kata's installer, so each carries the interpreter
entry.

What the model is told of a cell is nanocode's VISIBLE output of it. Both
backends keep the result's text items in order up to a 12,000-token budget (the
codex backend counts 4 bytes a token, the claude backend 4 UTF-16 units, each
item rounded up), middle-truncate the item that crosses it, drop the text items
after it and append a count of them (`[omitted <n> text items ...]`, `[<n> more
text blocks omitted]`); image items pass, and the codex backend drops audio
items. The budget counts the result's header (`Script failed`, its wall time and
`Output:`) and its `Script error:` item with the cell's text, and Code Mode
appends that error last, so once the header and the cell's text leave the error
fewer tokens than it holds it is cut past its reason, and once they fill the
budget it is dropped: the cell's result says `Script failed` without the reason.
That holds for a cell whose own text fits the budget: 47,900 bytes of text
(11,975 tokens) and the header leave the error under 20 tokens, which cut it
past QuickJS's `out of memory` on both backends
(`a_cell_text_under_the_budget_still_loses_the_reason_and_on_messages_the_report`).
An output-limit hit by a cell that emits TEXT is always past the budget (under
kata's 8 MiB limit the cell has emitted far more than 12,000 tokens of text
first), and any limit's hit can be. The guard's report (above) closes that gap
where nanocode lets it. nanocode delivers a Code Mode notification differently
on the two backends. The codex backend hands the model each one as an output of
its own for the call, after the result, truncated on its own budget, so the
report reaches the model on the Responses kind unless nanocode compacts the
turn's history before the model's next request: once the history reaches its
auto-compact threshold (90% of the model's context window for the gpt-6 models),
its compaction request rewrites tool outputs from the newest back, the call's
last output, the report, first, to `Output exceeded the available model context
and was truncated` until the history fits 95% of the window, and the model then
reads the compaction's item in place of them. A cell's own outputs can do that
alone: a notification flood inside kata's 8 MiB output limit is ~1.8M tokens
(`on_the_responses_kind_a_compaction_rewrites_the_report_and_the_record_stays`;
the claude backend's compaction is not measured). The claude backend appends
each notification to the same `tool_result` as one more text block, after the
error, which the same truncation drops: on the Messages kind the report reaches
the model only while the header, the cell's text and its error leave it room in
the budget, and whole only while they leave it its own length. Past that a hit
is told to the model as a bare `Script failed` and `[<n> more text blocks
omitted]`: a MEASURED residual, which the claude cells below pin. Read from
nanocode 2ac77424, not measured: no event the vendored engine can send lands
where that truncation keeps it in every result. It keeps non-text items, the
text items within the budget in order (the cell's own text, sent first, fills
it first), and the middle-truncated head and tail of the item that crosses it;
a report sent as cell text would end that item only when nanocode joins it to
the cell's last text, which it does only for an unstreamed text run. Moving the
report out of that result would change nanocode, which kata does not patch (the
2026-10-29 decision).

The record does not depend on what the model is told. On both backends nanocode
emits every notification as a `tool.notification` event, and the adapter records
a guard report's limit off it as `CodeModeLimit` (`wall`, `output`, `memory` or
`stack`; `adapter::events::guard_report`), once per hit: the failed result's own
text is not read for these limits. The adapter reads any notification whose
whole text is a report's, so a cell's own `notify` of one is recorded as a hit
though none happened (progress and evidence, never authority). A hit the guard
cannot tell (above) sends no report and is recorded nowhere. Every tool call's
result is recorded as `ToolResult`, by its id and nanocode's status word, on
both kinds: the adapter reads only those two fields of a `tool.result`, so the
claude backend's `{text}` / `{content_blocks}` result decodes as the codex
backend's tool output does (`adapter::events::ToolResultHead`). The live-worker
cap has no guard to report it (a refused cell never had a worker), so its
refusal, which nanocode appends bare to the `exec` result as the cell's only
text and so always inside the budget, is recorded as `CodeModeLimit{workers}`
off that result (`adapter::events::refused_a_worker`), in either backend's
result shape. A cell that yielded and failed on a limit
while no `wait` observed it is told to no model, but nanocode delivers its report
when it ends the turn's cells, before a completed or cancelled turn's outcome, so
the evidence records it then; a Responses-kind turn that fails with no tool call
in flight detaches its cells instead (read from nanocode, not measured), and a
report they deliver after the outcome reaches no record. The adapter-level cells drive the
real guard and assert the record, so a bump that rewords a report or the
live-worker refusal is red there:

- `code_mode_output_through_adapter.rs`, under kata's limits: a text flood past
  the output limit (its flood reached nanocode as exactly the whole texts the
  limit accepts, read off nanocode's truncation marker), a heap hit after one
  60,000-byte text beside the same allocation after a 600-byte text, and a stack
  hit after the long text; on the Responses kind each report reaches the model
  as an output of its own, on the Messages kind each past-budget report is
  dropped from the result; every hit is recorded once on both. Also: a heap hit
  QuickJS throws as a bare `null` (a small-object flood), told with the guard's
  memory message and report and recorded on both kinds; a heap hit after
  47,900 bytes of text, its error cut on both kinds and its report dropped on
  the Messages kind; and a notification flood whose compaction rewrites the
  report on the Responses kind, recorded all the same.
- `code_mode_wall_through_adapter.rs`: a wall hit after a 70,000-byte text, on
  both kinds, a yielded cell's wall hit, whose report reaches the model with the
  `wait` that observed it, and a yielded cell's wall hit no `wait` observes,
  recorded at the turn's end on both kinds and told to no one.
- `code_mode_workers_through_adapter.rs`: the refusal on both kinds.
- `code_mode_stack_through_adapter.rs`: the stack hit's report and record.

The worker publishes the record with a completed turn's evidence:
`crates/worker/tests/agent_turn_capsule.rs` reads a past-budget heap hit's
`CodeModeLimit{memory}` back off the CAS for each kind, and, for a turn whose
cells flood the heap twice with cells after each flood, the two
`CodeModeLimit{memory}` of a completed capsule whose later cells all ran; a
child of that binary runs the same turn and exits 0
(`a_worker_turn_whose_cells_hit_the_heap_ends_no_process`).

`crates/agent-nanocode/tests/code_mode_limits.rs`
drives the engine directly under small limits. It runs these cells:

- an allocation cell, whose resident high-water mark it reads from
  `/proc/self/status`;
- a spinning cell;
- two waiting cells, one on a timer and one on a promise nothing settles;
- a held cell;
- a microtask that requeues itself;
- a third live worker under a cap of two;
- a failed cell that leaves a job queued;
- three output floods, and four floods of near-empty events;
- a recursion past the stack limit;
- thrown errors that are no limit hit (a guard report's text among them), a
  caught out-of-memory error and a caught stack error, and thrown errors spelled
  as QuickJS's out-of-memory and stack errors, each read for the guard's report;
- a small-object flood whose heap hit QuickJS throws as a bare `null`, reported
  as the memory limit's, and the next cell;
- on one worker, that flood as its first cell, then nine heap floods twice over
  (a `Map`, typed arrays, closures, strings, a promise chain, a flood caught and
  resumed, a flood stored through the `Function` constructor `clearTimeout`
  inherits, a flood followed by a recursion past the stack limit), each
  followed by a trivial cell and a 14 MiB allocation of the 16 MiB heap; on a
  second worker, a first cell keeping 14 MiB in its globals and the same
  allocation after it; and the same in a child process, whose exit status the
  parent reads;
- a cell reading an earlier cell's global through that constructor;
- cells reading the free heap they start with, the first two and one after
  each of those nine floods, twice over;
- failures read as no limit's hit: QuickJS's words inside or below an error's
  first line, a heap and a stack hit rethrown as the `cause` of the cell's own
  error, a heap hit reported as `Uncaught null` or `Unhandled promise
  rejection: null` after its frame released the heap, a `throw null`, a run
  rejected with a bare `null` while the heap is far from its limit, and a flood
  of rejected promises whose run is rejected that way once its heap is released;
- a cell started after an idle wall's worth of time;
- the once-only setter.

`code_mode_context_failure.rs` runs trivial cells in child processes under one
byte and every 2 KiB up to 160 KiB of `memory_bytes`: every child exits 0, each
cell failing on the memory limit; and under a one-byte interpreter stack limit,
in which no context can be prepared: each cell fails with that, and the worker
answers the next. `code_mode_unlimited.rs` checks the behaviour when no limits
are installed, `terminate` on a microtask that requeues itself included.
`code_mode_out_of_memory_defects.rs` pins the residual above under a 4 MiB
heap, behind kata's interpreter process: a cell sweeps the headroom it leaves
before an operation, every 8 bytes up to 16 KiB; sweeping `bind` or the `eval` of
a class ends some cells' interpreter by SIGSEGV, sweeping `Array.fromAsync` ends
some interpreters after their cell's `Done`, and the test process runs on, the
next interpreter's cells starting with the whole heap; the same sweep of an
operation QuickJS handles runs it, fails it on the heap, and ends no interpreter.
Each is its own binary because the setter is process-wide.

`code_mode_stack_through_adapter.rs` measures the thread stack's headroom over
the interpreter's stack limit, through the adapter. Under kata's limits a cell
recurses through `sort`'s comparator (QuickJS's native sort calling the cell
back) until QuickJS throws `RangeError: Maximum call stack size exceeded`,
catches it, then recurses through a host call (each level is `setTimeout`,
whose native delay coercion calls the cell's `valueOf` back) until it throws
again. The model is told that error and the guard's report of the stack limit,
which the evidence records as `CodeModeLimit{stack}`; its next cell runs both
recursions counted in the same interpreter process, and the turn completes. MEASURED depths under kata's
limits: 264 levels through `sort`, 288 through `setTimeout`. The cell re-runs
itself in child processes under shrunk thread stacks. With a thread stack of
exactly `max_stack_bytes` the child dies by SIGABRT, after Rust names the
QuickJS thread as the one that overflowed its stack. A search to the page finds
the smallest thread stack the turn passes on, the need of the wider recursion.
MEASURED on the test build (the vendored engine, rquickjs and QuickJS at the dev
profile's opt-level 2): 1044 KiB, that is `max_stack_bytes` + 20 KiB, with
1040 KiB aborting. Measured one shape at a time, `sort` alone needs 20 KiB over `max_stack_bytes` and
`setTimeout`, plain JavaScript recursion, a `toJSON` recursion, `replace` and
`Proxy` trap callbacks, a `prepareStackTrace` callback, a `text` or `notify` at
every level and a tool call with 120-deep input at every level each need 16 KiB
over it. This is a bound for those shapes, not for every recursion a cell can
write. kata's 8 MiB leaves 7148 KiB over it, and the cell is red if
`thread_stack_bytes` drops below twice the need.

## A turn the provider failed

When nanocode ends a turn nobody asked to stop on its model provider's failure, after
a request left, kata classifies it from nanocode's own typed error, never from whether a
request body left (`kata_agent_nanocode::adapter::session::provider_failed`, nanocode
`2ac77424`):

- **transient** when nanocode's `BackendFailure::retryable` says so: the Messages
  client's `ClaudeError::is_transient` (HTTP 408, 409, 429 and 5xx unless the
  provider sent `x-should-retry: false`; the overloaded, rate-limit, API and timeout
  stream errors; a stream that ended early; a transport failure it calls transient,
  a refused connect among them) and the Responses client's
  `ResponsesError::retry_advice` (the same statuses unless the body names a terminal
  code, a premature close, a transport or timeout failure, an overload, rate-limit or
  server error event). nanocode has already retried it: the Messages client five
  times in all whatever kata asks, the Responses client up to its configured
  attempts.
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
response, a Responses HTTPS response the connection cut mid-body (MEASURED: nanocode
reports a body it could not decode, `error decoding response body`, with no retry
advice) — stays `Ambiguous`, as does every break of the tool-host wire and a provider
failure on a turn kata asked to stop. The outcome
is `TurnOutcome::ProviderFailed`, which also states whether a tool call left the
harness during the turn and what the turn is charged; the worker settles it
(`kata_worker::agent_turn`, and the protected-properties `agent-turn` construct).
`nanocode_qualification`'s `a_provider_refusal_fails_the_turn_with_the_providers_reason`,
`a_websocket_error_event_with_a_4xx_status_is_the_providers_refusal`,
`a_plan_usage_limit_is_refused_on_both_transports_naming_the_quota`,
`a_plan_usage_limit_in_a_response_failed_event_is_refused_naming_the_quota`,
`a_previous_response_not_found_is_transient_on_both_transports`,
`a_transient_failure_past_the_harness_retries_is_classed_transient`,
`a_server_error_the_harness_does_not_retry_stays_ambiguous`,
`a_model_connection_dropped_mid_response_is_ambiguous` and the
`a_refused_*_connect_is_marked_conservatively` cells pin this classification on both
kinds against the mock provider; `agent_change_live`'s
`a_provider_disconnect_mid_response_settles_proven_ambiguous_live` pins the cut's
settlement on a real node (PROVEN AMBIGUOUS, never re-run).

## Bumping nanocode

`just nanocode-bump <rev>` moves kata to another nanocode commit. `<rev>` is a
commit sha, or a branch or tag the remote resolves, such as `master`. It runs these
steps in order and stops at the first failure:

1. `scripts/nanocode-vendor.py bump` rewrites the three direct pins in `Cargo.toml`
   and `NANOCODE_REV`. It then re-derives `vendor/nanocode-code-mode-engine` at the
   new rev and re-applies the patch. If the patch no longer applies, it fails
   loudly with `git apply`'s error and leaves the tree as the pristine upstream
   copy. Port the delta by hand (the old patch file still holds it), run
   `python3 -B scripts/nanocode-vendor.py record`, and re-run the recipe.
2. `cargo metadata` re-resolves the lock. Every nanocode package moves to the new
   rev, along with whatever the new rev needs, and no other entry moves. It does
   not use `cargo update -p`, which also re-picks among duplicate versions of
   unrelated crates.
3. `scripts/nanocode-vendor.py flake-hash` rewrites `flake.nix`'s nanocode
   `outputHashes` entry. The key is the first nanocode git package in the lock,
   and the hash is `nix hash path` over the rev's `git archive`, which is how
   `fetchgit` stores it. For a rev with submodules, or a `.gitattributes`
   attribute that can change archived bytes, it refuses instead and names the
   recompute step: set the entry to `lib.fakeHash`, run `nix build .#kata`, and
   paste the hash it reports as `got:`.
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

- Run `nix build .#kata`, which checks the `outputHashes` entry step 3 wrote, and
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
  - the ChatGPT early-refresh window, five minutes at `2ac77424`
    (`REFRESH_EARLY_MILLIS` in nanocode's
    `crates/backends/codex/client/src/auth/subscription.rs`, `REFRESH_EARLY_SECONDS`
    in `auth/chatgpt.rs`). kata keeps no copy of it
    (`kata_agent_nanocode::credential::load_chatgpt`), but the operator guide's
    `kata_login` paragraph states it; a bump that moves it re-words that sentence.
  - the ChatGPT browser login's callback ports, `localhost:1455` then `1457` at
    `2ac77424` (`CALLBACK_PORTS` in `auth/chatgpt.rs`), and its five-minute wait for
    the callback (`LOGIN_TIMEOUT`, same file). The operator guide's `kata login`
    table, the CHANGELOG, `kata login openai --help` and its browser prompt
    (`bin/kata/src/cli/login.rs`) state both; a bump that moves either re-words them.
- Re-check, at the new rev, the error types the provider-failure classification
  reads (above): `NanocodeError::Response`, `BackendFailure::{retryable, as_any}`,
  `ClaudeError::{Http, is_transient}`, `ResponseError::responses_error` and
  `ResponsesError::{HttpRejected, HandshakeRejected, Api, retry_advice}` (the
  WebSocket `error` event's `status` field among them), and the Messages client's five
  attempts. A variant that moved fails the build; a classification
  that moved reds the cells named above, which are then re-measured, never weakened.
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
- Re-copy the Claude Code Mode instructions when
  `claude_system_blocks_are_nanocodes_defaults_less_the_agent_sdk_identity` is red
  (`crates/backends/claude/prompts/code_mode.md` at the new rev over
  `crates/agent-nanocode/src/adapter/claude_code_mode.md`), and re-read the
  default blocks for a new Claude Code or Agent SDK identity line: the qualification
  cell refuses the two nanocode names at `2ac77424`, not one upstream adds later.
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
