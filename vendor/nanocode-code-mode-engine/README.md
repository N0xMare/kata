# Code Mode execution worker

This crate owns the native QuickJS worker used by `nanocode-code-mode`. It has
no MCP, OAuth, HTTP, media-decoding, backend or agent-runtime dependency. Separating
the worker allows it to compile while the Code Mode facade's other dependencies
are still building. Existing Code Mode APIs continue to use this worker.

`EmbeddedHost::spawn` starts one worker thread. `start_cell` evaluates one cell
with its tool definitions and stored JSON values. `read_event` yields tool calls,
content, notifications, explicit yields, completion or script failure.
`send_tool_result` resolves or rejects a nested tool call. `terminate` interrupts
JavaScript and waits for the worker to exit; dropping the host signals shutdown.
Each cell receives a fresh JavaScript context. Code Mode owns cell admission,
tool execution, durable receipts and observation; the worker runs one cell at a
time and uses caller-supplied cell and tool-call identifiers.

`set_native_limits(NativeLimits { .. })` installs resource limits for every
native worker spawned after it, once per process; without it a worker is
unlimited. Each cell runs in a QuickJS runtime of its own, which the worker
builds before the cell (after the cell before it ends) and drops, with
everything the cell left in it, once the cell ends; the worker thread is kept.
The interpreter-stack limit is set when that runtime is built; the memory limit
only once the cell's context is prepared, just before the cell starts, because
QuickJS's context creation is not safe against it (a creation that runs out of
heap partway leaves a freed context in the runtime's garbage list, and the
runtime's next collection aborts the process). `thread_stack_bytes` sizes the
worker thread. `cell_wall` is armed
when a cell starts and disarmed when it ends, so idle context preparation
between cells is not charged; running JavaScript past the deadline is
interrupted at its next interrupt check, and a cell waiting on a tool result or
a timer, or held, ends at it: a hold does not stop the wall. A cell inside one
long native step (a built-in sort of millions of elements) has no interrupt
check to reach: it runs that step to its end, bounded by `memory_bytes`, before
the interrupt lands. `cell_emitted_bytes` caps what one cell emits:
every text, content item, notification, yield and tool call is charged its
payload (a tool call's input excepted) plus `CELL_EVENT_BYTES`, so it bounds the
number of events as well as their bytes. A limit hit, a failed context creation or a
failed execution ends that cell with an `Error` event; the worker keeps running
and the next cell runs in a fresh runtime, under all of `memory_bytes` but what
that runtime and its prepared context hold, whatever the cell before it did: a
runtime outlives a garbage collection in two ways one cell could otherwise pass
on to the next. rquickjs keeps, for a
runtime's life, the prototype of the first Rust function made in it, and so that
cell's context, its globals and whatever a later cell stores through the
`Function` constructor every later cell's native functions inherit; and
QuickJS's job queue belongs to the runtime, and a queued job keeps its context
alive and would run in the next cell's preparation with no wall armed. A memory
limit below what a cell's runtime holds once its context is prepared (about
200 KiB) fails every cell on the memory limit. Not every out-of-memory path in
QuickJS 0.16.2 is safe: an allocation that fails inside `Function.prototype.bind`
or inside `eval` compiling a class ends the process by SIGSEGV, and one inside
`Array.fromAsync` leaks an object, so dropping the cell's runtime trips
`JS_FreeRuntime`'s assertion and aborts the process (MEASURED; not a complete
list). A cell's own code reaches these paths; the worker cannot keep it off
them. Just before the `Error`
of a cell that failed on its wall, output, memory or interpreter stack limit,
the worker sends the guard's report of that limit as a `Notify`: the wall and
output reports come from the cell's budget; the memory and stack reports of a
failure the bootstrap reports, from its first line ending with QuickJS's
`InternalError: out of memory` or `RangeError: Maximum call stack size
exceeded`; and the memory report of a failure the bootstrap cannot report (the
run rejected, as when QuickJS, unable to allocate its own out-of-memory error,
throws a bare `null`), from the heap left within 64 KiB of `memory_bytes`, in
which case the cell's `Error` is that report too. A hit the cell catches and
rethrows inside an error of its own, and a heap hit whose bare `null` the
bootstrap reports (`Uncaught null`, `Unhandled promise rejection: null`), or
that rejects the run before the bootstrap can report it, after the cell's
frames released the heap, are reported as no limit. No job outlives
the cell that queued it: its runtime, job queue included, is dropped when it
ends. `live_workers` caps the workers live in the process at once, idle ones included,
so the process holds at most `live_workers` runtimes under `memory_bytes`;
`spawn` past it fails. `live_workers()` reads that same count, with or without
limits installed: every native worker from its spawn until its thread ends, so a
worker still inside a native step its interrupt cannot reach is counted. Once the
interrupt is raised (a limit hit, `terminate` or
a drop), the job drain
stops between two jobs, so a job that queues its successor before it spins
cannot keep a cell, or `terminate`, running.

`set_worker_backend(backend)` installs, once per process, what starts the worker
of every `EmbeddedHost` spawned after it, in place of a worker thread of this
process: `spawn` hands the backend the worker's ends (`WorkerEnds`: the
`HostCommand`s the host sends, the sender of the events it reads, the startup
failure it names once that channel closes, the signal `terminate` awaits, and the
worker's place in `live_workers()`, held until the backend drops it), and an
`Err` fails the spawn. kata installs one that runs each worker's cells in a
child process (`crates/code-mode-host` in kata's tree); everything above is the
thread that process runs. Without a backend, every worker is that thread.

`set_stored_loader(loader)` installs, once per process, what answers a cell's
`load` of a key the stored values its `start_cell` was given lack; it runs on the
worker's thread, inside the cell's JavaScript, which waits for it. Without it such
a `load` answers `undefined`, as before. kata's interpreter process installs one
that asks its parent for the value, so a cell's stored values cross to it one at
a time, as the cell loads them.

`set_cell_ended(ended)` installs, once per process, what a native worker calls
with a cell's id once the cell's terminal event is sent and before it drops the
runtime the cell ran in, which QuickJS can abort the process doing
(`Array.fromAsync`'s out-of-memory leak trips `JS_FreeRuntime`'s assertion).
Without it the worker drops the runtime at once, as before. kata's interpreter
process installs one that waits until it has written that event to its parent,
so such an abort never takes a cell's terminal event with it.

All native dependencies and worker APIs are gated out on WASM. WASM execution
continues through Code Mode's existing Rust host interface. This crate adds no
JavaScript bindings or wasm-bindgen interface.

The worker and its three bootstrap sources were moved from Code Mode without
behavior changes. Native worker checks exercise nested tool success/rejection,
storage, notifications, yielding, timers, fresh contexts and interruption.
