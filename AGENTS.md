# Agents

This file is the working guide for anyone changing kata — human contributors and
coding agents alike. [CONTRIBUTING.md](CONTRIBUTING.md) covers setup and the pull
request flow; this file covers how the code is meant to be changed.

kata is an agentic code-execution workflow engine. A user writes a workflow in
Starlark; kata checks it, lowers it to a content-hashed Rust execution IR, analyses
that IR statically for correctness and optimality, and runs it on kata's own durable
engine. A stage's process — a coding-agent turn or a shell command — runs as a
capsule inside a rootless OCI container on the pinned youki, the one execution engine;
waits, joins and routing resolve in the main, some stages are workspace effects mutating
VCS state through the jj provider, and recovery is replay from a durable transition
chain. The goal is execution that is formally hermetic wherever achievable, and
best-in-class durable-execution discipline everywhere it is not. Four principal surfaces
carry the contract: the Starlark frontend, the `kata` CLI, the API server, the Rust SDK.

## First reading

1. [`docs/architecture/0001-replacement-architecture.md`](docs/architecture/0001-replacement-architecture.md)
   — the accepted architecture and its trust boundaries.
   [`docs/architecture/0002-effect-permits.md`](docs/architecture/0002-effect-permits.md)
   is a proposed ADR (per-effect permits), implemented so far only for the forge export's
   push and pull request (ADR 0003's stage E1); the rest changes nothing until accepted,
   after 0.0.1.
2. [`docs/architecture/protected-properties.md`](docs/architecture/protected-properties.md)
   — the properties the engine preserves and the constructs it ships, each checked
   against the ledger of tests that prove it.
3. [`docs/development/verification.md`](docs/development/verification.md) — the routing
   authority read by `just verify` and the required verification layers.

## Dev

The pinned toolchain is in `rust-toolchain.toml` — the latest stable Rust, by policy;
builds, tests and `lint`'s clippy run on it. Only `fmt` uses the dated nightly named in
`.config/audit-nightly`, through rustup (keep `~/.cargo/bin` first on `PATH`). `nix
develop` provides the rest.

```text
just verify           # L0: route THIS diff to its checks and run them, after EVERY change (`route` = plan only);
                      #   with `cargo nextest run -p kata-eval -E 'binary(gate_exclusion)'` and
                      #   `cargo nextest run --workspace --no-run`, that is L0
just gate             # L1 commit tier: lint beside the test build, the suite beside the doctests;
                      #   no containment capability required
just gate-push        # L1 push tier: host checks first, one release build, footprint/soak on a
                      #   quiet host, then gate-containment. L1 = both tiers
just host-check       # can this host finish L1? seconds, not minutes
just gate-snapshot    # host checks + BOTH L1 tiers in one detached worktree of rev — the checkout
                      #   stays editable; stops after a red stage unless --keep-going
just test-crate <c>   # scoped; also validate-crate <c>, test-one-crate <c> <filter>
just fmt / lint       # dated-nightly rustfmt / clippy -D warnings
just deny             # cargo-deny: `just gate` runs it in the commit tier; run it alone after a
                      #   dependency change
just workflows-check-all     # load-check every shipped pack and workflows/smoke rig
just pgrep-kata / kill-kata  # before every commit and every live smoke
```

`just --list` for the rest. Derive a composite recipe's contents from the justfile — a
prose copy of an executable list drifts every time the list moves.

**Tests.** Never bare `cargo test`: it ignores `.config/nextest.toml` slow-timeouts
(doctests, which nextest cannot run, go through `just test-doc`). A bare nextest
filter matches a test NAME and can silently select zero tests (exit 4) — confirm a
non-zero count. Soak giants live in `just test-soak`, not `just test`.

**Parallel work.** Concurrent changes may each work in their own git worktree, on any
local disk; each worktree builds its own `target/`. Run `just gate-snapshot` from the
main checkout — run inside another worktree it nests a second snapshot worktree with its
own full `target/`. The installed main is a per-user singleton: run at most one gate,
live smoke or installed main per user at a time. On a shared box the protocol in
`scripts/gate-env.sh` serialises them: launch L1 with `just gate-launch <rev>`, run `just
lane-wait` before every build or test in a worktree, and run every live suite under
`flock -o` on the live-suite lock it names. Never delete a worktree or a `target/`
directory that a running gate reads; `just lanes-prune <root>` removes the worktrees whose
every patch is on main and refuses while a gate or the nightly holds the box.
cargo-mutants `--in-place` restores the mutated file from its own snapshot — never edit a
file while its scan is in flight.

## Working agreements

- Do not preserve backwards compatibility. Remove obsolete paths instead of adding
  compatibility layers, fallbacks, or migrations. A *durable* schema change still owes
  its version bump, its refusal of an older data directory (with the new-empty-directory
  recourse), and its crash-window treatment.
- Choose the simplest implementation that fully meets the current architecture;
  avoid speculative abstraction, configuration, and indirection.
- Grow in layers: smallest end-to-end product first, then add capability to one that
  already works. Never trade a working product for unfinished complexity.
- Keep concerns separated; visibility as narrow as possible (`private`, then
  `pub(crate)`, then public). Prefer libraries already in the tree — do not
  reimplement common functionality or add packages without checking what exists.
- Decide architecture for the long term; no stopgap meant to be replaced later.
  Design principles change only by an ADR.
- Optimize for the reader: explicit data flow, small modules, early returns, enums
  for distinct states, typed errors with sources, no hidden control flow. Keep
  parsing and presentation at the product boundary; neutral core types.
- Comments explain non-obvious invariants, not control flow the code already shows,
  and not the history of how the code got here. **A change updates every spec it
  staled, in place** — stacking a new doc on a stale one is the wrong fix; if you cannot
  name which sections your change obsoletes, it is not finished.
- **A check must refuse exactly what it claims to refuse.** A guarantee wider than
  its mechanism is this codebase's costliest recurring defect. State a refusal's
  refused set, and prove it.
- **Assert against something that does not share the code under test.** Every
  composition first run here has been broken under a green suite, because the suite
  asked kata whether kata worked. Read the outcome out of git, the filesystem, the
  database through a second read-only handle, or the remote.
- **Every bug fix needs a regression test, and you must watch it fail first.** Revert
  a falsification from a `cp` backup verified with `sha256sum -c` — never `git
  checkout`, which reverts to HEAD, and HEAD is often not your baseline.
- Cite the SYMBOL, not just the line: a coordinate rots onto different, real,
  correct code, which a re-read confirms instead of catching.
- **Self-verify everything you can.** Report verbatim output for every check your
  host can run, including live end-to-end smokes that spend no model budget. Defer
  only for: large model spend, hardware you lack, external-service mutation, taste.
- No credentials, auth headers, private session data, or unsanitized provider
  fixtures in the tree, logs, or tests; `just evidence-check` refuses them, by
  pattern, in the test fixtures and the committed evidence (`just
  evidence-sanitize` redacts a raw transcript). The workspace denies `unsafe_code`.

## Design principles

- **Starlark is the only authoring surface.** A pack compiles to a content-hashed IR
  frozen at admission and may not name a machine's facts — a branch, a host path. A
  stage authors a workspace VIEW, never a mount; there is no authoring form that carries
  an absolute host path.
- **Four principal surfaces, and two derived ones.** MCP derives from the API; the
  installed skill derives from the CLI. A derived surface may expose a SUBSET of
  its principal and may never advertise what its principal lacks — save MCP's pinned
  workstation-local forms (`author`, `check` of local files, the DSL catalog), which act
  only on the caller's own files through the CLI's code.
- **Hermetic where it can be made formal; durable-execution discipline where it
  cannot.** Effects are named at a boundary, recorded, and idempotent — never
  shelled from inside an agent sandbox.
- **kata inherits the host's answer and refuses when there is none.** Identity,
  trunk, credentials, toolchains: kata never invents one and never guesses. The one
  credential kata holds itself is the embedded harness's login: created only by an
  explicit `kata login`, stored in kata's own owner-only file, refreshed by kata, and
  never shared with or read from another tool; without it the turn refuses and names
  the login command.
- **Four gate layers, each required at its moment.** **L0** — `just verify`,
  `gate_exclusion` and the workspace `--no-run` build — after every change. **L1** —
  `just gate` then `just gate-push` (the release build, footprint, soak, then
  `gate-containment`: containment preconditions, `oci-live-smoke` — every no-spend rootless-OCI
  live binary, the adversarial column and the kata-floor seccomp corpus included — the
  no-budget and recovery-fault live smokes, the repository-barrier live proof, the product
  smokes) — is required before every merge to main, normally as `just gate-snapshot
  rev=<commit>`. **L2** — `just gate-nightly` (the timer-bound live cells, the writer measurement, a freshly fetched
  advisory database, a cold build, the Nix flake's checks, ADR 0003's checked model) —
  is run nightly on main by maintainers; **a red L2 blocks every further push until it
  is triaged**: the red cell fixed, or bisected to the commit that owns it and that
  commit fixed or reverted, and "flake" is not a verdict until its cause is named.
  **L3** — adversarial review with mutation testing, a construct→cell map and a live
  differential — is a maintainer review at every release boundary. A live cell leaves
  L1 for L2 only when it is timer- or load-bound AND a host-free twin pins its logic
  (`NIGHTLY_CELLS` in `bin/kata-eval/tests/gate_exclusion.rs` refuses any other move
  in the forms `docs/development/verification.md` states);
  every containment and adversarial proof stays in L1. Inside containment a capability
  SKIP is a FAILURE — a host that cannot prove containment cannot produce a green.
- **OS-specific behavior targets Linux.** macOS is not supported today; it is
  deferred debt — never an implicit target, and never a reason to delete a macOS
  path.
