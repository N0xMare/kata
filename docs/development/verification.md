# Verification

`just verify` routes the current diff and runs the resulting checks. `just route`
prints the same plan without running it. Both refuse an unclassified path. The gate has
four layers (below). Every contributor runs L0 after every change and L1 (`just gate`
then `just gate-push`, which ends in `gate-containment`) before a change is merged;
maintainers also run L2 (`just gate-nightly`) nightly on main and an L3 review at every
release boundary ([Maintainer release discipline](#maintainer-release-discipline)).
Containment capability skips are failures. Never use bare `cargo test`; use the
nextest-backed `just test*` recipes.

The table below is the routing authority parsed by `scripts/dev-loop.py`.

<!-- routing:begin -->
| Change class | Paths | Recipes | Reason |
|---|---|---|---|
| Rust applications | `bin/**` | `check` | Applications can affect workspace integration and packaging; the crate lanes below add `validate-crate` for the changed binary crate and its direct dependents. |
| Rust libraries | `crates/**` | `check` | Library changes require workspace type checking; the crate lanes below add `validate-crate` for the changed crate and its direct dependents, because a library's own tests never compile its consumers. |
| Workflows | `workflows/**` | `workflows-check-all` | Shipped packs and the `workflows/smoke` rigs must compile and preflight. |
| Test inputs | `test/**` | `check` | Shared fixtures and eval tasks feed Rust tests. |
| Build and release | `scripts/**`, `config/youki-pin.toml`, `nix/**`, `flake.nix`, `flake.lock`, `justfile`, `Cargo.toml`, `Cargo.lock`, `.cargo/**`, `.config/**`, `rust-toolchain.toml`, `deny.toml`, `clippy.toml`, `requirements-audit.txt` | `dev-loop-check` | Tooling and workspace topology must remain routable. `nix/**` is here for `config/youki-pin.toml`'s reason — `nix/youki.nix` is the expression the pinned containment binary is realised from, so editing it changes which bytes AppArmor is asked to cover and owes the same re-pin. |
| Youki pin refusals | `config/youki-pin.toml`, `nix/youki.nix` | `youki-pin-cells` | The pin is embedded at build time (`crates/types/src/youki_pin.rs`), so a re-pin changes what its refusal cells assert while touching no file a crate lane routes; this row runs them — the pin parse refusals (kata-types), the rendered-profile golden (kata-worker) and the install refusals (kata's `host_setup`). The commit tier does not re-run them: `just test` runs them and `youki-pin-cells-ran` reads its report. |
| Vendored nanocode engine | `vendor/**` | `nanocode-vendor-check`, `check`, `build-toolhost`, `test-crate code-mode-host`, `test-one-crate kata-worker the_node_term_is_pinned_and_carries_no_version_string`, `test-crate agent-nanocode` | `vendor/nanocode-code-mode-engine` must be exactly nanocode's crate at the pinned rev plus `vendor/nanocode-code-mode-engine.patch` ([nanocode.md](nanocode.md)); `scripts/nanocode-vendor.py check` refuses any other tree, and a change to the pins, the lock or the script reaches it through `dev-loop-check`. The patch changes how Code Mode behaves at run time, and the workspace excludes the copy, so the crate lanes never reach it: `check` type-checks its consumers, `test-crate code-mode-host` runs the cells that drive the engine's worker seam through kata's interpreter process (`interpreter_process`, `hostile_interpreter`, the probe and the residual in its `lib`), and `test-crate agent-nanocode` (after `build-toolhost`, because the suite's `toolhost_backpressure` execs the toolhost this tree builds) runs the cells that drive the engine directly (`code_mode_limits`, `code_mode_context_failure`, `code_mode_unlimited`), behind the interpreter process (`code_mode_out_of_memory_defects`) and through the adapter (`code_mode_through_adapter`, `code_mode_wall_through_adapter`, `code_mode_workers_through_adapter`, `code_mode_stack_through_adapter`, `code_mode_output_through_adapter`, `code_mode_interpreter_through_adapter`, and `nanocode_qualification`'s turn-end cells, which read the engine's live-worker count in the turn's evidence). kata-worker's `adapter_registry` cell reads the same setter back after building the production registry; this row does not reach it, and `the_installer_installs_kata_code_mode_limits` in `code_mode_through_adapter` pins the same setter behaviour. It is also a BUILD-INPUT edge the crate graph cannot see: `crates/agent-nanocode/build.rs` hashes every file of the copy and of the patch file (beside the interpreter host's manifest and `src/`, whose crate lanes reach kata-worker) into `CODE_MODE_ENGINE_DIGEST`, which `harness_identity` folds into kata-worker's executor term, so any byte of either moves the pinned term (`the_node_term_is_pinned_and_carries_no_version_string`), which this row runs by name; `test-crate agent-nanocode` runs `the_engine_digest_is_the_blake3_of_the_engine_as_kata_runs_it`. |
| Tool host source | `bin/kata-toolhost/**`, `crates/toolhost-protocol/**`, `crates/provider-protocol/**` | `build-toolhost`, `test-one-crate kata-worker the_node_term_is_pinned_and_carries_no_version_string`, `test-crate agent-nanocode` | A BUILD-INPUT edge the crate graph cannot see: `crates/toolhost-protocol/build.rs` hashes these three packages' manifests and sources into `TOOLHOST_SOURCE_DIGEST`, which kata-worker's executor term folds, yet nothing depends on `kata-toolhost` and kata-agent-nanocode is two levels from the provider protocol. So any byte of a covered package's `Cargo.toml` or `src/` (its `ROOTS`; not `bin/kata-toolhost/tests/` or `build.rs` itself, which the row still routes) moves the pinned term (`the_node_term_is_pinned_and_carries_no_version_string`) and changes the toolhost the real-toolhost cells exec (`kata-agent-nanocode`'s `toolhost_backpressure`, after `build-toolhost`). The rootless-OCI `toolhost_live` and `nanocode_capsule_live` cells are live and run in the push tier. |
| Executor term inputs the lock resolves | `Cargo.lock` | `test-one-crate kata-worker the_node_term_is_pinned_and_carries_no_version_string` | kata-worker's executor term (`executor_term::node_properties`) folds values that dependencies compute, not only kata's own bytes: the embedded harness's `code_mode_syscall_filter_digest` hashes the interpreter's seccomp filter as compiled from `libc`'s syscall numbers and flags, and its `codex` / `claude` tool definitions are what nanocode's crates build and serialize. So a lockfile-only change (a `libc` bump, a dependency of nanocode moving) can move the pinned term while touching no source a crate lane routes; this row runs the pin cell, so the move reds at L0, not at the next kata-worker suite run. The `Build and release` row still routes the same file to `dev-loop-check`. |
| Nix flake | `flake.nix`, `flake.lock`, `nix/**`, `config/youki-pin.toml` | `flake-checks` | `flake-checks` builds every one of the flake's `checks.x86_64-linux` (kata-build, youki-pin, packaged-layout), and nothing else runs them: the packaged layout's refusals (the capsule init must be static; `ip` declared, not copied), `packages.youki` equalling the pin's `store_path`, and the vendored-dependency hashes (`outputHashes`) the Nix build of the kata package needs. `dev-loop-check` evaluates no Nix. These are the files those checks read beyond the Rust tree. A Rust-only change reaches them nightly, in L2, not here: `flake-checks` is a Nix build of the whole workspace and is in no L1 tier. |
| Checked models | `docs/architecture/models/**`, `scripts/model-check.py`, `flake.lock` | `model-check-0003` | `docs/architecture/models/0003/` is ADR 0003's checked model (plan M0): TLA+ modules and the manifest `checks.toml`, which names every TLC run they owe and the verdict each must reach ([The checked models](#the-checked-models)). The models read no Rust, so only these files can change a verdict: the modules and manifest, the runner, and `flake.lock`, whose nixpkgs pins the `tlaplus` TLC comes from. Its 76 runs at M0 took 2390 s at 16 workers under a load of 100 to 150 (its fifteen ForgeIntent runs, as they stand now, took 90 s together at 8 workers), so it is L2 and in no L1 tier (`NIGHTLY_PROOFS`), and its recipe runs 32 TLC workers by default, past which TLC stopped scaling on the reference host; the commit tier's `dev-loop-check` audits the manifest and self-tests the runner without TLC. |
| Configuration | `config/**`, `.env.example` | `config-check` | Operator configuration must parse. |
| Product documentation | `README.md`, `CHANGELOG.md`, `CLAUDE.md`, `AGENTS.md`, `LICENSE-APACHE`, `LICENSE-MIT`, `NOTICE`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/**` | `dev-loop-check` | Documentation taxonomy and routing references must remain coherent. |
| Protected-property ledger | `docs/architecture/protected-properties.toml`, `docs/architecture/protected-properties.md`, `docs/architecture/0001-replacement-architecture.md`, `docs/architecture/0004-mcp-workstation-local-forms.md` | `test-crate kata-eval` | The ledger, the protected-property list and the `oci-constructs` table are checked against each other and against every cell by `bin/kata-eval/tests/protected_property_ledger.rs`, and ledger citations quote ADR 0001 and ADR 0004 verbatim; an edit to any of the four documents must run it, and the `docs/**` row alone would not. |
| Test timing budgets | `.config/nextest.toml`, `crates/test-macros/**` | `test-crate kata-eval` | Every `#[kata_timeout]` budget must sit below the slow-timeout kill nextest resolves for its test, or the watchdog's named expiry can never precede nextest's anonymous TIMEOUT; `bin/kata-eval/tests/timeout_budgets.rs` resolves each site's kill from this config and the macro's default from its source, so an edit to either must run it. A test file's own budget change reaches it in the commit tier's `just test`. |
| Evidence and fixtures | `docs/evidence/**`, `scripts/evidence-kit/**`, `test/**`, `crates/*/tests/fixtures/**`, `crates/*/tests/goldens/**`, `bin/*/tests/goldens/**` | `evidence-check` | The evidence page, its run records and the evidence kit that wrote them, and every fixture, are committed data, so they must carry no credential, auth header, bearer or OAuth token, cookie value, private session data, email address or unsanitized provider payload; `scripts/evidence-sanitize.py check` refuses each by pattern over exactly these globs (its docstring states every rule, and its self-test plants a sample per rule and holds these globs equal to its scanned set). A fixture spells a fake credential as a placeholder (`<token>`, `$TOKEN`). The same recipe runs `scripts/evidence-page.py check`, which refuses an incomplete or inconsistent run record, a record whose kit manifest (`kit-sha256.txt`) does not pin each file directly under `scripts/evidence-kit/` at its committed bytes, and a page whose rendered sections differ from the records. |
| Repository metadata | `.gitignore` | `dev-loop-check` | Repository policy changes must remain classified. |
<!-- routing:end -->

## The four layers

AGENTS.md states the rule; this is its table. Derive a layer's exact contents from the
justfile; this is the shape.

| Layer | When, and required? | Run | Contents |
|---|---|---|---|
| L0 | after EVERY change | `just verify`; `cargo nextest run -p kata-eval -E 'binary(gate_exclusion)'`; `cargo nextest run --workspace --no-run` | the routed fmt / clippy / crate tests for the diff, the static gate-graph guard, and a workspace test compile |
| L1 | before EVERY push to main | `just gate` then `just gate-push`, normally `just gate-snapshot rev=<commit>` | the commit tier and the push tier below |
| L2 | NIGHTLY on main (maintainers) | `just gate-nightly`, scheduled as `just gate-snapshot <rev> tier=nightly` | the timer-bound live cells and the writer measurement (`NIGHTLY_CELLS`, below), `deny-fresh`, `cold-build`, `flake-checks`, `model-check-0003` |
| L3 | at every release boundary (maintainers) | a process, not a recipe | adversarial review with mutation testing; a construct→cell map (every construct the release added, and the cell that fails without it); a live differential of its behaviour |

The two L1 tiers:

| Tier | Recipe | Steps |
|---|---|---|
| Commit | `just gate` | pgrep-stale, fmt, installed-main-lock (under a held lock) + smoke-harness self-tests, then `_gate-commit-core`: deny; **`_gate-common-preflight` ∥ lint ∥ derive-refusal-probe ∥ test-build**; **test ∥ test-doc**; source-tree-unchanged; agent-accept, test-conformance, youki-pin-cells-ran (each reads `test`'s JUnit report); then source-tree-unchanged, pgrep-stale |
| Push | `just gate-push` | pgrep-stale, `_containment-preconditions` (the host, first); `_gate-push-core`: **build**, quiet-box-wait, footprint-check, test-soak; quiet-box-wait; `gate-containment` (preconditions, oci-live-smoke — every no-spend rootless-OCI live binary including the adversarial column and the kata-floor seccomp corpus, smoke-no-budget, recovery-disk-full-live (its bounded-tmpfs child runs under the pinned youki), recovery-publication-fault-live, repository-barrier-live, product-cli-smoke, smoke-no-budget-factory); source-tree-unchanged |

`just gate-nightly` (L2) runs under the installed-main lock: pgrep-stale,
`_containment-preconditions`, test-build, build — then, KEEPING GOING past a red step
and recording each one's status — deny-fresh, quiet-box-wait, test-measurement,
quiet-box-wait, nightly-oci-live, recovery-checkpoint-live,
pgrep-kata, cold-build, flake-checks, model-check-0003, source-tree-unchanged, pgrep-stale. It exits red if any recorded
step was red and names them. Each nextest step's JUnit report is kept as
`target/gate-nightly/junit/<step>.xml`; the `tier=nightly` snapshot copies them to
`target/gate-snapshot/<rev>/nightly.junit/` beside `nightly.rc`, `nightly.seconds`,
`nightly.log`, `nightly.timing.txt`, `nightly.summary.txt` and the host stage's
`nightly.host.*`, and points `target/gate-snapshot/last-nightly` at the directory.

### What each layer guarantees, and what it does not

| Layer | A green GUARANTEES | A green does NOT guarantee |
|---|---|---|
| L0 | the diff's own crates and their direct dependents format, lint and pass their tests; the workspace's tests compile; the gate graph still routes every live test | anything in a crate the routing did not reach; any live or host property |
| L1 | no regression of any property the suite or a push-tier cell pins; the release artifact builds and fits its footprint floors; THIS host still contains a stage — the adversarial column inside a real rootless container, the kata-floor seccomp corpus, the delegated-scope preconditions — with a capability skip counted as a failure | design correctness (a pinned property can be the wrong property); the timer-bound behaviours L2 runs (only their host-free twins ran); advisories published since the host last fetched; that a clean build from nothing succeeds; that the flake's checks build; that ADR 0003's checked model still checks (only its manifest audit ran); timing under load |
| L2 | the real-timer cells hold on real clocks and real processes; the writer measurement pass completes; no advisory in today's database; the shipped build succeeds from an empty target dir; the flake's checks build (the Nix package, the youki pin, the packaged layout with its static capsule init); every TLC run of ADR 0003's checked model reaches the verdict its manifest expects | anything about a commit pushed after the revision it ran on; containment on a host it did not run on; that a checked model is faithful to the code it models, or holds beyond its bounds |
| L3 | the release's constructs are each held by a cell that fails without them, and its behaviour matches a live differential | anything beyond the constructs it reviewed |

### Which live cells run in L2

A live cell leaves the push tier for L2 only if it is (a) bound by a real timer or by
host load, (b) about 10 s or more, or a known false-red source, and (c) its logic is
ALSO pinned by a host-free twin that `just test` runs on every commit. Every containment
and adversarial proof stays in L1. `NIGHTLY_CELLS` in
`bin/kata-eval/tests/gate_exclusion.rs` names each L2 cell with its twins and refuses a
twin that is missing, `#[ignore]`d, outside the default suite, or in a file that can
capability-skip; `the_nightly_cells_leave_the_push_tier_for_exactly_the_nightly_tier`
holds every L1 `not test(=NAME)` subtraction equal to the L2 `test(=NAME)` selections.
A composed claim whose pieces only the twins pin — the recovery checkpoint cells'
restore, resume and timer-fires-once — is proved whole only live, so its
restart-and-successor-once half stays pinned per push by an L1 cell.

`every_gate_filter_negates_only_in_a_form_this_file_reads` holds a gate's nextest runs
to one written form, so that no negation and no skip takes a live cell out unread. It
parses no shell. In every recipe reachable from `gate`, `gate-push` or `gate-nightly` it
judges each body line as text. A linewise recipe's lines are joined as Just (1.59.0)
joins them: on any trailing `\`, an even run of them included, with the continuation's
leading blanks removed. A script recipe's lines are joined as its shell would, on an odd
run of `\` only.

- **A recipe whose body holds `nextest`, in any letter case, holds nothing but canonical
  runs,** or the test fails naming the recipe and the body line. It is linewise (a `#!`
  line is not a canonical run), takes no parameter and carries no attribute; a lock
  re-exec, a sourced temporary directory, a message or an exit status belongs to a
  recipe that calls it by `just NAME`. So a leaf that holds a gate's run (`_test-run`,
  `_smoke-no-budget-run`, `_nightly-oci-live-run`, `_recovery-*-live-run`,
  `_oci-live-smoke-*`) runs without its caller's installed-main lock, `build` dependency
  and test tmpfs when invoked directly. A canonical run is an optional prefix — any of
  `KATA_LIVE_SMOKE=1`, `KATA_SANDBOX_REQUIRE_LIVE=1`, or `env -u NAME…` with each NAME
  one of `KATA_TEST_PUBLICATION_FAULT_MODE`, `KATA_TEST_PUBLICATION_FAULT_ROOT`,
  `KATA_E3_AGENT`, `KATA_E3_FUNDED` and `KATA_E3_FORGE_CLONE` — then `cargo nextest
  run`, then, each at most once: `--workspace`, `--test-threads=1` (or `--test-threads
  1`), `-P live-smoke|measurement|soak`, `--run-ignored all|ignored-only|only`,
  `--success-output final|immediate`, and `-E 'FILTER'` with the filter in single
  quotes. The one other canonical run is exactly `cargo nextest run --workspace
  --no-run`. Nothing else may stand on the line, so it has no place for a libtest
  `--skip`, a `--`, a positional name filter, `-p`, `--exact`, `--partition`, another
  filter flag, `--no-run` on any other run, a second command, a redirection, a Just
  interpolation, or a `$` or a quote outside the filter.
- **In every other body, a `cargo` whose next word is not plain is refused,** since the
  shell or Just could make that word `nextest`. Any `'`, `"`, `}` and `)` directly
  after the `cargo` are passed over. If a blank follows, the next word is refused when
  it begins `-` (a cargo option, which can define an alias) or holds — a final `'` or
  `"` aside — a quote, `\`, `$`, a backquote, `{`, `*`, `?`, `[`, `(`, `<`, `>` or a
  Just interpolation; a `+TOOLCHAIN` word may come first and may hold a Just
  interpolation, nothing else of those. If anything but a blank follows, the `cargo`
  is refused when the text up to the next blank holds one of those characters
  (`cargo$x`, `cargo>log`), and otherwise not judged (`cargo-deny`, `cargo;`). A
  `cargo` directly after a letter, a digit, `_` or `.` is part of another name
  (`.cargo/`) and is not judged.
- **`nextest` written outside the text of a body line is refused** in any justfile
  variable and any setting `just --dump` reports as JSON (it leaves out
  `script-interpreter`, and an `unexport`), and in a reachable recipe's parameter (its
  name or its default), dependency argument, attribute, or body interpolation
  (`{{ "…" }}`, which the line rules see only as an interpolation).
- **In a canonical run's filter, every negation the readers do not model is refused** (a
  regex, glob or `~` matcher, a negated parenthesised group — `not (test(NAME))`
  included — or non-`test` predicate, `-`, `none()`), each `not test(NAME)` /
  `!test(NAME)` is held to the model-budget roster, and each `not test(=NAME)` to
  `NIGHTLY_CELLS`. A filter's positive structure — which binaries an inclusion pairs
  with — is not judged.

Two texts are judged by none of these rules: `target/nextest/` and `pgrep -x 'NAME'`.
The check guards against an edit that takes a live cell out of a gate by accident, not
against a justfile written to hide one, so it does not refuse a recipe that never writes
the word and builds the command at run time, wherever the `cargo` rule does not refuse
it: through a command word the shell builds (`"$c" nex""test`, `$c $s run`,
`"${argv[@]}"`), a string it runs or a program joins (`bash <<< "$line"`, `printf '%s'
'cargo nex' 'test run' | sh`), a program handed a bare `cargo` (`… | xargs cargo`), or
the word read from the environment, a file or a command's output; nor a string Just
builds (`"nex" + "test"`, `read(…)`), or what a script or program a recipe runs does
itself. `read_gates` follows every `just NAME` a reachable recipe writes, whether or not
the shell would reach it, so a leaf's runs are read as reached even when the call is
conditional — after an `exit 0`, inside `if false; then … fi`, or followed by `|| true`
— and that is not refused. Whether the shell finds cargo behind a canonical line's
`cargo` (a shell alias or function of that name, `hash -p`, `PATH`) is not judged. It
does not see a cargo alias outside the repository's root `.cargo/config.toml` and the
justfile's own text (`the_repository_defines_no_cargo_alias` refuses `alias` in the
first and `CARGO_ALIAS_` in the second), one a recipe exports under a name it builds at
run time, a `NEXTEST_*` variable the host's environment or `.env` sets or a recipe
builds the name of, or a nextest profile's `default-filter`; which `--run-ignored` mode a
step needs is `every_live_step_runs_each_binary_in_the_mode_its_cells_need`'s to judge;
and it does not check that a twin pins the moved cell's logic.

`∥` is a Just `[parallel]` group: its members start together, and the group fails
after all of them finish if any failed. Only steps that neither boot the per-uid
installed main nor assert wall-clock time may overlap —
`the_parallel_groups_overlap_only_what_cannot_contend` in
`bin/kata-eval/tests/gate_exclusion.rs` refuses a group that reaches footprint, soak,
measurement, `quiet-box-wait`, containment or the installed-main lock. `lint` builds in
`target/lint` so it never waits on the test build's lock.

ONE BUILD OF EACH KIND PER GATE. Every nextest step runs from the ONE workspace test build and selects with
`-E 'package(...) & ...'` instead of a `-p` list (each `-p` list was its own
feature-unified build — `every_gate_nextest_invocation_reuses_the_workspace_test_build`);
`footprint-check` and `smoke-no-budget` share the one `cargo build --workspace --release`,
which is the shipped artifact's build (`one_release_build_serves_both_tiers_and_it_is_the_shipped_one`);
`agent-accept`, `test-conformance` and `youki-pin-cells-ran` check `test`'s JUnit report
(`scripts/check-junit-ran.py`) that every test they select RAN AND PASSED, instead of
re-running tests `test` had just run. The shared preflight compiles nothing
(`the_preflight_compiles_nothing_and_overlaps_the_build_group`), so it runs inside the
build group, and a `just verify` that routes only to `dev-loop-check` builds no Rust.
`build-debug` IS the workspace bins build (`_workspace-bins`), and no tier builds a `-p`
variant of a host binary (`every_tier_builds_its_debug_binaries_with_the_workspace`):
`oci-live-smoke` takes the provider, its hook and `kata` (the kata-floor probe instrument)
from that build and builds only the static `kata-toolhost` (the subject of `toolhost_live`,
`nanocode_capsule_live`, `code_mode_host_live` and `nanocode_interruption_live`, built for
`x86_64-unknown-linux-musl`), so a run measures THIS tree's binaries.
Each of its steps runs a binary whose live cells are `#[ignore]`d with
`--run-ignored only` — the host-free cells ran in `test` — and only the
capability-conditional `sandbox_seccomp_tests` with `all`
(`every_live_step_runs_each_binary_in_the_mode_its_cells_need`).
L1 realises no Nix package of kata, and every `nix build`/`shell`/`run`/`eval`/
`path-info`/`develop`/`profile` it runs resolves `nixpkgs#…` only against `flake.lock`;
it runs no `nix-shell` or `nix-build`, which read `<nixpkgs>` from `NIX_PATH`
(`l1_builds_no_nix_kata_and_resolves_no_floating_channel`): the factory preflight smoke's
in-capsule `kata` is this tree's static musl build (a musl C compiler on the host,
`_containment-preconditions`), its in-capsule cargo and rustc are the flake's
`rust-toolchain` (the `rust-toolchain.toml` pin), and the flake package is built by L2's
`flake-checks`.
The `kata` and `kata-worker` its live cells spawn are the ones its nextest steps
rebuild in the workspace test build, which carries kata-worker's `test-support` model
door: `code_mode_host_live` and `nanocode_interruption_live` point nanocode's model client
at their mocks through `KATA_TEST_NANOCODE_ANTHROPIC_URL` or `KATA_TEST_NANOCODE_OPENAI_URL`,
and each of their cells first reads the door's line in the hosting process's log (a shipped
build has no such door).

Every tier ends with `just source-tree-unchanged` (the commit tier also right after the
suite): `scripts/source-tree-guard.py` refuses a run that changed any git-visible path
relative to the baseline the tier took at start, and any nested git repository in the
checkout. It cannot see writes to ignored paths or files created and removed within the
run. `quiet-box-wait` waits up to 10 minutes for the 1-minute load average to fall below
a quarter of the core count before the timing-sensitive steps, and proceeds with a
warning if it never does; it cannot fail a tier.

Every required tier (and `gate-nightly`) prints `[timing] <step> <seconds>s rc=<status>` after every step
(`|| <step>` for a parallel group's members, which are not summed) and a per-step
table at the end (`scripts/gate-timing.sh`, sourced into the recipes so the static call
graph in `bin/kata-eval/tests/gate_exclusion.rs` still sees each step's `just <recipe>`
at command position). `just gate-snapshot` runs `pgrep-stale` + `host-check`, then BOTH
tiers, in ONE detached worktree of a revision (`.worktrees/gate-snapshot`, gitignored)
with a persistent target dir, so gating
never freezes the checkout and the push tier starts on the commit tier's build. It refuses a worktree that is not a pristine checkout of the revision. The tiers
run sequentially there because the installed main is a per-uid singleton,
`gate-containment` holds the installed-main lock for its whole duration, `pgrep-stale`
cannot be scoped to one worktree, and the soak pass asserts timing that sibling load invalidates. A red
host skips both tiers and a red commit tier skips the push tier (push needs both green);
`just gate-snapshot <rev> --keep-going` runs every stage anyway. `just gate-snapshot
<rev> tier=nightly` runs the host checks and L2 in the same worktree instead (its files
are `nightly.*`, so it never overwrites the revision's L1 verdict). `just
gate-snapshot-status [tier=nightly]` prints the last summary. Neither form replaces the
layers it runs — it is the same recipes, run somewhere else. A worktree already at the
revision is not checked out again (a forced checkout rewrites `.git/index`, which
`bin/kata/build.rs` watches, and recompiled `kata` in three profiles at a revision L1 had
built), and every git read there passes `--no-optional-locks`.

**One box, three kinds of work.** A gate, the nightly and lanes (changes in progress in
their own worktrees) share one host, and one protocol (`scripts/gate-env.sh`, keyed on
the main checkout) serialises them, with no clock window: `just gate-launch <rev>`
(detached in the caller's session, on the unattended PATH; its printed waiter ends on the
rc or on a session with no process left) waits out a nightly, holds the `QUIET_BOX`
flag, takes the live-suite lock and drains the lanes' builds before the snapshot; the
nightly holds its `NIGHTLY` mark from its start and waits, bounded, for the box
(below); a lane runs `just lane-wait` before every build or test, and every live suite
under `flock -o -w 7200 <runtime dir>/live-suite.lock`. `lane-wait` does not wait on the
per-user installed-main singleton (`/tmp/kata-installed-main-<uid>/discovery.lock`) — a
live suite's `kata serve` holds it for that suite's whole run — but names, by pid, a
process holding it when it returns: until that process exits, a suite cell that boots an
installed main fails "already owns per-user discovery" whatever the lane changed, and is
re-run under the live-suite lock once it has. A reboot empties `/run/user`, so
every entry point that sources `scripts/gate-env.sh` (`lane-wait`, `gate-launch`,
`lanes-prune`, the nightly, `just nightly-install`) creates the runtime dir at 0700 when it
is absent, and refuses one that is not a directory this uid owns at 0700, leaving it as it
is; taking a flag ensures it again, so nothing else creates it. A runtime dir an earlier
`gate-launch` made at the umask's mode (0755 or 0775) is refused by every entry point,
the unattended nightly included, until its owner runs `chmod 700` on it once (or removes
it while nothing holds a flag or the lock in it). No self-test touches the user's runtime
dir: each points `KATA_RUNTIME_DIR` at its own scratch directory before sourcing, and
`dev-loop-check` runs the four under an `XDG_RUNTIME_DIR` whose parent cannot exist, so
one that touched or needed the host's would red.
`just lanes-prune <root> --dry-run` names each lane worktree landed (by patch identity),
unlanded, dirty, in use or locked; without `--dry-run` it removes the landed ones. A lane
replayed with a conflict or onto changed context reads unlanded (its patch ids differ on
main): remove it by hand once a `git range-diff` shows nothing missing.

`just fmt` runs for every route.

**The toolchain the recipes need.** Builds, tests and clippy (`just lint`,
`lint-crate`) run on the stable `rust-toolchain.toml` pins — the latest stable Rust, by
policy, and the workspace `rust-version`. Every recipe that runs `cargo +{{audit_nightly}}`
— `just fmt` and `fmt-fix`; `grep -n 'cargo +' justfile` lists the current set — uses the
dated nightly `.config/audit-nightly` names, and a `+toolchain` argument is a
rustup-proxy feature: those recipes need rustup with that nightly (rustfmt component).
`nix develop` supplies the pinned stable and that nightly, ruff at
`requirements-audit.txt`'s pin, but its `cargo` is the plain pinned stable, which
refuses `+nightly-…` (`error: no such command`), so inside it put rustup's `~/.cargo/bin`
first on PATH for those recipes. `just host-check` names the remaining host tools.

**The disk the gate writes.** `just host-check` refuses (tree verdict BLOCKED, exit 1)
when the filesystem holding the checkout's `target/`, `$TMPDIR` (the inherited one: smoke
data dirs and the soak, measurement and live rigs' tempdirs; the suite's are on the test
tmpfs, below) or `$HOME` reports `df` Use% of 80 or more, or cannot be read, and names
the mount with a free-space recourse. The
cause it names: every authoritative SQLite plane commits at `synchronous=FULL`, the
commit's fsync runs while the write lock is held, and a waiting writer gives up after the
workspace 5 s `busy_timeout` (`BUSY_TIMEOUT_MS`). The root QLC NVMe at 88% full stalled
those flushes past 5 s and the gate went red on rotating TIMEOUTs and `database is
locked`; the same disk at 40% flushes at p99 1.3 ms. The persistent target dirs are
bounded by age, not by a number: after every snapshot (`scripts/gate-snapshot.sh`) and
nightly run (`scripts/nightly.sh`, its own worktree) `scripts/prune-target.sh` deletes every
artifact no build has read in 3 days (snapshot) or 7 (nightly) — where `cargo-sweep` is on
PATH (`nix develop` carries it) and the target is not on a `noatime` mount; otherwise the
prune line says SKIPPED and nothing bounds the dir. The snapshot's `summary.txt` records
that line, the target's size and its `target/debug/deps` entry count before and after, so
the headroom 80 leaves is read off the summary.

**Test TMPDIR.** `just test`, `test-crate`, `test-one-crate`, `test-one` and
`youki-pin-cells` (so `validate-crate` and with it every crate lane of `just verify`,
`gate-scoped`, the commit tier's test step, and `just verify`'s youki-pin row) source
`scripts/test-tmpfs.sh` ahead of their `cargo nextest run`; gate_exclusion's
`the_suite_recipes_source_the_test_tmpfs_before_nextest` refuses any of the five without
that top-level line before its first nextest run. The run's `TMPDIR` is a fresh 0700
directory, `<root>/kata-test-<uid>/<pid>.<starttime>`, on a tmpfs: `root` is
`$XDG_RUNTIME_DIR` (logind's per-user tmpfs), or `KATA_TEST_TMPFS`. The recipe removes it
when it ends — after the suite has stopped, a TERM to the recipe's shell included — and
removes any earlier run's directory whose shell is gone. It REFUSES (exit 1, naming the
recourse: a tmpfs directory this uid owns at 0700) when neither variable is set; the root
is not a plain absolute path, not a directory or not `tmpfs`; the tmpfs has less than 2048
MiB available; the root or an ancestor is a symlink; the root is not this uid's or group
or other can write it; an ancestor is neither root's nor this uid's without group/other
write, nor root's sticky `/tmp` or `/var/tmp` (kata's owner-only publication rule for an
existing ancestor, so `/dev/shm` is refused here as kata refuses it); or the per-user
parent is a symlink or is not this uid's at 0700. It never falls back to a disk. `just
host-check` runs the same check, writing nothing (tree verdict BLOCKED), and so does
`test` before its build; `dev-loop-check` runs the script's `--self-test`, which watches
each refusal fire, through the sourced form too. A TERM sent to the recipe's shell (or the
`just` pid) alone waits for the suite to end before the directory goes; a signal to the
process group stops the suite. WHY: every test tempdir reads `TMPDIR`
(`tempfile::tempdir()`, `std::env::temp_dir()`), and the suite's cells commit SQLite at
`synchronous=FULL` inside them. On 2026-11-11 an L1 went red on a cell that runs in 2 s
alone: the QLC NVMe holding `/tmp` and `target/` had exhausted its SLC cache under a full
relink (160 MB/s at 100% util, w_await ~250 ms), and the per-crate test-time sums of the
crates that commit SQLite rose 7-21x while the CPU-only crates stayed at 0.7-1.2x.
Measured on the reference host (the same tree, a lane's `target/` on the same QLC model,
other lanes sharing the box), with a `dd` loop rewriting a 20 GiB file on the `target/`
disk (99-100% util; w_await ~215 ms read during the tmpfs arm — the disk arm's reading is
lost to a wrapped `/proc/diskstats` counter): TMPDIR on that disk ran the suite in 1057 s
with 274 slow and 1 TIMEOUT (154 s and 35 slow without the loop; test-time sums kata-api
250→2865 s, kata-workflow 1054→3573 s, kata 320→1991 s, kata-vcs 626→1869 s, the CPU-only
crates unchanged), and TMPDIR on the runtime tmpfs ran it in 122 s with 18 slow and none
red (121 s and 18 slow without the loop). Under the loop the tmpfs run's test-time sums
still rose (1.9x in all, kata-api 4.1x, kata-workflow 2.9x) with the box's load average at
225 against 73: the wall clock and the slow count no longer move with the disk, but what
still slows the cells under such load (CPU contention, the writer evicting test binaries
from the page cache) is not attributed. WHY NOT `/dev/shm`: kata's owner-only publication
refuses a root-owned 1777 ancestor other than `/tmp` and `/var/tmp`, and 78 `kata` cells
fail on that refusal under it — the product's refusal, and right. WHAT THE MOVE DROPPED:
with `TMPDIR` on `/tmp`, `kata` cells walked root's sticky `/tmp`, and so were the commit
tier's proof that kata ACCEPTS it as an anchor (with `/tmp` dropped from
`is_trusted_root_sticky_temporary`, 78 of them fail there); `$XDG_RUNTIME_DIR`'s ancestors
are root's without group/other write, so on it none walks a sticky anchor. The installed main's
coordination directory is `/tmp/kata-installed-main-<uid>`
(`owner_coordination_directory_for_uid`), so a kata that refused `/tmp` would refuse every
Linux installed main. `owner_only_publication`'s
`root_sticky_tmp_and_var_tmp_bind_as_anchors` replaces that coverage: it reads no
`TMPDIR`, binds a fresh 0700 directory under the real `/tmp` and `/var/tmp`, and creates
an owner-only one beneath each. With `/tmp` dropped from
`is_trusted_root_sticky_temporary`, it reds (and `just test` on the tmpfs stayed green,
5837 passed, before it existed); with `/var/tmp` dropped, it reds too. THE SIZE BOUND is the
tmpfs's own (logind: `RuntimeDirectorySize`, 10% of RAM by default); no per-run cap is
enforced. A `just test` run's measured peak is 0.6-1.0 GB (0.2 s samples of the tmpfs's
used bytes, over four runs), so the 2048 MiB floor is about twice the largest and leaves
the session's own sockets and locks room in the same directory. A run also leaves 170-310
MB of tempdirs its tests never remove; the recipe's removal is what keeps a RAM-backed
root from filling run after run.

What stays on disk, and why. A cell whose claim IS the disk names its directory instead of
reading `TMPDIR`: `operational_write_measurement` takes `CARGO_TARGET_TMPDIR`, because its
number is the disk's write latency (L2, `test-measurement`). `recovery-disk-full-live`
claims a real filesystem's ENOSPC and makes its own `size=`-bounded tmpfs per label for
it, so it needs no disk. `htree-preflight` reads `target/`, whose ext4 directory index is
its subject. Inside the parallel suite, kata-worker's
`a_wide_guest_directory_is_removed_in_time_linear_in_its_entries` plants 60 000 directories
under `CARGO_TARGET_TMPDIR` and refuses a tmpfs there: a removal that re-reads a listing
from its start is quadratic only where emptied directory blocks stay (ext4), and linear on a
tmpfs, so only there can the cell catch that regression. Its bound is the removal thread's on-CPU time, and nextest serializes it in
`heavy-io`. Every other recipe that runs tests keeps the inherited `TMPDIR`. Among them:
`test-doc` (the commit tier's doctests, which rustdoc compiles and runs from there);
`test-soak`, `test-measurement` and the live rigs (`oci-live-smoke`, `recovery-*-live`,
`live-nanocode`, `e3-crash-matrix`) run one test at a time after `quiet-box-wait`, outside
the parallel suite the stall starved; `smoke-no-budget`, `jj-parallel-smoke` and
`nightly-oci-live` are live smokes outside that suite too; and `eval`, `nanocode-bump`,
`bench-crate`, `flake-check` and `coverage` are by-hand or scoped enablers. Whether their
cells hold on the runtime tmpfs is not measured. The suite's own durability cells are
indifferent to the backing store, which is why they move with it: their claims are
syscall-level (`backup_durability_tests` injects fsync errors under `strace`;
`repository_durability`'s barrier cell, `just repository-barrier-live`, orders the
repository's `syncfs` against the writes and publications around it and injects its
failure), connection
posture (`synchronous=FULL` per connection, `ledger_cross_file_power_loss_tests`), or
process death (`operational_crash_matrix` kills a child at named commit boundaries, and a
dead process's page cache survives it on tmpfs and ext4 alike). `repository_durability`'s
and `boot_recovery_after_teardown`'s torn-repository cells write the state a power loss
leaves (zero-length loose objects and refs) with plain file I/O and read recovery's answer.
None claims a device's power-loss behaviour, and the headers of `operational_blob_fsync.rs` and
`ledger_cross_file_power_loss_tests.rs` disclaim it.

## The crate lanes

A path under `crates/**` or `bin/**` carries two independent answers and gets both:
the row's `check` (a library change can break workspace integration), AND the crate
lanes the workspace crate graph derives — a row never shadows the crate fallback, so a
library change gets clippy and its tests, not only a type-check.

The derived set is each CHANGED crate plus ONE level of reverse dependencies,
deduplicated and emitted in dependency order as `just validate-crate <crate>`
(`fmt`, `lint-crate`, `test-crate`). Dev-dependency edges count: a `kata-test-utils`
change is how a worker TEST changes. One level, not the transitive closure — a
changed crate's own tests do not compile its consumers, so one level is the set whose
COMPILE can break while the changed crate is green, and the transitive closure of a
leaf like `kata-types` is most of the workspace, i.e. `just test` wearing per-crate
clothes. `just route` prints the derived crates, which seed pulled each dependent in,
and the order.

CAP: above **6** crates the plan becomes `just check` + `just lint` + one
`just test` (which IS `cargo nextest run --workspace`). This WIDENS rather than
narrows — nothing the per-crate lanes would have run is dropped — because each
`validate-crate` re-runs the workspace `fmt` and starts its own clippy and nextest
process, so the per-crate arm grows per crate while the workspace arm is flat.
Measured warm on the reference host (128 cores, one NVMe):

| Arm | Crates | Wall |
|---|---|---|
| a five-crate lane set (`kata-provider-protocol` and the 4 direct dependents it had when measured) | 5 | **364 s** (13 + 30 + 22 + 34 + 265) |
| `just check` + `just lint` + `just test` (one workspace run) | all | **467 s** (8 + 23 + 436) |
| one `validate-crate`, mean over the 7 lanes measured | 1 | 75 s (13 / 22 / 30 / 34 / 67 / 94 / 265) |
| the `kata-types` set, had it not been capped, at that mean | 15 | ~1125 s |

The per-crate arm grows ~75 s per crate; the workspace arm is flat. They cross at
467/75 ≈ 6.2 crates, so 6 is the last breadth at which per-crate lanes are still
cheaper AND still name what they verified. Changing the number owes a fresh
measurement: `scripts/test-dev-loop.py` asserts the 6 by name, because a cap fixture
derived from the constant passes for any value — including one so high the workspace
arm is never taken.

A derived lane may name a crate with no tests at all — `kata-oci-hook` is a thin bin
whose proofs are the live cells that run it. `just test-crate`
therefore passes `--no-tests=warn` (warning, exit 0) on that unfiltered, package-scoped
run: its claim is "every test this package has, ran", and nextest's default exit 4 would
read as a test FAILURE for a package with nothing to run (in `just verify` and
`gate-scoped` alike). The FILTERED recipes keep the default, where zero tests means the
filter matched nothing.

A derived lane may also need a workspace BINARY that a crate-scoped test build does not
produce. `kata-agent-nanocode`'s `toolhost_backpressure` execs `target/<profile>/kata-toolhost`,
so `scripts/dev-loop.py`'s `LANE_PREREQUISITES` puts `just build-toolhost` ahead of that
crate's lane wherever the graph derives it (the crate changed, or a direct dependency of it
did); the over-cap `just test` builds every workspace binary first. The opposite edge, a
source the crate graph does not see as a dependency, is a table row: the "Tool host source"
row sends `bin/kata-toolhost/**`, `crates/toolhost-protocol/**` and
`crates/provider-protocol/**` to the executor-term pin cell and the real-toolhost suite,
because those packages' manifests and `src/` trees are hashed into the term kata-worker
pins.

A path under `crates/**` or `bin/**` that maps to no workspace crate REFUSES, even
though the row matches it: that is a typo or a stale path, and answering it with a
workspace type-check would report a clean plan for a file nobody verified. The
mapping is `cargo metadata`, read through `scripts/crate_graph.py`, which also carries
any workspace-`exclude`d sibling workspace as an island (none exists today).

## The OCI live rigs

Eight host-dependent rigs prove the one engine — rootless OCI capsules — end to end. None runs in the
commit tier (`just gate`); the push tier runs all eight, through `gate-containment`'s
`oci-live-smoke` step — except two real-timer cells (the LONG-CAPSULE cell below and
`oci_stage_live`'s wall-clock cell), which L2 runs (`nightly-oci-live`; `NIGHTLY_CELLS`
above). All need a certified rootless youki with its AppArmor profile installed
(see the operator guide), a delegated user scope, and the pinned closures realised in the
host's Nix store. Build `kata-provider-youki` first. Run each ALONE: never beside another
live OCI run or another installed main (each `bin/kata` rig's cells boot
installed mains, one at a time, and an installed main is a per-user
singleton).

| Rig | What it proves | Run |
|---|---|---|
| `crates/workflow/tests/oci_stage_live.rs` | a real capsule runs in a real container; the worker's result is adopted and accepted once; a fenced stop kills a running container; a post-launch refusal leaves no provider cgroup; a `full`-authored shell capsule streams its spooled stdout as `CapsuleProgress` before its terminal | `KATA_SANDBOX_REQUIRE_LIVE=1 cargo nextest run -p kata-workflow -P live-smoke --test-threads=1 --run-ignored all -E 'binary(oci_stage_live)'` |
| `bin/kata/tests/oci_main_live.rs` | the oci-MAIN live corpus — durable installed mains under `oci` on fresh data directories, asserted from outside (raw `operational.db`/`cas.db` reads, `git` on the fixture repo, the pinned youki's `list`, cgroup and `/proc/*/cgroup` censuses; no runtime state survives with the main up or stopped): the KILL cell (an `oci` main `SIGKILL`ed mid-container — the host sees the container die with it, the next main settles the attempt PROVEN AMBIGUOUS), the NODE-DOUBLE-FAULT cell (a delegated `oci` main's supervised node and the container's provider, stopped first, `SIGKILL`ed together mid-container — the container's `sleep` no longer runs, off `/proc`, when the main logs the node's end, so the main emptied the node's `kata.node` subtree before its pause and not at the next node's start; the attempt settles PROVEN AMBIGUOUS naming the worker's death and a new node runs), the NODE-STALL cell (the supervised node alone `SIGSTOP`ped mid-container — at the first raw read of its attempt's settlement the node is gone from `/proc` and the container's `sleep` no longer runs; the heartbeat leg's reason names the silence, the node's process in state `T` and its kill, never the closed connection; a new node runs in `kata.node` and a shell stage submitted next completes on a worker id the stopped node never had), the MAIN-STALL cell (the main `SIGSTOP`ped 7 s mid-container, past its node's 6 s deadline, and resumed — 12 s later the same node runs, the container's `sleep` runs, and the attempt is unsettled: the main's own stall never kills its node), the LONG-CAPSULE cell (a `timeout_ms = 180000` stage sleeping 130 s completes — the provider held to the capsule's own wall clock), the WORK-DELTA cell (the first stage's delta applies before the second runs, `head_seq` advanced, `git show` reads the candidate), the three workspace-effect cells (commit+promote lands on trunk; park preserves the candidate on `parked/<exec>-attempt0`; forge_export pushes `kata/<exec>` to a local bare `origin` with a recording `gh` shim), the KILL-MID-SLEEP cell (`SIGKILL` while a 20 s timer is parked — deadline unchanged, `after` runs exactly once, `before` not re-run), the CANCEL-CAPSULE cell (`kata run cancel` of a running capsule — the container's process and cgroup go, the attempt's last transition is `cancelled`, the lifecycle row is `cancelled`), the CAPSULE-REUSE cell (`capsule-reuse-smoke` submitted twice — run 2's `executor = 'main'` accept mints no capsule and adopts run 1's `/out/result.txt` byte-for-byte), the committed-base-head cell (an isolated execution's recorded base materializes inside the container — untracked/dirty shapes never appear), the two isolated fan-in cells (both branches land in ONE apply; the same-path conflict fails the join `work_fanin_conflict` and moves no head), the contested same-path topology writers (a real container fan-in conflict refuses), the shell validation-retry convergence, the `requires = ["git"]` cell (the capsule reads the run's history), and the `workflows/smoke` rig `workspace-commit-smoke` (`exec-<id>` holds exactly the line `dirty` left uncommitted, directly on the forked trunk, and the pack's own `observe` — its `workspace.*` reads rendered on the host — passes). | `cargo nextest run -p kata -P live-smoke --test oci_main_live --run-ignored all --test-threads=1` (the profile's one test thread keeps its cells from booting two installed mains at once) |
| `bin/kata/tests/agent_change_live.rs` | the representative agent pack, `workflows/std/agent-change.star`, on a real node — an installed `kata serve` main and an external `kata-worker`, its agent `nanocode_openai` against a scripted mock model on the loopback (the `test-support` door; the model's `exec_command` runs inside the turn's real container), driven through `kata run --submit` / `kata approvals` / `kata run approve`: the happy path to one PR (commit, promote, `kata/<exec>` on a local bare remote, one `pr create` in the fake `gh`'s log, the turn's scratch commit in its session evidence and in no landed history), a killed main and a killed worker at the parked gate resuming, a worker killed mid-turn settling PROVEN AMBIGUOUS, a rejected gate landing nothing and parking, a cancel mid-turn, a failed panel member retried on the next panel agent (the mock's own log holding the two members' turns, each capsule pinning its member's model), the agent fix loop landing its last iteration's tree or parking an exhausted one, a two-response `nanocode_anthropic` turn priced past a workflow `cost_bound` its last response alone stays under, worker liveness at `heartbeat_interval_ms = 1000` / `heartbeat_grace_ms = 5000` (a worker SIGSTOPped for 2 s and a main for 7 s across one of the worker's heartbeats keep the turn — raw chain unsettled, container live — and a worker stopped 12 s is settled by the heartbeat leg with its silence and its stopped process in the raw reason), a second run of a `model_reuse` agent stage adopting the first run's turn (no request in the mock's log, no capsule or command row, an authoritative zero charge), a model connection the mock cuts mid-response after the turn's command ran settling PROVEN AMBIGUOUS and never re-run, though its stage's two-member fallback panel leaves a next seat (one `failed` attempt, `verdict` `proven_ambiguous`, no `provider_failure`, no third request in the mock's log and none naming the second member's model, trunk unmoved), and the stage's own key streamed split across two text deltas under `progress_visibility = "full"` reaching a bare `GET /api/v1/events` reader neither whole nor as either half in its raw transcript, nor as any 4-byte window in a `progress` preview, while the text after it does | `cargo nextest run -p kata -P live-smoke --test agent_change_live --run-ignored all --test-threads=1` |
| `bin/kata/tests/code_mode_host_live.rs` | a defect model output reaches ends only the process it runs in, and that process is never the main: on the same rig, a `nanocode_anthropic` stage (the static `kata-toolhost` its capsule's init, a mock Messages model on the loopback through the `test-support` door). (1) A bind flood, then a cell in a fresh interpreter, under a `local_socket` `kata-worker` daemon: the daemon is alive off `/proc`, the stage's `event_accepted\|completed` is read through a second read-only handle, the mock's own log carries the flood's end naming `SIGSEGV` and the next cell's text, and no interpreter child of the daemon is left alive or unreaped. (2) `operational.after_first_provider_event` armed on a delegated `kata serve` whose node it supervises: the node (a `kata-worker` child of the main, off `/proc`) dies at the harness's first completed model call, the main stays alive throughout, the raw `failed` transition names the worker's death and PROVEN AMBIGUOUS, the mock saw exactly one request, no process is left in the dead node's provider cgroups and those directories are gone, a new node is the main's child, nothing is re-delivered, and the new node takes work: a shell stage submitted next completes (its raw `event_accepted\|completed` read through the second handle) while that node is still the main's only `kata-worker` child | `cargo nextest run -p kata -P live-smoke --test code_mode_host_live --run-ignored all --test-threads=1` |
| `bin/kata/tests/nanocode_interruption_live.rs` | the no-spend twins of `live-nanocode`'s interruption cells, on the same rig: the `agent-change` pack's `implement` on a nanocode kind whose model is a mock (through the `test-support` door) that logs each request body in its OWN log and never answers. The daemon worker SIGKILLed with that body logged and the capsule's cgroup holding only the toolhost (both kinds), and the main killed with its supervised node's model request outstanding and restarted, each settle PROVEN AMBIGUOUS (the death, or "the main restarted"), never re-claimed, the mock receiving no second body, the raw charge `unavailable`; the worker killed while the capsule runs a `sleep` leaves the capsule's cgroup empty within 10 s before any restart; an operator cancel with the request outstanding settles on the worker's record of the harness's confirmed stop. Beside them, the positive control of `live-nanocode`'s re-prompt measurement: a mock that answers a tool call, then an empty response, then the final message, its own log showing the one re-prompt, and the measurement's counter reading three completed model calls and one re-prompt off the turn's session evidence. Read off the mock's log, the kernel's cgroup hierarchy, second read-only SQLite handles, the raw CAS, git and the fake `gh`'s log | `cargo nextest run -p kata -P live-smoke --test nanocode_interruption_live --run-ignored all --test-threads=1` |
| `bin/kata/tests/checked_command_live.rs` | the same rig and matrix for the shell twin, `workflows/std/checked-command.star`, whose `implement` is a deterministic checked command in a real container: the happy path to one PR, the killed-main and killed-worker resumes at the gate, a worker killed mid-capsule and a dead node mid-capsule settling ambiguous, a rejected gate, a cancel mid-capsule, and an `implement` write outside its declared fence refused with nothing landed | `cargo nextest run -p kata -P live-smoke --test checked_command_live --run-ignored all --test-threads=1` |
| `bin/kata/tests/change_live.rs` | the shipped `change` pack on the same rig, a scripted mock model as `[agents.default]`: the fix loop to one PR (one refine, the G6-sanitised feedback, the approval view's target and params, trunk, the bare remote, the fake `gh` and a fresh clone at the tip read from git), the same PR under a 200-byte `data_dir` and an `Egress` shell capsule on that node (the main's `worker.sock` and the capsule's `handoff.sock` both past `sun_path`), the same PR into a repository whose only branch is `master` (`--base master`, no `main` anywhere), the exhaustion park, the closeout park of a loop a per-loop bound cut short, a byte written into the parked candidate refusing the commit, a provider entry with no tool host refusing the first agent turn `toolhost_unavailable` before its container with the reason on every face, a `kata-oci-hook` that never hands its listener over recorded as what the worker saw, and an operator promote onto a renamed trunk refused as a conflict on the CLI, REST and op faces | `cargo nextest run -p kata -P live-smoke --test change_live --run-ignored all --test-threads=1` |
| `bin/kata/tests/review_live.rs` | the shipped `review` pack on the same rig, a scripted mock model as `[agents.default]` whose answer a reviewer script computes inside the capsule: a `pr:1` target resolved through the fake `gh` and fetched from the local bare remote behind a forge URL, reviewed through the CLI and again through REST, and a trunk review against its parent; each run's raw frozen head and merge base read from git, `verify`'s raw answer checked by the cell's own `Review` validator against `git ls-tree`, one attempt row per stage, the remote's refs unchanged and `refs/kata/targets` empty once terminal; a REST run whose reviewer writes an untracked file and edits a tracked one in `/work` fails `work_delta_out_of_scope` naming both, with `main` unmoved; and a REST run whose reviewer writes only a `.gitignore`-ignored `target/` file completes, the path discarded (in no checkout, in no ref's history) | `cargo nextest run -p kata -P live-smoke --test review_live --run-ignored all --test-threads=1` |

`just oci-live-smoke` runs all eight, after kata-worker's OCI live binaries, and then E3's
process column (`bin/kata/tests/e3_crash_matrix_live.rs`, "The E3 crash matrix" below). A skip is a
failure: each rig fails by name on a missing precondition. The agent cells' model is a
mock: no gated rig spends model budget, and the shipped agent packs' runs on a real model
are `live-nanocode`'s, below.

One kata-worker cell proves a property of the pinned youki's BYTES, not of the host:
`oci_runtime_live`'s lost-SIGCHLD race cell (`fast_exiting_containers_never_strand_the_runtime_client_live`,
300 CPU-pinned containers, ~1 minute). It records a pass under `target/tmp` keyed by the
sha256 of the youki binary it ran (`YoukiPin.sha256` on a host whose pin certifies) and
of its own source file, and a later run with the same key prints the recorded verdict
instead of re-running. A re-pinned youki, an edited cell, a fresh target directory or
`KATA_YOUKI_RACE_REPROVE=1` re-proves; the kernel and the host's load are not in the key,
because the race and its fix are both in the binary. A recorded pass is ONE 300-run
sample: against an unpatched binary it misses the race with probability under 1%
(`RACE_ITERATIONS`), and that sample then stands for every later L1 on those bytes, where
an unrecorded cell would re-sample each time; `KATA_YOUKI_RACE_REPROVE=1` re-samples.
Every other cell runs every time.

## The live-nanocode lane

`just live-nanocode` runs `nanocode_live`: the embedded harness's live acceptance (a real
turn in a real capsule, the `agent-change` pack landing offline, the worker killed with a
model request outstanding and during a tool call, the main killed with its supervised
node's turn outstanding and restarted, an operator cancel, and the empty-response
re-prompt measured) on `nanocode_openai` × kata's own ChatGPT login and
`nanocode_anthropic` × `env:ANTHROPIC_API_KEY`, which that recipe's environment carries
(`( set -a; . .env; set +a; just live-nanocode )`); kata's own login is judged only by
kata (the verdict `kata login status --check` gives `openai-chatgpt.json` must read
`ok`), and each cell writes its record, with the checkout's `HEAD` and the nanocode rev
it ran, to `target/test-logs/live-agents/nanocode-<cell>.json`. It spends model budget,
so a maintainer runs it by hand, outside every gate.

Its two `nanocode_anthropic` cells ran once in the 0.0.1 round: A2
(`a2_the_agent_change_pack_lands_on_nanocode_anthropic_live`) passed; A1
(`a1_a_real_nanocode_anthropic_turn_in_a_real_capsule_live`) failed on two rig defects,
since fixed. The rig read the FIRST completed `event_accepted`
transition of `implement`, so A1 judged attempt 0 (accepted, its answer then failing the
stage's `outputs`, so validation minted attempt 1), not attempt 1, on which the run
settled (it completed, both changes in the published delta). `accepted_attempt`
(`agent_change_rig/nanocode.rs`) now reads the chain's last accepted attempt, refusing
one that is not the stage's last attempt or, when validation amended any outcome, not the
last one amended (`the_rig_reads_the_attempt_kata_settled_the_stage_on`, over A1's
recorded chain). A1's git check still reads the run's published delta, the union of every
accepted attempt's `/work` delta, as validation retry is designed ("Validation retry" in
protected-properties.md), so it does not attribute the two changes to the settled
attempt; at the round's run they were attempt 0's. And
the prompts asked for "the JSON object the output schema asks for" though none reaches
the model: the cells' pack declares a flat `outputs` table, which is sent to no adapter
(and `nanocode_anthropic` carries no schema at all). A pack over a flat table states the
shape in its prompt (operator guide, "A stage's `produces=` contract as the turn's output
schema"); every prompt `nanocode_live` runs now does
(`every_one_turn_prompt_states_the_answer_shape_its_outputs_check`). A rerun round ran
both cells once more, on the fixed rig: A1 and A2 passed. A1's run
settled on attempt 0 with no validation retry (one `implement` attempt, read a second
time through `ledger.py`), so the rerun did not exercise the retried-attempt read, which
stays pinned host-free only.

The gated suites' `kata doctor` cells never read the effective owner's own kata
logins (`~/.config/kata/logins/`, found through the account record, never `HOME`), which
`kata init`'s default agent declares: an in-process cell passes the report a directory
it planted (`doctor_report_with_logins_dir`, with `no_kata_logins` beside its config),
and a cell that runs the `kata` binary sets `KATA_TEST_KATA_LOGINS_DIR`, a
`test-support` door of `kata_worker::owner_home::kata_logins_dir` that a shipped build
does not carry. On a fresh init the `kata_login` row then warns naming `kata login
openai` (`doctor_fresh_box_tests`, which also reads the row's `logins_dir` back).

## The E3 crash matrix

`bin/kata/tests/e3_crash_matrix_live.rs` is E3's process column:
D2 §5.4's E3 cells (`gate-main-kill`, `gate-worker-kill`, `P1` placed not sent, `P2`
model call in flight, `P3` after the turn before acceptance, `P4` between the push and
the PR) on the OCI live rigs' node (an installed main, an external worker, the `change`
pack with `progress_visibility = "summary"` on its two agent stages, a local bare
`origin` and a fake `gh`). Each fault-injected cell holds three positive controls (the
boundary is registered, the killed process — the main, or P3's worker — printed the
point's `action=abort` line, it died by SIGABRT) or is VOID; a cell refuses to start
when the caller's environment sets `KATA_FAULT_INJECT` or `KATA_FAULT_INJECT_ACTION`,
which the node's processes would inherit. P2's control is the client-side SSE
transcript's open model call, at most three tries; P2 also runs the operator's CLI
recourse (`kata run show`, the parked candidate). Each try writes one record in the
`docs/evidence/runs/` shape under `target/e3-evidence/`, naming `kata_sha` and its tree
`kata_tree`, and on a VOID the control that did not hold as its `void_reason`. The
default agent is `nanocode-mock`, `nanocode_openai` against a scripted mock provider (no
spend, and a `nanocode-mock` record the evidence check refuses; for P2 the mock holds
`implement`'s request open); `KATA_E3_AGENT=nanocode-openai` or `=nanocode-anthropic`
spends model budget and is refused without `KATA_E3_FUNDED=1`.

What each cell proves, on the mock: `gate-main-kill` and `gate-worker-kill`
resume at the parked gate; P1 and P2 settle PROVEN AMBIGUOUS with no second attempt.
P3 kills the WORKER at `after_container_exited_before_result_published` (the turn
finished, its result not yet sent): the main accepts a capsule's result in the one
transaction that receives it and capsule re-delivery is not implemented, so P3 settles
PROVEN AMBIGUOUS through the main's worker-death leg, with one attempt row and one claim. P4
kills the main between the push and the pull request: the restarted main resumes the
run although its own promote removed the workspace, and opens one pull request, with one
`kata/<exec>` on the remote at the delivered commit. `KATA_E3_FORGE_CLONE` (a local
clone of our `kata-e2-fixture`, refused without `KATA_E3_FUNDED=1`) points P4 at the
real forge and the host's own `gh`, read through `git ls-remote origin` and `gh pr list
--state all`; the 0.0.1 round's process-column P4 cells ran against it on both arms
(P4-host used the guest's local bare and fake `gh`)
(`docs/evidence/README.md`, E3).

On the mock the process column is L1: `just oci-live-smoke`'s eighth step runs it with
`KATA_E3_AGENT`, `KATA_E3_FUNDED` and `KATA_E3_FORGE_CLONE` unset, so no shell turns the
gate into a funded run; its host-free cells ride `just test`. `just e3-crash-matrix`
runs it alone, or on a funded agent. The host column, which refuses the mock (the
machine's kill ends the process that serves it), is its own
binary, `bin/kata/tests/e3_crash_matrix_host_live.rs` (the two share the rig in
`bin/kata/tests/e3_matrix/`): it needs a machine to kill through
`KATA_E3_HOST_KILL_CMD` (its module doc states its two phases; on the E9 VM
`scripts/e9-vm.sh e3-host <case> <out>` drives both across the kill), and no gate runs
it (`gate_exclusion` lists it outside the containment lane). Its guest runner holds the
key, so a cell builds nothing: the rig reads the checkout's status with
`--no-optional-locks` (`tree_status`), and so does `kata run`'s uncommitted-edits notice
(`dirty_checkout`), which the rig's submit runs from the checkout, because a status that
rewrote a fresh clone's racy index, which `bin/kata/build.rs` watches, made the next cargo
invocation rebuild `kata` (2026-11-12: the rig's read rebuilt both dry-run P3-host arms
after a P1-host; with it fixed, P3-host's own submit rebuilt its resume). Its no-spend dry runs ran
on fresh VMs with a stand-in agent: kata's own `nanocode-anthropic` client under a
fake key, every provider host mapped to loopback on both families
(`e9-vm.sh block-providers`). Behind the repository's durability barrier (`kata_vcs::jj`
`durability`), P1-host and P3-host each stopped at their point, froze, were killed,
restarted on the same disk and settled PROVEN AMBIGUOUS, every oracle holding, and the
repository the power loss left read clean outside kata (no empty loose object or ref
file, `git fsck --full` clean) (2026-11-12). P3-host's point is reached only by a
completed turn (it fires in the `/out` publication), so a stand-in that reaches no
provider fails the turn in transport and VOIDs the cell; its dry run answered the plan
turn from a stand-in endpoint in the guest that the guest's system store trusted for
`api.anthropic.com` (the rig keeps the endpoint door shut for a funded harness), which
`e9-vm.sh standin-provider` sets up from the tree (`scripts/e9-standin-provider.py`
under a throwaway CA; refused unless every provider host is on loopback; its self-test
serves it on the host). Before
the barrier, P1-host's resumed main exited refusing recovery on git refs and loose objects
the power loss had emptied, and the rig recorded that node as not restarted: outcome
`fail`, settlement `other`, the main's last `Error:` line leading its detail and outcome
source; a forced VOID P2-host exercised the copy-out and `--retire` path. Funded, on
`nanocode-anthropic` in the 0.0.1 round (the E9 VM, one try per
case): P1-host, P3-host and P4-host passed, and P2-host FAILED on the rig, not on kata.
kata settled its attempt PROVEN AMBIGUOUS, "the main restarted" (NOT re-delivered by
its own reason; the rig did not check it). `judge_p2`, shared by both columns, required
the process column's "died" in the reason, so the cell stopped there and checked none of
P2's other oracles. It now judges the settlement off the chain read through a second
handle (`judge_p2_settlement`: one attempt row, one claim, one dispatch, no acceptance,
one `failed` terminal whose typed `verdict` is `proven_ambiguous`, its reason opening with
the cause of the leg the column's kill settles through, `worker <id> died: …` or `the
main restarted`), and runs every P2 oracle whatever an earlier one found. Its host-free
cells feed the settlement judge both recorded settlements and one negative per refusal
(`p2_admits_each_columns_own_ambiguous_settlement`,
`p2_refuses_a_redelivered_attempt_and_any_other_settlement`), and judge `judge_p2`'s read
oracles over the facts it reads (`judge_p2_facts`, in
`p2_judges_every_read_oracle_off_the_facts_it_was_given`: the leg it is given, the chain
it is given, every violation named, a failed read of each of the chain, the `/work` heads
and the usage rows, the settled attempt's own known charge, and PROVEN AMBIGUOUS observed
only on both the `failed` status and the typed verdict). What stays live is the reading itself, the
effect oracles after it, and which leg each column passes: the mock process-column P2
(`e3_p2_model_call_in_flight_live`, L1) pins the worker-death leg, and only P2-host's
funded run pins the restart leg. A rerun round ran it once (a fresh
E9 VM; `P1-host` first, as a shakedown, also passed): P2-host passed, the call open at
the kill, the attempt settled through the restart leg, and every P2 oracle holding. The
host column has not run on `nanocode-openai`.

## The protected-property ledger

[`docs/architecture/protected-properties.toml`](../architecture/protected-properties.toml)
makes "is the verification boundary complete?" a failing test instead of a review
question. It has one entry per protected property
[`protected-properties.md`](../architecture/protected-properties.md) declares (its
`## Protected properties` list, statement verbatim), per execution construct it declares
shipped (its `oci-constructs` table), and per crash boundary
`kata_core::fault_inject::OPERATIONAL_CRASH_BOUNDARIES` registers (by family). Each entry
names its CELLS — real `#[test]` functions, by package, test binary and test path exactly
as nextest lists them — with each cell's kind (`host-free` or `live`), layer (`L1` or
`L2`), and what it pins.

`bin/kata-eval/tests/protected_property_ledger.rs` checks it on every `just test`, so in
the commit tier; its module doc states the refused set. It resolves every cell to a
`#[test]` function through the module tree from the target's own `src_path` (cargo
metadata, no build), so a renamed, moved or deleted cell is a named failure. It derives
each cell's LAYER from the gate recipes rather than trusting the file: L1 is the structural
closure of the recipes required before a push, L2 the scheduled tier's (the ledger's
`[layers]` table names each layer's root recipes, and a root that names no recipe fails),
and a cell's layer is the lowest one with a `cargo nextest run` that
selects it — without `--run-ignored` for a `host-free` cell, with it for a `live` one —
evaluating each invocation's `-E` filterset and the profile's `default-filter`. A command
inside an `if`, a loop or a function body runs only possibly and is not counted; one
followed by `||` does not fail its recipe and is not counted. It refuses an entry with no
host-free cell and a host-dependent one with no live cell at L1, unless an `unpinned`
record names the gap (there is one engine, so no entry or cell names a profile). It cannot
see whether a cell's assertions pin what its `pins` text says, a capability skip inside a
helper in another file, or whether a recipe propagates a selected command's failure beyond
`||`.

**The rule.** A new protected property, a newly shipped construct (its row in the
`oci-constructs` table) or a newly registered crash boundary lands with its ledger entry
IN THE SAME COMMIT. Renaming, moving or deleting a cell updates its ledger entry in the
same commit; moving a live cell between tiers updates its `layer`. To add a cell: read the
test, confirm it asserts the property against something that does not share the code
under test, and add a `[[<entry>.cell]]` table naming it, with a `pins` sentence saying
what it asserts. A property or clause no cell pins is recorded as an
`[[<entry>.unpinned]]` record with `missing` (`cells`, `host-free`, `live-l1`, or `clause`
with the clause) and a reason — never as a cell that does not pin it. Only a maintainer
sets `acknowledged = true`; `every_ledger_gap_is_acknowledged` is red until then, and
names each pending gap. An acknowledged gap passes and is printed as a warning.

## The checked models

`docs/architecture/models/0003/` checks ADR 0003's node session, gateway slices,
restore, ingress fence and forge intents as TLA+ before any of it is built (plan M0);
its README maps each module to the ADR section it checks and lists the model's
assumptions and findings. `checks.toml` names every TLC run and the verdict it must
reach: `pass` (the whole bounded state space, no violation), or one invariant's name,
reached either by a MUTANT (one mechanism removed: the RED half that proves the
invariant rests on it) or by a FINDING (the design as ADR 0003's draft stated it breaks a
property it claims; the ADR now states each correction, and the finding stays pinned by
id until the model changes).
`just model-check-0003` runs them all with nixpkgs' `tlaplus` at the nixpkgs
`flake.lock` pins, through `scripts/model-check.py`, which first audits the manifest:
it refuses a check naming an invariant, constant, mutant or symmetry its module lacks,
a red check that runs more than its one invariant, a mutant the module declares that
no check runs, an invariant that no passing check runs or no mutant breaks (unless the
spec lists it as `typing`, or as `refuted` with a finding), an invariant the README's
row for its module does not name, and a finding without a README row naming its check
(or a README finding no check pins). Each run's TLC output stays in
`target/model-check/0003/<check>.log`.

A green says each invariant holds in every reachable state of the model at the bounds
its check states (`MaxFaults`, `MaxAttempts`, `MaxMarks` and the rest), with time
relative so no horizon bounds it. It says nothing about states beyond those bounds,
about behaviour the model abstracts away, or about whether the code built later does
what the model does: the cells each plan stage names are what pin that. Adding a
property means a passing check that runs it, a mutant check that breaks it, and its
name in the README's row for its module; `--audit` refuses the manifest until all three
exist. The audit reads the README's tables, not its prose.

## Maintainer release discipline

L2 and L3 are maintainer tooling and process. A contributor's change is complete at L1.

**L2, nightly.** `just gate-nightly` is required nightly on `main`. A systemd user timer
runs it through `scripts/nightly.sh`, whose header is the authority for what one run does.
`just nightly-install` renders `scripts/systemd/kata-nightly.{service,timer}` into
`~/.config/systemd/user` and enables the timer (daily at 03:00 local with up to 30
minutes of randomized delay, `Persistent=true`); it refuses a linked worktree (its git
dir differs from the repository's common dir), so install from the main checkout.
`just nightly-status` prints the timer,
the last run and the latest report's head; `just nightly-run` starts one now;
`just nightly-uninstall` removes the units. `scripts/nightly.sh --dry-run` prints the
guards' state, the target revision and the plan, and runs nothing.

One run first holds the `NIGHTLY` mark (lanes then start nothing new), then WAITS —
bounded by `NIGHTLY_BUSY_WAIT_SECS`, default 5400 — while the box is busy: the `QUIET_BOX`
flag (`$XDG_RUNTIME_DIR/kata<main checkout path with / as ->/QUIET_BOX`, overridable with
`NIGHTLY_QUIET_BOX_FLAG`) a gate holds, a running gate snapshot, a `cargo-nextest` in any
worktree of the repository, or a red `just pgrep-stale`; then it takes the live-suite lock
and holds it to its exit. It refuses (a REFUSED report, nothing built) only when that
bound runs out, at once on low free disk, on a load that never falls, or when a busy
reason appears during that load wait. Otherwise it fetches `origin/main`, runs the tier through
`just gate-snapshot <rev> tier=nightly` (in the snapshot's worktree,
`.worktrees/gate-snapshot`), compares the JUnit reports with the previous
runs' (`scripts/nightly-drift.py`), runs the report-only nanocode drift step (below),
and
then, on a red tier, bisects the first-parent
commits since `refs/nightly/last-green` by re-running only the first red step in its own
detached worktree (`.worktrees/nightly`); on a green tier it samples mutants with a pinned `cargo-mutants` over
the Rust lines changed since `nightly/last-green` (`--in-place` in that worktree — never
edit the file under a running scan) and moves `nightly/last-green` to the revision. It
never pushes and writes no other ref. The report is `target/nightly/latest/report.md`.
Flake drift, nanocode drift and mutation survivors never make a nightly
red, and a bisect
result explains a red without changing it. `scripts/nightly.sh --self-test` (run by `just
dev-loop-check`) proves the bisect over a synthetic repository, the failing-step parser,
the baseline-red report, the mutants listing (an empty one — cargo-mutants' answer to a
diff with no mutable function — is zero mutants; one that is not a JSON array is a red
step), the build of every located binary and example (`just _workspace-bins`) ahead of
cargo-mutants, the nanocode drift step (below) and `nightly-drift.py`.

**The nanocode drift step** (`nanocode_drift` in `scripts/nightly.sh`) asks every night
what moving kata to nanocode's `master` would cost now ([nanocode.md](nanocode.md)). It
fetches `master`'s head, copies the revision (`git archive`) into a scratch directory
outside the checkout (`NIGHTLY_NANOCODE_DRIFT_DIR`, default `~/.cache/kata/nanocode-drift`;
a directory inside the checkout, or one holding it, is refused, and so is a path that is
not one below `/` or a directory holding any entry the step does not make), runs
`scripts/nanocode-vendor.py bump` there to re-vendor `master` with `vendor/nanocode-code-mode-engine.patch`, re-resolves the lock,
and builds and runs kata-agent-nanocode's seam, qualification and Code Mode cells
(`nanocode_seam`, `nanocode_qualification`, `nanocode_thread_backend`, `code_mode_*`)
with their own target directory. Its target, CARGO_HOME and object cache are kept between nights, so a night
where `master` did not move rebuilds only kata's crates; on a night whose `master` rev
is not the one they were built for (`master-rev` in the scratch directory) the step
removes the target and CARGO_HOME and gc's the object cache down to that rev before it
builds, so the directory holds the build of at most one nanocode rev. Kata-side changes
across nights while `master` is quiet still accumulate in the kept target until `master`
moves. It deletes only its own named entries of a directory whose path is its own
canonical form. The self-test proves the prune, the keep on an unmoved
`master` and each refusal, reading the scratch directory and the object cache. The
report's "nanocode drift" section names `master`'s rev beside the
revision's pin, whether the patch applies, the lock, build and test results with the
test counts, and the host tool-set drift: each tool-set cell's result and the
`host tool-set drift:` line `host_sets_are_the_pinned_names` prints per moved backend
(names added and missing). It is REPORT-ONLY: it runs after the verdict is computed,
its rc is shown as informational, and a fetch failure, a patch that does not apply or a
red build or cell leaves a green night GREEN — the self-test proves each of those three
through `main()`, reading `nightly/last-green` out of git, and holds the checkout to the
source-tree guard. It is skipped under the `QUIET_BOX` flag or low disk, is capped at
`NIGHTLY_NANOCODE_DRIFT_SECS` (2700 s), and its seconds come out of the bisect's wall
cap, so a red night ends no later than it did without it, and at the default caps a
green one (drift, 2700 s, plus the mutants phase, at most 4500 s) stays inside the
bisect's 10800 s.

The step RUNS UNREVIEWED CODE on the nightly's host. A pin is reviewed at each deliberate
bump; `master` is not, and every night the step builds and runs it: its build scripts and
proc-macros, and its library code inside the test binaries. Every cargo call runs under
`drift_env` instead of the nightly's environment: an allowlist (`env -i`), so no token,
session bus, runtime directory or agent socket named in the nightly's environment reaches it; a HOME and TMPDIR under the scratch directory, fresh every run, and a CARGO_HOME
there, so neither a HOME-relative credential file nor `~/.cargo/credentials.toml` is where
it looks; and no rustc wrapper, so no compile-cache server started outside that environment
runs the compiler for it. The self-test proves the test binaries see the scratch HOME and
none of a canary variable set in the nightly's environment. That narrows what the code is
HANDED, not what it can REACH: it is not a sandbox. It runs as the nightly's user, with that
user's files readable and writable by absolute path and the network open, so one malicious
push to nanocode's `master` is code execution as that user at the next nightly. Only the
step's own fetch of `master`'s head follows `NIGHTLY_NANOCODE_URL`; the re-vendor and cargo
resolve nanocode at `https://github.com/gakonst/nanocode` whatever it says.

**A red L2** blocks every further push until it is TRIAGED: the red cell fixed, or
bisected to the commit that owns it and that commit fixed or reverted. The push that
carries the fix is the one push a red L2 admits. "Flake" is not a triage verdict until
its cause is named; a green re-run does not explain the red one.

**L3, at every release boundary.** An adversarial review with mutation testing, a
construct→cell map and a live differential of the release's behaviour. It reconciles the
ledger with its own map: every construct and property the review maps has a ledger entry;
every ledger cell the review relies on is read, and its `pins` is what the cell asserts; a
cell the review's mutations show does not kill its mutant is replaced or its `pins`
narrowed in the review's fix commit; and every gap the review finds becomes an `unpinned`
record, never a cell.
