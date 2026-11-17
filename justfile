# kata task runner.
#
# Every command a contributor (human or coding agent) needs to work on
# this repo lives here. Prefer a `just <recipe>` invocation over a raw
# `cargo ...` / `curl ...` string: the recipe is the source of truth, so
# when flags drift the docs and their readers don't need to.
#
# Override `api_url` and `config` via env vars for non-default
# deployments — e.g. `KATA_API_URL=http://127.0.0.1:18402 just api-health`.

# Load operator-local `.env` (if present) before any recipe runs, so
# secrets and runtime overrides land in the environment of every
# `just ...` invocation. `.env` is gitignored;
# `.env.example` documents the surface. kata binaries also load `.env`
# themselves via `dotenvy::dotenv()` for the direct `./target/release/...`
# path — this line only covers `just` recipes.
set dotenv-load := true

api_url := env_var_or_default("KATA_API_URL", "http://127.0.0.1:8400")
config := env_var_or_default("KATA_CONFIG", "config/kata.example.toml")
audit_nightly := trim(read(".config/audit-nightly"))

# Keep compile/link fanout below the point where large workspaces can saturate
# host storage. Operators may raise or lower this explicitly; nextest retains
# its independent all-core test-runtime scheduler after compilation completes.
export CARGO_BUILD_JOBS := env_var_or_default("CARGO_BUILD_JOBS", if os() == "macos" { "8" } else { "16" })

# No rustc wrapper and incremental builds, in-repo. A per-user
# `~/.cargo/config.toml` setting `rustc-wrapper` would otherwise win, and every
# `just` recipe would silently pay sccache's wrapper cost. sccache does NOT cache
# incremental builds, so the two are mutually exclusive and the wrapper buys the
# worse half of both.
#
# MEASURED on a 128-core host, `just build-debug` after touching kata-types,
# mold held CONSTANT in both arms so the linker is not the variable:
#
#   sccache on,  incremental off (as configured)   28.06s
#   sccache off, incremental on                    12.03s   <- 2.33x
#
# Corroborated by the daemon's own counters: 81 Rust cache hits against 347 Rust
# misses over 1113 requests, i.e. it paid wrapper overhead on nearly every
# Rust compile to serve a ~19% hit rate. The C/C++ side (258 hits) is unaffected
# because nothing here compiles C/C++ through cargo.
#
# Both are `env_var_or_default`, so an operator who wants sccache back for a cold
# build can still say `RUSTC_WRAPPER=$(which sccache) CARGO_INCREMENTAL=0 just ...`.
# This does NOT touch the user's global config, so other repos on the host keep
# sccache for the cold/CI builds where it does pay.
export RUSTC_WRAPPER := env_var_or_default("RUSTC_WRAPPER", "")
export CARGO_INCREMENTAL := env_var_or_default("CARGO_INCREMENTAL", "1")

# ─── Build / static analysis ──────────────────────────────────

check:
    cargo check --workspace --all-features

# EVERY no-spend rootless-OCI LIVE test (less `NIGHTLY_CELLS`), in the containment lane.
#
# ─ WHY IT IS A STEP AND NOT A NOTE ─
#
# Each rootless-OCI live falsifier is `#[ignore]`d (it needs the host's user
# namespaces, a delegated cgroup and the pinned youki), so this recipe is what
# runs them: the containment guarantee for this plane is the tests themselves, not
# `_containment-preconditions`' youki probe — one rootless `/bin/true` in a
# delegated scope. The probe stays, because it is what makes the lane refuse in
# SECONDS on a host that cannot finish it rather than in twenty minutes.
#
# ─ WHY IT IS ITS OWN STEP ─
#
# It runs every rootless-OCI live binary that spends no model budget (one that
# spends runs under `live-nanocode` instead), every cell under the no-skip rule
# below except the real-timer cells `NIGHTLY_CELLS` moves to L2 (each subtracted
# by name in its step's filter), from kata-worker, kata-workflow and the `kata`
# binary crate (durable installed mains, then the shipped packs end to end, one at
# a time). The list is the recipe itself: the numbered steps' filters name every
# binary.
# Each step is one nextest invocation restricted to its package by a
# `package(...)` clause, so each failure names its own proof. Every step runs from
# `just test`'s workspace build; a `-p` run would be its own feature-unified test
# build, and 165-334 s of this step's wall clock would be compiling.
#
# ─ A SKIP IS A FAILURE, AND HERE IT IS NOT EVEN POSSIBLE ─
#
# No OCI binary below READS `KATA_SANDBOX_REQUIRE_LIVE` — it is set only so the
# lane's live steps share one environment. The no-skip property is stricter than
# that knob and does not depend on it: every binary below calls `certify_youki`
# (or needs a delegated scope) and PANICS on a refusal naming its token, set or
# not. So on a host where the pinned youki's AppArmor profile is not installed
# this recipe FAILS with `profile_file_differs` — which is the no-skip rule
# working, not a defect. The
# recourse is one command:
#
#   sudo kata host apparmor-install
#
# ─ THE INSTRUMENT IS BUILT HERE, LOAD-BEARING ─
#
# `kata-provider-youki` is a SEPARATE package that kata deliberately does not link
# (the provider runs out of process), so no test build produces its binary, and
# every OCI binary below execs it. The `_workspace-bins` dependency builds it; without
# that build they fail for want of their instrument.
oci-live-smoke: _workspace-bins
    #!/usr/bin/env bash
    set -uo pipefail
    # The provider, `kata-oci-hook` beside it (an `Egress` capsule's createContainer
    # hooks are exec'd out of the provider entry) and `kata` come from the workspace
    # bins build this recipe depends on — the one the suite's build follows, so the
    # preamble compiles nothing a tier already built.

    # `oci_adversarial_live` rides this recipe now that the wrap drivers are
    # gone: its rows are argv probes inside a real rootless container, bound to
    # the OCI driver in the binary itself (any other driver knob is refused by
    # name), and it FAILS naming `profile_file_differs` on a
    # host missing the pinned youki's AppArmor profile — the no-skip rule
    # working, not a skip.
    # `sandbox_seccomp_tests` carries the kata-floor live cells: the probe under
    # test is `kata __syscall-probe`, an instrument this workspace builds, so a
    # missing `target/<profile>/kata` is a FAILURE under the knob here — which
    # is why this recipe depends on the workspace bins build.
    # `git_view_live` rides here: its subject is the OCI capsule's mounts
    # carrying the git view — rootless-youki, the same preconditions, the same
    # instrument.
    #
    # ONE MODE PER BINARY, BY ITS CELLS' SHAPE. A binary whose live cells are
    # `#[ignore]`d runs `--run-ignored only`: its host-free cells already ran in
    # `just test`, in parallel, and `all` would re-run them here serially (74
    # `agent_turn_capsule` cells, 92.6 s of step 1 at ba3b5c727, after the one
    # ignored cell the filter claimed had been deleted). `sandbox_seccomp_tests` is
    # the capability-conditional exception: none of its cells is ignored, each
    # asserts only under `KATA_SANDBOX_REQUIRE_LIVE`, so it runs `all` with the knob.
    # `every_live_step_runs_each_binary_in_the_mode_its_cells_need` (gate_exclusion)
    # refuses any other combination.
    # `toolhost_live` and `nanocode_capsule_live` provision the STATIC `kata-toolhost`
    # as the provider entry's `toolhost/kata-toolhost`: a nanocode agent capsule's
    # init, so its rootfs (the closure plus mappings) has no dynamic loader for it to
    # need. Their rig (`tests/common/toolhost_capsule.rs`) reads the musl DEBUG build
    # from this same target directory. `nanocode_capsule_live` drives it with the real
    # nanocode adapter against a mock provider on the loopback: no model budget.
    cargo build -p kata-toolhost --target x86_64-unknown-linux-musl || exit $?

    echo "== 1/8 — kata-worker's OCI live binaries, then the kata-floor seccomp corpus =="
    just _oci-live-smoke-worker
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: kata-worker's OCI live binaries FAILED (exit $rc)." >&2
        echo "  If the failure names \`profile_file_differs\`, the pinned youki's AppArmor" >&2
        echo "  profile is not installed:  sudo kata host apparmor-install" >&2
        echo "  The containment lane's own preconditions step diagnoses it in one line." >&2
        exit "$rc"
    fi
    # Its own command, at the recipe's top level and never inside an `if`: the
    # protected-property ledger counts only an unconditional invocation as one a
    # layer runs, and this one runs the ledger's live seccomp-floor cells.
    just _oci-live-smoke-seccomp
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: the kata-floor seccomp corpus FAILED (exit $rc)." >&2
        exit "$rc"
    fi

    echo
    echo "== 2/8 — kata-workflow's end-to-end capsule-in-a-container proof =="
    just _oci-live-smoke-stage
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: the end-to-end capsule proof FAILED (exit $rc)." >&2
        exit "$rc"
    fi

    # The OCI-MAIN corpus: durable installed mains under the `oci` profile run the
    # shipped packs through the normal client path, and runtime state is read off
    # the host. Its oci mains run in a delegated scope and provision the provider
    # built above; they need no other main running (one installed main per user
    # holds the discovery lease). The binary's KILL cells SIGKILL an oci main run
    # as a transient service mid-container/mid-sleep; `--test-threads=1` keeps the
    # cells apart. Its 130 s long capsule — a REAL-TIMER cell — is subtracted
    # EXACTLY and runs in L2 by `nightly-oci-live`, as is `oci_stage_live`'s 36 s
    # wall-clock cell above (`NIGHTLY_CELLS` in gate_exclusion.rs names each one's
    # host-free twins).
    echo
    echo "== 3/8 — kata's oci mains: the installed binary end to end =="
    just _oci-live-smoke-main
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: the oci-main cells FAILED (exit $rc)." >&2
        exit "$rc"
    fi

    # The representative pack: `agent-change` driven end to end on a REAL
    # external worker — the nanocode turn inside a real container against a
    # scripted mock model (`mock_model`: its `exec_command` writes the fixture's
    # change), the criterion, the parked gate decided through `kata run approve`,
    # and commit/promote/forge_export asserted from OUTSIDE kata (raw transitions,
    # git refs, the fake `gh`'s log, the mock's own request log). Every kill is a
    # SIGKILL at a durable park or with the mock holding a model request, never a
    # timer; the panel retry, the agent loop, the cost bound, worker liveness,
    # model reuse and a provider connection the mock cuts mid-response (PROVEN
    # AMBIGUOUS, never re-run) ride the same rig. Each cell asserts it fails by name rather
    # than skipping when the host cannot prove containment.
    # `code_mode_host_live`: a nanocode stage whose Code Mode
    # cell crashes QuickJS (a bind flood, mock model, no budget) ends only its
    # interpreter process under a `local_socket` worker daemon, read alive off
    # `/proc`; and the harness crash point armed on a `kata serve` that
    # supervises its node ends only that node — the main alive, the attempt
    # PROVEN AMBIGUOUS, the node's subtree empty, a new node started.
    # `nanocode_interruption_live` is the no-spend twin of `live-nanocode`'s
    # interruption cells: the pack's nanocode turn against a mock that logs a
    # request and never answers, the worker killed (both kinds), the main killed
    # with its supervised node's turn outstanding and restarted, the worker
    # killed during a tool call, and an operator cancel.
    echo
    echo "== 4/8 — the agent-change pack: mock model, real container, full gate; nanocode containment and interruption =="
    just _oci-live-smoke-agent-change
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: the agent-change end-to-end cells FAILED (exit $rc)." >&2
        exit "$rc"
    fi

    # The representative workflow's CHECKED-COMMAND twin: the same rig and an
    # external-worker matrix, `workflows/std/checked-command.star` running a
    # deterministic shell `implement` where an agent turn would stand — the
    # repo's own `tools/implement.sh`, which the cell's fixture authors; its
    # sleeping shape parks the implement capsule so the kill and cancel arms
    # act on a real running container, never a timer.
    echo
    echo "== 5/8 — the checked-command pack: real checked capsule, full gate =="
    just _oci-live-smoke-checked-command
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: the checked-command end-to-end cells FAILED (exit $rc)." >&2
        exit "$rc"
    fi

    # The shipped `change` pack on the same rig: plan, the implement -> test
    # fix loop with a scripted mock model as `[agents.default]`, the parked
    # approve, and commit -> promote -> forge_export into the local bare remote
    # and the fake `gh`, on a `main` trunk and on a `master` one; plus its
    # exhaustion park, the closeout park of a loop a per-loop bound cut short,
    # its on-disk mismatch refusal, a provider refusal before the container, and
    # an operator promote onto a renamed trunk refused as a conflict on every
    # face. Every outcome is read from git, the remote, a fresh clone, the shim
    # and the mock's own log.
    echo
    echo "== 6/8 — the change pack: fix loop, approval, PR, park and refusal =="
    just _oci-live-smoke-change
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: the change pack's end-to-end cells FAILED (exit $rc)." >&2
        exit "$rc"
    fi

    # The shipped `review` pack on the same rig: a `pr:1` target resolved
    # through the fake `gh` and fetched from the local bare remote, `find` and
    # `verify` answered by the mock model, through the CLI and through REST,
    # plus a trunk review. Each typed answer is validated against the contract
    # by the cell itself; the remote's refs, the shim's log and
    # `refs/kata/targets` are read from git and the filesystem.
    echo
    echo "== 7/8 — the review pack: pull request and trunk reviews, typed answers =="
    just _oci-live-smoke-review
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: the review pack's end-to-end cells FAILED (exit $rc)." >&2
        exit "$rc"
    fi

    # E3's process column (`e3_crash_matrix_live`, D2 §5.4) on the same rig and the
    # mock model: the main or the worker killed at the parked gate, at fixed fault
    # points (P1 placed not sent, P3 after the turn, P4 between push and PR) and mid
    # model call (P2, the mock holding `implement`'s request), then restarted, every
    # settlement read from outside kata. The selectors that would spend (a
    # provider-backed agent, the real forge) are unset here, so an operator's shell
    # cannot turn this step into a funded run; the host column is its own binary,
    # which needs a machine to kill and no gate runs.
    echo
    echo "== 8/8 — E3's process column: kills and restarts on the mock model =="
    just _oci-live-smoke-e3
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "oci-live-smoke: E3's process column FAILED (exit $rc)." >&2
        exit "$rc"
    fi
    echo "oci-live-smoke OK — the rootless-OCI route is proven live on this kernel."

# `oci-live-smoke`'s runs, one recipe each: a gate recipe that names nextest holds its
# runs and nothing else (gate_exclusion's `read_gates`), so each step's message and
# exit status are `oci-live-smoke`'s.
_oci-live-smoke-worker:
    KATA_SANDBOX_REQUIRE_LIVE=1 \
        cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored only --success-output final -E 'package(kata-worker) & (binary(oci_runtime_live) + binary(oci_bundle_live) + binary(oci_provider_live) + binary(interactive_capsule_live) + binary(egress_oci_live) + binary(git_view_live) + binary(oci_adversarial_live) + binary(toolhost_live) + binary(nanocode_capsule_live))'

_oci-live-smoke-seccomp:
    KATA_SANDBOX_REQUIRE_LIVE=1 \
        cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored all --success-output final -E 'package(kata-worker) & binary(sandbox_seccomp_tests)'

_oci-live-smoke-stage:
    KATA_SANDBOX_REQUIRE_LIVE=1 \
        cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored only --success-output final -E 'package(kata-workflow) & binary(oci_stage_live) & not test(=a_capsule_past_its_wall_clock_is_stopped_by_its_provider_budget_live)'

_oci-live-smoke-main:
    cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored only --success-output final -E 'package(kata) & binary(oci_main_live) & not test(=a_capsule_past_120_seconds_completes_on_its_own_wall_clock_live)'

_oci-live-smoke-agent-change:
    cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored only --success-output final -E 'package(kata) & (binary(agent_change_live) + binary(code_mode_host_live) + binary(nanocode_interruption_live))'

_oci-live-smoke-checked-command:
    cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored only --success-output final -E 'package(kata) & binary(checked_command_live)'

_oci-live-smoke-change:
    cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored only --success-output final -E 'package(kata) & binary(change_live)'

_oci-live-smoke-review:
    cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored only --success-output final -E 'package(kata) & binary(review_live)'

_oci-live-smoke-e3:
    env -u KATA_E3_AGENT -u KATA_E3_FUNDED -u KATA_E3_FORGE_CLONE \
        cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored only --success-output final -E 'package(kata) & binary(e3_crash_matrix_live)'

# Every workspace member, and nothing else: `--all` would also format the local
# path dependencies of the members, which is the vendored nanocode engine
# (`vendor/`), upstream code kept byte-exact by `just nanocode-vendor-check`.
fmt:
    cargo +{{audit_nightly}} fmt -- --check

fmt-fix:
    cargo +{{audit_nightly}} fmt

# The pre-commit clippy gate. `--all-targets` catches test + bench
# warnings in addition to lib/bin; `-D warnings` is the acceptance
# threshold.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    # `ruff==0.15.20` is PINNED in requirements-audit.txt and this is its runner: a
    # pin nobody runs is a named recourse nobody can invoke. `scripts/` is not
    # scratch: it holds `dev-loop.py` (which the routing table and the gate variants
    # depend on) and the validators that can red the gate. `scripts/evidence-kit/` is
    # excluded: it is the evidence kit committed byte for byte as the run records'
    # kit-sha256.txt pins it (evidence-page.py `kit_problems`), so it is never edited.
    just _ruff-pin
    ruff check scripts/ --extend-exclude scripts/evidence-kit

# Refuse a ruff that is absent or is not the version requirements-audit.txt pins.
# Presence alone does not make lint reproducible: another ruff's default rule set
# reports findings in scripts/ that the pinned one passes, so the gate would go red
# (or green) on whichever ruff the host happens to carry.
_ruff-pin:
    #!/usr/bin/env bash
    set -uo pipefail
    pin="$(sed -n 's/^ruff==//p' requirements-audit.txt)"
    recourse="  Recourse: 'nix develop' puts the pinned ruff first on PATH, or: python3 -m pip install -r requirements-audit.txt"
    if ! command -v ruff >/dev/null 2>&1; then
        echo "  MISSING ruff — requirements-audit.txt pins ruff==$pin and 'just lint' runs it." >&2
        echo "$recourse" >&2
        exit 1
    fi
    have="$(ruff --version | awk '{print $2}')"
    if [ "$have" != "$pin" ]; then
        echo "  WRONG ruff $have first on PATH ($(command -v ruff)); requirements-audit.txt pins ruff==$pin." >&2
        echo "$recourse" >&2
        exit 1
    fi

lint-crate crate:
    #!/usr/bin/env bash
    set -euo pipefail
    package="{{crate}}"
    if [ -f "crates/{{crate}}/Cargo.toml" ]; then
        package="$(sed -n 's/^name = "\(.*\)"/\1/p' "crates/{{crate}}/Cargo.toml" | head -n1)"
    fi
    cargo clippy -p "$package" \
        --all-targets --all-features -- -D warnings

# The release build, and the ONLY one either tier pays for: `footprint-check` and
# `smoke-no-budget` both measure these bytes. `--workspace` is the shape the flake
# builds the shipped artifact in (its `cargoBuildFlags`), so the gate measures the
# binary that ships (a `-p kata` release build unifies features differently and is a
# different, second ~155 s LTO build of `kata`).
build:
    cargo build --workspace --release

# The debug binaries every smoke boots: the workspace bins build, never a `-p` list.
# Resolver 2 unifies features per selected package set, so `cargo build -p kata` after
# the workspace build was a second variant (15 crates, 43.72 s, recompiled in
# `oci-live-smoke`'s preamble at ba3b5c727) and a `target/debug/kata` linked against
# features the suite never judged (`every_tier_builds_its_debug_binaries_with_the_workspace`).
build-debug: _workspace-bins


# ─── Packaging / distribution ───────────────────────────────
#
# `just package` builds the flake's `kata` package and produces a
# RELOCATABLE install tree under target/dist/:
#
#   target/dist/bin/kata
#   target/dist/bin/kata-worker
#   target/dist/bin/kata-provider-youki
#   target/dist/bin/kata-oci-hook
#   target/dist/share/kata/workflows/       (from workflows/std)
#   target/dist/share/kata/examples/        (verified learning surface)
#   target/dist/share/kata/kata-factory/    (from workflows/kata-factory)
#
# The tree is the Nix build output verbatim — the binaries are linked
# against the nix store, not the host loader. The kata binary resolves
# its workflow stdlib RELATIVE TO ITS OWN
# PATH — `<exe>/../share/kata/{workflows,kata-factory}` — via
# `WorkflowLibrary::default_roots` (crates/program/src/library.rs). So
# copying the whole `target/dist/` tree to a fresh host yields a working install
# that finds the bundled workflows. Without this step, a bare copied
# binary silently resolves ZERO workflows. Override the output dir with
# `KATA_DIST_DIR=/some/where just package`.

package:
    #!/usr/bin/env bash
    set -euo pipefail
    dist="${KATA_DIST_DIR:-target/dist}"
    out_path="$(nix build .#kata --max-jobs 4 --cores 32 --no-link --print-out-paths)"
    rm -rf "$dist"
    mkdir -p "$dist"
    cp -rL "$out_path/." "$dist/"
    chmod -R u+w "$dist"
    echo "packaged kata -> $dist"
    echo "  bin:           $dist/bin/kata"
    echo "  workflows:     $dist/share/kata/workflows  ($(ls "$dist/share/kata/workflows"/*.star 2>/dev/null | wc -l) .star files)"
    echo "  examples:      $dist/share/kata/examples  ($(ls "$dist/share/kata/examples"/*.star 2>/dev/null | wc -l) .star files)"
    echo "  kata-factory:  $dist/share/kata/kata-factory"
    bin_path="$(cd "$dist/bin" && pwd)/kata"

    # VERIFY the property the header states ("without this step, a bare copied
    # binary silently resolves ZERO workflows") instead of SUGGESTING a command
    # that cannot fail on it.
    #
    # Suggesting `( cd / && kata config check --config <cfg> )` would not do: that
    # command has NO failure mode for this. `render_stdlib_roots` prints an advisory
    # `WARNING:` line and
    # `config_check` returns `Ok(())` unconditionally, so it exits 0 with both
    # bundled roots marked `[missing]` — measured on a hand-built dist tree, exit 0
    # with and without `share/`. Worse, the advisory is SUPPRESSED whenever any one
    # candidate root exists (`no_roots_present_warning` short-circuits on
    # `any(is_dir)`), so a host where `kata init` created `$HOME/.kata/workflows`
    # gets a clean-looking summary and no warning at all. `kata doctor` is not a
    # fallback: `init_then_doctor_is_green_on_fresh_box_without_bundled_stdlib`
    # asserts doctor is GREEN with the bundled stdlib absent.
    #
    # So the recipe reads the MARKERS, from `/`, through the binary it just
    # packaged — which is the same observation an operator would make by eye, made
    # by something that can fail.
    check_log="$(mktemp -t kata-package-fresh-box.XXXXXX)"
    cfg="$(pwd)/config/kata.example.toml"
    ( cd / && "$bin_path" config check --config "$cfg" ) >"$check_log" 2>&1 || {
        echo "package: the packaged binary could not validate a config at all; see $check_log" >&2
        exit 1
    }
    missing=0
    for root in workflows kata-factory examples; do
        if ! grep -qE "^[[:space:]]*\[exists\] .*/share/kata/$root\$" "$check_log"; then
            echo "package: FRESH-BOX BOOT UNVERIFIED — the packaged binary does not resolve" >&2
            echo "  <exe>/../share/kata/$root. A copy of bin/kata alone resolves ZERO" >&2
            echo "  workflows, and \`config check\` reports that as an advisory line and exit 0." >&2
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        grep -E "^[[:space:]]*(workflow stdlib roots|\[exists\]|\[missing\]|  WARNING:)" "$check_log" >&2 || true
        exit 1
    fi
    rm -f "$check_log"
    echo "fresh-box boot VERIFIED: ( cd / && \"$bin_path\" config check ) resolves all three bundled"
    echo "  roots as [exists] — share/kata/{workflows,kata-factory,examples} travel with the binary."

# The source install (README): build the shipped binaries from this checkout
# (`default-members`, so `cargo build --release` builds exactly kata,
# kata-worker, kata-provider-youki and kata-oci-hook), then the static
# `kata-toolhost` a nanocode agent capsule runs as its init (musl: a capsule's
# rootfs has no dynamic loader; `kata host setup` stages it from
# `target/x86_64-unknown-linux-musl/release/`), and put `kata` and
# `kata-worker` on PATH as LINKS into `target/release/`. A link and not a copy:
# kata resolves its own path, so the linked binary is a checkout build — it
# finds the workflow library, and `kata host setup` finds the provider members
# beside it and builds the youki pin and the `share/kata` declarations from
# this checkout's `nix/`. A copied binary finds none of them. Rebuilding
# `target/release` changes what the links run. `KATA_BINDIR` overrides the
# link directory (default `~/.local/bin`).
install:
    #!/usr/bin/env bash
    set -euo pipefail
    bindir="${KATA_BINDIR:-$HOME/.local/bin}"
    # The README's build, exactly: the checkout's own target directory (a build
    # elsewhere is not one `kata host setup` recognises as a checkout build), and
    # without this file's exported `CARGO_INCREMENTAL`, which would make it a
    # second release build of the same tree.
    env -u CARGO_TARGET_DIR -u CARGO_INCREMENTAL cargo build --release --locked
    env -u CARGO_TARGET_DIR -u CARGO_INCREMENTAL cargo build --release --locked \
        --target x86_64-unknown-linux-musl -p kata-toolhost
    mkdir -p "$bindir"
    # The README's `chmod go-w ~/.local ~/.local/state`: the main refuses to publish
    # its address under ~/.local/state/kata while a directory of the user's on that
    # path is group/world-writable.
    mkdir -p "$HOME/.local/state"
    chmod go-w "$HOME/.local" "$HOME/.local/state"
    for bin in kata kata-worker; do
        ln -sfn "{{justfile_directory()}}/target/release/$bin" "$bindir/$bin"
    done
    echo "linked kata and kata-worker in $bindir -> {{justfile_directory()}}/target/release"
    "$bindir/kata" --version
    case ":$PATH:" in
        *":$bindir:"*) ;;
        *) echo "note: $bindir is not on PATH; add it to run \`kata\`" >&2 ;;
    esac

# The alternative install: the flake's `kata` package into the invoking user's
# nix profile (~/.nix-profile), carrying its own `share/kata` tree.
install-nix:
    nix profile install .#kata

# Push the build artifacts to the katacode Cachix cache so users and CI
# substitute instead of building. Pushes ONLY the kata package and the
# patched youki.
cache-push:
    #!/usr/bin/env bash
    set -euo pipefail
    kata_out="$(nix build .#kata --max-jobs 4 --cores 32 --no-link --print-out-paths)"
    youki_out="$(nix build .#youki --no-link --print-out-paths)"
    cachix push katacode "$kata_out" "$youki_out"


# ─── Testing (always nextest, never plain `cargo test`) ──────
#
# Plain `cargo test` is not used here (AGENTS.md): it ignores the slow-timeouts.
# These recipes all route through `cargo nextest run` and pick
# up per-test slow-timeouts from .config/nextest.toml.

# Full workspace test. This is the pre-commit baseline.
#
# The load-sensitive soak GIANTS (recovery_100k and the
# merge-queue soak) are EXCLUDED here by `[profile.default] default-filter`
# and run separately by `just test-soak`. `just gate` runs both. This keeps
# the parallel suite fast and free of the cross-suite contention that would
# starve the giants past their kill caps (the cap-inflation arms race).
#
# `test`, `test-crate`, `test-one-crate`, `test-one` and `youki-pin-cells` source
# `scripts/test-tmpfs.sh` first (gate_exclusion's
# `the_suite_recipes_source_the_test_tmpfs_before_nextest` keeps them so): the run's
# TMPDIR is a fresh 0700 directory on a tmpfs (`$XDG_RUNTIME_DIR`, or `KATA_TEST_TMPFS`)
# that the recipe removes when it ends, and a host without one is refused, never run on
# disk instead. Every test tempdir reads TMPDIR, so no cell's SQLite commit waits on the
# disk's flush (verification.md, "Test TMPDIR"; the 2026-11-11 L1 red was a QLC SLC-cache
# stall, 7-21x on the fsync-heavy crates). Other nextest recipes, the soak, measurement
# and live ones among them, keep the inherited TMPDIR; verification.md says which and why.
# The removal waits for the suite, so a TERM sent to the `just` pid alone does not stop
# the run early: it ends when the suite does. Signal the process group (Ctrl-C,
# `kill -- -<pgid>`, `timeout`) to stop the suite itself. `test` checks the tmpfs before
# `_workspace-bins`, so a refused host pays no build first.
test: _test-tmpfs-check _workspace-bins
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/test-tmpfs.sh
    just _test-run

# `test`'s run, on the TMPDIR `test` made. A gate recipe that names nextest holds its
# runs and nothing else (gate_exclusion's `read_gates`), so the tmpfs, a lock and an
# exit status are its caller's.
_test-run:
    cargo nextest run --workspace

_test-tmpfs-check:
    bash scripts/test-tmpfs.sh --check

# Every binary and example a cell locates NEXT TO its test binary in
# `target/<profile>`: the provider binaries, `kata-oci-hook`, `kata-worker` and
# `kata-toolhost` (built for the host). A test build produces runnable
# bins only for packages with integration tests and examples only for the packages
# it selects — the workspace test build never makes `kata-provider-*` or
# `kata-oci-hook`, and a scoped one (`-p kata-worker`, cargo-mutants' per-package
# runs) makes none of them. Without this step a stale artifact left by an older
# tree stands in for the current one — a cell that handshakes a stale provider
# reports `provider_protocol_too_old` — or a missing one panics the cell: a RIG
# defect presented as a product verdict. `just test` and `just live-nanocode` take
# this dep for the same reason the gate's test-build and the nightly's mutation
# phase do: the located binary must be the one THIS tree builds.
#
# `--examples` is LOAD-BEARING although no member has an example: selecting example
# targets makes cargo resolve the dev-dependencies' features, which this build's bins
# then link with. Measured on a built tree: the same command without it recompiled 51
# crates (a second variant of every bin), so dropping it is a build, not a cleanup.
_workspace-bins:
    cargo build --workspace --bins --examples

# `kata-toolhost` as this tree builds it, in `target/debug`, and nothing else: the
# cells that run the real toolhost on the host (`kata-agent-nanocode`'s
# `toolhost_backpressure`) exec it from beside their test binary and refuse a stale
# one `toolhost_mismatch`. `just verify` runs it ahead of every route into that suite
# (`scripts/dev-loop.py`'s `LANE_PREREQUISITES` and the routing table's rows).
build-toolhost:
    cargo build -p kata-toolhost

# Build exactly what `just test` runs, and run nothing. The commit tier pays the test
# build here, beside `lint`, so that `test` itself starts on a fresh build and
# `test-doc` can overlap its RUN (see `_gate-commit-core`).
test-build: _workspace-bins
    cargo nextest run --workspace --no-run

# Refuse a run that changed the source tree it was judging: compares against the
# baseline its tier took at start (scripts/gate-source-tree.sh), and refuses any nested
# git repository outwright. The refused set is stated in scripts/source-tree-guard.py.
source-tree-unchanged:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${KATA_SOURCE_TREE_BASELINE:?source-tree-unchanged compares against the baseline its tier took at start; it runs inside gate, gate-push and gate-hosted}"
    python3 -B scripts/source-tree-guard.py verify "$KATA_SOURCE_TREE_BASELINE"

# Non-model-spending host feasibility probes. Missing optional
# prerequisites report unsupported/not_run; an available capability that violates
# its narrow probe contract fails the recipe.
feasibility-probes:
    python3 -B scripts/feasibility-probes.py

# The container-tools `oci` node environment realised as store paths and
# printed as the same `[node.environment]` TOML the packaged
# `share/kata/node-environment.toml` carries. The `.kata/node-environment`
# result symlink is an indirect GC root — without one the realised closure is
# collectable by the next `nix store gc`, exactly like `.kata/youki-root`.
node-environment:
    #!/usr/bin/env bash
    set -euo pipefail
    nix build -o .kata/node-environment -f nix/node-environment.nix
    nix eval --impure --expr '(import ./nix/node-environment.nix {}).passthru.node-environment-toml' --raw

# Refuses a vendored nanocode Code Mode engine (`vendor/nanocode-code-mode-engine`)
# that is not exactly nanocode's `crates/runtime/code-mode-engine` at the rev the
# workspace pins, with its manifest's workspace fields resolved, plus
# `vendor/nanocode-code-mode-engine.patch`: every changed, missing or extra file and
# every changed mode, by name. It reads upstream from git objects it fetches once
# into `~/.cache/kata/nanocode.git`, and refuses when it cannot fetch them.
# `just verify` routes `vendor/**` here; `dev-loop-check` runs it and its self-test.
nanocode-vendor-check:
    python3 -B scripts/nanocode-vendor.py check

# Moves kata to nanocode `rev` (a commit sha, branch or tag) in one step: the three
# direct pins in Cargo.toml and `NANOCODE_REV` (`scripts/nanocode-vendor.py bump`,
# which also re-derives `vendor/nanocode-code-mode-engine` at the new rev and
# re-applies `vendor/nanocode-code-mode-engine.patch`, refusing loudly — tree left
# as the pristine upstream copy — when the patch no longer applies), then the lock (re-resolved: nothing else moves),
# then flake.nix's nanocode `outputHashes` entry (`flake-hash`, which refuses and
# names the `nix build` recompute step for a rev it cannot hash exactly), then the
# vendor check and kata-agent-nanocode's tests: the seam pins (host tool sets, lock)
# and the Code Mode limit cells. docs/development/nanocode.md.
nanocode-bump rev:
    #!/usr/bin/env bash
    set -euo pipefail
    python3 -B scripts/nanocode-vendor.py bump "{{ rev }}"
    # Resolve, not `cargo update -p`: a moved git rev re-resolves exactly the
    # nanocode packages and what they newly need, and leaves every other lock
    # entry as it was (`update -p` re-picks among duplicate versions too).
    cargo metadata --format-version 1 > /dev/null
    python3 -B scripts/nanocode-vendor.py flake-hash
    python3 -B scripts/nanocode-vendor.py check
    just build-toolhost
    cargo nextest run -p kata-agent-nanocode

# N6 — the embedded harness's live acceptance (`bin/kata/tests/nanocode_live.rs`):
# a real turn in a real capsule (A1), the shipped `agent-change` pack landing
# offline on a local bare remote (A2), the daemon worker killed with a model
# request outstanding (A3) and during a tool call (A4), the main killed with
# its supervised node's turn outstanding and restarted (A3m), an operator
# cancel (A5), and the empty-response
# re-prompt measured — on `nanocode_openai` × kata's own ChatGPT login
# (`kata login openai`, once per host) and `nanocode_anthropic` ×
# `env:ANTHROPIC_API_KEY`, which the recipe's environment must carry: `( set -a;
# . .env; set +a; just live-nanocode )`. REAL SPEND; NOT part of any gate. Each
# cell's evidence lands in `target/test-logs/live-agents/nanocode-*.json`; its
# no-spend twin is `nanocode_interruption_live`, in `oci-live-smoke`.
live-nanocode: _workspace-bins
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p kata-toolhost --target x86_64-unknown-linux-musl
    # The workspace test build: the `kata` and `kata-worker` it spawns are the ones
    # `_workspace-bins` built, under one feature set.
    cargo nextest run --workspace -P live-smoke --test-threads=1 --run-ignored all \
        -E 'package(kata) & binary(nanocode_live)'
    ls -1 target/test-logs/live-agents/

# E3 — the crash / restart matrix (D2 §5.4): `bin/kata/tests/e3_crash_matrix_live.rs`, the
# process column (gate-main-kill, gate-worker-kill, P1-P4) on an installed main plus an
# external worker, one record per cell under `target/e3-evidence/`
# (`KATA_E3_EVIDENCE_DIR`). The default agent is `nanocode-mock`, `nanocode_openai`
# against a scripted mock provider: NO SPEND, a dry run whose records `just
# evidence-check` refuses (harness `nanocode-mock`). `KATA_E3_AGENT=nanocode-openai` or
# `=nanocode-anthropic` runs the same cells on a real model and SPENDS BUDGET, so the
# binary refuses it unless `KATA_E3_FUNDED=1` is set too. `KATA_E3_FORGE_CLONE=<local
# clone of kata-e2-fixture>` points P4 at the real forge and the host's `gh`, and is
# refused without `KATA_E3_FUNDED=1` too. On the mock the same cells are L1:
# `oci-live-smoke`'s eighth step runs them with those selectors unset. The host column is
# its own binary,
# `e3_crash_matrix_host_live`, run by hand on the VM with `KATA_E3_HOST_KILL_CMD`
# (its module doc states its two phases); no gate runs it.
e3-crash-matrix: _workspace-bins
    #!/usr/bin/env bash
    set -uo pipefail
    cargo build -p kata-provider-youki --bin kata-provider-youki || exit $?
    cargo build -p kata-oci-hook --bin kata-oci-hook || exit $?
    cargo build -p kata-toolhost --target x86_64-unknown-linux-musl || exit $?
    cargo nextest run -p kata -P live-smoke --test-threads=1 --run-ignored all \
        --success-output final -E 'binary(e3_crash_matrix_live)'

# The serialized soak pass — the load-sensitive GIANTS only,
# run one-at-a-time (heavy-io-soak, max-threads=1) with no parallel
# suite thrashing them, so their timing is meaningful. `just gate`
# runs this AFTER `just test`; run it standalone to exercise the
# giants (a bare `-E test(recovery_100k…)` under the default profile
# is intentionally filtered to empty — reach them here). Runs the
# lane-partition invariant first so a giant-list desync fails loudly.
test-soak: soak-lane-invariant
    cargo nextest run --workspace -P soak

# Runs the full writer and live-HOME identity timing workloads serially.
# Completion proves their assertions, not controlled throughput qualification
# or a portable home-identity latency guarantee. This is not a host reservation.
test-measurement:
    cargo nextest run --workspace -P measurement --test-threads 1

# Guard the giant-list desync hazard. The set of soak GIANTS is
# hand-maintained in TWO places in `.config/nextest.toml`: the
# `[profile.default] default-filter` that EXCLUDES them from the parallel
# suite, and the `[profile.soak] default-filter` that INCLUDES exactly them.
# If those two lists drift, the default run and the soak pass stop
# PARTITIONING the suite — a giant runs in NEITHER lane (silent coverage
# hole) or BOTH (double run). Equal cardinalities do not prove a partition:
# an omission can cancel an overlap. Compare (binary-id, test-name) sets from
# nextest JSON, honoring testcase filter-match and ignored fields. Refuse
# overlap, omission, unexpected tests, empty lanes and malformed enumeration.
soak-lane-invariant:
    python3 -B scripts/check-test-partition.py

# One crate.
test-crate crate:
    #!/usr/bin/env bash
    set -euo pipefail
    package="{{crate}}"
    if [ -f "crates/{{crate}}/Cargo.toml" ]; then
        package="$(sed -n 's/^name = "\(.*\)"/\1/p' "crates/{{crate}}/Cargo.toml" | head -n1)"
    fi
    # `--no-tests=warn` (warning + exit 0), and ONLY on this unfiltered,
    # package-scoped recipe. The refused set is unchanged: this recipe claims "every
    # test this package has, ran", and for a package that has none —
    # `kata-oci-hook` is a thin bin whose proofs are the live cells that run it — that
    # claim is vacuously true, while nextest's default `fail` reports exit 4, which reads
    # as a test FAILURE. `dev-loop.py` derives `validate-crate` runs for a changed
    # crate's direct dependents, so a test-less dependent would otherwise fail `just
    # verify` (and `gate-scoped`) on a crate with nothing to run. The FILTERED recipes
    # below keep the default, where zero tests means the filter matched nothing and
    # the run really is vacuous.
    source scripts/test-tmpfs.sh
    cargo nextest run --no-tests=warn -p "$package"

# Filter by test name inside one crate. Prefer this over `test-one` when
# the touched files map cleanly to a single crate.
test-one-crate crate filter:
    #!/usr/bin/env bash
    set -euo pipefail
    package="{{crate}}"
    if [ -f "crates/{{crate}}/Cargo.toml" ]; then
        package="$(sed -n 's/^name = "\(.*\)"/\1/p' "crates/{{crate}}/Cargo.toml" | head -n1)"
    fi
    # --ignore-default-filter: the explicit filter is always present, so
    # this is safe, and it lets a filter for a soak GIANT (excluded from the
    # default profile) still reach the test instead of listing empty (exit 4).
    source scripts/test-tmpfs.sh
    cargo nextest run -p "$package" --ignore-default-filter "{{filter}}"

# Filter by test name across the entire workspace.
# Usage: just test-one max_concurrency_two_caps_in_flight_and_completes_all
# --ignore-default-filter: the explicit filter is always present (safe),
# and it lets a filter for a soak GIANT — excluded from `[profile.default]` — still
# reach the test rather than listing empty (nextest exit 4, misread as a FAIL).
test-one filter:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/test-tmpfs.sh
    cargo nextest run --workspace --ignore-default-filter {{filter}}

validate-crate crate filter="":
    #!/usr/bin/env bash
    set -euo pipefail
    just fmt
    just lint-crate "{{crate}}"
    if [ -n "{{filter}}" ]; then
        just test-one-crate "{{crate}}" "{{filter}}"
    else
        just test-crate "{{crate}}"
    fi

# Tier 1 — the deterministic, agent-shaped acceptance harness
# (`bin/kata/tests/agent_acceptance.rs`). A scripted agent-shaped driver
# issues real Operations ONLY through the shared surface in lifecycle order and
# VERIFIES each temporal invariant at a real engine observable (the counting
# MockAgentBackend), not by output-equality. Mock-backed + deterministic, so it
# GATES unconditionally. Rides in `just gate` after `just test`.
#
# It does not RE-RUN the harness. `agent_acceptance` has no `#[ignore]`, so `just test`
# already ran every test in it; a re-run under `-p kata` would rebuild `kata` for a
# second feature set and prove nothing the first run had not. It proves what a re-run
# would not: that every test in the harness is IN the suite and PASSED there — read
# from `just test`'s JUnit report (scripts/check-junit-ran.py,
# which refuses an empty selection, an absent test and a failed one). Standalone, it
# vouches for the most recent `just test` report and prints when that was written.
agent-accept:
    python3 -B scripts/check-junit-ran.py -E 'package(kata) & binary(agent_acceptance)'

# The youki pin's own refusals: pin parse field refusals (kata-types), the
# rendered-profile golden (kata-worker), and the non-root install / digest mismatch /
# failed-reload / loaded-list-fold refusals (kata's host_setup). Host-independent —
# each plants its own fixtures and never reads the pinned binary or /etc — and none is
# `#[ignore]`d, so `just test` runs every one. ONE filter, two readers:
#
#   * `youki-pin-cells` RUNS them: `just verify` routes the pin's own files
#     (`config/youki-pin.toml`, `nix/youki.nix`) here, which no crate lane reaches.
#   * `youki-pin-cells-ran` is the commit tier's: like `agent-accept` it reads `test`'s
#     JUnit report that every selected cell RAN AND PASSED instead of re-running them,
#     and a selection empty because every name drifted is refused (one drifted name
#     is not: the filter is a union, so the rest still select).
#
# `--workspace` + `package(...)`, never `-p`: the run reuses `just test`'s build rather
# than unifying features for a second variant (gate_exclusion refuses the other shape).
youki_pin_cells := "(package(kata-types) | package(kata-worker) | package(kata)) & (test(the_embedded_pin_parses_into_exactly_the_shipped_fields) + test(each_refusal_fires_and_names_its_field) + test(an_unknown_field_is_refused_rather_than_ignored) + test(the_rendered_profile_is_the_literal_golden) + test(a_non_root_install_refuses_and_writes_nothing) + test(the_install_writes_the_render_and_reloads_it) + test(a_failed_reload_names_the_argv_and_leaves_the_file) + test(the_loaded_check_folds_the_kernels_list))"

youki-pin-cells:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/test-tmpfs.sh
    cargo nextest run --workspace -E '{{ youki_pin_cells }}'

youki-pin-cells-ran:
    python3 -B scripts/check-junit-ran.py -E '{{ youki_pin_cells }}'

# The ADVERSARIAL-INPUT sweep, riding `just gate`.
#
# WHY IT IS NOT CALLED FUZZING. There is no `fuzz/` directory, no `cargo-fuzz`
# target, no proptest and no quickcheck anywhere in the workspace. "The gate runs
# fuzzing" and "the gate runs a handful of `arbitrary`-driven conformance modules"
# are different claims, and the name says the true one.
#
# THE PROPERTY, and the tests that assert it:
#   * kata-transport `types::conformance` — draws adversarial WorkerControl /
#     WorkerMessage VALUES and round-trips them through the live serde_json wire codec
#     (identity-checked; stable-hash corpus in `crates/transport/conformance.toml`).
#   * kata-transport `local_socket::conformance` — feeds arbitrary BYTES through the
#     length-prefixed frame decoder, asserting no panic and no unbounded allocation.
#   * kata-program `starlark_eval*::conformance` — the adversarial `.star`
#     inline-compile target, the untrusted authoring surface.
# Each draws a fixed deterministic sample budget with a small per-input wall-clock cap,
# so the whole set is a couple of seconds — fast and deterministic enough to gate.
#
# A SECOND, per-crate invocation would not be a guard: a `-p kata-program` run of the
# same filter is a strict SUBSET of the workspace run, and nothing about it FAILS if
# the workspace sweep stops reaching the starlark target. AN ASSERTION does.
# `test(conformance)` is a test-NAME substring filter, so renaming `mod conformance`
# anywhere quietly shrinks the selection and the recipe still exits 0 having proved
# less — a verification satisfiable by observing almost nothing. The floor below fails
# loudly instead, and names the
# packages rather than a test count, because a count is a number somebody will "fix" by
# editing the number.
test-conformance:
    #!/usr/bin/env bash
    set -euo pipefail
    # `binary(contract_parity)` is in the filter because `test(conformance)` is a
    # test-NAME substring. The CROSS-FACE conformance
    # harness is `bin/kata/tests/contract_parity.rs`, and not one of its four
    # tests has "conformance" anywhere in its name — measured: the workspace's tests
    # listed under `-E 'test(conformance)'` hold 0 `contract_parity` lines, while
    # `-E 'binary(contract_parity)'` lists 4. Without the binary
    # clause a REQUIRED gate step named for conformance would never run the harness
    # that proves it, and a floor asking only that the selection span `kata-transport`
    # and `kata-program` (the commonware adversarial-draw suites) could not see that.
    # It is the trap AGENTS.md names: a bare name filter is a test-NAME substring
    # and can silently select zero.
    filter='test(conformance) or binary(contract_parity)'

    # The selection, as one `<binary-id> <test>` line per selected test — and each one
    # already proven to have RUN AND PASSED in `just test`'s JUnit report. `just test`
    # ran the same tests under the same profile, so a re-run would be a second verdict
    # on nothing new. scripts/check-junit-ran.py refuses a selected test the report does
    # not show passing, and an empty selection.
    #
    # Its stderr is NOT discarded: the listing builds, and a compile error must read as
    # one, not as "selected 0 tests". A failure for the wrong reason is not evidence.
    if ! listing="$(python3 -B scripts/check-junit-ran.py -E "$filter")"; then
        echo "test-conformance: the selection is not vouched for by the 'just test' report (above)." >&2
        exit 1
    fi
    selected="$(printf '%s\n' "$listing" | grep -cE '\S' || true)"

    missing=0
    for pkg in kata-transport kata-program; do
        # A here-string, not `printf | grep -q`: under `pipefail` an early grep match
        # SIGPIPEs a producer still writing (rc 141) and reads as "not selected".
        if ! grep -q -- "$pkg" <<<"$listing"; then
            echo "test-conformance: NO adversarial-draw test selected from ${pkg}." >&2
            missing=1
        fi
    done
    # The floor above spans only the adversarial-draw packages, so it stays green
    # with the cross-face harness unselected. Named separately
    # because it is a different property: those two prove a protocol under an
    # adversarial draw, this one proves the FACES agree, and a recipe called
    # `test-conformance` is read as proving both.
    if ! grep -q 'contract_parity' <<<"$listing"; then
        echo "test-conformance: NO cross-face parity test selected. The harness is" >&2
        echo "  bin/kata/tests/contract_parity.rs and none of its test NAMES" >&2
        echo "  contain 'conformance', so a name filter alone selects zero of them and" >&2
        echo "  still exits 0." >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ] || [ "$selected" -lt 8 ]; then
        echo "test-conformance: the 'test(conformance)' filter selected ${selected} test(s)" >&2
        echo "  and did not span both adversarial-draw packages. That filter is a test-NAME" >&2
        echo "  SUBSTRING: renaming a 'mod conformance' does not fail anything, it just" >&2
        echo "  selects less, and the run still exits 0. If a harness moved, point this" >&2
        echo "  recipe at where it moved to — do not let the gate quietly prove less." >&2
        printf '%s\n' "$listing" >&2
        exit 1
    fi
    parity="$(printf '%s\n' "$listing" | grep -c 'contract_parity' || true)"
    echo "test-conformance: ${selected} tests selected, ran and passed in 'just test' — adversarial-draw across kata-transport + kata-program, plus ${parity} cross-face parity"

# ─── Eval harness ───────────────────────────────────────────────────
#
# `just eval` runs the DETERMINISTIC eval tier: every golden fixture's routing +
# rendering (crates/workflow/tests/fixture_corpus.rs), the checked-IR
# coverage authority (crates/workflow/tests/checked_ir_coverage.rs), AND the
# `kata-eval` proof-harness deterministic suite over the committed golden coding
# tasks under `test/eval/tasks/` — the honesty rail (every validator FAILS on its
# untouched fixture), the mock-backend pipeline (validators DISCRIMINATE: a
# canned solution passes, a no-op fails), the cap-guard trip, and the report
# render. No models, no cost. All are ordinary nextest tests so they ALSO ride in
# `just gate`; `just eval` is the focused entry.
eval:
    cargo nextest run -p kata-workflow \
        -E 'binary(fixture_corpus) or binary(checked_ir_coverage)'
    cargo nextest run -p kata-eval

# `just eval-live` runs the LIVE eval tier: the committed golden coding tasks
# under `test/eval/tasks/` driven through a REAL model backend on an installed main, ONE
# task at a time, under a HARD total-spend cap enforced from the metered ledger
# (`running_cost_micro_usd`) — the cap is `KATA_EVAL_CAP_USD` (default $20.00).
# OPERATOR-INVOKED ONLY: it requires the explicit `KATA_EVAL_LIVE=1` spend
# acknowledgment and is absent from the statically modelled `just gate` recipe graph
# by `gate_static_recipe_graph_excludes_the_live_eval_tier` in kata-eval's
# bounded structural model; external scripts are outside that model). It produces a
# generated report at `target/eval/reports/<date>-<model>.{md,json}`.
#
#   KATA_EVAL_LIVE=1 \
#   KATA_EVAL_CONFIG=/path/to/fragment.toml \  # [agents.*] FRAGMENT with capsule fields
#   KATA_EVAL_MODEL=claude-sonnet-4-5 \        # label recorded in the report
#   KATA_EVAL_CAP_USD=20.00 \
#   just eval-live
#
# The fragment is appended to a `kata init` config per task and must carry, for
# every `[agents.X]` it declares, the fields the `oci` admission judges:
# `adapter` and `credential`. A fragment without them is refused
# `adapter_undeclared`/`credential_undeclared` at check — the honest door,
# spent before any model call.
#
# Enforcement is kata-side metering, not vibes: before each task the cap guard
# (`kata-eval cap-check`) refuses to start a task whose declared upper-bound cost
# could push cumulative METERED spend past the cap, and the run aborts cleanly.
eval-live:
    #!/usr/bin/env bash
    set -euo pipefail
    # This recipe boots an installed main, a PER-UID singleton. Queue instead
    # of colliding. Safe ONLY because the watchdog armed below bounds a hang —
    # locking a hang would block every other run behind it.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just eval-live
    fi
    source scripts/smoke-harness.sh
    # A hung run holds the PER-UID installed main and breaks every
    # later one. The EXIT trap cannot help — a trap needs the shell to exit,
    # and a hang is precisely the shell not exiting. Only an external timer can.
    arm_watchdog "eval-live"
    repo_root="$(pwd)"

    if [ "${KATA_EVAL_LIVE:-}" != "1" ]; then
        echo "eval-live spends real model budget and runs only when the operator asks." >&2
        echo "Set KATA_EVAL_LIVE=1 to acknowledge the cost cap before running." >&2
        exit 2
    fi

    # Smokes must run FRESH binaries: a stale target/debug/kata smokes a tree
    # that is not the one under test.
    cargo build -p kata -p kata-eval -p kata-provider-youki -p kata-oci-hook
    kata_bin="$repo_root/target/debug/kata"
    eval_bin="$repo_root/target/debug/kata-eval"
    export PATH="$repo_root/target/debug:$PATH"
    source scripts/oci-smoke-node.sh

    cap_usd="${KATA_EVAL_CAP_USD:-20.00}"
    model="${KATA_EVAL_MODEL:-default}"
    src_config="${KATA_EVAL_CONFIG:-}"
    per_task_timeout="${KATA_EVAL_TASK_TIMEOUT_SECS:-600}"
    tasks_dir="$repo_root/test/eval/tasks"
    out_dir="$repo_root/target/eval/reports"

    tmp="$(mktemp -d)"
    results="$tmp/results.json"; echo "[]" >"$results"
    oci_smoke_provision_provider "$tmp" "$kata_bin" "$repo_root/target/debug"
    mapfile -t oci_extra < <(oci_smoke_nix_paths nixpkgs#python3)
    spent_micro=0
    aborted=false
    abort_reason=""
    pid=""
    cfg=""
    # eval-live OWNS its cleanup so the installed main is ALWAYS terminated and the
    # scratch dir ALWAYS removed on EVERY exit path. We override the sourced
    # cleanup() (which would run a recipe-defined `capture_evidence` first —
    # eval-live has no evidence packet; its deliverable is the report under
    # target/eval/reports/) because it has two `set -euo pipefail` hazards: (1) an
    # undefined capture_evidence makes the EXIT trap die with 127 before any
    # teardown; (2) the shared terminate_solo returns non-zero once the node is
    # dead (its `solo_alive || return` artifact), which would abort the sourced
    # cleanup BEFORE `remove_scratch "$tmp"` on a failure exit and leak the temp dir.
    # `terminate_solo || true` neutralizes both while still killing the node.
    # (Guarded by gate_exclusion.rs::eval_live_exit_trap_tears_down_cleanly.)
    cleanup() { disarm_watchdog || true; terminate_solo || true; remove_scratch "$tmp"; }
    trap cleanup EXIT

    tasklist="$("$eval_bin" task-list --tasks-dir "$tasks_dir")"
    total_tasks="$(printf '%s' "$tasklist" | jq 'length')"
    echo "eval-live: $total_tasks golden tasks, cap \$$cap_usd, model $model" >&2

    for id in $(printf '%s' "$tasklist" | jq -r '.[].id'); do
        row="$(printf '%s' "$tasklist" | jq -c --arg id "$id" '.[] | select(.id==$id)')"
        task_cap="$(printf '%s' "$row" | jq -r '.max_cost_micro_usd')"
        title="$(printf '%s' "$row" | jq -r '.title')"

        # Cap guard BEFORE spending on this task.
        if ! "$eval_bin" cap-check --cap-usd "$cap_usd" --spent-micro "$spent_micro" --task-cap-micro "$task_cap" 2>"$tmp/cap.err"; then
            aborted=true; abort_reason="$(cat "$tmp/cap.err")"
            echo "eval-live: cap guard tripped before $id — $abort_reason" >&2
            break
        fi

        # Materialize a per-task repo with ONLY the fixture + validator + workflow
        # (never solution/ or task.toml — the model must not see the answer).
        proj="$tmp/proj-$id"; mkdir -p "$proj"
        cp -r "$tasks_dir/$id/fixture/." "$proj/"
        cp "$tasks_dir/$id/validate.sh" "$proj/validate.sh"
        cp "$tasks_dir/$id/workflow.star" "$proj/workflow.star"
        git -C "$proj" init -b main >/dev/null
        git -C "$proj" config user.email "kata-eval@example.invalid"
        git -C "$proj" config user.name "kata eval"
        git -C "$proj" add -A
        git -C "$proj" commit -m "seed eval task $id" >/dev/null

        port=0; metrics_port=0
        api="http://127.0.0.1:${port}"
        runtime="$tmp/rt-$id"; cfg="$runtime/kata.toml"
        (cd "$proj" && "$kata_bin" init --config "$cfg" >/dev/null)
        perl -0pi -e 's/bind = "127\.0\.0\.1:8400"/bind = "127.0.0.1:'"$port"'"/' "$cfg"
        perl -0pi -e 's/metrics_bind = "127\.0\.0\.1:9400"/metrics_bind = "127.0.0.1:'"$metrics_port"'"/' "$cfg"
        # Append the DRIVER's real-backend config (an [agents.*]-only FRAGMENT).
        # The generated init config already defines [agents.default] and
        # [agents.shell]; TOML rejects duplicate tables (a fragment redefining
        # [agents.default] kills installed-main boot with "duplicate key
        # `default` in table `agents`"). So for every [agents.X]
        # table the fragment declares, STRIP the generated block of the same
        # name first, then append — the fragment wins, everything else is kept.
        if [ -n "$src_config" ]; then
            for tbl in $(grep -oE '^\[agents\.[A-Za-z0-9_-]+\]' "$src_config" | tr -d '[]'); do
                perl -0pi -e 's/\n\[\Q'"$tbl"'\E\][^\[]*/\n/s' "$cfg"
            done
            printf '\n' >>"$cfg"; cat "$src_config" >>"$cfg"
        fi

        # `kata init` cannot invent the machine facts an `oci` node
        # needs, so the recipe declares them once per task. The environment
        # closure is the pinned live roots plus `nixpkgs#python3` (the
        # validators' interpreter — a host binary's `/lib64` interpreter is
        # not in the capsule rootfs). The fragment above is the driver's own
        # config and must carry its OWN agent fields (`adapter`,
        # `credential`) — a fragment without them is refused
        # `adapter_undeclared` at check, which is the honest door.
        oci_smoke_inject_environment "$cfg" "eval-live-$id" \
            "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT" "${oci_extra[@]}"

        # `serve` hosts the capsule route — a delegated scope, bound above the
        # per-task timeout, provider exports already on this process's env.
        (cd "$proj" && exec systemd-run $(oci_smoke_delegate_args $((per_task_timeout + 600))) \
            "$kata_bin" serve --config "$cfg" >"$tmp/solo-$id.log" 2>&1) &
        pid="$!"
        remember_solo
        # Point the harness's fixed diagnostic path ($tmp/solo.log, tailed by
        # wait_for_api on a boot failure) at THIS task's per-task node log so the
        # first-failure dump the driver needs is never empty.
        ln -sfn "$tmp/solo-$id.log" "$tmp/solo.log"
        wait_for_api "eval-live:$id"

        start_ns="$(date +%s%N)"
        (cd "$proj" && "$kata_bin" --api-url "$api" run workflow.star --submit >"$tmp/submit-$id.json")
        exec_id="$(jq -r '.id' "$tmp/submit-$id.json")"
        "$kata_bin" --api-url "$api" run wait "$exec_id" --timeout-secs "$per_task_timeout" --poll-ms 500 >"$tmp/wait-$id.json" || true
        end_ns="$(date +%s%N)"
        wall_ms=$(( (end_ns - start_ns) / 1000000 ))

        "$kata_bin" --api-url "$api" run show "$exec_id" >"$tmp/show-$id.json"
        status="$(jq -r '.status // "unknown"' "$tmp/show-$id.json")"
        cost_micro="$(jq -r '.running_cost_micro_usd // 0' "$tmp/show-$id.json")"
        # pass/fail from the workflow's OWN shell validate stage (the eval IS kata
        # running); tokens best-effort from the solve stage's token_usage.
        "$kata_bin" --api-url "$api" run output "$exec_id" validate >"$tmp/validate-$id.json" 2>/dev/null || echo '{}' >"$tmp/validate-$id.json"
        "$kata_bin" --api-url "$api" run output "$exec_id" solve >"$tmp/solve-$id.json" 2>/dev/null || echo '{}' >"$tmp/solve-$id.json"
        passed="$(jq -r '(.parsed.passed // false)' "$tmp/validate-$id.json")"
        vexit="$(jq -r '(.parsed.exit_code // -1)' "$tmp/validate-$id.json")"
        tok_in="$(jq -r '(.token_usage.input // .parsed.token_usage.input // 0)' "$tmp/solve-$id.json")"
        tok_out="$(jq -r '(.token_usage.output // .parsed.token_usage.output // 0)' "$tmp/solve-$id.json")"

        # Same `solo_alive || return` artifact the cleanup() comment documents:
        # once the node is DEAD (the success case), terminate_solo returns
        # non-zero and would abort the whole run under set -e after task 1.
        terminate_solo || true
        pid=""

        spent_micro=$(( spent_micro + cost_micro ))
        jq \
          --arg id "$id" --arg title "$title" --arg status "$status" \
          --argjson passed "$passed" --argjson vexit "$vexit" \
          --argjson wall "$wall_ms" --argjson cost "$cost_micro" \
          --argjson tin "$tok_in" --argjson tout "$tok_out" \
          '. + [{
            id:$id, title:$title, passed:($passed==true), skipped:false,
            validator_exit_code:$vexit, wall_ms:$wall, tokens_in:$tin, tokens_out:$tout,
            cost_micro_usd:$cost, note:("run "+$status), detail:""
          }]' "$results" >"$results.next" && mv "$results.next" "$results"
        echo "eval-live: $id → $status (passed=$passed, cost=${cost_micro}µUSD, spent=${spent_micro}µUSD)" >&2

        # Post-charge cap check (task_cap 0 → pure over-cap guard).
        if ! "$eval_bin" cap-check --cap-usd "$cap_usd" --spent-micro "$spent_micro" --task-cap-micro 0 2>"$tmp/cap.err"; then
            aborted=true; abort_reason="$(cat "$tmp/cap.err")"
            echo "eval-live: metered spend crossed the cap after $id — $abort_reason" >&2
            break
        fi
    done

    report_args=(report --results-json "$results" --model "$model" --backend "$model" --cap-usd "$cap_usd" --tasks-total "$total_tasks" --out "$out_dir")
    if [ "$aborted" = true ]; then report_args+=(--aborted --abort-reason "$abort_reason"); fi
    "$eval_bin" "${report_args[@]}"
    echo "eval-live: report written under $out_dir (metered spend ${spent_micro}µUSD, cap \$$cap_usd)" >&2

# Criterion latency benches. NOT part of `just gate` — benches build the
# release profile and take minutes; the gate stays fast. `just bench` runs
# every workspace bench; `just bench-crate <crate>` scopes to one. The hot
# paths guarded: the agent-output validate/retry gate
# (`crates/types/benches/validate_retry`), the per-dispatch prompt render
# (`crates/workflow/benches/dispatch`), the orchestrator replay-fold
# (`crates/workflow/benches/replay_fold`), and the kata-core ledger + recovery
# paths (`crates/core/benches/**`).
bench:
    cargo bench --workspace

bench-crate crate:
    #!/usr/bin/env bash
    set -euo pipefail
    package="{{crate}}"
    if [ -f "crates/{{crate}}/Cargo.toml" ]; then
        package="$(sed -n 's/^name = "\(.*\)"/\1/p' "crates/{{crate}}/Cargo.toml" | head -n1)"
    fi
    cargo bench -p "$package"

# ── Criterion baseline + regression gate. ──
#
# OPERATOR-INVOKED, machine-dependent — deliberately NOT wired into `just gate`.
# Absolute bench timings depend on the host CPU/storage and ambient load, so a
# gated perf number would false-fail on a busy host; this is the perf sibling of
# `just eval-live` — a separate recipe a maintainer runs on a quiet machine.
#
# Two-step flow, both over the whole workspace (takes several minutes — the
# kata-core recovery bench alone builds a 100k-event corpus):
#
#   just bench-baseline           # snapshot current timings as baseline 'kata-main'
#   …make a change…
#   just bench-check              # re-measure + FAIL if any bench regressed > 20%
#
# `bench-check` re-runs criterion (saving baseline `kata-current`), prints the
# critcmp comparison table, then a machine-checked gate reads critcmp's JSON
# export of both baselines and exits non-zero if ANY benchmark's mean is more
# than THRESHOLD percent slower than the saved reference. Refresh the reference
# after an intentional perf change by re-running `just bench-baseline`.
BENCH_BASELINE := "kata-main"

bench-baseline name=BENCH_BASELINE:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "saving criterion baseline '{{name}}' across the workspace (several minutes)…"
    cargo bench --workspace -- --save-baseline "{{name}}"
    echo "baseline '{{name}}' saved. 'just bench-check' compares against it; re-run 'just bench-baseline' to refresh after an intentional perf change."

bench-check name=BENCH_BASELINE threshold="20":
    #!/usr/bin/env bash
    set -euo pipefail
    command -v critcmp >/dev/null 2>&1 || {
        echo "critcmp not found — install with: cargo install critcmp" >&2
        exit 1
    }
    if ! critcmp --baselines | grep -qx "{{name}}"; then
        echo "no saved baseline '{{name}}' — run 'just bench-baseline {{name}}' first" >&2
        exit 1
    fi
    echo "re-measuring the workspace benches (several minutes)…"
    cargo bench --workspace -- --save-baseline kata-current
    echo
    echo "=== critcmp {{name}} -> kata-current ==="
    critcmp "{{name}}" kata-current || true
    # Machine-checked threshold gate on each bench's mean point-estimate.
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    critcmp --export "{{name}}"     > "$tmp/base.json"
    critcmp --export kata-current   > "$tmp/cur.json"
    python3 - "$tmp/base.json" "$tmp/cur.json" "{{threshold}}" "{{name}}" <<'PY'
    import json, sys
    base = json.load(open(sys.argv[1]))["benchmarks"]
    cur  = json.load(open(sys.argv[2]))["benchmarks"]
    thr_pct = float(sys.argv[3]); thr = thr_pct / 100.0
    ref = sys.argv[4]
    regressions, compared = [], 0
    for name, cb in cur.items():
        bb = base.get(name)
        if bb is None:
            continue
        b = bb["criterion_estimates_v1"]["mean"]["point_estimate"]
        c = cb["criterion_estimates_v1"]["mean"]["point_estimate"]
        if b <= 0:
            continue
        compared += 1
        delta = (c - b) / b
        if delta > thr:
            regressions.append((name, b, c, delta * 100.0))
    if not compared:
        print(f"no benchmarks in common with baseline '{ref}' — nothing gated", file=sys.stderr)
        sys.exit(1)
    if regressions:
        print(f"\nPERF REGRESSION: {len(regressions)}/{compared} bench(es) slower than "
              f"baseline '{ref}' by > {thr_pct:g}%:")
        for n, b, c, d in sorted(regressions, key=lambda x: -x[3]):
            print(f"  {n}: {b:,.0f}ns -> {c:,.0f}ns (+{d:.1f}%)")
        sys.exit(1)
    print(f"\nOK: all {compared} benchmarks within {thr_pct:g}% of baseline '{ref}'.")
    PY

# ── Footprint floors ─────────────────────────────────────────────
#
# Two load-robust ceilings that ride `just gate-push` (a plain recipe
# called from the push tier's body). Both are ceilings,
# not tripwires: sized ~4x over the current measured value so normal
# growth passes and only egregious bloat (debug info leaking into
# release, a fat asset embed, a boot-time allocation blow-up) trips them.
#
#   1. RELEASE BINARY SIZE. The shipped RELEASE binary is ~42 MiB
#      (measured; the DEBUG build is far larger and is not what ships).
#      Gate it against a generous 160 MiB ceiling (~4x).
#   2. BOOT RSS. Boot an installed main on a throwaway tempdir (isolated HOME +
#      stdlib, kernel-assigned port), wait until its API accepts, read
#      VmRSS from /proc, and gate it against a generous 150 MiB ceiling.
#      Measured installed-main boot RSS ≈ 27-35 MiB across two hosts, so
#      150 MiB is ~4-5x — a shape guard, not a tripwire.
#
# Cost: `just build` — the workspace release build that IS the shipped artifact's
# build, and in the push tier already paid by `_gate-push-core`, so fresh here. A
# separate `--release -p kata` build would be different feature unification, a
# second LTO build, and not the bytes that ship.
#
# Cleanup is thorough — the node is fully killed before the recipe returns so
# the gate's trailing `pgrep-stale` stays green. Run standalone with
# `just footprint-check`.
FOOTPRINT_SIZE_CEIL_MIB := "160"
FOOTPRINT_RSS_CEIL_MIB := "150"
# Boot-ready wait budget (seconds). Loop step is 0.5s, so the recipe polls
# `2 * ready_secs` times. Sized generously (180s) because on a host under heavy
# concurrent `cargo` build load — the exact `just gate` condition — first-boot
# link/page-in can take well past a minute; a 60s window FALSE-FAILS under
# ~380s of concurrent build pressure. Recipe params are
# positional, so to shrink the window on a fast idle host pass all three:
# `just footprint-check 160 150 60`.
FOOTPRINT_READY_SECS := "180"

footprint-check size_ceil_mib=FOOTPRINT_SIZE_CEIL_MIB rss_ceil_mib=FOOTPRINT_RSS_CEIL_MIB ready_secs=FOOTPRINT_READY_SECS:
    #!/usr/bin/env bash
    set -euo pipefail
    python3 -B scripts/test-smoke-ownership.py
    source scripts/smoke-harness.sh

    # This recipe boots a REAL installed main, which claims the per-uid singleton at
    # `/tmp/kata-installed-main-<uid>/discovery.lock`. The comment further down says the
    # gate's "pgrep-stale bookends guarantee no other main contends" — true of one gate
    # in isolation, and false the moment another worktree runs a live smoke or the
    # containment lane. Take the lock so the two QUEUE; without it both lose and the
    # loser's failure names a timeout in the node under test rather than the contender.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just footprint-check {{size_ceil_mib}} {{rss_ceil_mib}} {{ready_secs}}
    fi

    echo "footprint-check: building the release workspace (the shipped artifact's build)…"
    just build
    bin="target/release/kata"
    [ -x "$bin" ] || { echo "footprint-check: release binary not found at $bin" >&2; exit 1; }
    source scripts/oci-smoke-node.sh

    # ── Floor 1: release binary size ──────────────────────────────
    size_bytes=$(stat -c%s "$bin")
    size_mib=$(( size_bytes / 1024 / 1024 ))
    ceil_mib="{{size_ceil_mib}}"
    echo "footprint-check: release binary size = ${size_mib} MiB (ceiling ${ceil_mib} MiB)"
    if [ "$size_mib" -gt "$ceil_mib" ]; then
        echo "footprint-check: FAIL — release binary ${size_mib} MiB exceeds ${ceil_mib} MiB ceiling." >&2
        echo "  Actionable: check for debug info in release (strip/split-debuginfo), a fat" >&2
        echo "  embedded asset, or an unintended heavy dependency. Compare 'cargo bloat" >&2
        echo "  --release -p kata --crates' against the prior build." >&2
        exit 1
    fi

    # ── Floor 2: solo boot RSS ────────────────────────────────────
    bin_abs="$PWD/$bin"
    tmp="$(mktemp -d)"
    data_dir="$tmp/data"; mkdir -p "$data_dir"
    stdlib_dir="$tmp/stdlib"; mkdir -p "$stdlib_dir"
    log="$tmp/kata.log"
    kata_pid=""
    pid=""
    cleanup() {
        terminate_solo || true
        # Only the main's generation-aware RAII withdrawal owns its attachment.
        # Process absence cannot prove that a shared descriptor belongs to this
        # measurement; forced termination leaves residue for explicit recovery.
        # The provider's export store is mode r-x by construction (immutable
        # store objects); `remove_scratch` restores the write bit first.
        remove_scratch "$tmp"
    }
    trap cleanup EXIT

    # Kernel-assigned ports + patched config. The derivation lives in
    # `scripts/footprint-config.sh` so this recipe and the guard that checks it
    # share ONE definition; that script's header carries the why. In short: the
    # gate is HOST-INDEPENDENT BY CONSTRUCTION and this is the only gate step
    # that boots the product, so it must not boot a config that needs anything
    # of the host. `config/kata.example.toml` verbatim declares model-agent
    # entries a footprint step never selects, and no `[node] environment` — a
    # verbatim boot is refused `node_environment_undeclared`.
    #
    # `metrics_bind` and `jj_repo` are patched for the same reason `bind` is:
    # unpatched, both reach outside this run's tempdir. A busy 9400 silently
    # drops the Prometheus recorder (soft degradation), and `jj_repo = ".."`
    # resolves from the CONFIG FILE's directory — which for a `mktemp -d` config
    # is `/tmp`, so boot opened and op-log-GC-swept whatever `/tmp/.jj` the host
    # happened to have. Both made the measured shape depend on host state.
    port=0
    metrics_port=0
    jj_repo="$tmp/repo"
    mkdir -p "$jj_repo"
    cfg="$tmp/kata.toml"
    # NON-VACUITY lives in the SCRIPT, not here. It reads the four patched values
    # back out of the parsed result and pins `[agents]` to exactly `shell` before
    # it emits a byte, so a broken derivation fails on THIS line, naming the key,
    # rather than 180s later as a ready-timeout. This recipe does not re-check the
    # agent table with `grep -E '^\[agents\.'` — a second predicate over one
    # artifact, which disagrees with a TOML parse on an `[agents.shell.env]`
    # sub-table and on an inline `agents.shell = {}`. Two
    # predicates that agree today are a drift waiting to happen; there is one.
    # `set -e` above makes the script's refusal fatal here.
    scripts/footprint-config.sh "$data_dir" "$port" "$metrics_port" "$jj_repo" > "$cfg"

    # The derived config declares the busybox `[node] environment` an `oci`
    # node boots, so this main passes three doors — the environment's
    # declare-time verify shells `nix`, the
    # capsule route needs the `KATA_EXTERNAL_*` provider exports (no PATH
    # fallback; `oci_provider_undeclared` otherwise), and boot certifies
    # rootless cgroup delegation (`oci_route_uncertified` outside a
    # delegated scope). The workspace release build above already produced
    # `kata-provider-youki` and `kata-oci-hook` at `target/release`. The
    # delegate argv ends in `--`, which makes systemd-run exec in place —
    # `$!` stays the kata pid every consumer below reads.
    command -v nix >/dev/null || {
        echo "footprint-check: nix required — the declared environment's declare-time verify shells it" >&2
        exit 1
    }
    oci_smoke_provision_provider "$tmp" "$bin_abs" "$(pwd)/target/release"

    echo "footprint-check: booting installed main (port $port, metrics $metrics_port, data_dir $data_dir)…"
    # The installed main refuses a redirected HOME by design (tilde
    # expansion must be stable across service startup) and owns the real
    # per-owner discovery lease, so this boots with the true owner HOME and
    # isolates through explicit config paths only. The gate's pgrep-stale
    # bookends guarantee no other main contends during the measurement.
    systemd-run $(oci_smoke_delegate_args 600) \
        env KATA_STDLIB_DIR="$stdlib_dir" "$bin_abs" serve --config "$cfg" \
        > "$log" 2>&1 &
    kata_pid=$!
    pid="$kata_pid"
    remember_solo

    # A reserved TCP listener is not runtime readiness. Require this process's
    # descriptor/lock identity AND a matching ready API status before RSS sampling.
    # Each probe has an external two-second timeout inside the wall-clock budget.
    ready_secs="{{ready_secs}}"
    ready_deadline=$(( SECONDS + ready_secs ))
    ready=0
    while [ "$SECONDS" -lt "$ready_deadline" ]; do
        if ! kill -0 "$kata_pid" 2>/dev/null; then
            echo "footprint-check: FAIL — installed main exited before ready. log tail:" >&2
            tail -30 "$log" >&2 || true
            exit 1
        fi
        if timeout --kill-after=1s 2s python3 scripts/smoke-endpoint.py "$cfg" "$kata_pid" --ready >/dev/null 2>&1 && [ "$SECONDS" -lt "$ready_deadline" ]; then ready=1; break; fi
        sleep 0.5
    done
    if [ "$ready" -ne 1 ]; then
        echo "footprint-check: FAIL — installed-main API never proved ready on 127.0.0.1:$port within ${ready_secs}s." >&2
        tail -30 "$log" >&2 || true
        exit 1
    fi
    # Small settle so post-ready lazy allocations land before we sample.
    sleep 1

    rss_kib="$(awk '/^VmRSS:/ {print $2}' "/proc/$kata_pid/status" 2>/dev/null || true)"
    [ -n "$rss_kib" ] || { echo "footprint-check: FAIL — could not read VmRSS for pid $kata_pid" >&2; exit 1; }
    rss_mib=$(( rss_kib / 1024 ))
    ceil_rss="{{rss_ceil_mib}}"
    echo "footprint-check: installed-main boot RSS = ${rss_mib} MiB (ceiling ${ceil_rss} MiB)"
    if [ "$rss_mib" -gt "$ceil_rss" ]; then
        echo "footprint-check: FAIL — installed-main boot RSS ${rss_mib} MiB exceeds ${ceil_rss} MiB ceiling." >&2
        echo "  Actionable: a boot-time allocation blow-up (oversized cache/buffer, an eager" >&2
        echo "  full-history fold, a runaway pool). Diff against the prior boot RSS; check" >&2
        echo "  page-cache/channel-buffer config sizing in kata.toml." >&2
        exit 1
    fi

    echo "footprint-check: OK — size ${size_mib}/${ceil_mib} MiB, boot RSS ${rss_mib}/${ceil_rss} MiB."

# `just fmt` is not a step here: the gate recipes run it ahead of anything that
# compiles. See the ORDERING note on `gate`.
#
# The COMMIT-TIER steps only; `footprint-check` and `test-soak` run in
# `_gate-push-core`, and `test-measurement` in L2 (`gate-nightly`). Which tier a step
# runs in changes WHEN it runs, never WHAT it proves: every L1 step is required
# before push, and the L2 steps nightly.
#
# ONE TEST BUILD, OVERLAPPED WHERE NOTHING CONTENDS. The steps are paid for once each:
#
#   * `lint` builds in its OWN target dir (`target/lint`) BESIDE the test build, with
#     the derive probe (in `target/derive-refusal-probe`) beside both —
#     `_gate-commit-build`. Clippy's own target dir shares no artifact with the test
#     build, so a serial order would only buy cargo's build-dir lock.
#   * `test-doc` runs BESIDE the `test` RUN — `_gate-commit-run`. Its libraries are the
#     test build's (fresh by then), and `cargo test --doc` releases the build-dir lock
#     before rustdoc compiles and runs the doctests: measured on a scratch workspace, a
#     `cargo nextest run` started during an 8 s doctest finished in 0.37 s.
#   * The shared preflight (`_gate-common-preflight`) runs in `_gate-commit-build` too, as
#     `_gate-par-preflight`: it compiles nothing, so it costs the group no build lock.
#   * `agent-accept`, `test-conformance` and `youki-pin-cells-ran` do not RE-RUN tests
#     `test` has just run (a `-p kata` feature set would rebuild `kata` for the
#     privilege). They check `test`'s own JUnit report that every test they select RAN
#     AND PASSED.
#   * `deny` runs ahead of the build group: seconds, no build, fails first.
#
# The timing-sensitive steps are NOT here and nothing below overlaps a step that
# boots an installed main. `the_parallel_groups_overlap_only_what_cannot_contend` in
# `bin/kata-eval/tests/gate_exclusion.rs` holds that.
[private]
_gate-commit-core:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh commit-core
    kata_timing_install_trap
    kata_timing_step deny
    just deny
    kata_timing_step build-group
    just _gate-commit-build
    # The report `agent-accept` and `test-conformance` read. Deleted here so that inside
    # a tier they can only ever read THIS run's report, never an older one.
    rm -f target/nextest/default/junit.xml
    kata_timing_step test-group
    just _gate-commit-run
    kata_timing_step source-tree-unchanged
    just source-tree-unchanged
    kata_timing_step agent-accept
    just agent-accept
    kata_timing_step test-conformance
    just test-conformance
    kata_timing_step youki-pin-cells-ran
    just youki-pin-cells-ran
    kata_timing_summary

# The commit tier's build group. Just's `[parallel]` starts every dependency at once
# and, if one fails, still waits for the others before failing (measured, Just 1.46).
# Each member records its own `|| <step>` timing row with its exit status.
[private]
[parallel]
_gate-commit-build: _gate-par-preflight _gate-par-lint _gate-par-derive-refusal-probe _gate-par-test-build

# The commit tier's run group: the workspace suite and the doctests.
[private]
[parallel]
_gate-commit-run: _gate-par-test _gate-par-test-doc

# The shared preflight, as a member of the build group: python and bash over the tree,
# no compile (`dev-loop-check` says so), so it overlaps the compiles instead of
# delaying them. A red preflight still reds the group, once its siblings finish.
[private]
_gate-par-preflight:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh preflight
    kata_timing_parallel_member preflight
    just _gate-common-preflight

[private]
_gate-par-lint:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh lint
    kata_timing_parallel_member lint
    CARGO_TARGET_DIR=target/lint just lint

[private]
_gate-par-derive-refusal-probe:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh derive-refusal-probe
    kata_timing_parallel_member derive-refusal-probe
    just derive-refusal-probe

[private]
_gate-par-test-build:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh test-build
    kata_timing_parallel_member test-build
    just test-build

[private]
_gate-par-test:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh test
    kata_timing_parallel_member test
    just test

[private]
_gate-par-test-doc:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh test-doc
    kata_timing_parallel_member test-doc
    just test-doc

# The PUSH-TIER tree checks: the four host-independent steps a commit rarely
# invalidates.
#
# ONE RELEASE BUILD. `footprint-check` and `smoke-no-budget` both use `just build`,
# which is the shipped artifact's build (the flake's `cargo build --workspace
# --release`), paid ONCE here; two different package lists would unify features
# differently and pay two ~155 s LTO builds of `kata`.
#
# Then the TIMING-SENSITIVE block, serial and after `quiet-box-wait`: `footprint-check`
# boots the release binary as an installed main and reads its RSS; then soak. Soak
# stays in L1 because it is cheap and steady: 15 s of nextest wall, 10 s of it
# `recovery_100k_resume_is_bounded`'s 20,000-attempt corpus (measured 2026-11-11 at a
# load average of 30-60; the 100,000-attempt cell it replaced took 122-172 s); the
# writer measurement pass is in L2 (`gate-nightly`) because it is not
# steady (11-32 s across runs — it measures the disk's load as much as the writer).
#
# Shared with `gate-hosted`, which is the same tree checks minus the `pgrep-stale`
# bookends; the containment lane is NOT here, because it is host-dependent.
[private]
_gate-push-core:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh push-core
    kata_timing_install_trap
    kata_timing_step build
    just build
    kata_timing_step quiet-box-wait
    just quiet-box-wait
    kata_timing_step footprint-check
    just footprint-check
    kata_timing_step test-soak
    just test-soak
    kata_timing_summary

# Wait, BOUNDED, for a quiet host before a timing-sensitive block.
#
# `test-soak`, `test-measurement`, `footprint-check`'s boot budget and the containment
# smokes all assert wall-clock bounds, and concurrent load moves them: one containment
# smoke is 1.4 s at loadavg 12 and trips its 30 s boot deadline at 496, and a soak
# giant has timed out at 600 s on a loaded host. A false red there costs a whole
# re-run and is the hardest kind to tell from a real one.
#
# So this waits until the 1-minute load average is below a threshold DERIVED FROM THE
# CORE COUNT — a quarter of `nproc`, floor 4; `KATA_QUIET_LOAD_MAX` overrides — for up
# to `max_secs`, logging the load every 30 s. It NEVER fails: if the host never quiets it
# proceeds with a WARNING naming the load, because refusing would hand every busy host a
# way to skip a required step. It is a scheduling aid, not a verdict.
quiet-box-wait max_secs="600":
    #!/usr/bin/env bash
    set -uo pipefail
    cores="$(nproc 2>/dev/null || echo 4)"
    limit="${KATA_QUIET_LOAD_MAX:-$(( cores / 4 > 4 ? cores / 4 : 4 ))}"
    load1() { awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0; }
    below() { awk -v l="$(load1)" -v m="$limit" 'BEGIN { exit !(l + 0 < m + 0) }'; }
    started="$(date +%s)"
    last_log=-30
    while ! below; do
        waited=$(( $(date +%s) - started ))
        if [ "$waited" -ge "{{max_secs}}" ]; then
            echo "quiet-box-wait: WARNING — loadavg $(load1) still >= ${limit} (${cores} cores / 4) after ${waited}s;"
            echo "  proceeding. A timing failure in the next steps must be read against this load."
            exit 0
        fi
        if [ $(( waited - last_log )) -ge 30 ]; then
            echo "quiet-box-wait: loadavg $(load1) >= ${limit} (${cores} cores / 4); waited ${waited}s of {{max_secs}}s"
            last_log="$waited"
        fi
        sleep 5
    done
    echo "quiet-box-wait: loadavg $(load1) < ${limit} (${cores} cores / 4) after $(( $(date +%s) - started ))s"

# SCOPED gate for work in progress: every cheap-but-load-bearing guard, plus fmt,
# plus lint and tests for ONLY the named crates. The full `just gate` is what a
# commit needs.
#
# Why this exists. The full gate is tens of minutes, dominated by compiles (release
# self-test, the pinned audit toolchain for lint, the test build) plus ~4,000 tests and
# the serialized soak giants. Running it after every edit re-proves work the edit did
# not touch. But a bare `just test-crate X` by hand SILENTLY SKIPS the guards below,
# which cost seconds and catch drift the crate's own tests cannot. This recipe is the
# honest middle: the guards are not optional, the expensive breadth is.
#
# What it does NOT prove, and callers must not claim it does: the soak giants (bounded
# recovery, compaction, the merge queue), agent acceptance, fuzz, footprint, and any
# crate you did not name. A commit does not rest on this — it rests on `just gate`.
#
#   just gate-scoped kata-core kata-workflow
# Shared checks remain literal calls for recipe-graph coverage. Formatting and
# process ownership stay in each caller; full-only checks are not added to scoped.
_gate-common-preflight:
    #!/usr/bin/env bash
    set -euo pipefail
    just htree-preflight
    just dev-loop-check

gate-scoped +crates:
    #!/usr/bin/env bash
    set -euo pipefail
    just pgrep-stale
    just fmt
    just _gate-common-preflight
    for crate in {{crates}}; do
        just lint-crate "$crate"
    done
    for crate in {{crates}}; do
        just test-crate "$crate"
    done
    just pgrep-stale
    echo "gate-scoped OK for: {{crates}}  (NOT a full gate — soak/agent-accept/fuzz/footprint/no push-tier checks unrun)"

# ORDERING IS CHEAPEST-AND-MOST-LIKELY-TO-FAIL FIRST, and this is a measured decision,
# not a preference: gate runs die far more often on cheap, non-defect causes (a
# deadline flake, `pgrep-stale` firing on its own caller, a `fmt` diff on a single
# wrapped `let` chain) than on defects, and a `fmt` diff found behind a self-test (100+
# process spawns) and a full workspace compile costs about twenty minutes to be told
# about a line wrap.
#
# So `just fmt` runs before anything that compiles.
# It costs seconds (rustfmt parses, it does not build), it has the highest observed
# failure rate of any step, and it is the only failing step with a one-command fix
# (`just fmt-fix`). Moving it up buys back ~20 minutes per formatting mistake and costs
# nothing when the tree is clean. Each variant runs formatting first, then the
# shared `_gate-common-preflight` (htree, truth guards, routing): `gate-scoped` runs it
# next, serially; `gate` and `gate-hosted` run it as a member of `_gate-commit-build`'s
# `[parallel]` group, because it compiles nothing and ~70 s of python and bash serial
# ahead of the compiles was the commit tier's largest avoidable wait. Process hygiene
# stays in gate/scoped; lock and smoke-harness self-tests stay in gate/hosted only.
#
# `htree-preflight` rides in the preflight, beside the build group, for a measured
# reason, the failure it anticipates being worse than a wasted run: a build that dies ENOSPC ~20
# minutes in while `df` reports 2.9 TB free, because ONE directory's ext4 htree index is
# full (`target/debug/deps` has reached 4,482,673 entries, all of it churn). It costs
# 2.3s including its own self-test, it is an ADVISORY that exits 0 whether or not it
# warns, and it therefore cannot fail a gate — which is the point: a hard refusal on a
# host with terabytes free would be worse than the defect.
#
# The remaining order is still deliberate: the cheap host-independent self-tests, then
# `_gate-commit-core` — deny, the preflight and lint beside the test build, the suite
# beside the doctests, then acceptance / conformance / the youki pin cells read off the
# suite's report. The note on `_gate-commit-core` gives the overlaps.
#
# FOUR LAYERS (AGENTS.md states the law, docs/development/verification.md the table):
# L0 `just verify` per change; L1 `gate` + `gate-push`, required before every push; L2
# `gate-nightly`, required nightly on main; L3 the adversarial maintainer review at
# every release boundary. The two-tier text below describes L1's internal split.
#
# TWO TIERS. `gate` is the COMMIT tier and `gate-push` is the PUSH tier. The split
# decides WHEN each proof runs and nothing about WHAT it proves: every step is required
# before push.
#
# Why split: `footprint-check` and `test-soak` are a large share of L1's wall clock in
# steps a per-commit edit almost never invalidates without also reddening something in
# this tier, and a half-hour pre-commit step is how a step gets skipped "just this
# once". The commit tier answers every question a commit can break; the push tier
# answers the rest, plus containment. `just gate-snapshot-status` prints the current
# figures.
#
# WHAT `gate` DOES NOT PROVE is stated in its own closing output, and `gate-push`
# names itself there. That is the same mechanism by which the containment lane is
# required without being concatenated, and it is asserted in
# `bin/kata-eval/tests/gate_exclusion.rs`.
#
# `bin/kata-eval/tests/gate_exclusion.rs` checks the static recipe graph using literal
# command-position calls and Just's recipe metadata; quoted prose is not a call.
# This structural check does not prove arbitrary shell or external-script execution.
# Keep gate calls explicit, and retain runtime receipts for the required lanes.
gate:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh gate
    kata_timing_install_trap
    source scripts/gate-source-tree.sh
    kata_timing_step pgrep-stale
    just pgrep-stale
    kata_timing_step fmt
    just fmt
    kata_timing_step installed-main-lock-selftest
    # Under a held lock, as a lane runs it: the self-test must unset the variable to
    # observe exclusion (gate_exclusion `the_two_tiers_partition_every_l1_step`).
    KATA_INSTALLED_MAIN_LOCK_HELD=1 scripts/installed-main-lock.sh --self-test
    kata_timing_step smoke-harness-selftest
    bash scripts/smoke-harness.sh --self-test
    kata_timing_close
    just _gate-commit-core
    kata_timing_step source-tree-unchanged-final
    just source-tree-unchanged
    kata_timing_step pgrep-stale-final
    just pgrep-stale
    kata_timing_summary
    echo
    echo "gate: OK — the COMMIT tier. Here is what it did NOT prove."
    echo "  This gate needs no containment capabilities: it runs no smoke, no"
    echo "  adversarial suite, and nothing that needs a user namespace or"
    echo "  delegated cgroup. It cannot see a containment regression."
    echo "  Timing remains host-dependent."
    echo "  Nor does it need a model CLI: no gate-reachable spawn of the product"
    echo "  boots a config that declares one — the push tier's footprint-check"
    echo "  boots a shell-only derivation of the example config"
    echo "  (scripts/footprint-config.sh). Its irreducible"
    echo "  host tools are python3, ruff and jj — 'host-check' names them."
    echo "  It does NOT run the footprint floors, the"
    echo "  soak giants, the writer measurement pass, or any containment proof. All of"
    echo "  those stay REQUIRED BEFORE PUSH, in the push tier:"
    echo "      'gate-push'   (which ends in 'gate-containment')"
    echo "  Normally both tiers together: 'gate-snapshot rev=<commit>'."
    echo "  The timer-bound live cells and the writer measurement are L2, 'gate-nightly'."

# ─── The PUSH tier ───────────────────────────────────────────────────────────
#
# The second half of L1, and it is REQUIRED BEFORE PUSH — not a nice-to-have and not a
# subset. `gate` answers "can this commit be a commit"; this answers "can this tree be
# pushed": the footprint floors, the soak giants, and
# containment ON THIS KERNEL. What it does NOT run — the writer measurement pass and
# the timer-bound live cells — is L2, `gate-nightly`, required nightly on main.
gate-push:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh gate-push
    kata_timing_install_trap
    source scripts/gate-source-tree.sh
    # THE HOST FIRST. Reached only after the tree checks, the containment
    # preconditions would fail on host state (leftover processes, a stale attachment
    # descriptor) after many minutes of other steps — facts these two recipes report
    # in seconds. `gate-containment` still re-checks both under its installed-main
    # lock; they are cheap, and the host can change in 20 minutes.
    kata_timing_step pgrep-stale
    just pgrep-stale
    kata_timing_step containment-preconditions
    just _containment-preconditions
    kata_timing_close
    just _gate-push-core
    kata_timing_step quiet-box-wait
    just quiet-box-wait
    kata_timing_close
    just gate-containment
    kata_timing_step source-tree-unchanged
    just source-tree-unchanged
    kata_timing_summary
    echo
    echo "gate-push: OK — the PUSH tier, on top of a green 'just gate'."
    echo "  Timing remains host-dependent."
    echo "  Both tiers are required before push and neither replaces the other: this one"
    echo "  never ran lint, the workspace test suite, the doctests, agent acceptance or"
    echo "  conformance, and 'gate' cannot see a containment regression."
    echo "  NOT run here (L2, 'gate-nightly', required nightly on main): the writer"
    echo "  measurement pass, the timer-bound live cells (NIGHTLY_CELLS in"
    echo "  bin/kata-eval/tests/gate_exclusion.rs), a freshly fetched advisory db, a cold build."

# The gate for workloads HOSTED BY a running kata node (the kata-gate-fix-loop
# pack): identical to `gate` minus the pgrep-stale bookends, which by design
# fail whenever any kata process is alive — and a hosted loop's own installed main,
# and the watching CLI are alive on purpose (a hosted run would fail in under a
# second on exactly this). Operators keep using `just gate`; process hygiene for
# hosted runs is the HOST's job, not the workload's.
#
# NOT TIERED, deliberately. The tiering splits L1 by WHEN a proof is worth paying for,
# and a hosted fix-loop run is a whole-tree verdict on a candidate, not a per-commit
# loop — so this variant keeps BOTH tiers' tree checks, `_gate-commit-core` then
# `_gate-push-core`. Containment is absent here because this runs with a live
# installed main, and the containment lane refuses that.
gate-hosted:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/gate-timing.sh gate-hosted
    kata_timing_install_trap
    source scripts/gate-source-tree.sh
    kata_timing_step fmt
    just fmt
    kata_timing_step installed-main-lock-selftest
    # Under a held lock, as a lane runs it: the self-test must unset the variable to
    # observe exclusion (gate_exclusion `the_two_tiers_partition_every_l1_step`).
    KATA_INSTALLED_MAIN_LOCK_HELD=1 scripts/installed-main-lock.sh --self-test
    kata_timing_step smoke-harness-selftest
    bash scripts/smoke-harness.sh --self-test
    kata_timing_close
    just _gate-commit-core
    kata_timing_close
    just _gate-push-core
    kata_timing_step source-tree-unchanged
    just source-tree-unchanged
    kata_timing_summary

# ─── L2: the NIGHTLY deep tier ────────────────────────────────────────────────
#
# L1 (`gate` + `gate-push`) is required before every push; L2 is required NIGHTLY on
# main, and a red L2 must be triaged — fixed, or bisected to the commit that owns it —
# before the next push. AGENTS.md states the law; docs/development/verification.md
# carries the split.
#
# WHAT MOVED HERE, AND THE RULE THAT MOVED IT. A cell left the push tier only if it is
# (a) bound by a real timer or by host load, (b) ~10 s or more, or a known false-red
# source, AND (c) its logic is ALSO pinned by a host-free twin that `just test` runs on
# every commit. `NIGHTLY_CELLS` in `bin/kata-eval/tests/gate_exclusion.rs` names every
# one with its twins and REFUSES a moved cell whose twin is missing, ignored, or lives in
# a binary that can capability-skip. Every containment and adversarial proof stays in
# the push tier; the selection is exact — each moved cell is subtracted from its L1
# step with `not test(=NAME)` and selected here with `test(=NAME)`, and the guard holds
# the two sets equal (`the_nightly_cells_leave_the_push_tier_for_exactly_the_nightly_tier`).
#
# Plus what no commit changes and only the calendar does: `deny-fresh` (a freshly
# FETCHED advisory database), and `cold-build` (the shipped release build from an empty
# target dir, so an artifact the incremental cache hides cannot keep main green). And
# `flake-checks`, the Nix flake's own checks, which no L1 tier pays for: a Nix build of
# the whole workspace from a clean source copy. And `model-check-0003`, ADR 0003's
# checked model: the 76 TLC runs it owed at M0 took 2390 s at 16 workers under a load of
# 100 to 150, and only its own files, its runner and the TLC pin can change a verdict,
# so `just verify` runs it for a diff to those and L2 re-runs it whole.
#
# KEEP-GOING, UNLIKE L1. Past the host checks and the two builds a red step is
# RECORDED (`kata_timing_record`) and the next step still runs, because this tier's
# reader is a morning report and a bisect, and the first red cell of a night is not
# the only one worth knowing. The tier's exit is red if any recorded step was
# (`kata_timing_exit` names them). Each nextest step's JUnit report is kept under
# `target/gate-nightly/junit/<step>.xml`; `just gate-snapshot rev=<r> tier=nightly`
# copies them to `target/gate-snapshot/<rev>/nightly.junit/` beside `nightly.rc`,
# `nightly.seconds`, `nightly.log` and `nightly.summary.txt`.
#
# UNDER THE INSTALLED-MAIN LOCK FOR ITS WHOLE DURATION, as `gate-containment` is,
# and for its reason: every live step boots the per-uid installed main.
gate-nightly:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just gate-nightly
    fi
    source scripts/gate-timing.sh gate-nightly
    kata_timing_install_trap
    source scripts/gate-source-tree.sh
    junit=target/gate-nightly/junit
    rm -rf target/gate-nightly
    mkdir -p "$junit"
    kata_timing_step pgrep-stale
    just pgrep-stale
    kata_timing_step containment-preconditions
    just _containment-preconditions
    kata_timing_step test-build
    just test-build
    kata_timing_step build
    just build
    set +e
    kata_timing_step deny-fresh
    just deny-fresh
    kata_timing_record $?
    kata_timing_step quiet-box-wait
    just quiet-box-wait
    kata_timing_record $?
    rm -f target/nextest/measurement/junit.xml target/nextest/live-smoke/junit.xml
    kata_timing_step test-measurement
    just test-measurement
    kata_timing_record $?
    kata_timing_step junit-test-measurement
    mv target/nextest/measurement/junit.xml "$junit/test-measurement.xml"
    kata_timing_record $?
    kata_timing_step quiet-box-wait
    just quiet-box-wait
    kata_timing_record $?
    kata_timing_step nightly-oci-live
    just nightly-oci-live
    kata_timing_record $?
    kata_timing_step junit-nightly-oci-live
    mv target/nextest/live-smoke/junit.xml "$junit/nightly-oci-live.xml"
    kata_timing_record $?
    kata_timing_step recovery-checkpoint-live
    just recovery-checkpoint-live
    kata_timing_record $?
    kata_timing_step junit-recovery-checkpoint-live
    mv target/nextest/live-smoke/junit.xml "$junit/recovery-checkpoint-live.xml"
    kata_timing_record $?
    kata_timing_step pgrep-kata
    just pgrep-kata
    kata_timing_record $?
    kata_timing_step cold-build
    just cold-build
    kata_timing_record $?
    kata_timing_step flake-checks
    just flake-checks
    kata_timing_record $?
    kata_timing_step model-check-0003
    just model-check-0003
    kata_timing_record $?
    kata_timing_step source-tree-unchanged
    just source-tree-unchanged
    kata_timing_record $?
    kata_timing_step pgrep-stale-final
    just pgrep-stale
    kata_timing_record $?
    kata_timing_summary
    kata_timing_exit

# The nightly OCI cells: the push tier's `oci-live-smoke` minus its timer-bound cells,
# run with the environment that step gave them (`KATA_SANDBOX_REQUIRE_LIVE=1` — which
# none of these binaries reads, so it is the same run — and the pinned youki's provider
# built first, their instrument). ONE invocation, so ONE JUnit report.
nightly-oci-live:
    #!/usr/bin/env bash
    set -uo pipefail
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just nightly-oci-live
    fi
    cargo build -p kata-provider-youki --bin kata-provider-youki || exit $?
    just _nightly-oci-live-run

_nightly-oci-live-run:
    KATA_SANDBOX_REQUIRE_LIVE=1 cargo nextest run --workspace -P live-smoke --test-threads=1 \
        --run-ignored all --success-output final \
        -E '(package(kata-workflow) & binary(oci_stage_live) & test(=a_capsule_past_its_wall_clock_is_stopped_by_its_provider_budget_live)) | (package(kata) & binary(oci_main_live) & test(=a_capsule_past_120_seconds_completes_on_its_own_wall_clock_live))'


# `cargo deny` against an advisory database FETCHED NOW. The advisory database changes
# without any commit, so the commit tier's `deny` answers "was this tree clean against
# whatever database this host last fetched"; this answers it against today's.
# REFUSES: a fetch that fails (offline, the source unreachable), and a fetch that
# updated no advisory-db checkout under `$CARGO_HOME/advisory-dbs` after this step
# began (so a stale database cannot pass as fresh); then whatever `just deny` refuses.
deny-fresh:
    #!/usr/bin/env bash
    set -euo pipefail
    started="$(mktemp -t kata-deny-fresh.XXXXXX)"
    trap 'rm -f "$started"' EXIT
    cargo deny fetch db
    fresh=""
    for head in "${CARGO_HOME:-$HOME/.cargo}"/advisory-dbs/*/.git/FETCH_HEAD; do
        if [ "$head" -nt "$started" ]; then fresh="${head%/.git/FETCH_HEAD}"; fi
    done
    if [ -z "$fresh" ]; then
        echo "deny-fresh: FAIL — 'cargo deny fetch db' updated no advisory database under" >&2
        echo "  ${CARGO_HOME:-$HOME/.cargo}/advisory-dbs, so the check below would read a stale one." >&2
        exit 1
    fi
    echo "deny-fresh: advisory db $(git -C "$fresh" log -1 --format='%h committed %cI') fetched $(date -Is)"
    just deny

# The shipped release build (the `build` recipe's command) from an EMPTY target
# dir. It proves the tree builds with no incremental state at all — what a stale
# artifact in the persistent snapshot target can hide. Its own dir, removed first, for
# the reason `derive-refusal-probe` has one; this is a BUILD, so the test-binary
# checkout-root inference that forbids `CARGO_TARGET_DIR` for the tiers does not apply.
cold-build:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=target/cold-build
    rm -rf "$dir"
    CARGO_TARGET_DIR="$dir" cargo build --workspace --release --locked --offline
    echo "cold-build: OK — $(du -sh "$dir" | cut -f1) in $dir"

# The flake's own checks: EVERY attribute of `checks.x86_64-linux` in flake.nix, as
# `nix eval` lists them (kata-build, youki-pin, packaged-layout today) — the kata
# package Nix builds from this tree (its vendored-dependency hashes included), the
# youki derivation equal to config/youki-pin.toml's `store_path`, and the packaged
# layout (kata-built provider members real executables, the capsule init STATIC, `ip`
# declared and not copied, the node-environment declaration naming every root). Nothing
# else runs them: `cold-build` is plain cargo, and `package` / `cache-push` are no
# tier's steps. L2 (`gate-nightly`), and `just verify` for a diff to the flake, its lock,
# `nix/**` or the youki pin; never L1 — it is a Nix build of the whole workspace.
# REFUSES: no `nix` on PATH, a flake with no checks for the system, and any check that
# does not build. `--no-link`, so the run leaves no `result` link in the tree.
flake-checks:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v nix >/dev/null; then
        echo "flake-checks: FAIL — no \`nix\` on PATH, so the flake's checks cannot run" >&2
        exit 1
    fi
    system=x86_64-linux
    names="$(nix eval --raw ".#checks.$system" \
        --apply 'checks: builtins.concatStringsSep " " (builtins.attrNames checks)')"
    if [ -z "$names" ]; then
        echo "flake-checks: FAIL — the flake defines no checks.$system" >&2
        exit 1
    fi
    attrs=()
    for name in $names; do attrs+=(".#checks.$system.$name"); done
    nix build --no-link "${attrs[@]}"
    echo "flake-checks: OK — checks.$system: $names"

# Every TLC run docs/architecture/models/0003/checks.toml owes — each real model
# explored whole at its stated bounds, each mutant and each finding stopped on exactly
# the invariant it names — through scripts/model-check.py, which audits the manifest
# first (its docstring states the refused set). TLC is nixpkgs' `tlaplus` at the
# nixpkgs flake.lock pins, resolved with `--inputs-from .`, so the flake gains no output
# and the TLC version moves only with that lock. L2 (`gate-nightly`), and `just verify`
# for a diff to the models, their runner or flake.lock; the commit tier's
# `dev-loop-check` runs the audit and the runner's self-test, which need no TLC. Each
# run's TLC output stays in target/model-check/0003/<check>.log.
# `workers` (TLC worker threads per run; the runs are sequential) defaults to 32, for the
# quiet box the nightly holds: on the 128-core reference host, run back to back,
# `lease-order-two-nodes` (22,104,035 distinct states) took 278 s at 16 workers, 223 s
# at 32, and 221 s at 64 and at 96, the first started at a 1-minute load of 0.4 and the
# others at 26, 36 and 54, mostly the run before them. TLC stops scaling past 32, so 32
# takes that gain and leaves the other cores idle rather than contended.
# REFUSES: no `nix` on PATH; a manifest the audit refuses; a run that reaches any verdict
# but the one its check expects.
#
# ADR 0003's checked model (plan M0): run every TLC check its manifest owes.
model-check-0003 workers="32":
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v nix >/dev/null; then
        echo "model-check-0003: FAIL — no \`nix\` on PATH; TLC comes from the nixpkgs flake.lock pins" >&2
        exit 1
    fi
    tlaplus="$(nix build --no-link --print-out-paths --inputs-from . nixpkgs#tlaplus)"
    python3 -B scripts/model-check.py docs/architecture/models/0003 \
        --tlc "$tlaplus/bin/tlc" --workers {{ workers }}

# ─── Gating without freezing the checkout ────────────────────────────────────
#
# BOTH TIERS — `gate` then `gate-push`, the push tier carrying containment — against a
# DETACHED worktree of `rev`, so an hour of gating no longer costs an hour of not being
# able to edit. First `pgrep-stale` + `host-check` (seconds; a host that cannot finish
# either tier is refused before any build), then the tiers SEQUENTIALLY:
# scripts/gate-snapshot.sh states the four collisions that forbid running them at once
# (per-uid installed-main singleton, the installed-main lock's whole-run hold, a
# `pgrep-stale` that cannot be scoped to a run, and load-sensitive soak/measurement
# timing). Both tiers share ONE worktree and therefore one default `target/`, which
# persists across snapshots, so the push tier starts on the commit tier's build.
# `CARGO_TARGET_DIR` is not an
# option and the script says why: it moves the checkout root the workflow library
# infers, and `footprint-check` and the product smokes hardcode
# `target/{debug,release}/kata`.
# A red host skips both tiers and a red commit tier skips the push tier — push needs
# both green — unless `--keep-going` / `keep_going=1` follows the revision.
# Both timing tables are recorded in the snapshot's `summary.txt`; rc is non-zero
# unless the host checks and BOTH tiers are green.
# Detachable: `setsid nohup just gate-snapshot rev=HEAD > snap.log 2>&1 &`.
# `tier=nightly` runs the host checks and L2 (`gate-nightly`) instead, in the same
# worktree, into `nightly.*` files of the same revision directory — the one command a
# nightly scheduler calls per revision: `just gate-snapshot <rev> tier=nightly`.
gate-snapshot rev="HEAD" *flags:
    scripts/gate-snapshot.sh {{ rev }} {{ flags }}

# The last snapshot's summary: rc per stage (host, gate, gate-push), wall times, the
# target-dir size, and the per-step timing table for both tiers. `tier=nightly`: the
# last L2 snapshot's instead.
gate-snapshot-status tier="push":
    scripts/gate-snapshot.sh --status {{ tier }}

# L1 for a coordinator on a shared box: wait out the nightly, hold QUIET_BOX, take the
# live-suite lock, drain the lanes' builds, then `gate-snapshot` from the main checkout,
# detached in this session on the unattended PATH `nightly-install` recorded (`--unit`: a
# transient user unit; `--foreground`: here). scripts/gate-launch.sh states every step,
# bound, rc and waiter.
gate-launch rev="HEAD" *flags:
    scripts/gate-launch.sh {{ rev }} {{ flags }}

# Block until a lane may start a build or test: while a gate holds QUIET_BOX or the
# nightly holds its mark (scripts/lane-wait.sh). Lanes run it before every cargo,
# nextest or just build. It then reports, without waiting, a `kata serve` holding the
# per-user installed-main singleton, which reds any cell that boots an installed main.
lane-wait:
    scripts/lane-wait.sh

# Remove the lane worktrees under `root` whose commits have all landed on main (patch
# identity, `git cherry`), keeping their lane-logs; `--dry-run` only prints each lane's
# verdict. Refused while a gate or the nightly holds the box (scripts/lanes-prune.sh).
lanes-prune root *flags:
    scripts/lanes-prune.sh {{ root }} {{ flags }}

# ─── The L2 NIGHTLY ──────────────────────────────────────────────────────────
#
# The deep tier on `main`, nightly, by a systemd USER timer on a maintainer's host
# (maintainer tooling; there is no CI). scripts/nightly.sh states what one run does,
# what it refuses, and what moves `nightly/last-green`; the report lands in
# target/nightly/latest/report.md. docs/development/verification.md is the policy.

# Install and start the timer for this user. Renders scripts/systemd/*.{service,timer}
# with `root` (default: this checkout) into ~/.config/systemd/user and records this
# shell's durable PATH as the unattended PATH the service and `gate-launch` run on. Refuses a linked worktree (its git dir is not the
# repository's common dir): it is deleted when pruned, and the unit with it.
nightly-install root=justfile_directory():
    #!/usr/bin/env bash
    set -euo pipefail
    root="$(cd "{{ root }}" && pwd)"
    git_dir="$(git -C "$root" rev-parse --path-format=absolute --git-dir)"
    common_dir="$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)"
    if [ "$git_dir" != "$common_dir" ]; then
        echo "nightly-install: $root is a linked worktree; install from the main checkout." >&2
        exit 1
    fi
    [ -x "$root/scripts/nightly.sh" ] || echo "nightly-install: WARNING — $root/scripts/nightly.sh does not exist yet; the service fails until it does." >&2
    units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    source scripts/gate-env.sh
    mkdir -p "$units" "$(dirname "$KATA_UNATTENDED_ENV")"
    for unit in kata-nightly.service kata-nightly.timer; do
        sed "s|@ROOT@|$root|g" "scripts/systemd/$unit" > "$units/$unit"
    done
    # The unattended PATH, shared with `gate-launch` (scripts/gate-env.sh): the
    # unit runs after a reboot, so only the PATH entries that outlive this shell.
    printf 'PATH=%s\n' "$(kata_durable_path)" > "$KATA_UNATTENDED_ENV"
    systemctl --user daemon-reload
    systemctl --user enable --now kata-nightly.timer
    systemctl --user list-timers kata-nightly.timer --no-pager

# Stop and remove the timer and service. Reports and `nightly/last-green` are kept.
nightly-uninstall:
    #!/usr/bin/env bash
    set -euo pipefail
    systemctl --user disable --now kata-nightly.timer 2>/dev/null || true
    systemctl --user stop kata-nightly.service 2>/dev/null || true
    rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/kata-nightly."{service,timer}
    rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/kata-nightly"
    systemctl --user daemon-reload
    echo "nightly-uninstall: timer and service removed (target/nightly and refs/nightly/last-green kept)."

# The timer, the last run's unit state, `nightly/last-green`, and the latest report's head.
nightly-status:
    #!/usr/bin/env bash
    set -uo pipefail
    systemctl --user list-timers kata-nightly.timer --no-pager
    echo
    systemctl --user status kata-nightly.service --no-pager --lines 5
    echo
    echo "nightly/last-green: $(git rev-parse --verify --quiet refs/nightly/last-green || echo none)"
    if [ -f target/nightly/latest/report.md ]; then
        echo "latest report: $(readlink -f target/nightly/latest)/report.md"
        head -25 target/nightly/latest/report.md
    else
        echo "latest report: none yet (target/nightly/latest)"
    fi

# Start one nightly now, detached, under the installed unit (same environment, same
# guards). Follow it with `journalctl --user -fu kata-nightly`; `just nightly-status`
# after. `scripts/nightly.sh --dry-run` prints the plan without running anything.
nightly-run:
    systemctl --user start --no-block kata-nightly.service
    @echo "nightly-run: started; journalctl --user -fu kata-nightly to follow."

# ─── The CONTAINMENT lane ────────────────────────────────────────────────────
#
# `just gate` contains ZERO smoke, adversarial, or live steps, and a live test nothing
# runs can stay red for a feature's whole lifetime (a smoke grepping for a string the
# product does not emit, say). Containment is the one property where being wrong is
# not a bug report but an escape, so its proofs are a REQUIRED step, not recipes
# someone may remember to call.
#
# This lane is the second REQUIRED step before push. `gate` proves the tree is
# self-consistent; this proves containment holds ON THIS KERNEL. Both, every push.
#
# ─ WHY A SEPARATE STEP AND NOT PART OF `gate` ─
#
# 1. A MACHINE VETO, and it is right. `bin/kata-eval/tests/gate_exclusion.rs` asserts the
#    `gate` recipe graph contains no `--run-ignored`. Every proof below needs
#    `--run-ignored` (`only`, or `all` for a capability-conditional binary), because `#[ignore]` is precisely what keeps a host-dependent
#    test out of `just test`. Folding them in would red the repo's only machine check on
#    the justfile — a check that exists so no unattended run can widen a filter into
#    budget-spending ignored tests.
# 2. THEY ANSWER DIFFERENT QUESTIONS. `gate` is host-independent on purpose: it must be
#    answerable on a host with no user namespaces and no delegated cgroup —
#    including macOS, which this repo carries as named debt. Folding containment in
#    makes "kata's tree is consistent" unanswerable anywhere containment cannot be
#    measured, and turns two verdicts into one conjunction that cannot say which half
#    failed.
# 3. COST, AND THE ROUTING-AROUND RISK. `gate` is tens of minutes. This lane is another
#    ~20 min and is serialized against every other
#    installed-main run on the host by construction. A ~60-minute single command is how
#    a step gets skipped "just this once", which is strictly worse than a named second
#    step someone can be held to.
#
# Required-ness is NOT achieved by concatenation. It is achieved by: `gate` printing, on
# success, that it did not prove containment and naming this lane; AGENTS.md and
# docs/development/verification.md listing both; and `gate_exclusion.rs` asserting this
# lane exists and still reaches all five proofs, so deleting one fails a test.
#
# ─ A SKIP IS A FAILURE ─
#
# Every step sets `KATA_SANDBOX_REQUIRE_LIVE=1`, which turns a capability skip into a
# failure, and every step verifies by an evidence LINE rather than an exit code. That is
# the whole point: a probe that quietly did not run is reported by the harness as a pass
# (a probe gating on a `/usr`-only bind exits 1 on a merged-usr host, and every live
# test it gates then SKIPS and reads as passed).
# The consequence is intended and must be stated plainly: a host without unprivileged
# user namespaces and a delegated cgroup cannot produce a complete green.
# `just host-check` answers that in seconds.
#
# ─ SERIALIZATION ─
#
# `/tmp/kata-installed-main-<uid>` is a per-uid singleton (attachment.rs), so two
# embedded-main runs cannot coexist — the loser fails with `HealthTimeout`, a message
# that names the node under test and not the contender. The lane takes
# scripts/installed-main-lock.sh for its WHOLE duration (reentrant, so the wrapped
# recipes do not re-acquire), which also serializes it against a concurrent gate's
# `footprint-check`.
#
# ─ LOAD ─
#
# Load matters more here than anywhere else in the repo: `smoke_shell_workspace_ro_sub_second`
# was measured at 1.396s at loadavg 12 and took 45s to trip a 30s boot deadline at
# loadavg 496 — a 32x spread. The lane cannot fix that from the justfile (the 30s budget
# is `await_healthy(...)` inside the smoke, ~20 call sites each also capped by
# `#[kata_timeout(secs = 60)]`), so it does the two things it can: it prints the loadavg
# at every step, and on failure it names starvation as a hypothesis with those numbers,
# so a false FAIL is diagnosable in seconds instead of being mistaken for a containment
# regression. Run this lane when the host is not also running other builds.
#
# ─ ORDER ─
#
# Cheapest-and-most-likely-to-fail first, the same rule `gate` follows. Preconditions
# (seconds) precede everything; the release build the product smokes need is paid only
# after the cheap kernel probes have passed. Every step runs ONCE; there is no lap
# comparison in this lane.
gate-containment:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just gate-containment
    fi

    source scripts/gate-timing.sh gate-containment
    started="$(date +%s)"
    _load() { awk '{print $1}' /proc/loadavg 2>/dev/null || echo '?'; }
    step() {
        printf '\n=== gate-containment %s  [loadavg %s, +%ss] ===\n' \
            "$1" "$(_load)" "$(( $(date +%s) - started ))"
    }
    on_exit() {
        rc=$?
        kata_timing_close "$rc"
        kata_timing_summary
        if [ "$rc" -ne 0 ]; then
            {
                echo
                echo "gate-containment: FAILED (exit $rc) after $(( $(date +%s) - started ))s at loadavg $(_load)."
                echo "  The cause remains unresolved. Preserve the failed step, logs, timeout and"
                echo "  resource observations before investigating startup, contention or a defect."
                echo "  Host load alone does not identify the cause of a timeout or missing evidence."
                echo "  A passing quiet rerun does not explain the original failure or replace it."
                echo "  Neither a failure nor a rerun changes the containment/recovery proof limits."
            } >&2
        fi
        exit "$rc"
    }
    trap on_exit EXIT

    kata_timing_step preconditions
    just _containment-preconditions
    # STRICT here even though this lane holds the installed-main lock: `pgrep-stale` excuses a
    # live `kata` only when SOMEONE ELSE holds it, so our own residue is still counted.
    kata_timing_step pgrep-stale
    just pgrep-stale
    # NO self-tests here: `installed-main-lock.sh` and `smoke-harness.sh` are tree
    # facts, self-tested by the commit tier (`gate`) over the same tree L1 gates. The
    # run here (11 s) was the only one under a held lock; `gate` now runs the lock's
    # self-test with KATA_INSTALLED_MAIN_LOCK_HELD=1 set, so a second run here proves
    # nothing new (gate_exclusion `the_two_tiers_partition_every_l1_step`).

    # The containment guarantee for the whole rootless-OCI plane: every no-spend
    # live OCI binary, not `_containment-preconditions`' youki probe (ONE rootless
    # `/bin/true` in a delegated scope). On a host missing the pinned youki's
    # AppArmor profile its first step fails naming `profile_file_differs`, and the
    # failure text names the recourse, `sudo kata host apparmor-install`.
    step "1/7 oci-live-smoke (every no-spend rootless-OCI live binary, incl. the adversarial column and the kata-floor corpus)"
    kata_timing_step oci-live-smoke
    just oci-live-smoke
    step "2/7 smoke-no-budget (every no-budget live smoke, through the PRODUCT path)"
    kata_timing_step smoke-no-budget
    just smoke-no-budget
    step "3/7 recovery-disk-full-live (real filesystem exhaustion before publication)"
    kata_timing_step recovery-disk-full-live
    just recovery-disk-full-live
    step "4/7 recovery-publication-fault-live (snapshot fsync errors and process death)"
    kata_timing_step recovery-publication-fault-live
    just recovery-publication-fault-live
    step "5/7 repository-barrier-live (repository writes synced before what depends on them, at the syscall boundary)"
    kata_timing_step repository-barrier-live
    just repository-barrier-live
    # `product-cli-smoke` is the ONLY exerciser of the first-run operator surface —
    # `kata init` into a repository, `kata doctor`, then the whole top-level CLI
    # against an installed main. Reachable only from the dev-loop routing table's
    # `bin/kata/src/cli/**` row, a change ANYWHERE ELSE that broke it would be
    # invisible (a doctor row refusing a project `kata init` had just created, say),
    # so it is a required step.
    #
    # It belongs in THIS lane and not in `just gate`. It spends no model budget
    # (shell agent only) and its config comes from `kata init`, which declares
    # `[agents.default]` only for a CLI it resolved — so the verdict is
    # host-independent. But it BOOTS THE PRODUCT, and
    # `the_gate_boots_no_config_that_needs_a_model_cli` rests on
    # `footprint-check` being the gate's only product boot; widening that premise
    # is a separate, design-bearing change. This lane already boots installed
    # mains under the same per-uid lock.
    step "6/7 product-cli-smoke (the first-run operator surface, end to end)"
    kata_timing_step product-cli-smoke
    just product-cli-smoke
    # The two live FACTORY proofs, $0 model budget. The `smoke-no-budget` set is
    # selected by a test filter and cannot reach a justfile recipe, so the packs whose
    # LIBRARY-DEFINED stages a sandbox-default change can silently break (a loopback
    # API call, declared validation commands resolving against the library roots)
    # are called here, or nothing that runs automatically covers them.
    step "7/7 smoke-no-budget-factory (the two live factory proofs, through the PRODUCT path)"
    kata_timing_step smoke-no-budget-factory
    just smoke-no-budget-factory
    kata_timing_step pgrep-kata
    just pgrep-kata
    kata_timing_close
    echo
    echo "gate-containment OK — $(( $(date +%s) - started ))s, finishing loadavg $(_load)."
    echo "  Proved ON THIS KERNEL: every no-spend rootless-OCI live binary end to end — the"
    echo "  adversarial column inside a real container and the kata-floor seccomp"
    echo "  corpus included (its two real-timer cells are L2's),"
    echo "  every no-budget live smoke through the product path (the one that drives a"
    echo "  real model turn spends model budget and runs manually; one timer-bound smoke"
    echo "  is L2's), the first-run operator surface end to end (init -> doctor ->"
    echo "  installed main), real filesystem exhaustion and publication faults before"
    echo "  durability, the repository's writes synced before what depends on them, all"
    echo "  on the single OCI/youki route."
    echo "  NOT proved here: anything the tree-level gate covers. Both are required."

# The Code Mode interpreter's syscall filter, asked of THIS kernel: a forked child must
# be able to install, with SECCOMP_FILTER_FLAG_TSYNC under no-new-privs, a filter whose
# kill_process leaf ends it by SIGSYS. That is what every Code Mode interpreter does to
# itself before it takes a cell (crates/code-mode-host/src/syscall_filter.rs): on a host
# that fails it no Code Mode cell runs, and the commit tier's Code Mode suites
# (kata-code-mode-host, kata-agent-nanocode) and gate-containment's nanocode cells fail.
# The probe, and its refused set, are scripts/code-mode-filter-probe.py's; it prints its
# own `code mode filter` row and exits non-zero on a refusal.
_code-mode-filter:
    @python3 -B scripts/code-mode-filter-probe.py

# The host preconditions the containment lane needs, as ONE piece of code with TWO
# callers — the lane's entry gate and `just host-check`. Two copies of this would be the
# ambiguous-name defect in its most expensive form: an operator's pre-flight answering a
# different question from the thing it claims to pre-flight.
#
# Every probe is FUNCTIONAL, never a `command -v`: a probe that merely finds a binary
# certifies a host on which every live test may silently skip.
[private]
_containment-preconditions:
    #!/usr/bin/env bash
    set -uo pipefail
    bad=0
    note() { printf '  %-22s %s\n' "$1" "$2"; }

    if python3 -c 'import os, signal; fd = os.pidfd_open(os.getpid()); signal.pidfd_send_signal(fd, 0); os.close(fd)' >/dev/null 2>&1; then
        note "pidfd" "ok — owned-process signaling functional"
    else
        note "pidfd" "MISSING — live smoke ownership requires Linux pidfd support"
        bad=1
    fi

    # 1. unprivileged user namespaces — the rootless-OCI route's first
    #    precondition: a confined capsule is a user-namespace mount/PID/net
    #    tree, and on a host where unprivileged userns is refused every OCI
    #    live cell cannot run.
    #    An AppArmor userns restriction (`kernel.apparmor_restrict_unprivileged_userns
    #    = 1`, Ubuntu's default) refuses an UNPROFILED `unshare` while the pinned youki,
    #    under its installed profile, still creates the namespace — the same
    #    `restricted` posture `kata doctor`'s containment_userns row reports. That is
    #    not a missing capability, so it is not refused here; the BLOCKING rootless-OCI
    #    row below proves the profiled route actually works.
    if unshare --user --map-root-user /bin/true >/dev/null 2>&1; then
        note "userns" "ok — unprivileged user namespaces functional"
    elif [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]; then
        note "userns" "restricted — AppArmor admits only profiled binaries; the rootless OCI row proves youki's"
    else
        note "userns" "REFUSED — unprivileged user namespaces are disabled."
        note "" "  Check kernel.unprivileged_userns_clone /"
        note "" "  user.max_user_namespaces."
        bad=1
    fi

    # 2. seccomp, which the adversarial suite's whole fence rests on.
    if [ -r /proc/sys/kernel/seccomp/actions_avail ]; then
        note "seccomp" "ok — $(tr '\n' ' ' < /proc/sys/kernel/seccomp/actions_avail)"
    else
        note "seccomp" "UNAVAILABLE — /proc/sys/kernel/seccomp/actions_avail is unreadable;"
        note "" "  oci_adversarial_live cannot measure the fence it certifies."
        bad=1
    fi
    #    and the Code Mode interpreter's own filter (`_code-mode-filter`, which prints
    #    its own row), which every nanocode cell in this lane's live rigs runs behind.
    if ! just _code-mode-filter; then
        bad=1
    fi

    # 3. cgroup v2 with the three controllers a capsule's bounds are expressed in.
    if [ -r /sys/fs/cgroup/cgroup.controllers ]; then
        controllers="$(cat /sys/fs/cgroup/cgroup.controllers)"
        want_missing=""
        for c in memory pids cpu; do
            case " $controllers " in *" $c "*) ;; *) want_missing="$want_missing $c" ;; esac
        done
        if [ -n "$want_missing" ]; then
            note "cgroup v2" "controllers missing:$want_missing — bounds fall to the DEGRADED arm"
            bad=1
        else
            note "cgroup v2" "ok — memory, pids, cpu present"
        fi
    else
        note "cgroup v2" "MISSING — no /sys/fs/cgroup/cgroup.controllers"
        bad=1
    fi

    # 4. A DELEGATED scope. This is the precondition nobody would guess and the one that
    #    silently costs the most: a login session's cgroup is NOT delegated on a typical host,
    #    so without `systemd-run --user --scope -p Delegate=yes` no memory or pids bound
    #    can be proven by round trip — the ENFORCED arm simply does not run, and a green
    #    exit says nothing about that.
    if ! command -v systemd-run >/dev/null 2>&1; then
        note "delegated cgroup" "systemd-run MISSING — the ENFORCED bounds arm cannot run"
        bad=1
    elif systemd-run --user --scope -q -p Delegate=yes /bin/true >/dev/null 2>&1; then
        note "delegated cgroup" "ok — a delegated user scope can be created"
    else
        note "delegated cgroup" "REFUSED — no user manager, or delegation is not permitted."
        note "" "  the delegated-scope live cells would measure only the DEGRADED arm."
        bad=1
    fi

    # 5. flock, which is how the lane keeps two installed mains from colliding.
    if command -v flock >/dev/null 2>&1; then
        note "flock" "ok"
    else
        note "flock" "MISSING — the per-uid installed-main singleton cannot be serialized"
        bad=1
    fi

    # 5b. A musl C compiler: the factory preflight smoke's in-capsule `kata` is the
    #     static `x86_64-unknown-linux-musl` build of this tree, and its C dependencies
    #     (SQLite, ring, zstd, QuickJS) compile with the compiler cc-rs looks for under
    #     these two names; without one that build cannot start.
    if command -v x86_64-linux-musl-gcc >/dev/null 2>&1 || command -v musl-gcc >/dev/null 2>&1; then
        note "musl cc" "ok — $(command -v x86_64-linux-musl-gcc || command -v musl-gcc)"
    else
        note "musl cc" "MISSING — the static in-capsule kata needs x86_64-linux-musl-gcc or musl-gcc (musl-tools)"
        bad=1
    fi

    # 6. Residue that makes a live smoke misreport. Not fatal to the KERNEL question, so
    #    it is reported as blocking only when it will actually break a boot.
    if [ -e "$HOME/.local/state/kata/main-attachment.json" ] && ! pgrep -x kata >/dev/null 2>&1; then
        note "attachment" "STALE $HOME/.local/state/kata/main-attachment.json with no live kata"
        note "" "  — remove it, or the product smokes read a node that is not there."
        bad=1
    else
        note "attachment" "ok — no stale installed-main descriptor"
    fi

    # 7. The ROOTLESS-OCI prerequisite, FUNCTIONAL and BLOCKING.
    #    Not a presence check: `probe_youki` refuses a youki that is not the pinned store
    #    path with the pinned bytes, then STARTS a rootless `/bin/true` container in a
    #    delegated scope and reports `passed` only if it exited 0. That is the same fact
    #    `crates/worker/tests/oci_runtime_live.rs` asserts and the same one
    #    `oci_runtime::certify_youki` refuses on.
    #
    #    THIS IS NOT THE LANE'S GUARANTEE — `just oci-live-smoke` is, and it runs every
    #    no-spend OCI live binary in both packages. The probe is BLOCKING for the reason
    #    every precondition here exists: it answers in seconds what that step would
    #    answer twenty minutes in, and on a host whose AppArmor profile is missing that
    #    is the difference between one diagnosable line and a lane an operator learns to
    #    skip. A host
    #    without the pinned youki cannot produce a containment green, by the same rule as
    #    userns above.
    #    `--only youki` so this lane does not also run the nix and portable-artifact
    #    probes — `just host-check` answers "can this host finish the lane", and paying
    #    for unrelated probes to learn one containment fact would make it slow enough
    #    that an operator would skip it, which is the one thing it must not be.
    youki_row="$(python3 -B scripts/feasibility-probes.py --only youki --json 2>/dev/null \
        | jq -r 'map(select(.probe == "rootless Youki OCI containment")) | .[0] // empty | "\(.status)\t\(.evidence)"' 2>/dev/null)"
    youki_status="${youki_row%%$'\t'*}"
    youki_evidence="${youki_row#*$'\t'}"
    if [ "$youki_status" = passed ]; then
        note "rootless OCI" "ok — $youki_evidence"
    else
        note "rootless OCI" "${youki_status:-unreadable} — ${youki_evidence:-the youki probe produced no row}"
        note "" "  The OCI route needs the PINNED youki (config/youki-pin.toml) with its"
        note "" "  exact-path AppArmor profile installed. From the kata checkout:"
        note "" "    nix build -o .kata/youki-root -f nix/youki.nix"
        note "" "      # NOT \`nix profile install nixpkgs#youki\`: that build has no libseccomp"
        note "" "      # and silently ignores linux.seccomp. \`-o\` roots it against nix gc."
        note "" "    sudo kata host apparmor-install"
        bad=1
    fi

    # 8. Load is not a precondition, it is a MEASUREMENT, and the lane's most common
    #    false failure comes from it. Reported always, blocking never: refusing above a
    #    threshold would hand every busy host a way to skip a required step.
    note "loadavg" "$(awk '{print $1, $2, $3}' /proc/loadavg 2>/dev/null || echo '?')  (reference: the product smoke is 1.4s at 12, and trips its 30s boot deadline at 496)"

    if [ "$bad" -ne 0 ]; then
        echo "containment preconditions: this host CANNOT produce a containment green." >&2
        echo "  Each line above names the missing capability rather than the symptom you" >&2
        echo "  would otherwise hit 25 minutes in. A SKIP is a FAILURE in this lane by" >&2
        echo "  design — a probe that quietly did not run reads as a pass." >&2
        exit 1
    fi
    echo "containment preconditions: ok — this host can run the containment lane."

# Run a specific test under workspace-wide load `count` times in a
# row. Fails on the first miss with the iteration count, so a flake
# rate of 1/N is reproducible. Use this when a test passes in
# isolation but fails under `just test` — running the test alone
# under `just test-one` doesn't reproduce contention. Filter syntax
# matches `just test-one` (e.g. `just flake-check max_iterations` or
# `just flake-check 'test(foo)'`).
flake-check name count="20":
    #!/usr/bin/env bash
    set -euo pipefail
    pass=0
    for i in $(seq 1 {{count}}); do
        # --ignore-default-filter: the `-E test(...)` filter is always
        # present, so a giant excluded from the default profile still reaches the
        # runner instead of listing empty (exit 4, misread as FAIL).
        if cargo nextest run --workspace --ignore-default-filter -E 'test({{name}})' >/tmp/kata-flake-check.log 2>&1; then
            pass=$((pass + 1))
            printf '  iter %2d: PASS (%d/%d)\n' "$i" "$pass" "{{count}}"
        else
            printf '  iter %2d: FAIL — see /tmp/kata-flake-check.log\n' "$i"
            exit 1
        fi
    done
    printf 'flake-check: {{name}} clean across {{count}} runs — IN ISOLATION.\n'
    printf '  This ran `-E test({{name}})`, so that test was the ONLY one running and\n'
    printf '  nothing was contending with it. A clean result here rules out an order- or\n'
    printf '  state-dependent flake. It says NOTHING about a load-sensitive one, and it\n'
    printf '  will report exactly this line for a test that fails regularly under load.\n'
    printf '  Measured, both clean here and red in a full lane:\n'
    printf '    worker_dies_mid_run_migrates_to_other_worker    1 of 3 `test` runs, 0 of 20 here\n'
    printf '    cancel_after_exit_before_reap_is_confirmed_...  1 containment lane, 0 of 5 here\n'
    printf '  To chase a load-sensitive flake, repeat the lane that showed it: `just test`\n'
    printf '  for a default-profile test, `just gate-containment` for an #[ignore]d one,\n'
    printf '  `just test-soak` for a giant. `retries = 0`, so the lane shows you the first\n'
    printf '  occurrence rather than hiding it behind a retry.\n'

# Live binary smoke tests — boots real `kata` / `kata-worker`
# subprocesses, drives them through the `kata` operator CLI. Auto-
# rebuilds release binaries first so a stale `target/release/`
# can't make the smokes lie (a smoke against binaries that predate
# the change under test fails, or passes, for the wrong reason).
#
# `just smoke` runs every test in both live-smoke integration binaries, INCLUDING
# the two that spend real model/API budget — this is the operator's door onto those,
# and it is the only one. `just smoke shell_` runs only the
# shell-stage variants (~3s total, no Claude API cost). `just smoke
# smoke_workspace_ro_outputs` runs one specific smoke.
#
# The REQUIRED `gate-containment` lane runs `just smoke-no-budget` below, not this
# recipe: same binaries, minus those two by name. Reach for `smoke-no-budget` when
# you want "everything the lane runs" and for `smoke <filter>` when you want one.
smoke filter="": build
    #!/usr/bin/env bash
    set -euo pipefail
    # Every test here boots an installed main, and that authority is a PER-UID
    # singleton by design (`/tmp/kata-installed-main-<uid>`). Explicit CLI threads=1
    # defeats NEXTEST_TEST_THREADS within a run; without the lock nothing serializes two
    # runs, so a smoke in one worktree and a gate's footprint-check in another both
    # fail — the loser with `HealthTimeout`, which reads as a defect in the node under
    # test. Queue.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just smoke "{{ filter }}"
    fi
    export KATA_LIVE_SMOKE=1
    if [ -z "{{ filter }}" ]; then
        expr='binary(smokes) or binary(live_smoke)'
    else
        expr='(binary(smokes) or binary(live_smoke)) and test({{ filter }})'
    fi
    cargo nextest run --workspace -P live-smoke --test-threads=1 --run-ignored all -E "$expr"

# The checkpoint acceptance runs a real contained timer after source loss. Its
# unit-test location needs an exact selector outside the ordinary host-independent gate.
# An L2 step (`gate-nightly`): three 15 s real-timer cells, ~75 s.
recovery-checkpoint-live:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just recovery-checkpoint-live
    fi
    just _recovery-checkpoint-live-run

_recovery-checkpoint-live-run:
    KATA_LIVE_SMOKE=1 KATA_SANDBOX_REQUIRE_LIVE=1 cargo nextest run --workspace -P live-smoke --test-threads=1 --run-ignored all -E 'package(kata) & kind(lib) & (test(=cli::recovery_capture::checkpoint_live_tests::checkpoint_source_loss_resumes_real_timer_and_successor_once_across_two_main_processes) | test(=cli::recovery_capture::checkpoint_live_tests::checkpoint_preserves_previously_validated_candidate_revalidates_and_lands_after_source_loss) | test(=cli::recovery_capture::checkpoint_live_tests::checkpoint_refuses_native_landing_when_restored_candidate_changes_after_revalidation))'

# Real ENOSPC on bounded tmpfs; this does not certify ext4 writeback/fsync failure.
# The bounded child runs in a rootless container of the PINNED youki — the runtime
# `_containment-preconditions`' blocking `rootless OCI` row proves.
recovery-disk-full-live:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just recovery-disk-full-live
    fi
    just _recovery-disk-full-live-run

_recovery-disk-full-live-run:
    KATA_LIVE_SMOKE=1 KATA_SANDBOX_REQUIRE_LIVE=1 cargo nextest run --workspace -P live-smoke --test-threads=1 --run-ignored all -E 'package(kata) & kind(lib) & (test(=cli::recovery_capture::disk_full_tests::recovery_capture_real_enospc_refuses_unpublished_artifacts))'

# Real publication syscalls with errno injection and process death, not physical
# power loss or ext4 allocator exhaustion. Requires working strace; no skip path.
recovery-publication-fault-live:
    env -u KATA_TEST_PUBLICATION_FAULT_MODE -u KATA_TEST_PUBLICATION_FAULT_ROOT cargo nextest run --workspace --test-threads=1 --run-ignored ignored-only -E 'package(kata-core) & kind(test) & binary(backup_durability_tests) & test(=publication_fault_experiment::publication_sync_faults_and_process_death_are_observed_at_the_syscall_boundary)' --success-output immediate

# The repository's durability barrier at the syscall boundary, read out of `strace`: a
# provider write is renamed into place, then a `syncfs` completes, then the jj operation
# naming it is published or the call returns (jj-lib's own `add workspace` operation the
# one exception, stated in `crates/vcs/src/jj/durability.rs`); a park's ref and its
# bookmark are synced before its teardown removes a file; an injected `syncfs` EIO is
# refused `repository_not_durable`; a kata `git` child fsyncs a ref and a loose object
# before it renames either into place. Not a power loss: the no-spend VM P1-host proof is.
# Requires working strace; no skip path.
repository-barrier-live:
    cargo nextest run --workspace --test-threads=1 --run-ignored ignored-only -E 'package(kata-vcs) & kind(test) & binary(repository_durability) & test(=barrier_syscalls::the_barrier_orders_writes_before_answers_at_the_syscall_boundary)' --success-output immediate

# Every live smoke that spends NO model/API budget: `gate-containment`'s product-path
# step.
#
# SELECTION IS BY SUBTRACTION, and that is the point rather than a shortcut. The
# expression is "both live-smoke binaries MINUS two named tests", so a smoke added to
# `crates/test-utils/tests/smokes.rs` or `live_smoke.rs` tomorrow rides the required
# lane with no edit here. Naming the wanted tests instead leaves every unnamed smoke to
# nothing automatic — and a live smoke nothing runs can stay red from the day it is
# written, asserting on strings production never emits.
#
# Its run carries NO exact subtractions (`not test(=...)`). The push tier's exact
# subtractions live in the `oci-live-smoke` steps, each one handing a timer-bound
# cell to L2; `the_nightly_cells_leave_the_push_tier_for_exactly_the_nightly_tier`
# holds that set equal to `NIGHTLY_CELLS`' binary-route cells, and
# `every_gate_filter_negates_only_in_a_form_this_file_reads` refuses any other way of
# negating in a gate `-E` expression, and a gate recipe naming nextest that holds
# anything but the one canonical run form it reads — which has no place for a libtest
# `--skip`, a positional name filter, `--exact` or `--partition` — so none of them can
# leave a cell that no tier selects. That is why the run below stands alone in
# `_smoke-no-budget-run`, its filter one single-quoted literal. What that check leaves
# out of scope is in docs/development/verification.md.
#
# THE EXCLUSION IS ABOUT MONEY, NOT FLAKINESS. It drives a real `nanocode_openai`
# turn on the host's `kata login openai`, so it spends real model budget, and runs
# only when an operator asks. It is not excluded for being slow, unreliable, or
# host-sensitive:
#     just smoke smoke_workspace_ro_outputs
# `bin/kata-eval/tests/gate_exclusion.rs` reads those clauses back out of the run
# (`the_lane_excludes_exactly_the_model_budget_smokes`) and requires
# `IGNORED_TESTS_OUTSIDE_THE_LANE` to name exactly them, so a further name added here
# fails `just gate` until somebody states whose budget it spends.
smoke-no-budget: build
    #!/usr/bin/env bash
    set -euo pipefail
    # Same per-uid installed-main singleton as `smoke` above; same lock, same queue.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just smoke-no-budget
    fi
    just _smoke-no-budget-run

# `smoke-no-budget`'s run. `--workspace` is what the run BUILDS, and `binary(...)` is
# matched against exactly that set. A narrower `-p` list would make both names select
# NOTHING, and a filter that selects nothing reports the same green as a real run.
_smoke-no-budget-run:
    KATA_LIVE_SMOKE=1 cargo nextest run --workspace -P live-smoke --test-threads=1 --run-ignored all -E '(binary(smokes) or binary(live_smoke)) and not test(smoke_workspace_ro_outputs)'

# The live factory proofs. They spend ZERO model budget — every stage is `agent =
# "shell"` — and they boot the product, which is why they sit here beside
# `product-cli-smoke` rather than in `just gate`.
#
# WHY THEY ARE NOT `#[ignore]`d smokes: they are justfile recipes and the lane's
# nextest selector cannot reach a recipe, so they have to be CALLED. What they catch
# is invisible elsewhere: a sandbox-default change that makes
# `memory_snapshot_stage`'s LOOPBACK `kata … memory snapshot` unreachable, or that
# resolves `factory_validation_stage`'s declared commands against the wrong library
# roots, stays green under `workflows-check-all` and the no-budget smoke set alike.
smoke-no-budget-factory: build-debug
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just smoke-no-budget-factory
    fi
    just factory-self-improve-preflight-smoke
    just factory-self-improve-implementation-smoke
    just product-factory-smoke

# ── THE GOLD LOOP ────────────────────────────────────────────────────
#
# `workflows/examples/gold-loop.star` is kata's agentic-change loop as ONE
# checked graph. Run by hand it is six steps — materialize the fixture,
# hand-derive a config, boot, health-poll, submit, poll, read the diff — and six
# steps nobody wrote down is a run that happens once. These three recipes are
# the written-down version.
#
# `gold-fixture-selftest` costs NOTHING and is the one to reach for first: it is
# a genuine regression check that the fixture is still an ORACLE (RED before the
# known fix, GREEN after). `gold-loop-smoke` SPENDS REAL MODEL BUDGET.

# Materialize the gold-loop playground repository into <dest> (idempotent).
gold-fixture-materialize dest:
    #!/usr/bin/env bash
    set -euo pipefail
    scripts/materialize-gold-fixture.sh "{{ dest }}"

# Prove the gold-loop fixture is still an ORACLE — $0, ~3s, no kata, no ports.
#
# It materializes into a temp dir it cleans up, asserts the suite is RED at the
# recorded failure count, applies `known-fix.patch`, asserts GREEN, and asserts
# the resulting diff touches exactly the files the patch names. A fixture that
# passes before the fix pins nothing, and this is what says so.
#
# HOST TOOLS, STATED RATHER THAN ASSUMED: `git`, `python3` and `cmp`, which the
# script checks at entry — and nothing else. The fixture is shell (`src/tally.sh`,
# `tests/test_tail.sh`, driven by `sh tests/check.sh`) and NOTHING in it compiles,
# so a toolchain precondition would refuse hosts that can run the suite and admit
# hosts that cannot. The honest form of "can this host run the suite at all" is not
# a `command -v` at all, it is `check.sh`'s own rc 2 (`"verdict":"error"`), which
# cell 2/4 names and blames the HOST for instead of the fixture. Green is 4/4 cells,
# 2 RED before the known fix and 0 after.
gold-fixture-selftest:
    #!/usr/bin/env bash
    set -euo pipefail
    scripts/materialize-gold-fixture.sh --self-test

# Run the gold agentic loop END TO END against a scratch fixture. SPENDS MODEL BUDGET.
#
# WHY THIS IS NOT IN ANY REQUIRED LANE, and what that rests on. The `implement`
# stage runs `agent = "default"`, so every run of this bills a real provider
# and runs only when an operator asks. THREE INDEPENDENT MECHANISMS
# keep it out, and only the third is a promise a future edit could break:
#
#   1. `just gate` reaches recipes by a STATIC walk of `just <name>` calls from
#      `gate` (`reachable_recipes`, `bin/kata-eval/tests/gate_exclusion.rs`).
#      Nothing in that graph names this recipe; the bounded check is
#      `gate_static_recipe_graph_excludes_the_live_eval_tier`. External script
#      contents and arbitrary shell execution are outside that static model.
#   2. `gate-containment`'s product-path step is `smoke-no-budget`, which selects
#      BY SUBTRACTION over nextest binaries: `(binary(smokes) or
#      binary(live_smoke))` minus two named tests. That expression can only ever
#      select a `#[test]` inside those two binaries. THIS IS A JUSTFILE RECIPE,
#      not a test in either binary, so the lane's selector cannot reach it —
#      which is exactly why the loop is driven from a recipe and NOT added as a
#      nineteenth `#[ignore]`d smoke in `crates/test-utils/tests/smokes.rs`. An
#      `#[ignore]`d test there would ride the required lane the day it landed,
#      and `the_lane_excludes_exactly_the_model_budget_smokes` would then FAIL
#      the gate until somebody named a third exclusion. Budget-spending work
#      belongs where the subtraction cannot see it.
#   3. Nobody adds `just gold-loop-smoke` to `gate`, `gate-hosted`,
#      `gate-scoped`, `gate-containment`, or to any recipe those reach. Only (3)
#      is a convention; (1) and (2) are machine-checked, and (1) would catch a
#      violation of (3) only if the guard grows a spend roster — it does not have
#      one today. STATED, NOT CLAIMED: there is no check that would refuse this
#      recipe being wired into the gate tomorrow.
#
# WHAT IT DOES: materializes the fixture into a scratch dir, DERIVES the node
# config from `config/kata.example.toml` (never hand-written — see below), boots
# one installed main, health-polls, load-checks the pack for free, submits it,
# polls to the human gate or to a terminal status, prints the execution id, the
# terminal status, every stage's timeline and the candidate diff, then tears the
# node and the scratch dir down on EVERY exit path.
#
# IT ASSERTS, IT DOES NOT MERELY PRINT. A run can print a clean timeline (every
# stage `completed`, terminal status `completed`) and have landed NOTHING: `land`
# reporting `{"commit_sha":"<sha>","operation":"promote","ref_name":"main"}` while
# the fixture repo's `refs/heads/main` never moved off the trunk base, the promoted
# commit's diff against that base is EMPTY, and the candidate worktree is then torn
# down — destroying the agent's real work. A recipe that prints `--- candidate diff
# --- / --- end candidate diff ---` with nothing between the markers and calls the
# run finished reads an empty diff after a promote as a pass.
#
# This recipe closes that. The fixture is a KNOWN-ANSWER test (RED before
# `known-fix.patch`, GREEN after, and that patch names the file a fix must touch),
# so a successful run has a knowable shape, and
# `scripts/materialize-gold-fixture.sh --verify-landed` asserts it against the
# fixture repo ON DISK: the base ref advanced, the envelope's CLAIM equals the
# repository's STATE, the landed diff is non-empty and touches what
# `known-fix.patch` names, and the fixture's own suite is GREEN on the landed tree
# — the same $0 oracle `gold-fixture-selftest` uses, so the assertion costs no
# model budget. Every one of those four TRIPS on the failure above, and the script
# names which symptom each catches beside the code.
#
# OUTCOME, NOT EDIT. None of it asserts the agent's diff: a model may fix `tail`
# differently than `known-fix.patch` does, and may add tests beside its fix. What
# it may not do is leave trunk where it was, or leave the suite red.
#
# READING THE EXIT CODE. `just gold-loop-smoke | tail -140` reports TAIL's status,
# not this recipe's, so a run that exited 1 reads as a pass. `$?` after any
# pipeline is the LAST command's, which is the same trap
# `docs/development/verification.md` records for `echo "EXIT=$?"`. Run it unpiped,
# or `just gold-loop-smoke >log 2>&1; echo "EXIT=$?"; tail -140 log`. The last line
# of stdout is the verdict, and a FAIL verdict is printed to stdout AND stderr
# precisely so that piping cannot hide it.
#
# THE HUMAN GATE IS OBSERVED BEFORE IT IS ANSWERED. The pack parks `approve` on
# a real operator decision and `land` promotes only after it. This recipe waits
# for that park, PRINTS the candidate diff an operator would be reading, and
# only then answers it — so a run that never parked cannot be mistaken for one
# that was approved. `KATA_GOLD_LOOP_APPROVE=0` leaves the gate parked and
# implies `KATA_GOLD_LOOP_KEEP_SCRATCH=1`, since a parked run whose data dir was
# deleted cannot be answered later.
#
# THE AGENT AND WHAT BOUNDS IT. The disposable config runs `default` as the
# example declares it — `nanocode_openai`, its model and effort unchanged — under
# an `api_key` credential through `OPENAI_API_KEY`, so the run bills the key it is
# handed rather than the operator's login, as the other spend recipes do. kata
# prices no `nanocode_openai` turn: the turn's cost is `quality: "unavailable"`,
# its reported tokens are the evidence of the spend, and the pack authors no
# dollar limit (CHECK would refuse one, `cost_bound_unenforceable_unpriced_adapter`).
# It is bounded by time: each `implement` attempt by the stage's own
# `timeout_ms`, which ends a runaway turn inside this recipe's 1200 s poll
# ceiling, and the run by its `time_bound`.
gold-loop-smoke: build-debug
    #!/usr/bin/env bash
    set -euo pipefail
    # Boots an installed main, which is a PER-UID SINGLETON. Queue instead of
    # colliding. Safe ONLY because the watchdog below bounds a hang.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just gold-loop-smoke
    fi
    source scripts/smoke-harness.sh
    # A hung run holds the per-uid installed main and breaks every later one. The
    # EXIT trap cannot help — a trap needs the shell to EXIT, and a hang is
    # precisely the shell not exiting. Only an external timer can.
    arm_watchdog "gold-loop-smoke"
    just pgrep-stale

    repo_root="$(pwd)"
    kata_bin="$repo_root/target/debug/kata"
    pack="$repo_root/workflows/examples/gold-loop.star"
    approve_gate="${KATA_GOLD_LOOP_APPROVE:-1}"
    keep_scratch="${KATA_GOLD_LOOP_KEEP_SCRATCH:-0}"
    if [ "$approve_gate" != "1" ]; then keep_scratch=1; fi
    # Under the 1800s harness watchdog by construction: a poll ceiling at or above
    # it would be reaped mid-poll and report nothing.
    timeout_secs="${KATA_GOLD_LOOP_TIMEOUT_SECS:-1200}"

    tmp="$(mktemp -d -t kata-gold-loop.XXXXXX)"
    fixture="$tmp/tally"
    runtime="$tmp/runtime"
    cfg="$runtime/kata.toml"
    data_dir="$tmp/data"
    pid=""
    id=""
    port="${KATA_GOLD_LOOP_PORT:-0}"
    metrics_port="${KATA_GOLD_LOOP_METRICS_PORT:-0}"
    api="http://127.0.0.1:${port}"
    export KATA_API_URL="$api"

    # SELF-CONTAINED CLEANUP, deliberately NOT the harness's sourced `cleanup`.
    # That one runs a recipe-defined `capture_evidence` first (undefined here, so
    # the trap would die with 127 before any teardown) and its `terminate_solo`
    # returns non-zero once the node is dead, which under `set -e` aborts the trap
    # before the scratch dir is removed. Same safe shape `eval-live` owns.
    cleanup() {
        disarm_watchdog || true
        terminate_solo || true
        if [ "$keep_scratch" = "1" ]; then
            echo "gold-loop-smoke: scratch KEPT at $tmp" >&2
        else
            remove_scratch "$tmp"
        fi
    }
    trap cleanup EXIT

    # AN ABORT MUST ANNOUNCE ITSELF, ON BOTH STREAMS. `set -e` exits SILENTLY,
    # so a run that dies partway shows an operator whatever the last
    # successful command printed and nothing else — and read through
    # `just gold-loop-smoke | tail -140`, which reports TAIL's status and not
    # this recipe's, that is indistinguishable from a pass. MEASURED:
    # `bash -c 'set -e; trap ... ERR; cmd || echo handled'` does NOT fire on a
    # handled failure, and `exit N` does not fire it either — so this line marks
    # exactly the unhandled aborts and never double-prints beside the final
    # verdict.
    trap 'code=$?; echo "gold-loop-smoke: FAIL — aborted (exit $code) at: $BASH_COMMAND"; echo "gold-loop-smoke: FAIL — aborted (exit $code) at: $BASH_COMMAND" >&2' ERR

    # TEARDOWN IS A STEP, NOT ONLY A TRAP — because `pgrep-stale` runs after it.
    #
    # THE DEFECT IT PREVENTS: ending with `just pgrep-stale` while the recipe's
    # OWN node is still up, since a node killed only by the EXIT trap dies when
    # the shell EXITS — strictly after every line of the body. The closing hygiene
    # check would count the recipe's own `kata` as residue and exit 1 on runs that
    # otherwise finished, and by the time an operator looked the process would be
    # gone (the trap reaped it), which reads as a flake and is not one. It is not
    # even a race: it could never pass. MEASURED with a stand-in process named
    # `kata` alive: `KATA_INSTALLED_MAIN_LOCK_HELD=1 just pgrep-stale` -> exit 1.
    # The env var is the reason — the lock re-exec above sets it, and `pgrep-stale`
    # deliberately does NOT excuse a live kata as another run's when the CALLER
    # holds the installed-main lock (that would make the check vacuous), so a live
    # node is always residue to it.
    #
    # DELETING THE CHECK WOULD BE THE WRONG FIX: a genuine leak must still fail
    # the recipe. So the node is stopped and WAITED FOR first, bounded, and a
    # node that outlives the budget REPORTS what survived and returns non-zero
    # rather than hanging. `terminate_solo` TERMs, polls 3s, then KILLs and
    # returns WITHOUT waiting on the kill — this is the wait it does not do.
    teardown_secs="${KATA_GOLD_LOOP_TEARDOWN_SECS:-30}"
    node_still_visible() {
        # Poll the EXACT condition the next check evaluates. `solo_alive` (the
        # harness) is the precise "our node" predicate; the two `pgrep -x` arms
        # are the surface `pgrep-stale` itself keys on, so a process visible to
        # it can never be missed here.
        solo_alive && return 0
        pgrep -x kata >/dev/null 2>&1 && return 0
        pgrep -x kata-worker >/dev/null 2>&1 && return 0
        return 1
    }
    stop_node_and_wait() {
        local deadline
        terminate_solo || true
        # Reap the direct child. MEASURED: `( cd X && prog ) &` makes
        # `$!` the PROGRAM (bash exec-optimizes the subshell — comm `kata`, no
        # children), so the node is this shell's own child and `wait` is what
        # collects it.
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
        deadline=$(( $(date +%s) + teardown_secs ))
        while node_still_visible; do
            if [ "$(date +%s)" -ge "$deadline" ]; then
                echo "gold-loop-smoke: a kata process is STILL up ${teardown_secs}s after TERM/KILL." >&2
                echo "  This is a genuine leak, not the teardown race; \`just pgrep-stale\` below" >&2
                echo "  will name it. Surviving processes:" >&2
                pgrep -a -x kata >&2 || true
                pgrep -a -x kata-worker >&2 || true
                return 1
            fi
            sleep 0.2
        done
        echo "gold-loop-smoke: node down (pid $pid), nothing named kata is left"
        return 0
    }

    # ── PRECONDITIONS, FUNCTIONAL RATHER THAN `command -v` ──────────────
    # The embedded harness runs in the worker; the capsule needs no model
    # program. What the run needs is the credential `default` is declared
    # under below: an API key through `OPENAI_API_KEY`, which the worker loads
    # for the nanocode turn.
    : "${OPENAI_API_KEY:?gold-loop-smoke needs OPENAI_API_KEY — the worker loads it for the nanocode turn}"
    # Under `oci` the confinement driver is rootless youki, and its
    # own precondition is a delegated cgroup: `oci_smoke_delegate_args`
    # mints the scope this recipe's `serve` then runs inside. A host whose
    # user manager cannot delegate fails HERE, not at the first capsule.
    source scripts/oci-smoke-node.sh
    if ! systemd-run $(oci_smoke_delegate_args 30) /bin/true >/dev/null 2>&1; then
        echo "gold-loop-smoke: systemd-run --user --scope -p Delegate=yes failed —" >&2
        echo "  rootless youki owns a cgroup only inside a delegated scope; without one" >&2
        echo "  the first capsule dispatch is where this run would die instead." >&2
        exit 2
    fi

    # ── 1. THE FIXTURE ──────────────────────────────────────────────────
    scripts/materialize-gold-fixture.sh "$fixture"
    base_sha="$(git -C "$fixture" rev-parse HEAD)"
    # Capture the trunk's REF NAME, not just its sha. The fixture is a COLOCATED
    # git+jj repo, and once jj owns the working copy the root checkout's `HEAD`
    # no longer follows the branch a promote moves — so a post-run `diff … HEAD`
    # reads an unrelated commit and prints NOTHING on a run that landed fine.
    base_ref="$(git -C "$fixture" symbolic-ref --short HEAD)"
    echo "gold-loop-smoke: fixture at $fixture, trunk $base_ref @ $base_sha"

    # ── 2. THE CONFIG — DERIVED FROM THE EXAMPLE, NEVER HAND-WRITTEN ────
    #
    # A committed `kata.gold-loop.toml` would be a hand-maintained twin of the
    # file whose `[runtime]`/`[workers]`/`[containment]` values decide what this
    # run MEANS, and the drift would be silent. So: patch the example's four
    # host-reaching keys and READ THEM BACK OUT of the parsed result. A `sed`
    # that matches nothing exits 0, and three of these four fail SILENTLY when
    # that happens — the run would boot against the operator's live
    # `~/.kata/data`, bind the host's 9400, and op-log-GC-sweep whatever `.jj`
    # sits beside the config. That is the discipline `scripts/footprint-config.sh`
    # follows and the reason it exists.
    #
    # WHY NOT REUSE THAT SCRIPT: it pins `[agents]` to exactly `["shell"]`,
    # because the GATE must boot only what a step exercises. This run's whole
    # point is the one stage that does bind a model agent, so the example's
    # agents stay and `[node] environment` and `default`'s adapter and
    # credential are injected below.
    mkdir -p "$runtime" "$data_dir"
    sed -e "s#data_dir = \"~/.kata/data\"#data_dir = \"$data_dir\"#" \
        -e "s#bind = \"127.0.0.1:8400\"#bind = \"127.0.0.1:$port\"#" \
        -e "s#^metrics_bind  *= \"127.0.0.1:9400\"#metrics_bind  = \"127.0.0.1:$metrics_port\"#" \
        -e "s#^jj_repo = \"\\.\\.\"#jj_repo = \"$fixture\"#" \
        "$repo_root/config/kata.example.toml" >"$cfg"

    # Two facts the example cannot carry, declared here. The
    # `[node] environment` closure is this host's — busybox/getent/git are
    # the pinned live roots; `nixpkgs#python3` runs the fixture's
    # `sh tests/check.sh` inside the capsule. No `egress_allow`: every stage
    # is `offline`, and the harness's model calls leave from the worker.
    # The agent declaration goes on `default`, the one model label this pack
    # binds: `nanocode_openai` under `api_key` via `OPENAI_API_KEY`, the
    # declaration the other spend recipes make.
    mapfile -t oci_extra < <(oci_smoke_nix_paths nixpkgs#python3)
    oci_smoke_inject_environment "$cfg" "gold-loop-smoke" \
        "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT" "${oci_extra[@]}"
    oci_smoke_agent_capsule "$cfg" default nanocode_openai \
        '{ mode = "api_key", source = "env:OPENAI_API_KEY" }'
    cargo build -p kata-provider-youki -p kata-oci-hook
    oci_smoke_provision_provider "$tmp" "$kata_bin" "$repo_root/target/debug"

    python3 - "$cfg" "$data_dir" "127.0.0.1:$port" "127.0.0.1:$metrics_port" "$fixture" <<'PY'
    import sys, tomllib

    path, want_data, want_api, want_metrics, want_repo = sys.argv[1:6]
    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)

    def lookup(dotted):
        cur = cfg
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur

    problems = []
    for dotted, expected in (
        ("node.data_dir", want_data),
        ("node.environment.system", "x86_64-linux"),
        ("api.bind", want_api),
        ("telemetry.metrics_bind", want_metrics),
        ("vcs.jj_repo", want_repo),
        ("agents.default.adapter", "nanocode_openai"),
        ("agents.default.credential.mode", "api_key"),
        ("agents.default.credential.source", "env:OPENAI_API_KEY"),
    ):
        got = lookup(dotted)
        if got != expected:
            problems.append(
                f"  {dotted} = {got!r}, expected {expected!r} — the substitution for this "
                f"key matched NOTHING in the derived config, so it still points at host "
                f"state or a capsule fact the recipe just declared did not land"
            )
    if not lookup("node.environment.store_paths"):
        problems.append("  node.environment.store_paths is empty — the capsule has no programs")

    agents = cfg.get("agents")
    names = sorted(agents) if isinstance(agents, dict) else agents
    if names != ["default", "gate", "reviewer", "shell"]:
        problems.append(
            f"  [agents] declares {names!r}, expected ['default', 'gate', 'reviewer', "
            f"'shell'] — the pack binds `default` and `shell`, and any other set means "
            f"the derivation added or dropped an entry this run was not checked against."
        )

    if problems:
        sys.exit("gold-loop-smoke: FAIL - the derived config is wrong:\n" + "\n".join(problems))
    PY
    echo "gold-loop-smoke: config derived at $cfg (api $api, metrics 127.0.0.1:$metrics_port)"

    # ── 3. LOAD-CHECK BEFORE SPENDING A TOKEN ───────────────────────────
    # Free, and it catches everything structural. A pack that does not compile is
    # not a thing to discover after a provider has been billed.
    "$kata_bin" check "$pack" --config "$cfg" >"$tmp/check.json"

    # ── 4. BOOT + HEALTH-POLL ───────────────────────────────────────────
    # `serve`'s supervised node hosts the capsule route — a delegated
    # scope, bound above the recipe's own poll ceiling, and the provider
    # exports plus OPENAI_API_KEY already on this process's env.
    ( cd "$fixture" && exec systemd-run $(oci_smoke_delegate_args $((timeout_secs + 600))) \
        "$kata_bin" serve --config "$cfg" >"$tmp/solo.log" 2>&1 ) &
    pid="$!"
    remember_solo
    wait_for_api "gold-loop-smoke"

    # ── 5. SUBMIT ───────────────────────────────────────────────────────
    # By PATH, not by the library name the pack's own header shows. The name form
    # resolves against `./.kata/workflows/`, which would mean writing an untracked
    # `.kata/` INTO the fixture repo — and an untracked file in the tree is
    # exactly what `require_promotable_workspace_for_promotion` refuses. The path
    # form reads the Starlark client-side and posts the source, so the fixture
    # stays byte-clean at trunk.
    "$kata_bin" --api-url "$api" run "$pack" --submit >"$tmp/submit.json"
    id="$(jq -r '.id' "$tmp/submit.json")"
    [ -n "$id" ] && [ "$id" != "null" ] || { cat "$tmp/submit.json" >&2; exit 1; }
    echo "gold-loop-smoke: execution $id submitted"

    # ── 6. POLL TO THE GATE, OR TO TERMINAL ─────────────────────────────
    #
    # `ExecutionStatus` has no `awaiting_approval` variant — a parked gate is
    # still `running` — so polling `status` ALONE would sit here until the
    # watchdog reaped a run that was waiting correctly. The gate is read from
    # `kata approvals`, which is where the park is actually visible.
    status="unknown"
    parked_assignment=""
    approved=0
    deadline=$(( $(date +%s) + timeout_secs ))
    while :; do
        "$kata_bin" --api-url "$api" run show "$id" >"$tmp/show.json" || true
        status="$(jq -r '.status // "unknown"' "$tmp/show.json" 2>/dev/null || echo unknown)"
        case "$status" in
            completed|failed) break ;;
        esac
        # `kata approvals` emits NDJSON unconditionally (`emit_list`); `--format`
        # does not reach it, so passing the flag would claim a control this call
        # does not have. jq reads the stream as-is, and an empty file is no gate.
        "$kata_bin" --api-url "$api" approvals >"$tmp/approvals.json" 2>/dev/null || : >"$tmp/approvals.json"
        parked_assignment="$(jq -r --arg id "$id" 'select(.execution_id == $id) | .assignment_id' "$tmp/approvals.json" 2>/dev/null | head -n1 || true)"
        if [ -n "$parked_assignment" ] && [ "$approved" -eq 0 ]; then
            echo
            echo "gold-loop-smoke: the human gate PARKED — execution $id, assignment $parked_assignment"
            "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace.json" || true
            worktree="$(jq -r '.worktree.path // empty' "$tmp/workspace.json" 2>/dev/null || true)"
            if [ -n "$worktree" ] && [ -d "$worktree" ]; then
                echo "--- candidate diff (base $base_sha .. candidate) ---"
                git -C "$worktree" --no-pager diff "$base_sha" || true
                echo "--- end candidate diff ---"
            else
                echo "gold-loop-smoke: no candidate worktree reported; workspace.json follows" >&2
                cat "$tmp/workspace.json" >&2 || true
            fi
            if [ "$approve_gate" = "1" ]; then
                echo "gold-loop-smoke: answering the gate (KATA_GOLD_LOOP_APPROVE=0 to leave it parked)"
                "$kata_bin" --api-url "$api" run approve "$id" "$parked_assignment"
                approved=1
            else
                echo "gold-loop-smoke: gate LEFT PARKED. The node is about to be torn down;"
                echo "  the durable park survives in $data_dir. Re-boot against that config and:"
                echo "    $kata_bin --api-url <url> run approve $id $parked_assignment"
                break
            fi
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "gold-loop-smoke: execution $id did not reach terminal within ${timeout_secs}s" >&2
            tail -120 "$tmp/solo.log" >&2 || true
            break
        fi
        sleep 2
    done

    # ── 7. REPORT ───────────────────────────────────────────────────────
    echo
    echo "===== gold-loop-smoke: execution $id ====="
    # NOT "terminal status": this prints whatever the last poll SAW, and the loop
    # also exits on the poll ceiling and on a deliberately-unanswered gate. A
    # label that says terminal for a `running` run is the fabricated-certainty
    # class, in the one line an operator reads first.
    echo "last observed status: $status"
    echo
    echo "----- stages -----"
    "$kata_bin" --api-url "$api" timeline "$id" || true
    echo
    echo "----- candidate diff, final (base $base_sha .. candidate or landed trunk) -----"
    "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace-final.json" || true
    worktree="$(jq -r '.worktree.path // empty' "$tmp/workspace-final.json" 2>/dev/null || true)"
    if [ -n "$worktree" ] && [ -d "$worktree" ]; then
        git -C "$worktree" --no-pager diff "$base_sha" || true
    else
        # After a promote the worktree is torn down BY DESIGN and the candidate is
        # on the fixture's trunk. Read it THERE, and by REF NAME — `HEAD` in a
        # colocated repo is the jj working copy, not the branch that was promoted.
        git -C "$fixture" --no-pager diff "$base_sha" "$base_ref" || true
    fi
    echo "----- end candidate diff -----"
    echo

    # THE LAND ENVELOPE, read while the node is still up. Everything after the
    # node stops reads only the fixture repo on disk, so this is the last thing that
    # needs the API. `outputs` is the per-stage map on the execution record
    # (`ExecutionRecord::outputs`, crates/types/src/execution.rs), a stage's
    # value is the worker's completed-output object (`build_completed_output`,
    # crates/worker/src/agent_turn.rs), and `.content` is the backend's raw string
    # — which for `workspace_effect` is the envelope
    # `{"operation","ref_name","commit_sha"}`.
    "$kata_bin" --api-url "$api" run show "$id" >"$tmp/final.json" || true
    land_envelope="$(jq -r '.outputs.land.content // empty' "$tmp/final.json" 2>/dev/null || true)"
    halt_envelope="$(jq -r '.outputs.halt.content // empty' "$tmp/final.json" 2>/dev/null || true)"
    land_op="$(printf '%s' "$land_envelope" | jq -r '.operation // empty' 2>/dev/null || true)"
    land_ref="$(printf '%s' "$land_envelope" | jq -r '.ref_name // empty' 2>/dev/null || true)"
    land_sha="$(printf '%s' "$land_envelope" | jq -r '.commit_sha // empty' 2>/dev/null || true)"

    # ── 8. TEARDOWN, THEN HYGIENE — IN THAT ORDER ───────────────────────
    #
    # `smoke_exit` is accumulated from here on rather than exiting at the first
    # failure: an operator who has just spent model budget deserves every true
    # thing this run can tell them, not the first one. Nothing below is allowed
    # to LOWER it.
    smoke_exit=0
    stop_node_and_wait || smoke_exit=1
    just pgrep-stale || smoke_exit=1

    # ── 9. THE ORACLE — what a successful run MUST have produced ────────
    if [ "$status" = "completed" ]; then
        if [ -z "$land_sha" ]; then
            smoke_exit=1
            echo "gold-loop-smoke: the run completed but the \`land\` stage recorded NO output." >&2
            if [ -n "$halt_envelope" ]; then
                echo "  \`halt\` did: $halt_envelope" >&2
                echo "  The route took the halt arm, so validation said failed and NOTHING was" >&2
                echo "  promoted. That is the LOOP working and the SMOKE failing: this recipe" >&2
                echo "  exists to prove a change lands, so a run that lands nothing is red." >&2
            else
                echo "  Neither did \`halt\`. Stages that produced output:" >&2
                jq -r '.outputs // {} | keys | join(", ")' "$tmp/final.json" >&2 || true
            fi
        elif [ "$land_op" != "promote" ]; then
            # An INPUT guard, not one of the four assertions: --verify-landed is
            # written for a promote envelope, and checking a park's candidate ref
            # against trunk would report confident nonsense.
            smoke_exit=1
            echo "gold-loop-smoke: the \`land\` envelope reports operation='$land_op', expected 'promote': $land_envelope" >&2
        elif ! scripts/materialize-gold-fixture.sh \
                --verify-landed "$fixture" "$base_sha" "$land_ref" "$land_sha"; then
            smoke_exit=1
        fi
    elif [ "$approve_gate" != "1" ] && [ -n "$parked_assignment" ]; then
        # Not a failure: the operator asked for the gate to stay parked, and it
        # did. Nothing landed BY REQUEST, so nothing about landing is asserted.
        :
    else
        smoke_exit=1
    fi

    # ── 10. THE VERDICT, ON STDOUT AND (WHEN RED) ON STDERR ─────────────
    echo
    if [ "$smoke_exit" -ne 0 ]; then
        # THE EVIDENCE SURVIVES A RED VERDICT. The fixture repo is now where that
        # verdict is READ FROM, and the default teardown deletes the one tree an
        # operator needs to open. `cleanup` reads this at EXIT, so setting it here
        # is enough; it costs a green run nothing.
        keep_scratch=1
        # Both streams on purpose: `| tail` keeps stdout only, and this recipe
        # has already been read as green through exactly that pipe.
        echo "gold-loop-smoke: FAIL (last observed status=$status) id=$id api=$api"
        echo "gold-loop-smoke: FAIL (last observed status=$status) id=$id api=$api" >&2
    elif [ "$status" = "completed" ]; then
        echo "gold-loop-smoke: PASS id=$id api=$api — trunk advanced onto the candidate and the fixture suite is GREEN on what landed"
    else
        echo "gold-loop-smoke: PARKED AT THE HUMAN GATE (by request) id=$id assignment=$parked_assignment"
    fi
    exit "$smoke_exit"


# jj OP-LOG CONTENTION posture under N parallel workspaces.
# Boots ONE installed main on the native jj execution-workspace provider against a
# SINGLE shared jj repo, then submits N file-producing shell workflows
# CONCURRENTLY. Each execution gets its own execution-scoped jj workspace
# sharing that repo's operation log, so the run drives N concurrent jj
# workspace create/snapshot/status ops against ONE shared op-log.
#
# PASS := all N executions reach Completed, each wrote + re-read its distinct
# marker file, and each jj workspace is dirty with exactly its own marker path
# — i.e. jj's optimistic-concurrency op-log absorbed N concurrent workspace ops
# with NO wedge, NO corruption, NO cross-workspace bleed — the live read behind
# jj being the default execution-workspace backend.
#
# N defaults to 6; `KATA_JJ_SMOKE_N=<2..=16>` overrides. Shell agent only — no
# model, no Claude API cost. Stale-process preflight (`just pgrep-stale`) runs
# first and last; on a hang, `just kill-kata` reaps the node subprocess tree.
# `build` first so the smoke spawns FRESH release binaries.
#
# jj op-log contention read under N parallel jj workspaces (run by hand).
jj-parallel-smoke: build
    #!/usr/bin/env bash
    set -euo pipefail
    # Boots ONE installed main — the same per-uid singleton `smoke` guards.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just jj-parallel-smoke
    fi
    just pgrep-stale
    export KATA_LIVE_SMOKE=1
    export KATA_JJ_SMOKE_N="${KATA_JJ_SMOKE_N:-6}"
    cargo nextest run -p kata-test-utils \
        -P live-smoke --test-threads=1 --run-ignored all \
        -E 'test(smoke_jj_parallel_workspaces_op_log_contention)'
    just pgrep-stale

# Workspace line/region coverage via cargo-llvm-cov, driving nextest
# so per-test slow-timeouts from .config/nextest.toml still apply.
# ENABLER recipe — not part of `just gate` (instrumented builds are
# ~2-4x slower). Runs under the `coverage` nextest profile, which
# widens slow-timeouts so instrumentation overhead doesn't false-kill
# otherwise-fast tests. `just coverage` prints a summary; pass an
# output flag through as needed, e.g.
#   just coverage --html        # writes target/llvm-cov/html/index.html
#   just coverage --lcov --output-path lcov.info
# Requires the `cargo-llvm-cov` component/subcommand:
#   rustup component add llvm-tools-preview
#   cargo install cargo-llvm-cov
coverage *args:
    cargo llvm-cov nextest --workspace -P coverage {{args}}

# Doctests — the one exception where plain `cargo test` is still
# canonical (nextest does not cover doctests). Runs inside `just gate`
# beside the test run; invoke it directly when iterating on doc
# comments, so a rustdoc break costs seconds rather than a gate run.
test-doc:
    cargo test --doc --workspace

# Plain `cargo test` runs here for doctests and nowhere else: a libtest run that
# selects zero tests exits 0, so a `cargo test … -- --ignored` recipe is an exit
# code that cannot distinguish "ran" from "nothing ran".
# `the_justfile_runs_cargo_test_only_for_doctests` in
# `bin/kata-eval/tests/gate_exclusion.rs` keeps it that way.

deny:
    #!/usr/bin/env bash
    set -uo pipefail
    # This GATES: a `deny.toml` nothing runs is a named recourse nobody can invoke.
    #
    # `--hide-inclusion-graph` is not cosmetic. Without it this prints **14,578
    # lines** (measured), almost all of it dependency trees for 53 duplicate-crate
    # warnings; with it, 892. A gate step that dumps fourteen thousand lines on
    # every green run trains every reader to scroll past it, which destroys the
    # signal the step exists for.
    #
    # So: quiet on success, EVERYTHING on failure. Gating here has a known, accepted
    # cost — an upstream advisory nobody in this repo can fix can red
    # a pre-push gate on a diff that did not cause it. The sanctioned response is a
    # `deny.toml` exception WITH A REASON, never deleting the check.
    log="$(mktemp -t kata-deny.XXXXXX)"
    cargo deny check --hide-inclusion-graph >"$log" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "deny: cargo-deny FAILED (exit $rc). Full output follows." >&2
        echo "  An advisory you cannot fix upstream is answered with a deny.toml" >&2
        echo "  exception AND a reason — not by removing this step." >&2
        cat "$log" >&2
        rm -f "$log"
        exit "$rc"
    fi
    # Green: the verdict line, plus a census of what it WARNED about, because a
    # warning nobody ever sees is the same defect one layer down.
    grep -E "^(advisories|bans|licenses|sources) " "$log" || tail -1 "$log"
    warnings="$(grep -cE "^warning" "$log" || true)"
    if [ "${warnings:-0}" -gt 0 ]; then
        echo "deny: $warnings warning(s), by class:"
        grep -E "^warning" "$log" | sed 's/.*\[\(.*\)\].*/  \1/' | sort | uniq -c \
            | sort -rn | sed 's/^/  /'
        echo "  (full detail: just deny 2>&1 | grep -A3 warning)"
    fi
    rm -f "$log"

# The execution-provenance derive probe — "the derives cannot come back", observed by
# the COMPILER instead of asserted in a comment.
#
# WHAT IS BEING PROVED. `ExecutionProvenance` keeps its wire vocabulary in ONE door
# by OWNING the `Deserialize` slot (`from_wire` refuses every token outside its two
# arms, by name; a derive would construct straight past `Attribution`'s private
# field), by having a shape `#[derive(Default)]` cannot compile on (a derive would
# fabricate a provenance nobody established), and by keeping `Attribution(..)`
# unconstructible downstream, so every mint is one of the named doors in
# `execution_provenance.rs`. Each is a property of an ABSENCE, and no runtime test
# can see an absence: a suite asserting "the derive is not there" passes just as
# happily on a tree where it is. So the observation has to be a compile failure, and
# this repo has no trybuild/compiletest harness (grep-confirmed) — hence a
# `--cfg`-gated probe, which is the smallest thing that can watch rustc refuse.
#
# WHY A DEDICATED `CARGO_TARGET_DIR`. A cfg change is a compiler-input change, and
# sharing `target/` would invalidate the workspace's artifacts on every arm — the
# gate would then pay a full rebuild twice per run, for a probe that compiles one
# crate. The stated cost, because this repo is disk-sensitive: the probe's target dir
# holds **611 MiB** measured, it is inside the gitignored `target/`
# so `clean` reclaims it, and the recipe runs 46s cold / 13s warm.
#
# WHY `cargo rustc --profile check` AND NOT `RUSTFLAGS`. `RUSTFLAGS` applies to the
# whole graph, so every arm would rebuild serde, chrono, criterion and the rest;
# measured, that is ~32s per arm against ~6s. `cargo rustc -- --cfg X` passes the cfg
# to the ONE target under test and leaves the dependency cache alone. It also scopes
# the blast radius honestly: the probe attributes are on kata-types' own items.
#
# THE CONTROL IS WHAT MAKES THIS NON-VACUOUS, and it is the first arm on purpose. A
# harness that failed for a toolchain, path or dependency reason and reported
# "refused" would be a verification satisfiable by observing nothing. So: arm 1 must
# SUCCEED, proving the probe
# attributes are inert and the crate is healthy under the same command shape; arms
# 2-4 must FAIL **and name the expected error code**; and a failure that does not
# name it exits INCONCLUSIVE (status 2) BY NAME rather than being read as a green
# refusal.
#
# HOST-INDEPENDENT, so it rides `gate` and not the containment lane: it runs no test
# binary, needs no `--run-ignored`, and asks the kernel nothing.
derive-refusal-probe:
    #!/usr/bin/env bash
    set -uo pipefail

    export CARGO_TARGET_DIR="target/derive-refusal-probe"
    log="$(mktemp -t kata-derive-probe.XXXXXX)"
    trap 'rm -f "$log"' EXIT

    inconclusive() {
        echo "DERIVE-PROBE INCONCLUSIVE: $1" >&2
        echo "  This is NOT a green refusal, and must not be read as one. The arm failed," >&2
        echo "  but not with the diagnostic the mechanism produces. Two very different" >&2
        echo "  things look like this and the probe cannot tell them apart:" >&2
        echo "    (a) the run broke for a toolchain, path or stale-cache reason; or" >&2
        echo "    (b) the arm failed for an unrelated compile error that hides whether" >&2
        echo "        the mechanism itself still refuses — requiring the named code AND" >&2
        echo "        the named file is what tells the two apart." >&2
        echo "  Full output follows." >&2
        cat "$log" >&2
        exit 2
    }
    accepted() {
        echo "DERIVE-PROBE FAILED: $1" >&2
        echo "  The compiler ACCEPTED something the provenance design requires it to refuse, so an" >&2
        echo "  execution provenance can now be minted outside its named doors. One of the" >&2
        echo "  three mechanisms is gone: the hand-written 'impl Deserialize', a variant's" >&2
        echo "  field, or 'Attribution''s private field. Restore it — do not relax this" >&2
        echo "  probe." >&2
        exit 1
    }
    require() {
        grep -qF "$1" "$log" || inconclusive "arm '$2' failed without any line containing '$1'"
    }

    # ── ARM 1: THE CONTROL. Must SUCCEED. ────────────────────────────────────────
    if ! cargo check -p kata-types --all-targets --all-features >"$log" 2>&1; then
        inconclusive "the no-cfg CONTROL did not compile, so nothing below can be attributed to a derive"
    fi
    echo "DERIVE-PROBE control: kata-types compiles clean, probe attributes inert"

    # ── ARM 2: #[derive(Deserialize)] on ExecutionProvenance. Must FAIL, E0119. ──
    if cargo rustc --profile check -p kata-types --lib --all-features -- \
        --cfg kata_probe_derive_deserialize >"$log" 2>&1; then
        accepted "'#[derive(Deserialize)]' compiled alongside the hand-written impl"
    fi
    require 'error[E0119]' deserialize
    require 'ExecutionProvenance' deserialize
    echo "DERIVE-PROBE deserialize: E0119 on ExecutionProvenance"

    # ── ARM 3: #[derive(Default)] on ExecutionProvenance. Must FAIL, E0665. ──────
    # E0665 is "no #[default] variant": every variant carries a field.
    if cargo rustc --profile check -p kata-types --lib --all-features -- \
        --cfg kata_probe_derive_default >"$log" 2>&1; then
        accepted "'#[derive(Default)]' compiled, so a provenance nobody established can be fabricated"
    fi
    require 'error[E0665]' default
    require 'execution_provenance.rs' default
    echo "DERIVE-PROBE default: E0665 on ExecutionProvenance"

    # ── ARM 4: a DOWNSTREAM crate minting past the private field. E0603. ─────────
    # `crates/types/tests/` is a separate crate, which is the exact vantage the
    # claim "a downstream crate cannot mint one" is about.
    if cargo rustc --profile check -p kata-types --test execution_provenance_tests --all-features -- \
        --cfg kata_probe_mint_attribution >"$log" 2>&1; then
        accepted "a downstream crate constructed 'Attribution' past its private field"
    fi
    require 'error[E0603]' mint
    require 'private tuple struct constructor' mint
    echo "DERIVE-PROBE mint: E0603 on Attribution, from a downstream crate"

    echo "DERIVE-PROBE: the provenance derives stay refused — 1 control + 3 refusals"

doc:
    cargo doc --workspace --no-deps --open

# No build or test seals a directory under `target/`; sealed provider stores live in
# the live tests' `$TMPDIR` tempdirs, which this recipe does not touch.
# Remove `target/` (`cargo clean`).
clean:
    cargo clean

# ─── Running kata ─────────────────────────────────────────────
#
# All commands honour `config` (default `config/kata.example.toml`,
# override via `KATA_CONFIG=path just <recipe>`).

# Run the one installed durable main in the foreground.
serve:
    cargo run -- serve --config {{config}}

# Point-in-time backup of the durable stores under `node.data_dir`
# (ledger + native memory + workflow state + config) into an artifact
# directory. Consistent even while a node is live (VACUUM INTO copies).
# Usage: just backup /path/to/artifact-dir
backup out:
    cargo run -- backup --config {{config}} --out {{out}}

# Restore a `node.data_dir` from a `just backup` artifact. Refuses to
# run while a node is live against the target — `just kill-kata` first.
# Usage: just restore /path/to/artifact-dir
restore from:
    cargo run -- restore --from {{from}} --config {{config}}

# Validate the kata TOML config (syntax + field ranges).
config-check:
    cargo run -- config check --config {{config}}

# ─── Workflow library ────────────────────────────────────────

# Compile and preflight a workflow without executing it.
# Usage: just workflows-check kata-loop-lite
workflows-check workflow:
    cargo run --quiet -- workflows check {{workflow}}

# Compile and preflight every effective workflow in the layered library, the
# `workflows/smoke` rigs included: the explicit stdlib dir opens its `smoke`
# sibling, which neither a bundle nor a checkout build resolves.
workflows-check-all:
    KATA_STDLIB_DIR="$PWD/workflows/std" cargo run --quiet -- workflows check --all

# Strict pre-run check that treats verifier warnings as launch blockers.
# Usage: just workflows-check-strict kata-loop-lite
workflows-check-strict workflow:
    cargo run --quiet -- workflows check {{workflow}} --deny-warnings

# Preflight the canonical Kata-on-Kata factory pack before a live model-backed run.
factory-self-improve-preflight out_dir="/tmp/kata-factory-self-improve-preflight":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{out_dir}}"
    just build
    export PATH="$(pwd)/target/release:$PATH"
    implementation_ref="std.software_factory.kata_self_improve"
    preflight_ref="std.software_factory.kata_self_improve_preflight"
    # The packs' own validate stages run `kata check`/`kata build` as children
    # of the `serve` process; `KATA_CONFIG` — `--config` spelled in the
    # environment — is the only door that reaches pack-authored commands (a
    # flag cannot be edited into them). `kata init` emits no profile key, so
    # the judgment lands on the shipped `oci` default — which judges agent
    # stages against the config's `[agents]` map. The packs bind `default` and
    # `shell`, and `kata init` writes `default`; `implement` authors `net = "host"`, which refuses
    # `egress_undeclared` on an empty `egress_allow`: the crates.io pair is the
    # honest authority its `cargo` validation reaches.
    (cd "{{out_dir}}" && kata init --config kata.toml --force >/dev/null)
    source scripts/oci-smoke-node.sh
    OCI_SMOKE_EGRESS_ALLOW="index.crates.io:443 static.crates.io:443" \
        oci_smoke_inject_environment "{{out_dir}}/kata.toml" "factory-self-improve-preflight" \
        "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT"
    export KATA_CONFIG="{{out_dir}}/kata.toml"
    kata check "$implementation_ref"
    kata build "$implementation_ref" \
        --out "{{out_dir}}/$implementation_ref.build.json"
    kata check "$preflight_ref"
    kata build "$preflight_ref" \
        --out "{{out_dir}}/$preflight_ref.build.json"
    jq -e '
      .build.passed == true
      and .execution_program.summary.validation_criterion_count == 6
      and .execution_program.summary.review_loop_count == 0
      and .execution_program.stages.implement.policies.sandbox.data == "factory-review"
      and ((.execution_program.stages.implement.invocation_envelope.mutation_policy // "advisory") != "owned_paths")
      and (.preflight.execution_program.verifier_passes[] | select(.id == "factory_stage_policy") | .evidence.workspace_rw_stage_count == 0 and .evidence.mutating_stage_count == 0)
    ' "{{out_dir}}/$preflight_ref.build.json" >/dev/null
    just test-one-crate kata-program starlark_eval_kata_self_improve_pack_builds
    just test-one-crate kata-program starlark_eval_kata_self_improve_preflight_pack_builds
    echo "factory-self-improve-preflight: PASS out={{out_dir}}"

# Run the live API-backed validation-only Kata-on-Kata proof.
factory-self-improve-preflight-smoke: build-debug
    #!/usr/bin/env bash
    set -euo pipefail
    # This recipe boots an installed main, a PER-UID singleton. Queue instead
    # of colliding. Safe ONLY because the watchdog armed below bounds a hang —
    # locking a hang would block every other run behind it.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just factory-self-improve-preflight-smoke
    fi
    source scripts/smoke-harness.sh
    # A hung run holds the PER-UID installed main and breaks every
    # later one. The EXIT trap cannot help — a trap needs the shell to exit,
    # and a hang is precisely the shell not exiting. Only an external timer can.
    arm_watchdog "factory-self-improve-preflight-smoke"
    repo_root="$(pwd)"
    kata_bin="$repo_root/target/debug/kata"
    port="${KATA_FACTORY_SELF_IMPROVE_PREFLIGHT_PORT:-0}"
    metrics_port="${KATA_FACTORY_SELF_IMPROVE_PREFLIGHT_METRICS_PORT:-0}"
    api="http://127.0.0.1:${port}"
    evidence_dir="${KATA_FACTORY_SELF_IMPROVE_PREFLIGHT_EVIDENCE_DIR:-}"
    tmp="$(mktemp -d)"
    project="$tmp/project"
    runtime="$tmp/runtime"
    cfg="$runtime/kata.toml"
    pid=""
    smoke_status="failed"
    implementation_ref="std.software_factory.kata_self_improve"
    preflight_ref="std.software_factory.kata_self_improve_preflight"
    id=""
    snapshot_sha=""
    export PATH="$repo_root/target/debug:$repo_root/target/release:$PATH"
    export KATA_API_URL="$api"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target/factory-self-improve-evidence}"

    capture_evidence() {
        if [ -z "$evidence_dir" ]; then
            return
        fi
        mkdir -p "$evidence_dir"
        cp "$tmp"/*.json "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.txt "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.stderr "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp/solo.log" "$evidence_dir/solo.log" 2>/dev/null || true
        if [ -f "$tmp/operator-status.diff" ]; then
            cp "$tmp/operator-status.diff" "$evidence_dir/operator-status.diff"
        fi
        jq -n \
            --arg status "$smoke_status" \
            --arg workflow "$preflight_ref" \
            --arg api "$api" \
            --arg project "$project" \
            --arg execution_id "$id" \
            --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg repo_sha "$(git -C "$repo_root" rev-parse HEAD)" \
            --arg snapshot_sha "$snapshot_sha" \
            '{
              summary_kind: "factory_self_improve_preflight_evidence",
              status: $status,
              workflow: $workflow,
              captured_at: $captured_at,
              repo_sha: $repo_sha,
              snapshot_sha: $snapshot_sha,
              api_url: $api,
              temp_project: $project,
              execution_id: $execution_id,
              artifacts: [
                "operator-status-before.txt",
                "operator-status-after.txt",
                "operator-status.diff",
                "snapshot-status.txt",
                "implementation-check.txt",
                "implementation-build.json",
                "preflight-check.txt",
                "preflight-build.json",
                "memory-import.json",
                "submit.json",
                "initial-input.json",
                "wait.json",
                "show.json",
                "summary.json",
                "replay.json",
                "replay.stderr",
                "workspace.json",
                "factory-status.json",
                "explain.json",
                "memory-snapshot.json",
                "output-memory_context.json",
                "output-context.json",
                "output-plan.json",
                "output-implement.json",
                "output-review.json",
                "output-validate.json",
                "output-controller.json",
                "output-closeout.json",
                "solo.log"
              ]
            }' >"$evidence_dir/evidence-summary.json"
        {
            printf '# Factory Self-Improve Preflight Evidence\n\n'
            printf 'Status: %s\n' "$smoke_status"
            printf 'Workflow: %s\n' "$preflight_ref"
            printf 'API: %s\n' "$api"
            printf 'Execution: %s\n' "${id:-unknown}"
            printf 'Snapshot commit: %s\n\n' "${snapshot_sha:-unknown}"
            printf 'Start with `evidence-summary.json`, `preflight-build.json`,\n'
            printf '`summary.json`, `factory-status.json`, `explain.json`,\n'
            printf '`workspace.json`, `output-validate.json`, `output-controller.json`,\n'
            printf 'and `output-closeout.json` when reviewing the Kata-on-Kata\n'
            printf 'validation-only proof.\n'
        } >"$evidence_dir/README.md"
    }
    trap cleanup EXIT

    # Snapshot the operator checkout into a clean temp Git project.
    #
    # THE CLEAN-CHECKOUT REFUSAL IS NARROWED TO THE EVIDENCE RUN, and the narrowing
    # is what makes this recipe RUNNABLE by a required lane. The refusal's own
    # sentence says why it exists — *commit-grade* evidence, whose `repo_sha` field
    # must resolve to the tree that was proven — and that claim is only made when
    # `evidence_dir` is set (`capture_evidence` writes `repo_sha` and is a no-op
    # otherwise). Refusing a dirty checkout on a run that publishes no evidence would
    # refuse more than it claims, and would keep this smoke out of the containment
    # lane, the only automatic runner of this pack's `memory_context` stage. The
    # snapshot is self-describing either way — it is committed here and reported as
    # `snapshot_sha` — and the operator-checkout-unchanged proof below compares
    # BEFORE against AFTER, which is a stronger statement on a dirty tree, not a
    # weaker one. Written with `git status` on both sides so the two files are
    # byte-comparable whether or not the status is empty.
    git -C "$repo_root" status --short --untracked-files=all >"$tmp/operator-status-before.txt"
    if [ -n "$evidence_dir" ] && [ -s "$tmp/operator-status-before.txt" ]; then
        echo "factory-self-improve-preflight-smoke: operator checkout must be clean for commit-grade evidence." >&2
        cat "$tmp/operator-status-before.txt" >&2
        exit 1
    fi
    mkdir -p "$project"
    # A NESTED `.git` OR `.jj` BREAKS THE `git add -A` BELOW, and one gets there
    # without anybody choosing it. Cargo runs an integration test with CWD set to
    # its PACKAGE ROOT, so a test that boots a node whose `vcs.jj_repo` resolves
    # relatively COLOCATES jj into `bin/kata/` — a `.jj/` plus the `.git/`
    # that colocation creates. `.gitignore` already names `.jj/` for exactly this
    # reason and says so in its own comment; it cannot name a nested `.git`, and
    # git does not need it to, because git never descends into one. THIS tar
    # does: after a plain `just test` a `bin/kata/.git` can exist, and without the
    # exclusions this recipe dies with
    # `error: 'bin/kata/' does not have a commit checked out` (exit 128) —
    # an ORDER-DEPENDENT break of a required containment-lane step, invisible on
    # a host that had not run the suite first.
    tar \
        --exclude='./.git' \
        --exclude='*/.git' \
        --exclude='./.jj' \
        --exclude='*/.jj' \
        --exclude='./agents' \
        --exclude='./.github' \
        --exclude='./.kata' \
        --exclude='./.claude' \
        --exclude='./.worktrees' \
        --exclude='./target' \
        --exclude='*/target' \
        --exclude='./node_modules' \
        --exclude='*/node_modules' \
        --exclude='./.env' \
        -C "$repo_root" -cf - . | tar -C "$project" -xf -
    git -C "$project" init -b main >/dev/null
    git -C "$project" config user.email "kata-self-improve-preflight@example.invalid"
    git -C "$project" config user.name "Kata Self Improve Preflight"
    git -C "$project" add -A
    git -C "$project" commit -m "snapshot kata self-improve preflight evidence project" >/dev/null
    snapshot_sha="$(git -C "$project" rev-parse HEAD)"
    git -C "$project" status --short --untracked-files=all >"$tmp/snapshot-status.txt"
    test ! -s "$tmp/snapshot-status.txt"

    (cd "$project" && "$kata_bin" init --config "$cfg" >/dev/null)
    perl -0pi -e 's/bind = "127\.0\.0\.1:8400"/bind = "127.0.0.1:'"$port"'"/' "$cfg"
    perl -0pi -e 's/metrics_bind = "127\.0\.0\.1:9400"/metrics_bind = "127.0.0.1:'"$metrics_port"'"/' "$cfg"
    # `jj_repo = ".."` resolves against the CONFIG FILE's directory — this
    # recipe's `$cfg` lives at `$tmp/runtime/kata.toml`, outside the project,
    # so `..` named `$tmp` — a trunkless directory: the workspace provider
    # minted an empty-root base (`git_view_base_commit_absent` on the zero
    # sha). Point it at the project.
    perl -0pi -e 's|^jj_repo = "\.\."$|jj_repo = "'"$project"'"|m' "$cfg"
    grep -qF 'jj_repo = "'"$project"'"' "$cfg"

    # `kata init` declares no `[node] environment` and this pack's
    # `validate` stage authors `net = "host"` plus
    # `requires = ["cargo", "git", "just", "kata", "python3"]` — the
    # environment is the node fact `node_environment_undeclared` refuses
    # without, the egress list is the `net = "host"` authority
    # (`egress_undeclared`), and every `requires` entry is judged against
    # the environment's PATH programs at check
    # (`environment_requirement_unmet`). The toolchain programs are
    # DERIVED from flake.lock's nixpkgs, not pinned: only the three base roots
    # share the live rig's pins. The in-capsule `kata` the pack's
    # `kata check`/`kata build` validation commands exec is THIS tree's static
    # musl build (`oci_smoke_kata_tool`) — a host-built glibc binary cannot
    # serve (its `/lib64` interpreter is not in the capsule rootfs), and a Nix
    # build of the flake package is L2's work, not L1's
    # (`l1_builds_no_nix_kata_and_resolves_no_floating_channel`).
    # `index.crates.io`/`static.crates.io` are the honest `net = "host"`
    # authorities — the declared commands reach no other host, and a stage
    # that tries is refused by the proxy.
    source scripts/oci-smoke-node.sh
    # The pack's model stages select `default` (the init-written agent,
    # re-declared under an `api_key` credential, which the check judges without
    # resolving), and its model stages' `factory-verdict` profile authors
    # `net = "host"`, which the check judges against `egress_allow`.
    oci_smoke_agent_capsule "$cfg" default nanocode_openai \
        '{ mode = "api_key", source = "env:OPENAI_API_KEY" }'
    mapfile -t extra_paths < <(oci_smoke_nix_paths \
        nixpkgs#python3 nixpkgs#just "$repo_root#rust-toolchain")
    # The exported CARGO_TARGET_DIR is the PACK's build dir; the static kata goes to
    # the default one, beside the static `kata-toolhost`.
    CARGO_TARGET_DIR="$repo_root/target" cargo build -p kata --bin kata --target x86_64-unknown-linux-musl
    extra_paths+=("$(oci_smoke_kata_tool "$repo_root" "$tmp/kata-tool")")
    OCI_SMOKE_EGRESS_ALLOW="index.crates.io:443 static.crates.io:443" \
        oci_smoke_inject_environment "$cfg" "factory-self-improve-preflight" \
        "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT" "${extra_paths[@]}"
    # The provider is provisioned from target/debug beside `kata_bin`: `build-debug`
    # (this recipe's dependency) built it with every other workspace bin.
    oci_smoke_provision_provider "$runtime" "$kata_bin" "$repo_root/target/debug"

    export KATA_STDLIB_DIR="$project/workflows/std"
    # `KATA_CONFIG` is `--config` spelled in the environment — the pack's own
    # validate stage runs `kata check`/`kata build` as children of the `serve`
    # process, and an env export is the only door that reaches them (a flag
    # cannot be edited into pack-authored commands).
    export KATA_CONFIG="$cfg"
    (cd "$project" && "$kata_bin" check --config "$cfg" "$implementation_ref" >"$tmp/implementation-check.txt")
    (cd "$project" && "$kata_bin" build --config "$cfg" "$implementation_ref" --out "$tmp/implementation-build.json" >/dev/null)
    jq -e '.build.passed == true and .execution_program.summary.validation_criterion_count == 6 and .execution_program.summary.review_loop_count == 1' "$tmp/implementation-build.json" >/dev/null
    (cd "$project" && "$kata_bin" check --config "$cfg" "$preflight_ref" >"$tmp/preflight-check.txt")
    (cd "$project" && "$kata_bin" build --config "$cfg" "$preflight_ref" --out "$tmp/preflight-build.json" >/dev/null)
    jq -e '
      .build.passed == true
      and .execution_program.summary.validation_criterion_count == 6
      and .execution_program.summary.review_loop_count == 0
      and .execution_program.stages.implement.policies.sandbox.data == "factory-review"
      and ((.execution_program.stages.implement.invocation_envelope.mutation_policy // "advisory") != "owned_paths")
      and (.preflight.execution_program.verifier_passes[] | select(.id == "factory_stage_policy") | .evidence.workspace_rw_stage_count == 0 and .evidence.mutating_stage_count == 0)
    ' "$tmp/preflight-build.json" >/dev/null

    # `serve`'s supervised node hosts the capsule route — its rootless
    # youki containers own a cgroup only inside a delegated scope, and the
    # provider exports are already on this process's env, which the scope
    # inherits. 1500s > the 900s `run wait` bound, so a hang is the
    # kernel's to reap, not the harness's.
    (cd "$project" && exec systemd-run $(oci_smoke_delegate_args 1500) \
        "$kata_bin" serve --config "$cfg" >"$tmp/solo.log" 2>&1) &
    pid="$!"
    remember_solo

    wait_for_api "factory-self-improve-preflight-smoke"

    "$kata_bin" --api-url "$api" memory import-inbox --dir "$runtime/memory/inbox" >"$tmp/memory-import.json"
    # The inbox ENTRY COUNTS are not pinned to literals, on purpose. Literal counts
    # (`.applied == 2 and .skipped == 1 …`) would be a second spelling of how many
    # starter files `kata init` scaffolds. The authority is `cli/init.rs`, which
    # writes `README.md`, `000-objective.json` and `010-validation-criteria.json`,
    # and `cli/operator/memory.rs`, where `total_entries` is a bare dirent count and
    # `skipped` is "not a JSON proposal file". With literals, adding one starter
    # proposal to `kata init` would red every recipe holding this line for a change
    # that broke nothing.
    #
    # What the smoke owns is that the import PATH works on the scaffold it was
    # handed: nothing failed, nothing conflicted, at least one JSON proposal
    # applied, and the non-JSON README was filtered rather than parsed. Those
    # hold for any starter set `kata init` ships.
    jq -e '.failed == 0 and .conflicted == 0 and .imported >= 1 and .applied == .imported and .skipped >= 1' "$tmp/memory-import.json" >/dev/null

    (cd "$project" && "$kata_bin" --api-url "$api" factory run "$preflight_ref" --context "Validation-only self-improve evidence." --input-id factory-self-improve-preflight-001 >"$tmp/submit.json")
    id="$(jq -r '.id' "$tmp/submit.json")"
    jq -e --arg id "$id" '.id == $id and .status == "pending"' "$tmp/submit.json" >/dev/null

    "$kata_bin" --api-url "$api" run show "$id" >"$tmp/initial-input.json"
    jq -e '(.evidence.external_inputs | length == 1) and .evidence.external_inputs[0].id == "factory-self-improve-preflight-001" and .evidence.external_inputs[0].channel == "operator_steering" and .evidence.external_inputs[0].source == "operator" and .evidence.external_inputs[0].text == "Validation-only self-improve evidence."' "$tmp/initial-input.json" >/dev/null

    "$kata_bin" --api-url "$api" run wait "$id" --timeout-secs 900 --poll-ms 250 >"$tmp/wait.json"
    jq -e --arg id "$id" --arg workflow "$preflight_ref" '.id == $id and .status == "completed" and .workflow_name == $workflow' "$tmp/wait.json" >/dev/null

    "$kata_bin" --api-url "$api" run show "$id" >"$tmp/show.json"
    summary_ready=0
    for _ in $(seq 100); do
        "$kata_bin" --api-url "$api" run-summary "$id" >"$tmp/summary.json"
        if jq -e --arg id "$id" '.id == $id and .summary_kind == "operator_run_summary" and .status == "completed" and .controller_decision_count == 1 and .controller_decisions[0].decision_id == "kata-self-improve-preflight-stop" and .controller_decisions[0].decision == "stop"' "$tmp/summary.json" >/dev/null; then
            summary_ready=1
            break
        fi
        sleep 0.2
    done
    if [ "$summary_ready" -ne 1 ]; then
        cat "$tmp/summary.json" >&2
        exit 1
    fi
    "$kata_bin" --api-url "$api" replay "$id" >"$tmp/replay.json" 2>"$tmp/replay.stderr" || {
        cat "$tmp/replay.stderr" >&2
        exit 1
    }
    jq -e --arg id "$id" '.id == $id and .status == "completed" and .operator_packet.terminal == true' "$tmp/replay.json" >/dev/null
    "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace.json"
    # jj is the one execution-workspace backend.
    jq -e '.workspace_provider_attached == true and .workspace_provider_backend == "jj" and .worktree.exists == true and .worktree.dirty == false and (.worktree.changed_paths | length == 0) and .promotion.safe_to_promote == true' "$tmp/workspace.json" >/dev/null
    "$kata_bin" --api-url "$api" factory status "$id" >"$tmp/factory-status.json"
    jq -e --arg id "$id" '.summary_kind == "factory_controller_status" and .execution_id == $id and .latest_decision.decision_id == "kata-self-improve-preflight-stop" and .latest_decision.decision == "stop" and .action.applicable == false' "$tmp/factory-status.json" >/dev/null
    "$kata_bin" --api-url "$api" --format json explain "$id" | jq '.' >"$tmp/explain.json"
    jq -e --arg id "$id" '.summary_kind == "operator_explain" and .execution_id == $id and .terminal == true and .factory.latest_decision.decision == "stop" and .factory.action.applicable == false and (.recommended_actions | length >= 1)' "$tmp/explain.json" >/dev/null
    "$kata_bin" --api-url "$api" memory snapshot --limit 20 >"$tmp/memory-snapshot.json"
    jq -e '(.objects | length) >= 1' "$tmp/memory-snapshot.json" >/dev/null

    for stage in memory_context context plan implement review validate controller closeout; do
        "$kata_bin" --api-url "$api" run output "$id" "$stage" >"$tmp/output-${stage}.json"
    done
    jq -e '.parsed.object_count >= 1' "$tmp/output-memory_context.json" >/dev/null
    jq -e '((.parsed // (try (.content | fromjson) catch {})).operator_steering_count == 1) or ((.content // "") | contains("operator_steering"))' "$tmp/output-context.json" >/dev/null
    jq -e '.parsed.wave_id == "kata-self-improve-preflight" and (.parsed.owned_paths | length == 0)' "$tmp/output-plan.json" >/dev/null
    jq -e '.parsed.ready_for_review == true and (.parsed.changed_files | length == 0) and ([.parsed.deviations[]? | select(. != "")] | length == 0)' "$tmp/output-implement.json" >/dev/null
    jq -e '.parsed.verdict == "approve" and (.parsed.required_changes | length == 0)' "$tmp/output-review.json" >/dev/null
    # The command COUNT is not pinned to a literal, on purpose: a literal would be a
    # second spelling of the pack's own command list — a shell constant duplicating
    # a product fact it cannot see, which goes stale the moment the pack drops or
    # adds a command.
    #
    # What this smoke owns is that EVERY declared command ran and none is missing —
    # so it asserts the shape, and the pack's `validation_commands` stays the one
    # place the set is stated.
    jq -e '.parsed.status == "passed" and (.parsed.commands | length >= 1) and (.parsed.missing | length == 0)' "$tmp/output-validate.json" >/dev/null
    jq -e '.parsed.decision_id == "kata-self-improve-preflight-stop" and .parsed.decision == "stop" and .parsed.human_required == false' "$tmp/output-controller.json" >/dev/null
    jq -e '.parsed.outcome == "complete" and .parsed.candidate_state == "none"' "$tmp/output-closeout.json" >/dev/null

    git -C "$repo_root" status --short --untracked-files=all >"$tmp/operator-status-after.txt"
    diff -u "$tmp/operator-status-before.txt" "$tmp/operator-status-after.txt" >"$tmp/operator-status.diff" || {
        cat "$tmp/operator-status.diff" >&2
        exit 1
    }
    smoke_status="passed"
    if [ -n "$evidence_dir" ]; then
        echo "factory-self-improve-preflight-smoke: PASS id=$id api=$api evidence=$evidence_dir"
    else
        echo "factory-self-improve-preflight-smoke: PASS id=$id api=$api"
    fi
# THE FIRST LIVE PROOF: one Starlark workflow, one real model call, end to end.
#
# The product's whole reason for existing — write a workflow, run it, it works —
# needs a live model run whose evidence is kept, and this is the smallest thing that
# provides it.
#
# It is deliberately the NORTH-STAR SPELLING and nothing more: a `.star` file, one
# stage, a real model, a parsed structured output. No factory, no self-improve
# ladder, no kata-on-kata. Those are the second step, and a first live proof that
# fails should fail because the model call failed, not because a nine-stage pack did.
# The run spelling is `serve` + `--submit`: a workflow runs only on an
# installed main.
#
# COST. `gpt-6-luna` on `nanocode_openai` at `reasoning_effort = low`, one call,
# tens of output tokens. kata prices no `nanocode_openai` turn, so the recorded
# cost is `quality: "unavailable"` and the tokens are the evidence of the spend.
#
# The evidence lands under `out_dir` (default `target/dist/evidence/first-live-proof`,
# timestamped). `target/` is gitignored, so a packet meant to be kept is copied
# somewhere tracked by hand.
first-live-proof out_dir="target/dist/evidence/first-live-proof":
    #!/usr/bin/env bash
    set -euo pipefail
    # Boots an installed main — a per-uid singleton. Queue instead of colliding,
    # and bound a hang externally: an EXIT trap cannot fire while the shell
    # does not exit.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just first-live-proof "{{ out_dir }}"
    fi
    : "${OPENAI_API_KEY:?first-live-proof needs OPENAI_API_KEY — the worker loads it for the nanocode turn}"
    source scripts/smoke-harness.sh
    arm_watchdog "first-live-proof"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    evidence_dir="{{ out_dir }}/$stamp"
    mkdir -p "$evidence_dir"
    tmp="$(mktemp -d)"
    pid=""
    trap 'disarm_watchdog || true; terminate_solo || true; remove_scratch "$tmp"' EXIT

    cfg="$tmp/.kata/kata.toml"
    target/debug/kata init --config "$cfg" >/dev/null

    source scripts/oci-smoke-node.sh
    # The stage is a capsule turn, so the config needs the three facts
    # `kata init` cannot invent: the `[node] environment` closure, the
    # certified provider exports, and the agent's `credential` — `api_key`
    # through `OPENAI_API_KEY`, so the recipe bills an API key it is handed
    # rather than the operator's login. No `egress_allow`: no stage authors
    # `net = "host"`, and the harness's model calls leave from the worker.
    oci_smoke_inject_environment "$cfg" "first-live-proof" \
        "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT"
    cargo build -p kata-provider-youki -p kata-oci-hook
    oci_smoke_provision_provider "$tmp" "$(pwd)/target/debug/kata" "$(pwd)/target/debug"
    # Kernel-assigned listeners: the init default 8400/9400 collide with any
    # other main on this uid.
    perl -0pi -e 's/bind = "127\.0\.0\.1:8400"/bind = "127.0.0.1:0"/; s/metrics_bind = "127\.0\.0\.1:9400"/metrics_bind = "127.0.0.1:0"/' "$cfg"

    # Pin the tier explicitly rather than inheriting `<default>`: this recipe's
    # whole claim is "a REAL model answered", and a default that silently moved
    # would change what the evidence means without changing the evidence.
    python3 - "$cfg" <<'PYEOF'
    import sys
    path = sys.argv[1]
    text = open(path).read()
    old = '[agents.default]\nadapter = "nanocode_openai"\nmodel = "gpt-6-luna"\nreasoning_effort = "medium"\n'
    new = '[agents.default]\nadapter = "nanocode_openai"\nmodel = "gpt-6-luna"\nreasoning_effort = "low"\n'
    assert text.count(old) == 1, "kata init's [agents.default] block moved; re-pin it"
    open(path, "w").write(text.replace(old, new, 1))
    PYEOF
    oci_smoke_agent_capsule "$cfg" default nanocode_openai \
        '{ mode = "api_key", source = "env:OPENAI_API_KEY" }'

    star="$tmp/first-live-proof.star"
    cat >"$star" <<'STAREOF'
    answer = stage(
        id = "answer",
        agent = "default",
        prompt = "Reply with exactly this JSON and nothing else: {\"proof\": \"kata-live\", \"two_plus_two\": 4}",
        outputs = {
            "proof": "string",
            "two_plus_two": "int",
        },
    )
    workflow("kata-first-live-proof", root = [answer])
    STAREOF

    # Compile before spending anything. A workflow that does not check is a bug
    # this recipe must not pay a model call to discover.
    target/debug/kata check "$star" >"$evidence_dir/check.json"

    # A workflow runs only on an installed main, so the run is one on a
    # throwaway data dir: `serve` inside a delegated
    # scope (its worker hosts the route; provider exports and OPENAI_API_KEY
    # already on this env), submit, wait, read the stage's own record back.
    # `wait_for_api` resolves the kernel-assigned listener off the discovery
    # descriptor and exports the endpoint, so the calls below need no port.
    systemd-run $(oci_smoke_delegate_args 900) \
        target/debug/kata serve --config "$cfg" >"$tmp/solo.log" 2>&1 &
    pid="$!"
    remember_solo
    api="http://127.0.0.1:0"
    wait_for_api "first-live-proof"

    target/debug/kata --api-url "$api" run "$star" --submit >"$tmp/submit.json"
    exec_id="$(jq -r '.id' "$tmp/submit.json")"
    target/debug/kata --api-url "$api" run wait "$exec_id" --timeout-secs 780 \
        >"$evidence_dir/run.json"
    target/debug/kata --api-url "$api" run output "$exec_id" answer \
        >"$evidence_dir/answer.json"
    terminate_solo || true

    # The proof is the PARSED output, not the raw text. `content` only shows the
    # model emitted something; `parsed` shows kata's typed `outputs` contract
    # accepted it, which is the half a shell agent could never exercise.
    jq -e '.parsed.proof == "kata-live" and .parsed.two_plus_two == 4' \
        "$evidence_dir/answer.json" >/dev/null
    # NON-VACUITY: a real model call consumed real input tokens. A stubbed or
    # short-circuited backend reports zero, and every assertion above would still
    # hold on a canned reply.
    jq -e '.token_usage.input > 0' "$evidence_dir/answer.json" >/dev/null

    jq -n --arg stamp "$stamp" --arg sha "$(git rev-parse HEAD)" \
        --slurpfile stage "$evidence_dir/answer.json" \
        '{summary_kind: "first_live_proof_evidence",
          captured_at: $stamp,
          snapshot_sha: $sha,
          workflow: "kata-first-live-proof",
          spelling: "kata serve + kata run <wf> --submit + kata run output <id> answer",
          model: $stage[0].token_usage.cost.basis.model,
          rate_source: $stage[0].token_usage.cost.basis.rate_source,
          cost_quality: $stage[0].token_usage.cost.quality,
          metered_micro_usd: $stage[0].token_usage.cost_micro_usd,
          tokens: {input: $stage[0].token_usage.input,
                   output: $stage[0].token_usage.output,
                   cache_read: $stage[0].token_usage.cache_read},
          parsed: $stage[0].parsed}' >"$evidence_dir/evidence-summary.json"

    echo "first-live-proof: PASS out=$evidence_dir"
    jq -c '{model, rate_source, cost_quality, metered_micro_usd, tokens, parsed}' \
        "$evidence_dir/evidence-summary.json"

# Preserve a timestamped live Kata-on-Kata preflight evidence packet.
factory-self-improve-preflight-evidence out_dir="target/dist/evidence/factory-self-improve-preflight":
    #!/usr/bin/env bash
    set -euo pipefail
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    evidence_dir="{{out_dir}}/$stamp"
    KATA_FACTORY_SELF_IMPROVE_PREFLIGHT_EVIDENCE_DIR="$evidence_dir" just factory-self-improve-preflight-smoke
    jq -e '.summary_kind == "factory_self_improve_preflight_evidence" and .status == "passed" and .workflow == "std.software_factory.kata_self_improve_preflight" and (.execution_id | length > 0) and (.snapshot_sha | length > 0)' "$evidence_dir/evidence-summary.json" >/dev/null
    echo "factory-self-improve-preflight-evidence: PASS out=$evidence_dir"

# Run the live API-backed source-changing Kata-on-Kata proof.
factory-self-improve-implementation-smoke: build-debug
    #!/usr/bin/env bash
    set -euo pipefail
    # This recipe boots an installed main, a PER-UID singleton. Queue instead
    # of colliding. Safe ONLY because the watchdog armed below bounds a hang —
    # locking a hang would block every other run behind it.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just factory-self-improve-implementation-smoke
    fi
    source scripts/smoke-harness.sh
    # A hung run holds the PER-UID installed main and breaks every
    # later one. The EXIT trap cannot help — a trap needs the shell to exit,
    # and a hang is precisely the shell not exiting. Only an external timer can.
    arm_watchdog "factory-self-improve-implementation-smoke"
    repo_root="$(pwd)"
    kata_bin="$repo_root/target/debug/kata"
    port="${KATA_FACTORY_SELF_IMPROVE_IMPLEMENTATION_PORT:-0}"
    metrics_port="${KATA_FACTORY_SELF_IMPROVE_IMPLEMENTATION_METRICS_PORT:-0}"
    api="http://127.0.0.1:${port}"
    evidence_dir="${KATA_FACTORY_SELF_IMPROVE_IMPLEMENTATION_EVIDENCE_DIR:-}"
    tmp="$(mktemp -d)"
    project="$tmp/project"
    # THE CONFIG LIVES INSIDE THE PROJECT, for the reason `product-factory-smoke`
    # states beside its own `cfg=` line: `kata init` writes `jj_repo = ".."`,
    # resolved against the config FILE'S directory, so a config at
    # `$tmp/runtime/kata.toml` points the execution-workspace provider at `$tmp` —
    # not the project, and holding no trunk. The symptom is `stage "implement"
    # failed schema validation: content is not valid JSON: EOF while parsing a value
    # at line 1 column 0`, because the candidate worktree materializes EMPTY and the
    # stage's `cat > roadmap/…` writes nothing.
    #
    # A config inside the project does NOT break this recipe's `test ! -s` on `git
    # -C "$project" status --short --untracked-files=all`, and the reason is one
    # line of the operator checkout this project is a copy of: `.gitignore` ignores
    # `.kata/`, and the tar below copies
    # `.gitignore` in. So `$project/.kata/` — config, memory inbox, data dir,
    # every byte `kata init` and `kata serve` write — is INVISIBLE to
    # `--untracked-files=all`, which lists untracked files and not ignored ones.
    # The pristine claim is therefore kept EXACTLY as authored: nothing is
    # excluded from it by hand, and `.worktree.changed_paths == [$target]` below
    # is untouched.
    #
    # That is an INHERITED fact, not a local one, so it is PROVEN rather than
    # assumed — `project-status-after-init.txt` below fails this recipe loudly on
    # the day `.gitignore` stops ignoring `.kata/`, instead of letting the
    # pristine assertions quietly start covering kata's own runtime state.
    runtime="$project/.kata"
    cfg="$runtime/kata.toml"
    pid=""
    smoke_status="failed"
    implementation_ref="std.software_factory.kata_self_improve"
    proof_ref="std.software_factory.kata_self_improve_implementation_smoke"
    target_path="roadmap/kata-self-improve-implementation-smoke.md"
    park_name="kata-self-improve-implementation-smoke"
    decision_id="factory-smoke-controller-001"
    id=""
    snapshot_sha=""
    export PATH="$repo_root/target/debug:$repo_root/target/release:$PATH"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target/factory-self-improve-evidence}"
    export KATA_API_URL="$api"

    capture_evidence() {
        if [ -z "$evidence_dir" ]; then
            return
        fi
        mkdir -p "$evidence_dir"
        cp "$tmp"/*.json "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.txt "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.stderr "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.diff "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp/solo.log" "$evidence_dir/solo.log" 2>/dev/null || true
        jq -n \
            --arg status "$smoke_status" \
            --arg workflow "$proof_ref" \
            --arg canonical_workflow "$implementation_ref" \
            --arg target_path "$target_path" \
            --arg api "$api" \
            --arg project "$project" \
            --arg execution_id "$id" \
            --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg repo_sha "$(git -C "$repo_root" rev-parse HEAD)" \
            --arg snapshot_sha "$snapshot_sha" \
            '{
              summary_kind: "factory_self_improve_implementation_evidence",
              status: $status,
              workflow: $workflow,
              canonical_workflow_checked: $canonical_workflow,
              target_path: $target_path,
              captured_at: $captured_at,
              repo_sha: $repo_sha,
              snapshot_sha: $snapshot_sha,
              api_url: $api,
              temp_project: $project,
              execution_id: $execution_id,
              artifacts: [
                "operator-status-before.txt",
                "operator-status-after.txt",
                "operator-status.diff",
                "snapshot-status.txt",
                "project-status-after-init.txt",
                "implementation-check.txt",
                "implementation-build.json",
                "proof-check.txt",
                "proof-build.json",
                "memory-import.json",
                "submit.json",
                "initial-input.json",
                "wait.json",
                "show.json",
                "summary.json",
                "replay.json",
                "replay.stderr",
                "workspace-before.json",
                "candidate-status.txt",
                "candidate-status-unexpected.txt",
                "candidate-diff.diff",
                "project-status-after-run.txt",
                "factory-status.json",
                "explain.json",
                "memory-snapshot.json",
                "output-context.json",
                "output-plan.json",
                "output-implement.json",
                "output-review.json",
                "output-validate.json",
                "output-controller.json",
                "output-closeout.json",
                "park.json",
                "park-retry.json",
                "project-status-after-park.txt",
                "workspace-after.json",
                "factory-status-after.json",
                "solo.log"
              ]
            }' >"$evidence_dir/evidence-summary.json"
        {
            printf '# Factory Self-Improve Implementation Evidence\n\n'
            printf 'Status: %s\n' "$smoke_status"
            printf 'Workflow: %s\n' "$proof_ref"
            printf 'Canonical workflow checked: %s\n' "$implementation_ref"
            printf 'Target path: %s\n' "$target_path"
            printf 'API: %s\n' "$api"
            printf 'Execution: %s\n' "${id:-unknown}"
            printf 'Snapshot commit: %s\n\n' "${snapshot_sha:-unknown}"
            printf 'Start with `evidence-summary.json`, `proof-build.json`,\n'
            printf '`summary.json`, `workspace-before.json`, `candidate-diff.diff`,\n'
            printf '`factory-status.json`, `park.json`, and `workspace-after.json`\n'
            printf 'when reviewing the source-changing Kata-on-Kata proof.\n'
        } >"$evidence_dir/README.md"
    }
    trap record_failure ERR
    trap cleanup EXIT


    git -C "$repo_root" status --short --untracked-files=all >"$tmp/operator-status-before.txt"
    mkdir -p "$project"
    # A NESTED `.git` OR `.jj` BREAKS THE `git add -A` BELOW, and one gets there
    # without anybody choosing it. Cargo runs an integration test with CWD set to
    # its PACKAGE ROOT, so a test that boots a node whose `vcs.jj_repo` resolves
    # relatively COLOCATES jj into `bin/kata/` — a `.jj/` plus the `.git/`
    # that colocation creates. `.gitignore` already names `.jj/` for exactly this
    # reason and says so in its own comment; it cannot name a nested `.git`, and
    # git does not need it to, because git never descends into one. THIS tar
    # does: after a plain `just test` a `bin/kata/.git` can exist, and without the
    # exclusions this recipe dies with
    # `error: 'bin/kata/' does not have a commit checked out` (exit 128) —
    # an ORDER-DEPENDENT break of a required containment-lane step, invisible on
    # a host that had not run the suite first.
    tar \
        --exclude='./.git' \
        --exclude='*/.git' \
        --exclude='./.jj' \
        --exclude='*/.jj' \
        --exclude='./agents' \
        --exclude='./.github' \
        --exclude='./.kata' \
        --exclude='./.claude' \
        --exclude='./.worktrees' \
        --exclude='./target' \
        --exclude='*/target' \
        --exclude='./node_modules' \
        --exclude='*/node_modules' \
        --exclude='./.env' \
        -C "$repo_root" -cf - . | tar -C "$project" -xf -
    mkdir -p "$project/$(dirname "$target_path")"
    {
        printf '# Kata Self-Improve Implementation Smoke Baseline\n\n'
        printf 'This tracked baseline exists only inside the evidence snapshot.\n'
        printf 'The implementation-smoke candidate must replace it with validated output.\n'
    } >"$project/$target_path"
    git -C "$project" init -b main >/dev/null
    git -C "$project" config user.email "kata-self-improve-implementation@example.invalid"
    git -C "$project" config user.name "Kata Self Improve Implementation"
    git -C "$project" add -A
    git -C "$project" commit -m "snapshot kata self-improve implementation evidence project" >/dev/null
    snapshot_sha="$(git -C "$project" rev-parse HEAD)"
    git -C "$project" status --short --untracked-files=all >"$tmp/snapshot-status.txt"
    test ! -s "$tmp/snapshot-status.txt"

    (cd "$project" && "$kata_bin" init --config "$cfg" >/dev/null)
    perl -0pi -e 's/bind = "127\.0\.0\.1:8400"/bind = "127.0.0.1:'"$port"'"/' "$cfg"
    perl -0pi -e 's/metrics_bind = "127\.0\.0\.1:9400"/metrics_bind = "127.0.0.1:'"$metrics_port"'"/' "$cfg"

    # `kata init` declares no `[node] environment`, so without this the
    # `oci` boot refuses `node_environment_undeclared`. The deterministic pack's
    # stages are `printf`-only shell under offline workspaces — the pinned
    # live environment (busybox/getent/git) covers them, and no
    # `net = "host"` authoring means no `egress_allow` is declared.
    source scripts/oci-smoke-node.sh
    # The recipe `kata check`s `kata_self_improve`, whose model stages select
    # `default` (the init-written agent, re-declared under an `api_key`
    # credential, as the preflight recipe does), and its model stages'
    # `factory-verdict` profile authors `net = "host"`, which the check judges
    # against `egress_allow`.
    oci_smoke_agent_capsule "$cfg" default nanocode_openai \
        '{ mode = "api_key", source = "env:OPENAI_API_KEY" }'
    # The crates.io pair is the honest `net = "host"` authority of the
    # checked pack's cargo validation; the deterministic pack this recipe
    # runs authors no `net = "host"`.
    OCI_SMOKE_EGRESS_ALLOW="index.crates.io:443 static.crates.io:443" \
        oci_smoke_inject_environment "$cfg" "factory-self-improve-implementation" \
        "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT"
    # The provider is provisioned from target/debug beside `kata_bin`: `build-debug`
    # (this recipe's dependency) built it with every other workspace bin.
    oci_smoke_provision_provider "$tmp" "$kata_bin" "$repo_root/target/debug"

    export KATA_STDLIB_DIR="$project/workflows/std"
    # The premise the `cfg=` paragraph above rests on, PROVEN rather than
    # assumed: `kata init` has just written a config, a data dir and a memory
    # inbox under `$project/.kata/`, and the project's own `.gitignore` — copied
    # in by the tar above — must keep every one of them out of
    # `--untracked-files=all`. If that stops holding, this line fails HERE, with
    # the offending paths in the file, rather than three pristine assertions
    # later where the failure would read as a run that mutated the project.
    test -f "$cfg"
    git -C "$project" status --short --untracked-files=all >"$tmp/project-status-after-init.txt"
    test ! -s "$tmp/project-status-after-init.txt"
    (cd "$project" && "$kata_bin" check --config "$cfg" "$implementation_ref" >"$tmp/implementation-check.txt")
    (cd "$project" && "$kata_bin" build --config "$cfg" "$implementation_ref" --out "$tmp/implementation-build.json" >/dev/null)
    jq -e '.build.passed == true and .execution_program.summary.validation_criterion_count == 6 and .execution_program.summary.review_loop_count == 1' "$tmp/implementation-build.json" >/dev/null
    (cd "$project" && "$kata_bin" check --config "$cfg" "$proof_ref" >"$tmp/proof-check.txt")
    (cd "$project" && "$kata_bin" build --config "$cfg" "$proof_ref" --out "$tmp/proof-build.json" >/dev/null)
    jq -e --arg target "$target_path" '
      .build.passed == true
      and .execution_program.summary.validation_criterion_count == 5
      and .execution_program.summary.review_loop_count == 1
      and .execution_program.workflow_pattern.name == "software_factory_smoke"
      and (.execution_program.stages.implement.op.prompt_template | contains($target))
      and (.preflight.execution_program.verifier_passes[] | select(.id == "factory_stage_policy") | .evidence.worktree_isolated == true and .evidence.validation_criterion_count == 5)
    ' "$tmp/proof-build.json" >/dev/null

    # `serve`'s supervised node hosts the capsule route — its rootless
    # youki containers own a cgroup only inside a delegated scope, and the
    # provider exports are already on this process's env, which the scope
    # inherits.
    (cd "$project" && exec systemd-run $(oci_smoke_delegate_args 600) \
        "$kata_bin" serve --config "$cfg" >"$tmp/solo.log" 2>&1) &
    pid="$!"
    remember_solo

    wait_for_api "factory-self-improve-implementation-smoke"

    "$kata_bin" --api-url "$api" memory import-inbox --dir "$runtime/memory/inbox" >"$tmp/memory-import.json"
    # Not pinned to the `kata init` scaffold's file count — see the same line in
    # `factory-self-improve-preflight-smoke` for the authority and the reasoning.
    jq -e '.failed == 0 and .conflicted == 0 and .imported >= 1 and .applied == .imported and .skipped >= 1' "$tmp/memory-import.json" >/dev/null

    (cd "$project" && "$kata_bin" --api-url "$api" factory run "$proof_ref" --context "Kata self-improve implementation proof: mutate only ${target_path} and park the candidate." --input-id factory-self-improve-implementation-001 >"$tmp/submit.json")
    id="$(jq -r '.id' "$tmp/submit.json")"
    jq -e --arg id "$id" '.id == $id and .status == "pending"' "$tmp/submit.json" >/dev/null

    "$kata_bin" --api-url "$api" run show "$id" >"$tmp/initial-input.json"
    jq -e --arg text "Kata self-improve implementation proof: mutate only ${target_path} and park the candidate." '(.evidence.external_inputs | length == 1) and .evidence.external_inputs[0].id == "factory-self-improve-implementation-001" and .evidence.external_inputs[0].channel == "operator_steering" and .evidence.external_inputs[0].source == "operator" and .evidence.external_inputs[0].text == $text' "$tmp/initial-input.json" >/dev/null

    "$kata_bin" --api-url "$api" run wait "$id" --timeout-secs 180 --poll-ms 100 >"$tmp/wait.json"
    jq -e --arg id "$id" --arg workflow "$proof_ref" '.id == $id and .status == "completed" and .workflow_name == $workflow' "$tmp/wait.json" >/dev/null
    git -C "$project" status --short --untracked-files=all >"$tmp/project-status-after-run.txt"
    test ! -s "$tmp/project-status-after-run.txt"
    ! grep -q "criterion: validation-passed" "$project/$target_path"

    "$kata_bin" --api-url "$api" run show "$id" >"$tmp/show.json"
    summary_ready=0
    for _ in $(seq 100); do
        "$kata_bin" --api-url "$api" run-summary "$id" >"$tmp/summary.json"
        if jq -e --arg id "$id" '.id == $id and .summary_kind == "operator_run_summary" and .status == "completed" and .controller_decision_count == 1 and .controller_decisions[0].decision_id == "factory-smoke-controller-001" and .controller_decisions[0].decision == "park"' "$tmp/summary.json" >/dev/null; then
            summary_ready=1
            break
        fi
        sleep 0.2
    done
    if [ "$summary_ready" -ne 1 ]; then
        cat "$tmp/summary.json" >&2
        exit 1
    fi
    "$kata_bin" --api-url "$api" replay "$id" >"$tmp/replay.json" 2>"$tmp/replay.stderr" || {
        cat "$tmp/replay.stderr" >&2
        exit 1
    }
    jq -e --arg id "$id" '.id == $id and .status == "completed" and .operator_packet.terminal == true' "$tmp/replay.json" >/dev/null

    "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace-before.json"
    # `jj` EXACTLY — the only workspace provider, and the one that carries the
    # pack's apply and workspace effects under `oci`. Under OCI the candidate is
    # already COMMITTED by the time this reads: `worktree.dirty` is false and
    # `changed_path_count` is 0 because the apply folded the implement stage's
    # delta into the recorded candidate — the write is proven by reading it out
    # of that commit, not by a dirty working copy. `promotion.status` is
    # `ready`: clean tree, criteria satisfied against the recorded candidate.
    jq -e --arg target "$target_path" '.workspace_provider_attached == true and .workspace_provider_backend == "jj" and .worktree.exists == true and .worktree.dirty == false and .worktree.changed_path_count == 0 and .promotion.safe_to_promote == true and .promotion.status == "ready" and .parking.available == true' "$tmp/workspace-before.json" >/dev/null
    worktree_path="$(jq -r '.worktree.path' "$tmp/workspace-before.json")"
    # The RECORDED CANDIDATE commit — `identity.workspace_commit_sha`, the jj
    # workspace's `@`, not the colocated git HEAD (which names the checked-out
    # base) — must carry the implement stage's write: the marker the pack's
    # `criterion` authors is the blob-level proof the delta landed.
    candidate_commit="$(jq -r '.worktree.identity.workspace_commit_sha' "$tmp/workspace-before.json")"
    git -C "$worktree_path" show "$candidate_commit:$target_path" >"$tmp/candidate-target.txt"
    grep -q "criterion: validation-passed" "$tmp/candidate-target.txt"
    git -C "$worktree_path" status --short --untracked-files=all >"$tmp/candidate-status.txt"
    test ! -s "$tmp/candidate-status.txt"

    "$kata_bin" --api-url "$api" factory status "$id" >"$tmp/factory-status.json"
    jq -e --arg id "$id" '.summary_kind == "factory_controller_status" and .execution_id == $id and .latest_decision.decision_id == "factory-smoke-controller-001" and .latest_decision.decision == "park" and .action.action == "park" and .action.applicable == true and .workspace.parking.available == true' "$tmp/factory-status.json" >/dev/null
    "$kata_bin" --api-url "$api" --format json explain "$id" | jq '.' >"$tmp/explain.json"
    jq -e --arg id "$id" '.summary_kind == "operator_explain" and .execution_id == $id and .factory.latest_decision.decision == "park" and .factory.action.applicable == true and .recommended_actions[0].action == "park"' "$tmp/explain.json" >/dev/null
    "$kata_bin" --api-url "$api" memory snapshot --limit 20 >"$tmp/memory-snapshot.json"
    jq -e '(.objects | length) >= 1' "$tmp/memory-snapshot.json" >/dev/null

    for stage in context plan implement review validate controller closeout; do
        "$kata_bin" --api-url "$api" run output "$id" "$stage" >"$tmp/output-${stage}.json"
    done
    jq -e --arg target "$target_path" '((.parsed // (try (.content | fromjson) catch {})).candidate_source_areas == [$target]) or ((.content // "") | contains($target))' "$tmp/output-context.json" >/dev/null
    # Neither command COUNT is pinned to a literal, on purpose: a literal would be
    # a second spelling of a list the PACK states — the plan stage's
    # `validation_commands` printf and the validate stage's `commands` printf in
    # `workflows/kata-factory/kata/factory.star`. The two lists are authored side
    # by side and this recipe cannot see either, so a literal would turn this smoke
    # red for a pack edit that broke nothing.
    #
    # What the smoke owns is that the plan declared commands at all, that the
    # validate stage ran and passed, and that NOTHING is missing — `.missing`
    # is the pack's own report of a declared command that did not produce
    # evidence, so a dropped command still fails here without the count.
    jq -e --arg target "$target_path" '.parsed.owned_paths == [$target] and (.parsed.validation_commands | length >= 1)' "$tmp/output-plan.json" >/dev/null
    jq -e --arg target "$target_path" '.parsed.ready_for_review == true and .parsed.changed_files == [$target] and ([.parsed.deviations[]? | select(. != "")] | length == 0)' "$tmp/output-implement.json" >/dev/null
    jq -e '.parsed.verdict == "approve" and (.parsed.required_changes | length == 0)' "$tmp/output-review.json" >/dev/null
    jq -e '.parsed.status == "passed" and (.parsed.commands | length >= 1) and (.parsed.missing | length == 0)' "$tmp/output-validate.json" >/dev/null
    jq -e '.parsed.decision_id == "factory-smoke-controller-001" and .parsed.decision == "park" and .parsed.human_required == false' "$tmp/output-controller.json" >/dev/null
    jq -e '.parsed.outcome == "complete" and (.parsed.candidate_state == "changed" or .parsed.candidate_state == "parked")' "$tmp/output-closeout.json" >/dev/null

    "$kata_bin" --api-url "$api" factory apply "$id" --decision-id "$decision_id" --name "$park_name" >"$tmp/park.json"
    jq -e --arg ref "parked/${park_name}" '.summary_kind == "factory_controller_apply" and .status == "applied" and .applied == true and .action == "park" and .parked_candidate.parked_ref == $ref and (.parked_candidate.commit_sha | type == "string") and (.parked_candidate.commit_sha | length > 0) and .controller_application.decision_id == "factory-smoke-controller-001" and .controller_application.action == "park" and .controller_application.applied == true and .controller_application.parked_candidate.parked_ref == $ref' "$tmp/park.json" >/dev/null
    "$kata_bin" --api-url "$api" factory apply "$id" --decision-id "$decision_id" --name "$park_name" >"$tmp/park-retry.json"
    jq -e --arg ref "parked/${park_name}" '.summary_kind == "factory_controller_apply" and .status == "already_applied" and .applied == false and .action == "park" and .parked_candidate.parked_ref == $ref and .controller_application.decision_id == "factory-smoke-controller-001" and .controller_application.action == "park" and .controller_application.applied == true' "$tmp/park-retry.json" >/dev/null
    git -C "$project" status --short --untracked-files=all >"$tmp/project-status-after-park.txt"
    test ! -s "$tmp/project-status-after-park.txt"
    ! grep -q "criterion: validation-passed" "$project/$target_path"

    "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace-after.json"
    jq -e --arg ref "parked/${park_name}" '.parking.parked == true and .parking.available == false and .parking.candidate.parked_ref == $ref and (.worktree == null or .worktree.exists == false)' "$tmp/workspace-after.json" >/dev/null
    "$kata_bin" --api-url "$api" factory status "$id" >"$tmp/factory-status-after.json"
    jq -e '.controller_application_count == 1 and .latest_application.action == "park" and .action.action == "none" and .action.applicable == false' "$tmp/factory-status-after.json" >/dev/null

    git -C "$repo_root" status --short --untracked-files=all >"$tmp/operator-status-after.txt"
    diff -u "$tmp/operator-status-before.txt" "$tmp/operator-status-after.txt" >"$tmp/operator-status.diff" || {
        cat "$tmp/operator-status.diff" >&2
        exit 1
    }
    smoke_status="passed"
    if [ -n "$evidence_dir" ]; then
        echo "factory-self-improve-implementation-smoke: PASS id=$id api=$api evidence=$evidence_dir"
    else
        echo "factory-self-improve-implementation-smoke: PASS id=$id api=$api"
    fi

# Preserve a timestamped live source-changing Kata-on-Kata evidence packet.
factory-self-improve-implementation-evidence out_dir="target/dist/evidence/factory-self-improve-implementation":
    #!/usr/bin/env bash
    set -euo pipefail
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    evidence_dir="{{out_dir}}/$stamp"
    KATA_FACTORY_SELF_IMPROVE_IMPLEMENTATION_EVIDENCE_DIR="$evidence_dir" just factory-self-improve-implementation-smoke
    jq -e '.summary_kind == "factory_self_improve_implementation_evidence" and .status == "passed" and .workflow == "std.software_factory.kata_self_improve_implementation_smoke" and .canonical_workflow_checked == "std.software_factory.kata_self_improve" and (.execution_id | length > 0) and (.snapshot_sha | length > 0)' "$evidence_dir/evidence-summary.json" >/dev/null
    echo "factory-self-improve-implementation-evidence: PASS out=$evidence_dir"

# Run the live model-backed Kata-on-Kata proof against the canonical pack.
factory-self-improve-smoke: build-debug
    #!/usr/bin/env bash
    set -euo pipefail
    # This recipe boots an installed main, a PER-UID singleton. Queue instead
    # of colliding. Safe ONLY because the watchdog armed below bounds a hang —
    # locking a hang would block every other run behind it.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just factory-self-improve-smoke
    fi
    source scripts/smoke-harness.sh
    # A hung run holds the PER-UID installed main and breaks every
    # later one. The EXIT trap cannot help — a trap needs the shell to exit,
    # and a hang is precisely the shell not exiting. Only an external timer can.
    arm_watchdog "factory-self-improve-smoke"
    repo_root="$(pwd)"
    kata_bin="$repo_root/target/debug/kata"
    port="${KATA_FACTORY_SELF_IMPROVE_PORT:-0}"
    metrics_port="${KATA_FACTORY_SELF_IMPROVE_METRICS_PORT:-0}"
    timeout_secs="${KATA_FACTORY_SELF_IMPROVE_TIMEOUT_SECS:-1800}"
    # Adapter for the factory's model stages (the `default` agent label):
    # `nanocode_openai` over `OPENAI_API_KEY`.
    api="http://127.0.0.1:${port}"
    evidence_dir="${KATA_FACTORY_SELF_IMPROVE_EVIDENCE_DIR:-}"
    tmp="$(mktemp -d)"
    project="$tmp/project"
    runtime="$tmp/runtime"
    cfg="$runtime/kata.toml"
    context_file="$tmp/self-improve-context.md"
    pid=""
    smoke_status="failed"
    workflow_ref="${KATA_FACTORY_SELF_IMPROVE_WORKFLOW:-std.software_factory.kata_self_improve}"
    expected_validation_criteria="${KATA_FACTORY_SELF_IMPROVE_VALIDATION_CRITERIA:-8}"
    min_controller_decisions="${KATA_FACTORY_SELF_IMPROVE_MIN_DECISIONS:-1}"
    target_path="${KATA_FACTORY_SELF_IMPROVE_TARGET_PATH:-docs/product/operator-guide.md}"
    objective_id="${KATA_FACTORY_SELF_IMPROVE_OBJECTIVE_ID:-factory-self-improve-001}"
    input_id="${KATA_FACTORY_SELF_IMPROVE_INPUT_ID:-factory-self-improve-001}"
    park_name="${KATA_FACTORY_SELF_IMPROVE_PARK_NAME:-kata-self-improve}"
    # Terminal-decision mode. Default `park` (the proven park-and-prove path,
    # byte-identical to before). `promote` flips the goal + the post-completion
    # proof so the controller LANDS the validated change via ff-only promote — into
    # the throwaway `$project` temp copy only; the operator checkout ($repo_root) is
    # asserted clean in BOTH modes, so promote can never touch the real tree.
    decision_mode="${KATA_FACTORY_SELF_IMPROVE_MODE:-park}"
    case "$decision_mode" in
        park|promote) ;;
        *) echo "factory-self-improve-smoke: KATA_FACTORY_SELF_IMPROVE_MODE must be park|promote (got '$decision_mode')" >&2; exit 2 ;;
    esac
    context_file_override="${KATA_FACTORY_SELF_IMPROVE_CONTEXT_FILE:-}"
    decision_id=""
    id=""
    snapshot_sha=""
    candidate_packet_proven=false
    controller_policy_proven=false
    export PATH="$repo_root/target/debug:$repo_root/target/release:$PATH"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target/factory-self-improve-evidence}"
    export KATA_API_URL="$api"

    capture_evidence() {
        if [ -z "$evidence_dir" ]; then
            return
        fi
        mkdir -p "$evidence_dir"
        cp "$tmp"/*.json "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.txt "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.stderr "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.diff "$evidence_dir"/ 2>/dev/null || true
        cp "$context_file" "$evidence_dir/self-improve-context.md" 2>/dev/null || true
        cp "$tmp/solo.log" "$evidence_dir/solo.log" 2>/dev/null || true
        candidate_diff_sha256=""
        if [ -s "$tmp/candidate-diff.diff" ]; then
            candidate_diff_sha256="$(sha256sum "$tmp/candidate-diff.diff" | awk '{print $1}')"
            printf '%s\n' "$candidate_diff_sha256" >"$tmp/candidate-diff.sha256"
            cp "$tmp/candidate-diff.sha256" "$evidence_dir/candidate-diff.sha256" 2>/dev/null || true
        fi
        if [ -f "$tmp/candidate-diff-name-only.txt" ]; then
            jq -R . "$tmp/candidate-diff-name-only.txt" | jq -s . >"$tmp/candidate-changed-paths.json"
            cp "$tmp/candidate-changed-paths.json" "$evidence_dir/candidate-changed-paths.json" 2>/dev/null || true
        else
            printf '[]\n' >"$tmp/candidate-changed-paths.json"
        fi
        jq -n \
            --arg status "$smoke_status" \
            --arg workflow "$workflow_ref" \
            --arg target_path "$target_path" \
            --arg objective_id "$objective_id" \
            --arg input_id "$input_id" \
            --arg park_name "$park_name" \
            --arg candidate_diff_sha256 "$candidate_diff_sha256" \
            --arg api "$api" \
            --arg project "$project" \
            --arg execution_id "$id" \
            --arg decision_id "$decision_id" \
            --argjson candidate_packet_proven "$candidate_packet_proven" \
            --argjson controller_policy_proven "$controller_policy_proven" \
            --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg repo_sha "$(git -C "$repo_root" rev-parse HEAD)" \
            --arg snapshot_sha "$snapshot_sha" \
            --slurpfile candidate_changed_paths "$tmp/candidate-changed-paths.json" \
            '{
              summary_kind: "factory_self_improve_evidence",
              status: $status,
              workflow: $workflow,
              target_path: $target_path,
              objective_id: $objective_id,
              input_id: $input_id,
              park_name: $park_name,
              candidate_diff_sha256: $candidate_diff_sha256,
              candidate_changed_paths: $candidate_changed_paths[0],
              captured_at: $captured_at,
              repo_sha: $repo_sha,
              snapshot_sha: $snapshot_sha,
              api_url: $api,
              temp_project: $project,
              execution_id: $execution_id,
              decision_id: $decision_id,
              candidate_packet_proven: $candidate_packet_proven,
              controller_policy_proven: $controller_policy_proven,
              artifacts: [
                "operator-status-before.txt",
                "operator-status-after.txt",
                "operator-status.diff",
                "snapshot-status.txt",
                "config-check.txt",
                "self-improve-check.txt",
                "self-improve-build.json",
                "memory-import.json",
                "self-improve-context.md",
                "submit.json",
                "initial-input.json",
                "wait.json",
                "show.json",
                "summary.json",
                "replay.json",
                "replay.stderr",
                "workspace-before.json",
                "factory-candidate-before.json",
                "candidate-status.txt",
                "candidate-diff-name-only.txt",
                "candidate-changed-paths.json",
                "candidate-diff.sha256",
                "candidate-status-unexpected.txt",
                "candidate-diff.diff",
                "project-status-after-run.txt",
                "factory-status.json",
                "explain.json",
                "memory-snapshot.json",
                "output-memory_context.json",
                "output-context.json",
                "output-plan.json",
                "output-implement.json",
                "output-review.json",
                "output-validate.json",
                "output-controller.json",
                "output-closeout.json",
                "park.json",
                "park-retry.json",
                "project-status-after-park.txt",
                "workspace-after.json",
                "factory-candidate-after.json",
                "factory-status-after.json",
                "solo.log"
              ]
            }' >"$evidence_dir/evidence-summary.json"
        {
            printf '# Factory Self-Improve Evidence\n\n'
            printf 'Status: %s\n' "$smoke_status"
            printf 'Workflow: %s\n' "$workflow_ref"
            printf 'Target path: %s\n' "$target_path"
            printf 'API: %s\n' "$api"
            printf 'Execution: %s\n' "${id:-unknown}"
            printf 'Decision: %s\n' "${decision_id:-unknown}"
            printf 'Candidate packet proven: %s\n' "$candidate_packet_proven"
            printf 'Controller policy proven: %s\n' "$controller_policy_proven"
            printf 'Snapshot commit: %s\n\n' "${snapshot_sha:-unknown}"
            printf 'Start with `evidence-summary.json`, `self-improve-build.json`,\n'
            printf '`summary.json`, `workspace-before.json`, `factory-candidate-before.json`,\n'
            printf '`candidate-diff.diff`, `output-validate.json`, `output-controller.json`,\n'
            printf '`park.json`, `park-retry.json`, `workspace-after.json`, and\n'
            printf '`factory-candidate-after.json` when reviewing\n'
            printf 'the model-backed Kata-on-Kata proof.\n'
        } >"$evidence_dir/README.md"
    }
    trap record_failure ERR
    trap cleanup EXIT


    git -C "$repo_root" status --short --untracked-files=all >"$tmp/operator-status-before.txt"
    mkdir -p "$project"
    # A NESTED `.git` OR `.jj` BREAKS THE `git add -A` BELOW, and one gets there
    # without anybody choosing it. Cargo runs an integration test with CWD set to
    # its PACKAGE ROOT, so a test that boots a node whose `vcs.jj_repo` resolves
    # relatively COLOCATES jj into `bin/kata/` — a `.jj/` plus the `.git/`
    # that colocation creates. `.gitignore` already names `.jj/` for exactly this
    # reason and says so in its own comment; it cannot name a nested `.git`, and
    # git does not need it to, because git never descends into one. THIS tar
    # does: after a plain `just test` a `bin/kata/.git` can exist, and without the
    # exclusions this recipe dies with
    # `error: 'bin/kata/' does not have a commit checked out` (exit 128) —
    # an ORDER-DEPENDENT break of a required containment-lane step, invisible on
    # a host that had not run the suite first.
    tar \
        --exclude='./.git' \
        --exclude='*/.git' \
        --exclude='./.jj' \
        --exclude='*/.jj' \
        --exclude='./agents' \
        --exclude='./.github' \
        --exclude='./.kata' \
        --exclude='./.claude' \
        --exclude='./.worktrees' \
        --exclude='./target' \
        --exclude='*/target' \
        --exclude='./node_modules' \
        --exclude='*/node_modules' \
        --exclude='./.env' \
        -C "$repo_root" -cf - . | tar -C "$project" -xf -
    git -C "$project" init -b main >/dev/null
    git -C "$project" config user.email "kata-self-improve@example.invalid"
    git -C "$project" config user.name "Kata Self Improve"
    git -C "$project" add -A
    git -C "$project" commit -m "snapshot kata self-improve evidence project" >/dev/null
    snapshot_sha="$(git -C "$project" rev-parse HEAD)"
    git -C "$project" status --short --untracked-files=all >"$tmp/snapshot-status.txt"
    test ! -s "$tmp/snapshot-status.txt"

    (cd "$project" && "$kata_bin" init --config "$cfg" >/dev/null)
    perl -0pi -e 's/bind = "127\.0\.0\.1:8400"/bind = "127.0.0.1:'"$port"'"/' "$cfg"
    perl -0pi -e 's/metrics_bind = "127\.0\.0\.1:9400"/metrics_bind = "127.0.0.1:'"$metrics_port"'"/' "$cfg"

    source scripts/oci-smoke-node.sh
    # Under the shipped `oci` profile a model stage is a capsule turn. Three
    # facts the recipe must declare rather than take from the host:
    #
    #  * THE AGENT — `adapter`/`credential` on the harness block:
    #    `nanocode_openai` under an `api_key`
    #    through the env var, so this run bills the key it is handed rather
    #    than the operator's login.
    #  * THE ENVIRONMENT — `node_environment_undeclared` without it: the pack's
    #    `requires = [cargo, git, just, kata, python3]` as Nix closures (a host
    #    binary's `/lib64` interpreter is not in the capsule rootfs).
    #  * THE EGRESS — the `implement`/`validate` stages author `net = "host"`,
    #    which draws `[node] egress_allow`: the crates.io pair a `cargo`/`just`
    #    validation command fetches through. The harness's model calls leave
    #    from the worker, never the capsule.
    # `kata init` wrote `[agents.default]` and the `gate` role agent; each is
    # re-pointed at this run's key, and at a requested model and effort.
    agent_credential='{ mode = "api_key", source = "env:OPENAI_API_KEY" }'
    agent_tier() { # <label> <model or empty> <effort or empty>
        python3 - "$cfg" "$1" "$2" "$3" <<'PY'
    import sys
    cfg, label, model, effort = sys.argv[1:5]
    lines = open(cfg).read().splitlines(keepends=True)
    start = lines.index(f"[agents.{label}]\n")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("[")), len(lines))
    keep = [
        line
        for line in lines[start + 1 : end]
        if not (model and line.startswith("model ="))
        and not (effort and line.startswith("reasoning_effort ="))
    ]
    add = (f'model = "{model}"\n' if model else "") + (f'reasoning_effort = "{effort}"\n' if effort else "")
    open(cfg, "w").write("".join(lines[: start + 1]) + add + "".join(keep) + "".join(lines[end:]))
    PY
        oci_smoke_agent_capsule "$cfg" "$1" nanocode_openai "$agent_credential"
    }
    model_effort=""
    if [ -n "${KATA_FACTORY_SELF_IMPROVE_MODEL:-}" ]; then
        model_effort="${KATA_FACTORY_SELF_IMPROVE_REASONING_EFFORT:-}"
    fi
    agent_tier default "${KATA_FACTORY_SELF_IMPROVE_MODEL:-}" "$model_effort"
    # Optional worker/gate model split: the
    # `std.software_factory.kata_self_improve_inloop_gatesplit` pack routes the
    # controller GATE stage to the `gate` agent. Point it at a stronger model
    # only when requested; otherwise it runs as `kata init` wrote it.
    if [ -n "${KATA_FACTORY_SELF_IMPROVE_GATE_MODEL:-}" ]; then
        agent_tier gate "$KATA_FACTORY_SELF_IMPROVE_GATE_MODEL" \
            "${KATA_FACTORY_SELF_IMPROVE_GATE_REASONING_EFFORT:-medium}"
    else
        agent_tier gate "" ""
    fi
    mapfile -t extra_paths < <(oci_smoke_nix_paths \
        nixpkgs#python3 nixpkgs#just "$repo_root#rust-toolchain" "$repo_root#kata")
    OCI_SMOKE_EGRESS_ALLOW="index.crates.io:443 static.crates.io:443" \
        oci_smoke_inject_environment "$cfg" "factory-self-improve" \
        "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT" "${extra_paths[@]}"
    # The provider is provisioned from target/debug beside `kata_bin`: `build-debug`
    # (this recipe's dependency) built it with every other workspace bin.
    oci_smoke_provision_provider "$tmp" "$kata_bin" "$repo_root/target/debug"

    "$kata_bin" config check --config "$cfg" >"$tmp/config-check.txt"

    if [ -n "$context_file_override" ]; then
        cp "$context_file_override" "$context_file"
    else
        {
            printf '%s\n' 'Kata model-backed self-improve proof.'
            printf '\n'
            printf '%s\n' 'Goal:'
            printf '%s\n' '- In the isolated candidate workspace only, make exactly one tiny useful docs'
            printf '  update to `%s`.\n' "$target_path"
            printf '%s\n' '- The update should add a short note to the Factory proof ladder clarifying'
            printf '%s\n' '  that failed self-improve evidence packets are retained for debugging but do'
            printf '%s\n' '  not satisfy the model-backed proof rung; only a completed passing packet'
            printf '%s\n' '  does.'
            printf '\n'
            printf '%s\n' 'Hard constraints:'
            printf '%s\n' "- Edit only \`$target_path\`."
            printf '%s\n' '- Do not edit code, tests, fixtures, generated evidence, config, or CI.'
            if [ "$decision_mode" = "promote" ]; then
                printf '%s\n' '- Do not mutate the operator checkout.'
            else
                printf '%s\n' '- Do not commit, push, promote, or mutate the operator checkout.'
            fi
            printf '%s\n' '- Validation must pass with the declared commands.'
            if [ "$decision_mode" = "promote" ]; then
                printf '%s\n' '- The change is validated and bounded, so the controller decision should be'
                printf '%s\n' '  `promote` to LAND it (ff-only) into the isolated project workspace.'
            else
                printf '%s\n' '- The controller decision should be `park` so the candidate is preserved for'
                printf '%s\n' '  inspection instead of accepted automatically.'
            fi
            printf '\n'
            printf '%s\n' 'Success criteria:'
            printf '%s\n' "- \`plan.owned_paths\` is exactly [\"$target_path\"]."
            printf '%s\n' "- \`implement.changed_files\` contains only \`$target_path\`."
            printf '%s\n' '- `review.verdict` is `approve`.'
            printf '%s\n' '- `validate.status` is `passed` with no missing evidence.'
            if [ "$decision_mode" = "promote" ]; then
                printf '%s\n' '- `controller.decision` is `promote` and `human_required` is false.'
            else
                printf '%s\n' '- `controller.decision` is `park` and `human_required` is false.'
            fi
        } >"$context_file"
    fi

    export KATA_STDLIB_DIR="$project/workflows/std"
    # `KATA_CONFIG` is `--config` spelled in the environment — the pack's own
    # validate stage runs `kata check`/`kata build` as children of the `serve`
    # process, and an env export is the only door that reaches them (a flag
    # cannot be edited into pack-authored commands).
    export KATA_CONFIG="$cfg"
    (cd "$project" && "$kata_bin" check --config "$cfg" "$workflow_ref" >"$tmp/self-improve-check.txt")
    (cd "$project" && "$kata_bin" build --config "$cfg" "$workflow_ref" --out "$tmp/self-improve-build.json" >/dev/null)
    jq -e --argjson vc "$expected_validation_criteria" '
      .build.passed == true
      and .execution_program.summary.validation_criterion_count == $vc
      and .execution_program.summary.review_loop_count == 1
      and .execution_program.workflow_pattern.name == "software_factory"
      and (.preflight.execution_program.verifier_passes[] | select(.id == "factory_stage_policy") | .evidence.worktree_isolated == true and .evidence.mutating_stage_count == 1 and .evidence.workspace_rw_stage_count == 1 and .evidence.validation_criterion_count == $vc)
    ' "$tmp/self-improve-build.json" >/dev/null

    # `serve`'s supervised node hosts the capsule route — its rootless
    # youki containers own a cgroup only inside a delegated scope, and the
    # provider exports plus the model API key are already on this process's
    # env, which the scope inherits. The bound sits above the recipe's own
    # `timeout_secs` so a hang is the kernel's to reap.
    (cd "$project" && exec systemd-run $(oci_smoke_delegate_args $((timeout_secs + 600))) \
        "$kata_bin" serve --config "$cfg" >"$tmp/solo.log" 2>&1) &
    pid="$!"
    remember_solo

    wait_for_api "factory-self-improve-smoke"

    "$kata_bin" --api-url "$api" memory import-inbox --dir "$runtime/memory/inbox" >"$tmp/memory-import.json"
    # Not pinned to the `kata init` scaffold's file count — see the same line in
    # `factory-self-improve-preflight-smoke` for the authority and the reasoning.
    jq -e '.failed == 0 and .conflicted == 0 and .imported >= 1 and .applied == .imported and .skipped >= 1' "$tmp/memory-import.json" >/dev/null

    (cd "$project" && "$kata_bin" --api-url "$api" factory run "$workflow_ref" --context-file "$context_file" --input-id "$input_id" >"$tmp/submit.json")
    id="$(jq -r '.id' "$tmp/submit.json")"
    jq -e --arg id "$id" '.id == $id and .status == "pending"' "$tmp/submit.json" >/dev/null

    "$kata_bin" --api-url "$api" run show "$id" >"$tmp/initial-input.json"
    jq -e --arg input_id "$input_id" --arg target "$target_path" '(.evidence.external_inputs | length == 1) and .evidence.external_inputs[0].id == $input_id and .evidence.external_inputs[0].channel == "operator_steering" and .evidence.external_inputs[0].source == "operator" and (.evidence.external_inputs[0].text | contains("Edit only `" + $target + "`"))' "$tmp/initial-input.json" >/dev/null

    "$kata_bin" --api-url "$api" run wait "$id" --timeout-secs "$timeout_secs" --poll-ms 1000 >"$tmp/wait.json"
    jq -e --arg id "$id" --arg workflow "$workflow_ref" '.id == $id and .status == "completed" and .workflow_name == $workflow' "$tmp/wait.json" >/dev/null
    git -C "$project" status --short --untracked-files=all >"$tmp/project-status-after-run.txt"
    test ! -s "$tmp/project-status-after-run.txt"

    "$kata_bin" --api-url "$api" run show "$id" >"$tmp/show.json"

    if [ "${KATA_FACTORY_SELF_IMPROVE_MULTIWAVE:-0}" = 1 ]; then
        # In-execution MULTI-WAVE loop proof. The inloop pack runs the WHOLE wave
        # body inside ONE durable execution and re-dispatches it per wave on the
        # controller's refine verdict. Proof: the execution completed (terminal —
        # whether via a terminal controller decision OR a bounded max_waves
        # exhaust, both valid for an always-bounded unattended loop); the WHOLE
        # body re-ran for a second wave (controller AND implement carry an
        # iteration-1 row); the cheap-worker/strong-gate split was active; and the
        # loop improved the target (dirty candidate touching the owned path).
        jq -e --arg id "$id" '.id == $id and .status == "completed"' "$tmp/show.json" >/dev/null
        # The WHOLE wave body re-ran for wave 2 (model stages carry an iter-1 row).
        # For the two-wave-pressure pack, this iteration is STRUCTURALLY forced: its
        # wave-1 validation fails the sentinel grep, and the controller's admission
        # gate refuses `promote` on failed validation — so a `#iter-1` row is direct
        # evidence the failure (not a model-choice refine) forced a second wave.
        grep -q '"controller#iter-1"' "$tmp/show.json"
        grep -q '"implement#iter-1"' "$tmp/show.json"
        # Worker/gate split log line — only when a gate model was configured.
        if [ -n "${KATA_FACTORY_SELF_IMPROVE_GATE_MODEL:-}" ]; then
            grep -q "gate -> harness (model: ${KATA_FACTORY_SELF_IMPROVE_GATE_MODEL})" "$tmp/solo.log"
            split_note="gate=${KATA_FACTORY_SELF_IMPROVE_GATE_MODEL} split"
        else
            split_note="single-model (no gate split)"
        fi
        "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace-before.json"
        jq -e --arg target "$target_path" '.worktree.dirty == true and (.worktree.changed_paths | index($target) != null)' "$tmp/workspace-before.json" >/dev/null
        wave_iters="$(grep -oE '"controller#iter-[0-9]+"' "$tmp/show.json" | sort -u | wc -l | tr -d ' ')"
        smoke_status="passed"
        printf 'factory-self-improve-smoke: PASS (MULTIWAVE) id=%s body re-ran across %s extra wave(s) beyond iteration 0; %s; validate re-ran in wave 2; terminal=completed\n' "$id" "$wave_iters" "$split_note"
        exit 0
    fi

    summary_ready=0
    for _ in $(seq 100); do
        "$kata_bin" --api-url "$api" run-summary "$id" >"$tmp/summary.json"
        if jq -e --arg id "$id" --argjson mindec "$min_controller_decisions" '.id == $id and .summary_kind == "operator_run_summary" and .status == "completed" and .controller_decision_count >= $mindec' "$tmp/summary.json" >/dev/null; then
            summary_ready=1
            break
        fi
        sleep 0.2
    done
    if [ "$summary_ready" -ne 1 ]; then
        cat "$tmp/summary.json" >&2
        exit 1
    fi
    "$kata_bin" --api-url "$api" replay "$id" >"$tmp/replay.json" 2>"$tmp/replay.stderr" || {
        cat "$tmp/replay.stderr" >&2
        exit 1
    }
    jq -e --arg id "$id" '.id == $id and .status == "completed" and .operator_packet.terminal == true' "$tmp/replay.json" >/dev/null

    "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace-before.json"
    jq -e --arg target "$target_path" '.workspace_provider_attached == true and .workspace_provider_backend == "jj" and .worktree.exists == true and .worktree.dirty == true and .worktree.changed_paths == [$target] and .promotion.safe_to_promote == true and .promotion.status == "ready_dirty_snapshot" and .parking.available == true' "$tmp/workspace-before.json" >/dev/null
    worktree_path="$(jq -r '.worktree.path' "$tmp/workspace-before.json")"
    git -C "$worktree_path" status --short --untracked-files=all >"$tmp/candidate-status.txt"
    git -C "$worktree_path" diff --name-only >"$tmp/candidate-diff-name-only.txt"
    git -C "$worktree_path" diff -- "$target_path" >"$tmp/candidate-diff.diff"
    test -s "$tmp/candidate-diff.diff"
    grep -qx "$target_path" "$tmp/candidate-diff-name-only.txt"
    awk -v target="$target_path" '$2 != target && $0 != "" { print }' "$tmp/candidate-status.txt" >"$tmp/candidate-status-unexpected.txt"
    test ! -s "$tmp/candidate-status-unexpected.txt"

    if [ "$decision_mode" = "promote" ]; then
    # ========================= PROMOTE proof =========================
    # The controller LANDS the validated change (ff-only) into the isolated
    # $project temp copy. Wave-stage assertions are re-verified here (kept
    # disjoint from the park else-branch below so the park path stays
    # byte-identical). The operator checkout ($repo_root) clean-check in the
    # shared tail is the safety invariant — promote can only touch $project.
    "$kata_bin" --api-url "$api" factory status "$id" >"$tmp/factory-status.json"
    jq -e --arg id "$id" '.summary_kind == "factory_controller_status" and .execution_id == $id and .latest_decision.decision == "promote" and .action.action == "promote" and .action.applicable == true' "$tmp/factory-status.json" >/dev/null
    "$kata_bin" --api-url "$api" --format json explain "$id" | jq '.' >"$tmp/explain.json"
    jq -e --arg id "$id" '.summary_kind == "operator_explain" and .execution_id == $id and .factory.latest_decision.decision == "promote" and .factory.action.applicable == true and (.recommended_actions | map(.action) | index("promote") != null)' "$tmp/explain.json" >/dev/null
    "$kata_bin" --api-url "$api" memory snapshot --limit 20 >"$tmp/memory-snapshot.json"
    jq -e '(.objects | length) >= 1' "$tmp/memory-snapshot.json" >/dev/null
    for stage in memory_context context plan implement review validate controller closeout; do
        "$kata_bin" --api-url "$api" run output "$id" "$stage" >"$tmp/output-${stage}.json"
    done
    jq -e --arg target "$target_path" '.parsed.owned_paths == [$target]' "$tmp/output-plan.json" >/dev/null
    jq -e --arg target "$target_path" '.parsed.ready_for_review == true and .parsed.changed_files == [$target] and ([.parsed.deviations[]? | select(. != "")] | length == 0)' "$tmp/output-implement.json" >/dev/null
    jq -e '.parsed.verdict == "approve" and (.parsed.required_changes | length == 0)' "$tmp/output-review.json" >/dev/null
    jq -e '.parsed.status == "passed" and (.parsed.missing | length == 0)' "$tmp/output-validate.json" >/dev/null
    jq -e '.parsed.decision == "promote" and .parsed.human_required == false and .parsed.completion.validation_passed == true' "$tmp/output-controller.json" >/dev/null
    jq -e '.parsed.outcome == "complete" and (.parsed.candidate_state == "changed" or .parsed.candidate_state == "promoted")' "$tmp/output-closeout.json" >/dev/null
    jq -e --arg target "$target_path" '.latest_decision.scope.owned_paths == [$target] and .latest_decision.completion.validation_passed == true and ((.latest_decision.scope.validation_blockers // []) | length == 0)' "$tmp/factory-status.json" >/dev/null
    controller_policy_proven=true
    decision_id="$(jq -r '.parsed.decision_id' "$tmp/output-controller.json")"
    printf '%s\n' "$decision_id" >"$tmp/decision-id.txt"
    test -n "$decision_id"
    # Land it: ff-only promote into the isolated $project workspace.
    "$kata_bin" --api-url "$api" factory apply "$id" --decision-id "$decision_id" --action promote >"$tmp/promote.json"
    jq -e --arg decision_id "$decision_id" '.summary_kind == "factory_controller_apply" and .status == "applied" and .applied == true and .action == "promote" and .decision == "promote" and .promotion.status == "promoted" and (.promotion.promoted_commit_sha | type == "string") and (.promotion.promoted_commit_sha | length > 0) and (.promotion.promoted_ref | type == "string") and (.promotion.promoted_ref | length > 0) and .controller_application.decision_id == $decision_id and .controller_application.action == "promote" and .controller_application.applied == true' "$tmp/promote.json" >/dev/null
    promoted_sha="$(jq -r '.promotion.promoted_commit_sha' "$tmp/promote.json")"
    # Idempotent re-apply: same decision returns already_applied, no re-landing.
    "$kata_bin" --api-url "$api" factory apply "$id" --decision-id "$decision_id" --action promote >"$tmp/promote-retry.json"
    jq -e '.summary_kind == "factory_controller_apply" and .status == "already_applied" and .applied == false and .action == "promote"' "$tmp/promote-retry.json" >/dev/null
    # The landed commit carries the target change (best-effort reachability in the
    # provider-managed store; the API promotion evidence above is authoritative).
    if git -C "$project" cat-file -e "${promoted_sha}^{commit}" 2>/dev/null; then
        git -C "$project" show "$promoted_sha" -- "$target_path" >"$tmp/promoted-change.diff" 2>/dev/null || true
        test -s "$tmp/promoted-change.diff" && echo "factory-self-improve-smoke: promoted commit $promoted_sha lands $target_path in \$project"
    else
        echo "factory-self-improve-smoke: promoted commit $promoted_sha is in the provider-managed worktree store (not \$project main); API promotion evidence is authoritative"
    fi
    candidate_packet_proven=true
    else
    "$kata_bin" --api-url "$api" factory status "$id" >"$tmp/factory-status.json"
    jq -e --arg id "$id" '.summary_kind == "factory_controller_status" and .execution_id == $id and .latest_decision.decision == "park" and .action.action == "park" and .action.applicable == true and .workspace.parking.available == true' "$tmp/factory-status.json" >/dev/null
    "$kata_bin" --api-url "$api" factory candidate "$id" >"$tmp/factory-candidate-before.json"
    jq -e --arg id "$id" --arg target "$target_path" '
      .summary_kind == "factory_candidate"
      and .execution_id == $id
      and .candidate_state == "live_worktree"
      and .source == "workspace_worktree"
      and .workspace_provider_attached == true
      and .live_worktree.exists == true
      and .live_worktree.dirty == true
      and .changed_paths == [$target]
      and .promotion_safe == true
      and .parking_available == true
      and (.recommended_actions | map(.action) | index("inspect_workspace") != null)
      and (.recommended_actions | map(.action) | index("inspect_live_diff") != null)
      and (.recommended_actions | map(.action) | index("park") != null)
    ' "$tmp/factory-candidate-before.json" >/dev/null
    "$kata_bin" --api-url "$api" --format json explain "$id" | jq '.' >"$tmp/explain.json"
    jq -e --arg id "$id" '.summary_kind == "operator_explain" and .execution_id == $id and .factory.latest_decision.decision == "park" and .factory.action.applicable == true and .recommended_actions[0].action == "park"' "$tmp/explain.json" >/dev/null
    "$kata_bin" --api-url "$api" memory snapshot --limit 20 >"$tmp/memory-snapshot.json"
    jq -e '(.objects | length) >= 1' "$tmp/memory-snapshot.json" >/dev/null

    for stage in memory_context context plan implement review validate controller closeout; do
        "$kata_bin" --api-url "$api" run output "$id" "$stage" >"$tmp/output-${stage}.json"
    done
    jq -e '.parsed.object_count >= 0' "$tmp/output-memory_context.json" >/dev/null
    jq -e --arg target "$target_path" '(((.parsed // (try (.content | fromjson) catch {})).candidate_source_areas // [] | map(sub("[[:space:]]+\\([^)]*\\)$"; "")) | index($target) != null) or ((.content // "") | contains($target)))' "$tmp/output-context.json" >/dev/null
    jq -e --arg target "$target_path" '.parsed.owned_paths == [$target]' "$tmp/output-plan.json" >/dev/null
    jq -e --arg target "$target_path" '.parsed.ready_for_review == true and .parsed.changed_files == [$target] and ([.parsed.deviations[]? | select(. != "")] | length == 0)' "$tmp/output-implement.json" >/dev/null
    jq -e '.parsed.verdict == "approve" and (.parsed.required_changes | length == 0)' "$tmp/output-review.json" >/dev/null
    jq -e '.parsed.status == "passed" and (.parsed.missing | length == 0)' "$tmp/output-validate.json" >/dev/null
    jq -e '.parsed.decision == "park" and .parsed.human_required == false and .parsed.completion.validation_passed == true' "$tmp/output-controller.json" >/dev/null
    jq -e --arg target "$target_path" '
      .parsed.decision == "park"
      and .parsed.human_required == false
      and .parsed.scope.owned_paths == [$target]
      and .parsed.completion.validation_passed == true
      and (.parsed.completion.status == "complete" or .parsed.completion.status == "partial")
      and (.parsed.memory_policy | type == "object")
      and ((.parsed.memory_policy.selectors // []) | all(. == "factory_active_context"))
      and ((.parsed.memory_policy.writebacks // []) | all(. == "factory_validation_writebacks" or . == "factory_controller_decisions"))
    ' "$tmp/output-controller.json" >/dev/null
    jq -e --arg target "$target_path" '
      .latest_decision.scope.owned_paths == [$target]
      and .latest_decision.completion.validation_passed == true
      and ((.latest_decision.scope.validation_blockers // []) | length == 0)
    ' "$tmp/factory-status.json" >/dev/null
    controller_policy_proven=true
    jq -e '.parsed.outcome == "complete" and (.parsed.candidate_state == "changed" or .parsed.candidate_state == "parked")' "$tmp/output-closeout.json" >/dev/null
    decision_id="$(jq -r '.parsed.decision_id' "$tmp/output-controller.json")"
    printf '%s\n' "$decision_id" >"$tmp/decision-id.txt"
    test -n "$decision_id"

    "$kata_bin" --api-url "$api" factory apply "$id" --decision-id "$decision_id" --name "$park_name" >"$tmp/park.json"
    jq -e --arg ref "parked/${park_name}" --arg decision_id "$decision_id" '.summary_kind == "factory_controller_apply" and .status == "applied" and .applied == true and .action == "park" and .parked_candidate.parked_ref == $ref and (.parked_candidate.commit_sha | type == "string") and (.parked_candidate.commit_sha | length > 0) and .controller_application.decision_id == $decision_id and .controller_application.action == "park" and .controller_application.applied == true and .controller_application.parked_candidate.parked_ref == $ref' "$tmp/park.json" >/dev/null
    "$kata_bin" --api-url "$api" factory apply "$id" --decision-id "$decision_id" --name "$park_name" >"$tmp/park-retry.json"
    jq -e --arg ref "parked/${park_name}" --arg decision_id "$decision_id" '.summary_kind == "factory_controller_apply" and .status == "already_applied" and .applied == false and .action == "park" and .parked_candidate.parked_ref == $ref and .controller_application.decision_id == $decision_id and .controller_application.action == "park" and .controller_application.applied == true' "$tmp/park-retry.json" >/dev/null
    git -C "$project" status --short --untracked-files=all >"$tmp/project-status-after-park.txt"
    test ! -s "$tmp/project-status-after-park.txt"

    "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace-after.json"
    jq -e --arg ref "parked/${park_name}" '.parking.parked == true and .parking.available == false and .parking.candidate.parked_ref == $ref and (.worktree == null or .worktree.exists == false)' "$tmp/workspace-after.json" >/dev/null
    "$kata_bin" --api-url "$api" factory candidate "$id" >"$tmp/factory-candidate-after.json"
    jq -e --arg id "$id" --arg ref "parked/${park_name}" '
      .summary_kind == "factory_candidate"
      and .execution_id == $id
      and .candidate_state == "parked"
      and .source == "parked_candidate_evidence"
      and .parked_candidate.parked_ref == $ref
      and (.parked_candidate.commit_sha | type == "string")
      and (.parked_candidate.commit_sha | length > 0)
      and (.live_worktree == null)
      and .changed_path_count == 0
      and (.recommended_actions | map(.action) | index("inspect_workspace") != null)
      and (.recommended_actions | map(.action) | index("replay_evidence") != null)
    ' "$tmp/factory-candidate-after.json" >/dev/null
    "$kata_bin" --api-url "$api" factory status "$id" >"$tmp/factory-status-after.json"
    jq -e '.controller_application_count == 1 and .latest_application.action == "park" and .action.action == "none" and .action.applicable == false' "$tmp/factory-status-after.json" >/dev/null
    candidate_packet_proven=true
    fi

    git -C "$repo_root" status --short --untracked-files=all >"$tmp/operator-status-after.txt"
    diff -u "$tmp/operator-status-before.txt" "$tmp/operator-status-after.txt" >"$tmp/operator-status.diff" || {
        cat "$tmp/operator-status.diff" >&2
        exit 1
    }
    smoke_status="passed"
    if [ -n "$evidence_dir" ]; then
        echo "factory-self-improve-smoke: PASS id=$id decision=$decision_id api=$api evidence=$evidence_dir"
    else
        echo "factory-self-improve-smoke: PASS id=$id decision=$decision_id api=$api"
    fi

# Preserve a timestamped live model-backed Kata-on-Kata evidence packet.
factory-self-improve-evidence out_dir="target/dist/evidence/factory-self-improve":
    #!/usr/bin/env bash
    set -euo pipefail
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    evidence_dir="{{out_dir}}/$stamp"
    KATA_FACTORY_SELF_IMPROVE_EVIDENCE_DIR="$evidence_dir" just factory-self-improve-smoke
    jq -e '.summary_kind == "factory_self_improve_evidence" and .status == "passed" and .workflow == "std.software_factory.kata_self_improve" and (.objective_id | length > 0) and (.input_id | length > 0) and (.park_name | length > 0) and (.execution_id | length > 0) and (.decision_id | length > 0) and (.snapshot_sha | length > 0) and (.candidate_diff_sha256 | length > 0) and .candidate_changed_paths == [.target_path] and .candidate_packet_proven == true and .controller_policy_proven == true' "$evidence_dir/evidence-summary.json" >/dev/null
    echo "factory-self-improve-evidence: PASS out=$evidence_dir"

# ─── REST API (installed-main steering surface) ──────────────
#
# These recipes are how an operator or a coding agent queries and steers a
# running Kata main. Start it with `just serve` first. Override the URL with
# `KATA_API_URL=http://host:port just api-<recipe>`.

# Subsystem health snapshot.
api-health: build
    target/release/kata --api-url {{api_url}} health

# Redeploy the running kata daemon so it matches the operator's
# local HEAD. Three-step:
#   1. cargo build --release (idempotent — no-op when up-to-date)
#   2. just kill-kata           (graceful SIGTERM by exact binary name)
#   3. spawn fresh `target/release/kata serve …` in
#      background (detached via signal_diag::daemonize_self()). It is the
#      installed main, so `kata replay` evidence survives a redeploy between
#      runs.
#   4. poll /api/v1/version until git_sha matches HEAD or 30s
#      elapses
#
# Use after any code change that the running daemon needs to
# reflect (new endpoint, new workflow contract, new agent backend
# behavior). Without this, the daemon stays on the previous build
# and operators get confusing failure modes where new tests run
# against stale infrastructure.
redeploy: build
    #!/usr/bin/env bash
    set -euo pipefail
    just kill-kata >/dev/null 2>&1 || true
    sleep 1
    # A stage's only deadline is its checked `timeout_ms`; no config key or
    # env var adds another. The delegated scope below inherits this
    # process's env, so an operator's export survives the wrap. That
    # scope is not optional: `serve` hosts the OCI capsule route,
    # and rootless youki can own a cgroup only inside a delegated
    # systemd-run scope. No RuntimeMaxSec — this is an operator daemon,
    # bound by `kill-kata`, not by a smoke's deadline. `disown` survives
    # because the scope object outlives this shell either way.
    KATA_API_URL="{{api_url}}" systemd-run --user --scope --quiet -p Delegate=yes -- \
        target/release/kata serve --config {{config}} \
        > /tmp/kata-redeploy.log 2>&1 &
    disown
    expected=$(git rev-parse HEAD)
    deadline=$(( $(date +%s) + 30 ))
    while (( $(date +%s) < deadline )); do
        actual=$(target/release/kata --api-url {{api_url}} version 2>/dev/null \
            | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("git_sha",""))' 2>/dev/null \
            || echo "")
        if [[ "$actual" == "$expected" ]]; then
            echo "redeploy OK: running git_sha=$actual matches HEAD"
            exit 0
        fi
        sleep 1
    done
    echo "redeploy FAILED: daemon never reported git_sha=$expected within 30s" >&2
    echo "tail of /tmp/kata-redeploy.log:" >&2
    tail -20 /tmp/kata-redeploy.log >&2 || true
    exit 1

# List every execution the main knows about, newest first (terse table).
api-executions: build
    target/release/kata --api-url {{api_url}} run list

# Inspect a single execution by id.
# Usage: just api-execution 01KP4AKK2MKR3Q0D1XZCAREXCR
api-execution id: build
    target/release/kata --api-url {{api_url}} run show {{id}}

# Fetch the output of a completed stage within a running or finished execution.
# Usage: just api-stage-output 01KP4AKK2MKR3Q0D1XZCAREXCR plan_dump
api-stage-output id stage: build
    target/release/kata --api-url {{api_url}} run output {{id}} {{stage}}

# Submit a workflow by library ref (project/user/bundled resolution).
# Usage: just api-submit-ref self-review
api-submit-ref name: build
    target/release/kata --api-url {{api_url}} run {{name}} --submit

# End-to-end product CLI smoke for the primary single-operator loop:
# init a temp project, boot an installed main, submit a Starlark workflow
# through the API-backed `kata run ... --wait` path, then prove watch,
# output, worker inventory, workspace awareness, and execution workspace
# views from the top-level `kata` CLI.
product-cli-smoke: build-debug
    #!/usr/bin/env bash
    set -euo pipefail
    # This recipe boots an installed main, and `kata serve` publishes the
    # attachment descriptor UNCONDITIONALLY to the fixed per-owner path
    # (`cli/solo.rs` -> `attachment.rs`, which has no config or env redirection in
    # production). So it is a PER-UID singleton writer and must queue: a `just
    # smoke`, a gate's `footprint-check`, or a `gate-containment` in another
    # worktree could be holding that authority, and the loser fails with
    # `HealthTimeout` — which reads as a defect in the node under test rather than
    # as contention. Every main-booting recipe takes this lock.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just product-cli-smoke
    fi
    source scripts/smoke-harness.sh
    source scripts/oci-smoke-node.sh
    # A hung run holds the PER-UID installed main and breaks every
    # later one. The EXIT trap cannot help — a trap needs the shell to exit,
    # and a hang is precisely the shell not exiting. Only an external timer can.
    arm_watchdog "product-cli-smoke"
    kata_bin="$(pwd)/target/debug/kata"
    tmp="$(mktemp -d)"
    pid=""
    cleanup() {
        disarm_watchdog || true
        terminate_solo || true
        # The provisioned provider store is read-only by design;
        # `remove_scratch` restores the write bit first.
        remove_scratch "$tmp" || true
    }
    trap cleanup EXIT

    # The provider's two binaries are their own packages — `build-debug`'s
    # `-p kata` does not build them, and the provider store refuses a missing
    # binary. Provision BEFORE the port tests: under `oci` every `serve`
    # passes the capsule-route doors — the declared environment's
    # declare-time verify shells `nix`, an undeclared provider is
    # `oci_provider_undeclared` (the route has no PATH fallback, so the
    # `KATA_EXTERNAL_*` exports a python child inherits are the only door),
    # and capsule dispatch needs the delegated cgroup `KATA_SERVE_WRAP`
    # carries into `scripts/test-smoke-ports.py`.
    command -v nix >/dev/null || {
        echo "product-cli-smoke: nix required — the declared environment's declare-time verify shells it" >&2
        exit 1
    }
    oci_smoke_provision_provider "$tmp" "$kata_bin" "$(pwd)/target/debug"
    export KATA_SERVE_WRAP="systemd-run $(oci_smoke_delegate_args 600)"
    python3 -B scripts/test-smoke-ownership.py
    python3 -B scripts/test-smoke-ports.py
    port="${KATA_PRODUCT_SMOKE_PORT:-0}"
    metrics_port="${KATA_PRODUCT_SMOKE_METRICS_PORT:-0}"
    api="http://127.0.0.1:${port}"

    # THE FIXTURE IS A GIT REPOSITORY, and that is load-bearing. `kata init`
    # writes `jj_repo = ".."` — the project root — so every doctor row about the
    # target repository is only OBSERVABLE when that root is one. Against a bare
    # `mktemp -d`, `target_repo_ignore` and `trunk_resolution` could only WARN
    # "cannot verify"; the first doctor call would be green for a reason that has
    # nothing to do with the project being ready, and the second one — after `kata
    # serve` has colocated jj and MADE the directory a repository — fails:
    #
    #   the target repository /tmp/tmp.XXXXXXXXXX does NOT ignore `.jj/` and
    #   `agents/`, and kata writes them there under
    #   `execution_workspace_backend = "jj"` ...
    #
    # `commit.gpgsign=false` because a fixture must never reach for the operator's
    # signing key.
    git -C "$tmp" init -q -b main
    git -C "$tmp" config user.email "product-cli-smoke@kata.invalid"
    git -C "$tmp" config user.name "product-cli-smoke"
    printf 'product-cli-smoke fixture\n' > "$tmp/README.md"
    git -C "$tmp" add README.md
    git -C "$tmp" -c commit.gpgsign=false commit -q -m "fixture trunk"

    cfg="$tmp/.kata/kata.toml"
    target/debug/kata init --config "$cfg" >/dev/null
    perl -0pi -e 's/bind = "127\.0\.0\.1:8400"/bind = "127.0.0.1:'"$port"'"/' "$cfg"
    perl -0pi -e 's/metrics_bind = "127\.0\.0\.1:9400"/metrics_bind = "127.0.0.1:'"$metrics_port"'"/' "$cfg"

    # The shipped `oci` profile is what this config boots, and it needs
    # the `[node] environment` closure `kata init` cannot invent
    # (`node_environment_undeclared` otherwise); the certified capsule
    # provider was already provisioned above for the port tests. This pack's
    # one stage is a `printf` under `net`-default: the pinned live
    # environment's busybox carries it, and no egress authority is needed.
    oci_smoke_inject_environment "$cfg" "product-cli-smoke" \
        "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT"

    # A FRESH `kata init` INSIDE A REPOSITORY IS DOCTOR-GREEN, and the row's TEETH
    # are proved separately, below.
    #
    # kata materializes `.jj/`, `agents/` and its whole
    # data directory inside `vcs.jj_repo`, and `target_repo_ignore` FAILS until
    # that repository ignores them — the failure mode is kata's internals
    # committed into history kata does not own (measured: 46 files / 333
    # insertions on a live gold-loop run). `kata init` DECLARES those roots itself,
    # because the first `kata doctor` a new operator runs is the one init's own
    # `next:` list routes to, and it must not fail over paths init has just created
    # (the data directory exists only because init chose where to put it). So the
    # first-run assertion is GREEN, and the row's TEETH are proved by taking the
    # declaration away.
    target/debug/kata doctor --config "$cfg" --format json | jq '.' >"$tmp/doctor-firstrun.json"
    jq -e '.summary_kind == "project_doctor" and .passed == true and .failure_count == 0 and (.checks | map(select(.name == "target_repo_ignore" and .status == "pass")) | length == 1) and (.checks | map(select(.name == "workflow_check")) | length >= 2)' "$tmp/doctor-firstrun.json" >/dev/null
    test -s "$tmp/.gitignore"
    mv "$tmp/.gitignore" "$tmp/gitignore-init-wrote"

    # THE ROW STILL REFUSES. Take away exactly what init wrote and doctor must
    # go red again — otherwise "green first run" would be indistinguishable from
    # a row that stopped looking.
    if target/debug/kata doctor --config "$cfg" --format json 2>/dev/null | jq '.' >"$tmp/doctor-preremedy.json"; then
        echo "product-cli-smoke: a repository that ignores NOTHING kata writes into it was" >&2
        echo 'GREEN. The `target_repo_ignore` row stopped refusing, and a fresh' >&2
        echo "project's green first run no longer proves anything." >&2
        exit 1
    fi
    jq -e '.passed == false and (.checks | map(select(.name == "target_repo_ignore" and .status == "fail")) | length == 1)' "$tmp/doctor-preremedy.json" >/dev/null

    # Apply the remedy DERIVED FROM DOCTOR'S OWN ANSWER, never a list retyped
    # here. `details.artifact_roots` is what `repo_local_artifact_roots` /
    # `repo_local_artifact_paths` declared for this config, so a root added there
    # is covered by this smoke the day it lands, and a shell copy cannot go stale
    # the way this file's `schema_version == 1` did.
    jq -r '.checks[] | select(.name == "target_repo_ignore") | .details.artifact_roots' \
        "$tmp/doctor-preremedy.json" | tr ',' '\n' | sed -e 's|^|/|' -e 's|$|/|' \
        > "$tmp/.gitignore"
    test -s "$tmp/.gitignore"

    # GREEN after, through the product path: the remedy kata printed clears the
    # row kata printed it for.
    target/debug/kata doctor --config "$cfg" --format json | jq -e '.summary_kind == "project_doctor" and .passed == true and .failure_count == 0 and (.checks | map(select(.name == "target_repo_ignore" and .status == "pass")) | length == 1) and (.checks | map(select(.name == "workflow_check")) | length >= 2)' >/dev/null

    # ONE SPELLING, TWO COMMANDS: the patterns `kata init` wrote must be exactly
    # the remedy `kata doctor` derives. If these ever diverge, init writes rules
    # that do not clear the row it routes the operator at — the defect class this
    # whole block exists for, wearing the opposite costume.
    diff <(sort "$tmp/.gitignore") \
         <(grep -Ev '^[[:space:]]*(#|$)' "$tmp/gitignore-init-wrote" | sort)

    star="$tmp/product-cli-smoke.star"
    cat >"$star" <<'STAR'
    probe = stage(
        id = "probe",
        agent = "shell",
        prompt = "printf '{\"ok\":true,\"source\":\"starlark_api\"}\\n'",
        outputs = {
            "ok": "bool",
            "source": "string",
        },
    )
    workflow(
        "product-cli-starlark-smoke",
        root = [probe],
    )
    STAR

    target/debug/kata build "$star" --out "$tmp/build.json" >/dev/null
    # The execution-program schema version is NOT pinned to a literal here, on
    # purpose. The lowering derives it from `EXECUTION_PROGRAM_SCHEMA_VERSION`
    # (`execution_program/lowering.rs`), so a shell literal is a textual pin
    # duplicating a constant its holder cannot see, and goes stale on every
    # correct bump. The VALUE is the typed lowering's business and its own tests';
    # what this product-path smoke owns is that the field is present and sane.
    jq -e '.build.passed == true and (.execution_program.schema_version | type == "number" and . >= 1) and (.execution_program.program_hash | type == "string")' "$tmp/build.json" >/dev/null
    target/debug/kata check "$star" >/dev/null

    # A workflow runs only on the installed main. `kata
    # run` has no daemon-free face — `--scratch` and `--config` are not its
    # arguments, so clap refuses either at parse with exit 2 before any config
    # is read. Asserting that on the shipped binary is this arm's covering
    # assertion; the installed-main submit below is the run.
    rc=0
    "$kata_bin" run "$star" --config "$cfg" >"$tmp/config-run.out" 2>&1 || rc=$?
    if [ "$rc" -ne 2 ] || ! grep -q "unexpected argument '--config' found" "$tmp/config-run.out"; then
        echo "product-cli-smoke: 'kata run <wf> --config' was not refused at parse (exit $rc)" >&2
        cat "$tmp/config-run.out" >&2
        exit 1
    fi

    systemd-run $(oci_smoke_delegate_args 600) \
        "$kata_bin" serve --config "$cfg" >"$tmp/solo.log" 2>&1 &
    pid="$!"
    remember_solo

    # Require our data-directory/process generation AND a live API; port-number
    # coincidence is not ownership. The helper resolves the actual retained :0
    # listener and exports the endpoint for subsequent attached CLI calls.
    wait_for_api "product-cli-smoke"

    # THE NORTH-STAR SPELLING: a user writes a Starlark workflow and runs it with
    # no --api-url, no mode flag and no ceremony. This is the bare `Submit` form,
    # and it reaches the main through the attachment descriptor — which is why the
    # readiness probe above had to wait for that FILE and not for the port.
    target/debug/kata run "$star" >"$tmp/local-run.json"
    # The bare form SUBMITS and returns immediately — it is fire-and-forget, so it
    # answers with an accepted id and a lifecycle status, NOT with stage outputs.
    # Asserting `.probe.parsed` here would assert stage outputs the submit
    # answer does not carry.
    jq -e '(.id | type == "string" and (. | length) > 0) and (.status | type == "string")' "$tmp/local-run.json" >/dev/null
    # The typed `outputs` contract, read where the submit path publishes
    # it: `run output` on the finished
    # execution. This is also the recipe's one actual capsule dispatch — the
    # shell stage runs inside the declared environment's youki container.
    probe_id="$(jq -r '.id' "$tmp/local-run.json")"
    target/debug/kata --api-url "$api" run wait "$probe_id" --timeout-secs 240 >/dev/null
    target/debug/kata --api-url "$api" run output "$probe_id" probe \
        | jq -e '.parsed.ok == true and .parsed.source == "starlark_api"' >/dev/null
    target/debug/kata --api-url "$api" health | jq -e '.subsystems | length >= 1' >/dev/null
    # `process_mode` is the `OperatorStatus` field that says which authority
    # answered (`cli/operator/status.rs`), pinned to `installed` because that is
    # the authority this block asserts against. (`jq` yields `null` for a missing
    # key, so an assertion on a field the product does not emit can only ever fail.)
    target/debug/kata --api-url "$api" status | jq -e '.summary_kind == "operator_status" and (.uptime_seconds >= 0) and .process_mode == "installed" and (.node_id | type == "string") and .ready == true and .health.status == "healthy" and (.recommended_actions | length >= 1)' >/dev/null
    target/debug/kata --api-url "$api" doctor --config "$cfg" --online --format json | jq -e '.summary_kind == "project_doctor" and .passed == true and .online_checked == true and (.checks | map(select(.name == "online_health" and .status == "pass")) | length == 1) and (.checks | map(select(.name == "online_status" and .status == "pass")) | length == 1)' >/dev/null
    target/debug/kata --api-url "$api" version | jq -e '.git_sha | type == "string"' >/dev/null
    target/debug/kata --api-url "$api" workers | jq -e 'length >= 1' >/dev/null
    target/debug/kata --api-url "$api" approvals >/dev/null
    target/debug/kata --api-url "$api" memory import-inbox --dir "$tmp/.kata/memory/inbox" --archive-dir "$tmp/.kata/memory/archive" >"$tmp/memory-import.json"
    # Not pinned to the `kata init` scaffold's file count — see the same line in
    # `factory-self-improve-preflight-smoke` for the authority and the reasoning.
    # `.responses` is `skipped ++ files` by construction (`memory.rs:59-79`), so
    # its length was only ever a third spelling of `.total_entries`; the archive
    # assertions below are what this recipe uniquely owns over the other three.
    jq -e '.failed == 0 and .conflicted == 0 and .imported >= 1 and .applied == .imported and .skipped >= 1' "$tmp/memory-import.json" >/dev/null
    test -f "$tmp/.kata/memory/archive/000-objective.json"
    test -f "$tmp/.kata/memory/archive/010-validation-criteria.json"
    test ! -f "$tmp/.kata/memory/inbox/000-objective.json"
    test ! -f "$tmp/.kata/memory/inbox/010-validation-criteria.json"
    test -f "$tmp/.kata/memory/inbox/README.md"
    target/debug/kata --api-url "$api" run "$star" --wait --timeout-secs 45 --poll-ms 100 >"$tmp/wait.json"
    jq -e '.status == "completed" and .workflow_name == "product-cli-starlark-smoke"' "$tmp/wait.json" >/dev/null
    id="$(jq -r '.id' "$tmp/wait.json")"
    target/debug/kata --api-url "$api" run current | jq -e --arg id "$id" '.id == $id and .status == "completed"' >/dev/null
    target/debug/kata --api-url "$api" run output "$id" probe | jq -e '.parsed.ok == true and .parsed.source == "starlark_api"' >/dev/null
    target/debug/kata --api-url "$api" watch "$id" --include-outputs | jq -e '.kind == "snapshot" and .execution.status == "completed" and .execution.operator_packet.terminal == true' >/dev/null
    target/debug/kata --api-url "$api" replay "$id" | jq -e '.status == "completed" and .operator_packet.terminal == true' >/dev/null
    target/debug/kata --api-url "$api" run-summary "$id" | jq -e '.summary_kind == "operator_run_summary" and .status == "completed" and .terminal == true' >/dev/null
    target/debug/kata --api-url "$api" --format json explain "$id" | jq -e --arg id "$id" '.summary_kind == "operator_explain" and .execution_id == $id and .terminal == true and .run_summary.summary_kind == "operator_run_summary" and .factory.summary_kind == "factory_controller_status" and (.recommended_actions | length >= 1)' >/dev/null
    # Captured, then matched (not `| grep -q`): under `pipefail` an early match SIGPIPEs
    # a report still being written, and the rc 141 would fail this smoke.
    report_text="$(target/debug/kata --api-url "$api" report "$id")"
    grep -q "Kata report: $id" <<<"$report_text"
    # The text report's per-stage line counts the derived invocation graph's
    # nodes: the pack's one stage ran, so the table is not empty.
    grep -Eq '^stages: total=[1-9][0-9]* ' <<<"$report_text"
    # `.stages` is the per-stage table: one row per attempt the checked program
    # authorizes, DERIVED from the attempt rows — so the pack's one
    # stage, `probe`, has a row, beside the typed output the census names.
    target/debug/kata --api-url "$api" --format json report "$id" | jq -e --arg id "$id" '.summary_kind == "operator_report" and .execution_id == $id and .terminal == true and .explain.summary_kind == "operator_explain" and .explain.run_summary.summary_kind == "operator_run_summary" and .explain.factory.summary_kind == "factory_controller_status" and .candidate.summary_kind == "factory_candidate" and .stages.total >= 1 and (.stages.stages | map(.stage_name) | index("probe") != null) and .stages.output_count >= 1 and (.stages.output_stages | index("probe") != null) and (.validation.report_count | type == "number") and (.closeout.report_count | type == "number") and (.memory.selector_count | type == "number") and (.controller.decision_count | type == "number") and (.recommended_actions | length >= 1)' >/dev/null
    target/debug/kata --api-url "$api" report "$id" --bundle | jq -e --arg id "$id" '.summary_kind == "operator_report_bundle" and .execution_id == $id and .report.summary_kind == "operator_report" and .report.execution_id == $id and (.suggested_artifacts | index("report.json") != null)' >/dev/null
    target/debug/kata --api-url "$api" report "$id" --bundle-dir "$tmp/report-bundle" | jq -e --arg id "$id" '.summary_kind == "operator_report_bundle" and .execution_id == $id and (.artifacts | index("report.json") != null) and (.artifacts | index("factory-candidate.json") != null) and (.artifacts | index("evidence-summary.json") != null)' >/dev/null
    test -f "$tmp/report-bundle/report.json"
    test -f "$tmp/report-bundle/evidence-summary.json"
    target/debug/kata --api-url "$api" watch --current --include-outputs | jq -e --arg id "$id" '.kind == "snapshot" and .execution.id == $id and .execution.status == "completed"' >/dev/null
    target/debug/kata --api-url "$api" replay --current | jq -e --arg id "$id" '.id == $id and .status == "completed" and .operator_packet.terminal == true' >/dev/null
    target/debug/kata --api-url "$api" run-summary --current | jq -e --arg id "$id" '.id == $id and .summary_kind == "operator_run_summary" and .status == "completed" and .terminal == true' >/dev/null
    target/debug/kata --api-url "$api" --format json explain --current | jq -e --arg id "$id" '.summary_kind == "operator_explain" and .execution_id == $id and .terminal == true' >/dev/null
    target/debug/kata --api-url "$api" --format json factory report --current | jq -e --arg id "$id" '.summary_kind == "operator_report" and .execution_id == $id and .terminal == true' >/dev/null
    # Same rule as the execution-program `schema_version` above, on the two
    # payloads that carry their own versions: the values are owned by the typed
    # constants `WORKSPACE_AWARENESS_SCHEMA_VERSION` (types/src/workspace_awareness.rs)
    # and `EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION` (types/src/execution.rs).
    # A version bump is the typed constant's business and its own tests'; this
    # product-path smoke owns only that the field is present and sane.
    target/debug/kata --api-url "$api" workspace | jq -e '(.schema_version | type == "number" and . >= 1) and .workers.total >= 1 and .executions.total >= 1' >/dev/null
    target/debug/kata --api-url "$api" execution-workspace "$id" | jq -e --arg id "$id" '(.schema_version | type == "number" and . >= 1) and .execution_id == $id' >/dev/null
    target/debug/kata --api-url "$api" steer human-requests >/dev/null
    target/debug/kata --api-url "$api" steer external-inputs >/dev/null
    echo "product-cli-smoke: PASS id=$id api=$api"

# End-to-end deterministic software-factory smoke. Boots an installed main in a temp
# Git project, submits the bundled std factory smoke through the API path, proves
# the operator checkout stayed untouched, then parks the isolated candidate.
# Set `KATA_FACTORY_SMOKE_EVIDENCE_DIR=...` to preserve replay/run-summary,
# workspace, factory-status, apply, auto-advance, build, submit, and daemon-log
# artifacts after the temp project is removed.
product-factory-smoke: build-debug
    #!/usr/bin/env bash
    set -euo pipefail
    # This recipe boots an installed main, a PER-UID singleton. Queue instead
    # of colliding. Safe ONLY because the watchdog armed below bounds a hang —
    # locking a hang would block every other run behind it.
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ]; then
        exec scripts/installed-main-lock.sh just product-factory-smoke
    fi
    source scripts/smoke-harness.sh
    # A hung run holds the PER-UID installed main and breaks every
    # later one. The EXIT trap cannot help — a trap needs the shell to exit,
    # and a hang is precisely the shell not exiting. Only an external timer can.
    arm_watchdog "product-factory-smoke"
    repo_root="$(pwd)"
    kata_bin="$repo_root/target/debug/kata"
    # `std.software_factory.smoke` is a `workflows/smoke` rig, which no bundle and
    # no checkout build resolves: the explicit stdlib dir opens its `smoke`
    # sibling, for the CLI and the `serve` it starts.
    export KATA_STDLIB_DIR="$repo_root/workflows/std"
    port="${KATA_FACTORY_SMOKE_PORT:-0}"
    metrics_port="${KATA_FACTORY_SMOKE_METRICS_PORT:-0}"
    api="http://127.0.0.1:${port}"
    evidence_dir="${KATA_FACTORY_SMOKE_EVIDENCE_DIR:-}"
    tmp="$(mktemp -d)"
    project="$tmp/project"
    # THE CONFIG LIVES INSIDE THE PROJECT, and that is load-bearing rather than
    # tidy. `kata init` writes `jj_repo = ".."`, resolved against the config
    # FILE'S directory — so a config at `$tmp/.kata/kata.toml` points the
    # execution-workspace provider at `$tmp`, which is not the project and holds
    # no trunk. With the config outside the project the run dies with
    # `worktree isolation failed: ... this repository has no trunk yet — it holds
    # no branch that kata did not create itself`, and the sibling factory smokes
    # fail the same way one step later with an EMPTY candidate worktree.
    cfg="$project/.kata/kata.toml"
    pid=""
    smoke_status="failed"
    id=""
    candidate_packet_proven=false
    report_packet_proven=false
    report_application_state_proven=false
    capture_evidence() {
        if [ -z "$evidence_dir" ]; then
            return
        fi
        mkdir -p "$evidence_dir"
        cp "$tmp"/*.json "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.txt "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp"/*.toml "$evidence_dir"/ 2>/dev/null || true
        cp "$tmp/solo.log" "$evidence_dir/solo.log" 2>/dev/null || true
        jq -n \
            --arg status "$smoke_status" \
            --arg api "$api" \
            --arg project "$project" \
            --arg execution_id "$id" \
            --argjson candidate_packet_proven "$candidate_packet_proven" \
            --argjson report_packet_proven "$report_packet_proven" \
            --argjson report_application_state_proven "$report_application_state_proven" \
            --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --arg repo_sha "$(git -C "$repo_root" rev-parse HEAD)" \
            '{
              summary_kind: "product_factory_smoke_evidence",
              status: $status,
              captured_at: $captured_at,
              repo_sha: $repo_sha,
              api_url: $api,
              temp_project: $project,
              execution_id: $execution_id,
              candidate_packet_proven: $candidate_packet_proven,
              report_packet_proven: $report_packet_proven,
              report_application_state_proven: $report_application_state_proven,
              artifacts: [
                "build.json",
                "submit.json",
                "initial-input.json",
                "wait.json",
                "summary.json",
                "report.json",
                "report-bundle.json",
                "report-after-park.json",
                "report-after-park-bundle.json",
                "workspace-before.json",
                "factory-candidate-before.json",
                "factory-status.json",
                "explain.json",
                "park.json",
                "park-retry.json",
                "workspace-after.json",
                "factory-candidate-after.json",
                "factory-status-after.json",
                "solo.log"
              ]
            }' >"$evidence_dir/evidence-summary.json"
        {
            printf '# Product Factory Smoke Evidence\n\n'
            printf 'Status: %s\n' "$smoke_status"
            printf 'API: %s\n' "$api"
            printf 'Execution: %s\n\n' "${id:-unknown}"
            printf 'Candidate packet proven: %s\n\n' "$candidate_packet_proven"
            printf 'Report packet proven: %s\n\n' "$report_packet_proven"
            printf 'Report application state proven: %s\n\n' "$report_application_state_proven"
            printf 'Start with `evidence-summary.json`, `summary.json`, `workspace-before.json`,\n'
            printf '`report.json`, `report-after-park.json`, `factory-candidate-before.json`, `factory-status.json`, `park.json`,\n'
            printf 'and `factory-candidate-after.json` when reviewing the\n'
            printf 'software-factory lifecycle proof ladder.\n'
        } >"$evidence_dir/README.md"
    }
    trap cleanup EXIT


    mkdir -p "$project"
    git -C "$project" init -b main >/dev/null
    git -C "$project" config user.email "kata-smoke@example.invalid"
    git -C "$project" config user.name "Kata Factory Smoke"
    printf '# Kata factory smoke project\n' >"$project/README.md"
    git -C "$project" add README.md
    git -C "$project" commit -m "seed factory smoke project" >/dev/null

    (cd "$project" && "$kata_bin" init --config "$cfg" >/dev/null)
    perl -0pi -e 's/bind = "127\.0\.0\.1:8400"/bind = "127.0.0.1:'"$port"'"/' "$cfg"
    perl -0pi -e 's/metrics_bind = "127\.0\.0\.1:9400"/metrics_bind = "127.0.0.1:'"$metrics_port"'"/' "$cfg"
    # jj is the only execution-workspace provider, and it carries this pack's park.
    # The workspace assertions below read the oci truth: a COMMITTED candidate
    # (clean wc, zero changed-paths) whose write is proven out of the recorded
    # commit, not a dirty working copy.

    # `kata init` declares no `[node] environment`, so without this the
    # `oci` boot refuses `node_environment_undeclared`. The deterministic pack's
    # stages are `printf`-only shell under offline workspaces — the pinned
    # live environment (busybox/getent/git) covers them, and no
    # `net = "host"` authoring means no `egress_allow` is declared.
    source scripts/oci-smoke-node.sh
    oci_smoke_inject_environment "$cfg" "product-factory-smoke" \
        "$OCI_SMOKE_BUSYBOX" "$OCI_SMOKE_GETENT" "$OCI_SMOKE_GIT"
    oci_smoke_provision_provider "$tmp" "$kata_bin" "$repo_root/target/debug"

    (cd "$project" && "$kata_bin" build --config "$cfg" std.software_factory.smoke --out "$tmp/build.json" >/dev/null)
    jq -e '.build.passed == true and .execution_program.summary.validation_criterion_count == 5 and (.preflight.execution_program.verifier_passes[] | select(.id == "factory_validation_criteria") | .evidence.criterion_count == 5)' "$tmp/build.json" >/dev/null
    (cd "$project" && "$kata_bin" check --config "$cfg" std.software_factory.smoke >/dev/null)

    # `serve`'s supervised node hosts the capsule route — its rootless
    # youki containers own a cgroup only inside a delegated scope, and the
    # provider exports are already on this process's env, which the scope
    # inherits.
    (cd "$project" && exec systemd-run $(oci_smoke_delegate_args 600) \
        "$kata_bin" serve --config "$cfg" >"$tmp/solo.log" 2>&1) &
    pid="$!"
    remember_solo

    wait_for_api "product-factory-smoke"

    (cd "$project" && "$kata_bin" --api-url "$api" factory run std.software_factory.smoke --context "Factory smoke steering evidence." --input-id factory-smoke-steering-001 >"$tmp/submit.json")
    id="$(jq -r '.id' "$tmp/submit.json")"
    jq -e --arg id "$id" '.id == $id and .status == "pending"' "$tmp/submit.json" >/dev/null

    "$kata_bin" --api-url "$api" run show "$id" >"$tmp/initial-input.json"
    jq -e '(.evidence.external_inputs | length == 1) and .evidence.external_inputs[0].id == "factory-smoke-steering-001" and .evidence.external_inputs[0].channel == "operator_steering" and .evidence.external_inputs[0].source == "operator" and .evidence.external_inputs[0].text == "Factory smoke steering evidence."' "$tmp/initial-input.json" >/dev/null

    "$kata_bin" --api-url "$api" run wait "$id" --timeout-secs 60 --poll-ms 100 >"$tmp/wait.json"
    jq -e --arg id "$id" '.id == $id and .status == "completed" and .workflow_name == "std.software_factory.smoke"' "$tmp/wait.json" >/dev/null
    test ! -e "$project/factory-smoke.txt"

    "$kata_bin" --api-url "$api" run-summary --current >"$tmp/summary.json"
    # `next_action` is matched by SUBSTRING, not by its exact sentence. The full
    # string is the pack's default (`workflows/kata-factory/kata/factory.star`,
    # `controller_next_action or "park the isolated candidate workspace for
    # inspection"`) — operator-facing prose that a pack author may reword at any
    # time without changing a single fact this smoke is here to prove. What the
    # smoke owns is that the decision carried a next action NAMING the action it
    # decided; the wording is the pack's.
    jq -e --arg id "$id" '.id == $id and .summary_kind == "operator_run_summary" and .status == "completed" and .controller_decision_count == 1 and .controller_decisions[0].decision == "park" and (.controller_decisions[0].next_action | contains("park"))' "$tmp/summary.json" >/dev/null
    "$kata_bin" --api-url "$api" report --current >"$tmp/report.txt"
    grep -Eq '^stages: total=[1-9][0-9]* ' "$tmp/report.txt"
    "$kata_bin" --api-url "$api" --format json report --current | jq '.' >"$tmp/report.json"
    jq -e --arg id "$id" '.summary_kind == "operator_report" and .execution_id == $id and .terminal == true and .checked_program != null and .explain.summary_kind == "operator_explain" and .explain.run_summary.summary_kind == "operator_run_summary" and .explain.factory.summary_kind == "factory_controller_status" and .candidate.summary_kind == "factory_candidate" and .stages.total >= 1 and .stages.output_count >= 1 and .validation.report_count >= 1 and .closeout.report_count >= 1 and .controller.decision_count == 1 and .controller.latest_decision == "park" and (.memory.selector_count | type == "number") and (.recommended_actions | length >= 1)' "$tmp/report.json" >/dev/null
    "$kata_bin" --api-url "$api" factory report --current --bundle >"$tmp/report-bundle.json"
    jq -e --arg id "$id" '.summary_kind == "operator_report_bundle" and .execution_id == $id and .report.summary_kind == "operator_report" and .report.execution_id == $id and (.suggested_artifacts | index("report.json") != null)' "$tmp/report-bundle.json" >/dev/null
    "$kata_bin" --api-url "$api" factory report --current --bundle-dir "$tmp/report-bundle-dir" >"$tmp/report-bundle-dir.json"
    jq -e --arg id "$id" '.summary_kind == "operator_report_bundle" and .status == "passed" and .execution_id == $id and (.artifacts | index("report.json") != null) and (.artifacts | index("factory-candidate.json") != null) and (.artifacts | index("evidence-summary.json") != null)' "$tmp/report-bundle-dir.json" >/dev/null
    "$kata_bin" evidence summary "$tmp/report-bundle-dir" --strict >/dev/null
    report_packet_proven=true

    "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace-before.json"
    # The oci truth: backend `jj` (the only provider that carries a
    # workspace_effect), a COMMITTED candidate (dirty=false, no wc changes —
    # the apply folded the write into the recorded commit), and promotion
    # `ready` — clean tree, criteria satisfied on the recorded candidate.
    jq -e '.workspace_provider_attached == true and .workspace_provider_backend == "jj" and .worktree.exists == true and .worktree.dirty == false and .worktree.changed_path_count == 0 and .promotion.safe_to_promote == true and .promotion.status == "ready" and .parking.available == true' "$tmp/workspace-before.json" >/dev/null
    # The candidate's WRITE is in its commit, not a dirty wc — read it out of
    # `identity.workspace_commit_sha` (the jj workspace's @; the colocated
    # git HEAD names the base, measured on the first converted run).
    candidate_commit="$(jq -r '.worktree.identity.workspace_commit_sha' "$tmp/workspace-before.json")"
    git -C "$(jq -r '.worktree.path' "$tmp/workspace-before.json")" show "$candidate_commit:factory-smoke.txt" | grep -q "criterion: validation-passed"

    "$kata_bin" --api-url "$api" factory status --current >"$tmp/factory-status.json"
    jq -e --arg id "$id" '.summary_kind == "factory_controller_status" and .execution_id == $id and .latest_decision.decision == "park" and .action.action == "park" and .action.applicable == true and .workspace.parking.available == true' "$tmp/factory-status.json" >/dev/null
    "$kata_bin" --api-url "$api" factory candidate --current >"$tmp/factory-candidate-before.json"
    # Under `oci` the committed candidate reads `dirty=false` /
    # `changed_path_count == 0` and the live-diff action is correctly absent
    # (it is the dirty-wc arm's command) — the write the candidate carries is
    # proven above out of its recorded commit.
    jq -e --arg id "$id" '
      .summary_kind == "factory_candidate"
      and .execution_id == $id
      and .candidate_state == "live_worktree"
      and .source == "workspace_worktree"
      and .workspace_provider_attached == true
      and .live_worktree.exists == true
      and .live_worktree.dirty == false
      and .live_worktree.changed_path_count == 0
      and .promotion_safe == true
      and .parking_available == true
      and (.recommended_actions | map(.action) | index("inspect_workspace") != null)
      and (.recommended_actions | map(.action) | index("park") != null)
    ' "$tmp/factory-candidate-before.json" >/dev/null
    "$kata_bin" --api-url "$api" --format json explain --current | jq '.' >"$tmp/explain.json"
    # `.headline` is matched by SUBSTRING for the same reason as `next_action`
    # above. The exact sentence is one arm of a match in
    # `client/src/operator_projection/explain.rs` — a
    # rendered operator string whose siblings differ only in wording. The two
    # assertions beside it (`recommended_actions[0].action == "park"` and
    # `factory.action.applicable == true`) are the FACTS; the headline check only
    # needs to prove the prose is about the same decision.
    jq -e --arg id "$id" '.summary_kind == "operator_explain" and .execution_id == $id and (.headline | contains("park")) and .recommended_actions[0].action == "park" and .factory.action.applicable == true' "$tmp/explain.json" >/dev/null

    "$kata_bin" --api-url "$api" factory apply --current --decision-id factory-smoke-controller-001 --name product-factory-smoke >"$tmp/park.json"
    jq -e '.summary_kind == "factory_controller_apply" and .status == "applied" and .applied == true and .action == "park" and .parked_candidate.parked_ref == "parked/product-factory-smoke" and (.parked_candidate.commit_sha | type == "string") and (.parked_candidate.commit_sha | length > 0) and .controller_application.decision_id == "factory-smoke-controller-001" and .controller_application.action == "park" and .controller_application.applied == true and .controller_application.parked_candidate.parked_ref == "parked/product-factory-smoke"' "$tmp/park.json" >/dev/null
    "$kata_bin" --api-url "$api" factory apply "$id" --decision-id factory-smoke-controller-001 --name product-factory-smoke >"$tmp/park-retry.json"
    jq -e '.summary_kind == "factory_controller_apply" and .status == "already_applied" and .applied == false and .action == "park" and .parked_candidate.parked_ref == "parked/product-factory-smoke" and .controller_application.decision_id == "factory-smoke-controller-001" and .controller_application.action == "park" and .controller_application.applied == true' "$tmp/park-retry.json" >/dev/null
    test ! -e "$project/factory-smoke.txt"

    "$kata_bin" --api-url "$api" execution-workspace "$id" >"$tmp/workspace-after.json"
    jq -e '.parking.parked == true and .parking.available == false and .parking.candidate.parked_ref == "parked/product-factory-smoke" and (.worktree == null or .worktree.exists == false)' "$tmp/workspace-after.json" >/dev/null
    "$kata_bin" --api-url "$api" factory candidate "$id" >"$tmp/factory-candidate-after.json"
    jq -e --arg id "$id" '
      .summary_kind == "factory_candidate"
      and .execution_id == $id
      and .candidate_state == "parked"
      and .source == "parked_candidate_evidence"
      and .parked_candidate.parked_ref == "parked/product-factory-smoke"
      and (.parked_candidate.commit_sha | type == "string")
      and (.parked_candidate.commit_sha | length > 0)
      and (.live_worktree == null)
      and .changed_path_count == 0
      and (.recommended_actions | map(.action) | index("inspect_workspace") != null)
      and (.recommended_actions | map(.action) | index("replay_evidence") != null)
    ' "$tmp/factory-candidate-after.json" >/dev/null
    "$kata_bin" --api-url "$api" factory status "$id" >"$tmp/factory-status-after.json"
    jq -e '.controller_application_count == 1 and .latest_application.action == "park" and .action.action == "none" and .action.applicable == false' "$tmp/factory-status-after.json" >/dev/null
    "$kata_bin" --api-url "$api" --format json factory report "$id" | jq '.' >"$tmp/report-after-park.json"
    jq -e --arg id "$id" '
      .summary_kind == "operator_report"
      and .execution_id == $id
      and .controller.application_count == 1
      and .controller.latest_application_id == "park:factory-smoke-controller-001"
      and .controller.latest_application_status == "applied"
      and .controller.latest_application_action == "park"
      and (.controller.latest_application_recovery_mode | not)
      and .explain.factory.latest_application.application_id == "park:factory-smoke-controller-001"
      and .explain.factory.latest_application.applied == true
      and .candidate.candidate_state == "parked"
    ' "$tmp/report-after-park.json" >/dev/null
    "$kata_bin" --api-url "$api" factory report "$id" --bundle >"$tmp/report-after-park-bundle.json"
    jq -e --arg id "$id" '
      .summary_kind == "operator_report_bundle"
      and .execution_id == $id
      and .report.controller.latest_application_id == "park:factory-smoke-controller-001"
      and .report.controller.latest_application_status == "applied"
      and .report.controller.latest_application_action == "park"
    ' "$tmp/report-after-park-bundle.json" >/dev/null
    report_application_state_proven=true
    candidate_packet_proven=true

    smoke_status="passed"
    if [ -n "$evidence_dir" ]; then
        echo "product-factory-smoke: PASS id=$id api=$api evidence=$evidence_dir"
    else
        echo "product-factory-smoke: PASS id=$id api=$api"
    fi

product-factory-evidence out_dir="target/dist/evidence/product-factory-smoke":
    #!/usr/bin/env bash
    set -euo pipefail
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    evidence_dir="{{out_dir}}/$stamp"
    KATA_FACTORY_SMOKE_EVIDENCE_DIR="$evidence_dir" just product-factory-smoke
    jq -e '.summary_kind == "product_factory_smoke_evidence" and .status == "passed" and (.execution_id | length > 0) and .candidate_packet_proven == true and .report_packet_proven == true and .report_application_state_proven == true' "$evidence_dir/evidence-summary.json" >/dev/null
    echo "product-factory-evidence: PASS out=$evidence_dir"

# Preserve a timestamped aggregate of repeated model-backed Kata-on-Kata proof packets.
factory-self-improve-series-evidence out_dir="target/dist/evidence/factory-self-improve-series" waves="3":
    #!/usr/bin/env bash
    set -euo pipefail
    repo_root="$(pwd)"
    series_out_dir="{{out_dir}}"
    wave_arg="{{waves}}"
    if [[ "$series_out_dir" == waves=* ]]; then
        wave_arg="${series_out_dir#waves=}"
        series_out_dir="target/dist/evidence/factory-self-improve-series"
    elif [[ "$series_out_dir" == out_dir=* ]]; then
        series_out_dir="${series_out_dir#out_dir=}"
    fi
    if [[ "$wave_arg" == waves=* ]]; then
        wave_arg="${wave_arg#waves=}"
    fi
    series_out_dir="${KATA_FACTORY_SELF_IMPROVE_SERIES_OUT_DIR:-$series_out_dir}"
    wave_count="${KATA_FACTORY_SELF_IMPROVE_SERIES_WAVES:-$wave_arg}"
    default_wave_count=3
    series_context_dir="${KATA_FACTORY_SELF_IMPROVE_SERIES_CONTEXT_DIR:-}"
    case "$wave_count" in
        ''|*[!0-9]*)
            echo "factory-self-improve-series-evidence: waves must be a positive integer" >&2
            exit 1
            ;;
    esac
    if [ "$wave_count" -lt 1 ]; then
        echo "factory-self-improve-series-evidence: waves must be >= 1" >&2
        exit 1
    fi
    if [ -z "$series_context_dir" ] && [ "$wave_count" -gt "$default_wave_count" ]; then
        echo "factory-self-improve-series-evidence: default distinct objective set supports ${default_wave_count} waves; set KATA_FACTORY_SELF_IMPROVE_SERIES_CONTEXT_DIR for more" >&2
        exit 1
    fi
    operator_status="$(git -C "$repo_root" status --short --untracked-files=all)"
    if [ -n "$operator_status" ]; then
        echo "factory-self-improve-series-evidence: operator checkout must be clean for commit-grade model-backed evidence." >&2
        printf '%s\n' "$operator_status" >&2
        exit 1
    fi
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    evidence_dir="$series_out_dir/$stamp"
    default_context_dir="$evidence_dir/default-contexts"
    mkdir -p "$evidence_dir"
    mkdir -p "$default_context_dir"
    repo_sha="$(git -C "$repo_root" rev-parse HEAD)"
    printf '%s' "$operator_status" >"$evidence_dir/operator-status-before.txt"
    default_wave_target() {
        case "$1" in
            1) printf '%s\n' "docs/product/operator-guide.md" ;;
            2) printf '%s\n' "README.md" ;;
            3) printf '%s\n' "docs/development/verification.md" ;;
            *)
                echo "factory-self-improve-series-evidence: no default target for wave $1" >&2
                return 1
                ;;
        esac
    }
    write_default_wave_context() {
        wave_index="$1"
        target="$2"
        output="$3"
        case "$wave_index" in
            1)
                {
                    printf 'Kata model-backed self-improve series wave %s.\n\n' "$wave_index"
                    printf '%s\n' 'Goal:'
                    printf '%s\n' '- In the isolated candidate workspace only, make exactly one tiny useful docs'
                    printf '  update to `%s`.\n' "$target"
                    printf '%s\n' '- Add a short note to the Factory proof ladder clarifying that the self-improve'
                    printf '%s\n' '  series proof uses distinct objective packets and unique candidate diff hashes'
                    printf '%s\n' '  rather than replaying the same model-backed prompt.'
                    printf '\n'
                    printf '%s\n' 'Hard constraints:'
                    printf '%s\n' "- Edit only \`$target\`."
                    printf '%s\n' '- Do not edit code, tests, fixtures, generated evidence, config, or CI.'
                    printf '%s\n' '- Do not commit, push, promote, or mutate the operator checkout.'
                    printf '%s\n' '- Validation must pass with the declared commands.'
                    printf '%s\n' '- The controller decision should be `park` so the candidate is preserved for'
                    printf '%s\n' '  inspection instead of accepted automatically.'
                    printf '\n'
                    printf '%s\n' 'Success criteria:'
                    printf '%s\n' "- \`plan.owned_paths\` is exactly [\"$target\"]."
                    printf '%s\n' "- \`implement.changed_files\` contains only \`$target\`."
                    printf '%s\n' '- `review.verdict` is `approve`.'
                    printf '%s\n' '- `validate.status` is `passed` with no missing evidence.'
                    printf '%s\n' '- `controller.decision` is `park` and `human_required` is false.'
                } >"$output"
                ;;
            2)
                {
                    printf 'Kata model-backed self-improve series wave %s.\n\n' "$wave_index"
                    printf '%s\n' 'Goal:'
                    printf '%s\n' '- In the isolated candidate workspace only, make exactly one tiny useful docs'
                    printf '  update to `%s`.\n' "$target"
                    printf '%s\n' '- Update the model-backed self-improve paragraph to clarify that the series recipe'
                    printf '%s\n' '  now drives distinct objective packets by default and aggregates unique'
                    printf '%s\n' '  candidate diff hashes.'
                    printf '\n'
                    printf '%s\n' 'Hard constraints:'
                    printf '%s\n' "- Edit only \`$target\`."
                    printf '%s\n' '- Do not edit code, tests, fixtures, generated evidence, config, or CI.'
                    printf '%s\n' '- Do not commit, push, promote, or mutate the operator checkout.'
                    printf '%s\n' '- Validation must pass with the declared commands.'
                    printf '%s\n' '- The controller decision should be `park` so the candidate is preserved for'
                    printf '%s\n' '  inspection instead of accepted automatically.'
                    printf '\n'
                    printf '%s\n' 'Success criteria:'
                    printf '%s\n' "- \`plan.owned_paths\` is exactly [\"$target\"]."
                    printf '%s\n' "- \`implement.changed_files\` contains only \`$target\`."
                    printf '%s\n' '- `review.verdict` is `approve`.'
                    printf '%s\n' '- `validate.status` is `passed` with no missing evidence.'
                    printf '%s\n' '- `controller.decision` is `park` and `human_required` is false.'
                } >"$output"
                ;;
            3)
                {
                    printf 'Kata model-backed self-improve series wave %s.\n\n' "$wave_index"
                    printf '%s\n' 'Goal:'
                    printf '%s\n' '- In the isolated candidate workspace only, make exactly one tiny useful docs'
                    printf '  update to `%s`.\n' "$target"
                    printf '%s\n' '- Add a short checklist note near the manual self-improve proof entry explaining'
                    printf '%s\n' '  that series evidence should be reviewed for distinct wave targets and unique'
                    printf '%s\n' '  candidate diff hashes.'
                    printf '\n'
                    printf '%s\n' 'Hard constraints:'
                    printf '%s\n' "- Edit only \`$target\`."
                    printf '%s\n' '- Do not edit code, tests, fixtures, generated evidence, config, or CI.'
                    printf '%s\n' '- Do not commit, push, promote, or mutate the operator checkout.'
                    printf '%s\n' '- Validation must pass with the declared commands.'
                    printf '%s\n' '- The controller decision should be `park` so the candidate is preserved for'
                    printf '%s\n' '  inspection instead of accepted automatically.'
                    printf '\n'
                    printf '%s\n' 'Success criteria:'
                    printf '%s\n' "- \`plan.owned_paths\` is exactly [\"$target\"]."
                    printf '%s\n' "- \`implement.changed_files\` contains only \`$target\`."
                    printf '%s\n' '- `review.verdict` is `approve`.'
                    printf '%s\n' '- `validate.status` is `passed` with no missing evidence.'
                    printf '%s\n' '- `controller.decision` is `park` and `human_required` is false.'
                } >"$output"
                ;;
            *)
                echo "factory-self-improve-series-evidence: no default context for wave $wave_index" >&2
                return 1
                ;;
        esac
    }
    validate_wave_target() {
        target="$1"
        case "$target" in
            ""|/*|../*|*/../*|*/..|.|..|*//*)
                echo "factory-self-improve-series-evidence: invalid target path: $target" >&2
                return 1
                ;;
        esac
        if printf '%s' "$target" | grep -Eq '[[:space:]]'; then
            echo "factory-self-improve-series-evidence: target path contains whitespace: $target" >&2
            return 1
        fi
        if [ ! -f "$repo_root/$target" ]; then
            echo "factory-self-improve-series-evidence: target path does not exist: $target" >&2
            return 1
        fi
    }
    read_custom_wave_target() {
        target_file="$1"
        line_count="$(awk 'END { print NR }' "$target_file")"
        if [ "$line_count" -ne 1 ]; then
            echo "factory-self-improve-series-evidence: target file must contain exactly one line: $target_file" >&2
            return 1
        fi
        target="$(tr -d '\r\n' <"$target_file")"
        validate_wave_target "$target"
        printf '%s\n' "$target"
    }
    if [ -n "$series_context_dir" ]; then
        custom_targets="$evidence_dir/custom-targets.txt"
        : >"$custom_targets"
        for index in $(seq "$wave_count"); do
            wave_context_file="$series_context_dir/wave-${index}.md"
            wave_target_file="$series_context_dir/wave-${index}.target"
            test -f "$wave_context_file"
            test -f "$wave_target_file"
            wave_target="$(read_custom_wave_target "$wave_target_file")"
            if grep -Fxq "$wave_target" "$custom_targets"; then
                echo "factory-self-improve-series-evidence: duplicate target path in custom context set: $wave_target" >&2
                exit 1
            fi
            printf '%s\n' "$wave_target" >>"$custom_targets"
        done
    fi
    passed=0
    failed=0
    useful=0
    for index in $(seq "$wave_count"); do
        wave_dir="$evidence_dir/wave-${index}"
        mkdir -p "$wave_dir"
        wave_objective_id="${KATA_FACTORY_SELF_IMPROVE_OBJECTIVE_ID_PREFIX:-factory-self-improve-series}-$index"
        wave_input_id="${KATA_FACTORY_SELF_IMPROVE_INPUT_ID_PREFIX:-factory-self-improve-series}-$index"
        wave_park_name="${KATA_FACTORY_SELF_IMPROVE_PARK_NAME_PREFIX:-kata-self-improve-series}-$index"
        if [ -n "$series_context_dir" ]; then
            wave_context_file="$series_context_dir/wave-${index}.md"
            wave_target_file="$series_context_dir/wave-${index}.target"
            test -f "$wave_context_file"
            test -f "$wave_target_file"
            wave_target="$(read_custom_wave_target "$wave_target_file")"
        else
            wave_target="$(default_wave_target "$index")"
            wave_context_file="$default_context_dir/wave-${index}.md"
            write_default_wave_context "$index" "$wave_target" "$wave_context_file"
        fi
        printf '%s\n' "$wave_objective_id" >"$wave_dir/objective-id.txt"
        printf '%s\n' "$wave_target" >"$wave_dir/target-path.txt"
        set +e
        KATA_FACTORY_SELF_IMPROVE_EVIDENCE_DIR="$wave_dir" \
            KATA_FACTORY_SELF_IMPROVE_OBJECTIVE_ID="$wave_objective_id" \
            KATA_FACTORY_SELF_IMPROVE_INPUT_ID="$wave_input_id" \
            KATA_FACTORY_SELF_IMPROVE_PARK_NAME="$wave_park_name" \
            KATA_FACTORY_SELF_IMPROVE_TARGET_PATH="$wave_target" \
            KATA_FACTORY_SELF_IMPROVE_CONTEXT_FILE="$wave_context_file" \
            just factory-self-improve-smoke >"$wave_dir/run.log" 2>"$wave_dir/run.stderr"
        code="$?"
        set -e
        if [ "$code" -eq 0 ] && jq -e --arg repo_sha "$repo_sha" --arg objective_id "$wave_objective_id" --arg input_id "$wave_input_id" --arg park_name "$wave_park_name" --arg target_path "$wave_target" '.summary_kind == "factory_self_improve_evidence" and .status == "passed" and .repo_sha == $repo_sha and .objective_id == $objective_id and .input_id == $input_id and .park_name == $park_name and .target_path == $target_path and (.execution_id | length > 0) and (.decision_id | length > 0) and (.candidate_diff_sha256 | length > 0) and .candidate_changed_paths == [$target_path] and .candidate_packet_proven == true and .controller_policy_proven == true' "$wave_dir/evidence-summary.json" >/dev/null 2>&1; then
            passed=$((passed + 1))
            if [ -s "$wave_dir/candidate-diff.diff" ]; then
                useful=$((useful + 1))
            fi
        else
            failed=$((failed + 1))
            if [ ! -f "$wave_dir/evidence-summary.json" ]; then
                jq -n \
                    --arg status "failed" \
                    --arg repo_sha "$repo_sha" \
                    --arg objective_id "$wave_objective_id" \
                    --arg input_id "$wave_input_id" \
                    --arg park_name "$wave_park_name" \
                    --arg target_path "$wave_target" \
                    --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                    --argjson exit_code "$code" \
                    '{summary_kind:"factory_self_improve_evidence", status:$status, repo_sha:$repo_sha, objective_id:$objective_id, input_id:$input_id, park_name:$park_name, target_path:$target_path, captured_at:$captured_at, exit_code:$exit_code, candidate_diff_sha256:"", candidate_changed_paths:[], candidate_packet_proven:false, controller_policy_proven:false}' \
                    >"$wave_dir/evidence-summary.json"
            fi
        fi
    done
    git -C "$repo_root" status --short --untracked-files=all >"$evidence_dir/operator-status-after.txt"
    diff -u "$evidence_dir/operator-status-before.txt" "$evidence_dir/operator-status-after.txt" >"$evidence_dir/operator-status.diff" || true
    find "$evidence_dir" -path '*/objective-id.txt' -type f -exec cat {} \; | sort -u | jq -R . | jq -s . >"$evidence_dir/objective-ids.json"
    find "$evidence_dir" -path '*/target-path.txt' -type f -exec cat {} \; | sort -u | jq -R . | jq -s . >"$evidence_dir/target-paths.json"
    find "$evidence_dir" -path '*/candidate-diff.sha256' -type f -exec cat {} \; | sort -u | jq -R . | jq -s . >"$evidence_dir/candidate-diff-hashes.json"
    jq -s '[.[] | select(.candidate_packet_proven == true)] | length' "$evidence_dir"/wave-*/evidence-summary.json >"$evidence_dir/candidate-packet-proof-count.txt"
    jq -s '[.[] | select(.controller_policy_proven == true)] | length' "$evidence_dir"/wave-*/evidence-summary.json >"$evidence_dir/controller-policy-proof-count.txt"
    jq -s \
        --slurpfile objective_ids "$evidence_dir/objective-ids.json" \
        --slurpfile target_paths "$evidence_dir/target-paths.json" \
        --slurpfile candidate_diff_hashes "$evidence_dir/candidate-diff-hashes.json" \
        --arg status "$([ "$failed" -eq 0 ] && echo passed || echo failed)" \
        --arg repo_sha "$repo_sha" \
        --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson wave_count "$wave_count" \
        --argjson passed_count "$passed" \
        --argjson failed_count "$failed" \
        --argjson useful_candidate_count "$useful" \
        --argjson candidate_packet_proof_count "$(cat "$evidence_dir/candidate-packet-proof-count.txt")" \
        --argjson controller_policy_proof_count "$(cat "$evidence_dir/controller-policy-proof-count.txt")" \
        --argjson operator_checkout_clean "$([ -s "$evidence_dir/operator-status.diff" ] && echo false || echo true)" \
        '{
          summary_kind: "factory_self_improve_series_evidence",
          status: $status,
          repo_sha: $repo_sha,
          captured_at: $captured_at,
          wave_count: $wave_count,
          passed_count: $passed_count,
          failed_count: $failed_count,
          useful_candidate_count: $useful_candidate_count,
          candidate_packet_proof_count: $candidate_packet_proof_count,
          controller_policy_proof_count: $controller_policy_proof_count,
          distinct_objective_count: ($objective_ids[0] | length),
          distinct_target_count: ($target_paths[0] | length),
          distinct_candidate_diff_count: ($candidate_diff_hashes[0] | length),
          objective_ids: $objective_ids[0],
          target_paths: $target_paths[0],
          candidate_diff_hashes: $candidate_diff_hashes[0],
          operator_checkout_clean: $operator_checkout_clean,
          waves: .
        }' "$evidence_dir"/wave-*/evidence-summary.json >"$evidence_dir/evidence-summary.json"
    {
        printf '# Factory Self-Improve Series Evidence\n\n'
        printf 'Status: %s\n' "$([ "$failed" -eq 0 ] && echo passed || echo failed)"
        printf 'Repo SHA: %s\n' "$repo_sha"
        printf 'Waves: %s\n' "$wave_count"
        printf 'Passed: %s\n' "$passed"
        printf 'Failed: %s\n' "$failed"
        printf 'Useful candidates: %s\n' "$useful"
        printf 'Candidate packet proofs: %s\n' "$(jq -r '.candidate_packet_proof_count' "$evidence_dir/evidence-summary.json")"
        printf 'Controller policy proofs: %s\n' "$(jq -r '.controller_policy_proof_count' "$evidence_dir/evidence-summary.json")"
        printf 'Distinct objectives: %s\n' "$(jq -r '.distinct_objective_count' "$evidence_dir/evidence-summary.json")"
        printf 'Distinct targets: %s\n' "$(jq -r '.distinct_target_count' "$evidence_dir/evidence-summary.json")"
        printf 'Distinct candidate diffs: %s\n' "$(jq -r '.distinct_candidate_diff_count' "$evidence_dir/evidence-summary.json")"
    } >"$evidence_dir/README.md"
    jq -e --arg repo_sha "$repo_sha" --argjson wave_count "$wave_count" '.summary_kind == "factory_self_improve_series_evidence" and .status == "passed" and .repo_sha == $repo_sha and .wave_count == $wave_count and .passed_count == $wave_count and .failed_count == 0 and .useful_candidate_count == $wave_count and .candidate_packet_proof_count == $wave_count and .controller_policy_proof_count == $wave_count and .distinct_objective_count == $wave_count and .distinct_target_count == $wave_count and .distinct_candidate_diff_count == $wave_count and .operator_checkout_clean == true and all(.waves[]; .status == "passed" and (.candidate_diff_sha256 | length > 0) and .candidate_changed_paths == [.target_path] and .candidate_packet_proven == true and .controller_policy_proven == true)' "$evidence_dir/evidence-summary.json" >/dev/null
    echo "factory-self-improve-series-evidence: PASS out=$evidence_dir"

# List every parked assignment waiting for operator review across
# all executions, sorted oldest-first. Empty array when nothing is
# gated. See `docs/product/operator-guide.md` for the response shape.
api-approvals: build
    target/release/kata --api-url {{api_url}} approvals

# Approve a parked stage. Usage:
#   just api-approve <execution_id> <assignment_id>
api-approve execution_id assignment_id: build
    target/release/kata --api-url {{api_url}} run approve {{execution_id}} {{assignment_id}}

# Reject a parked stage. Usage:
#   just api-reject <execution_id> <assignment_id> "<reason>"
api-reject execution_id assignment_id reason: build
    target/release/kata --api-url {{api_url}} run reject {{execution_id}} {{assignment_id}} "{{reason}}"

# ─── Work-item ergonomics ────────────────────────────────────
#
# Three thin wrappers that cover the common driver loop (a coding
# agent or a person at a terminal): submit a work item, tail its
# events, approve the single parked
# gate. They shell out to the `kata` operator CLI; the underlying `api-*`
# recipes remain available for anything outside the common path.
# See `docs/product/operator-guide.md` for the intent → command
# cheat sheet.

# Submit a kata-work-item run with a natural-language description.
# Reads `workflows/std/kata-work-item.star`, substitutes every
# `__WORK_DESCRIPTION__` placeholder (outside comment lines) with the
# operator's description, writes the result to
# `/tmp/kata-work-item-<stamp>.star`, and submits via
# `kata run <path> --submit`. Prints the `{id, status}` JSON response
# on stdout; writes the instantiated Starlark path to stderr so scripts
# that consume stdout aren't polluted.
#
# The description is one positional arg — quote it so your shell
# doesn't word-split on spaces. Multi-line descriptions are fine
# (pass via `"$desc"` with `desc=$(cat <<EOF ... EOF)` or similar).
# Known edge case: a description containing `"""` terminates the
# Starlark prompt string early and breaks parsing; avoid or hand-edit
# in that case.
#
# Implementation notes:
# - Substitution uses Python `str.replace` (literal, no regex and no
#   `&`-as-match bash ${//} footgun).
# - Comment lines in the template (first non-whitespace is `#`) are
#   skipped so the placeholder reference inside the file's own
#   header stays literal.
#
# Template override for dry-runs / smokes:
#   KATA_WORK_ITEM_TEMPLATE=workflows/smoke/work-item-plumbing-smoke.star just submit-work "..."
# Points the substituter at a different Starlark pack (e.g. the
# shell-only `work-item-plumbing-smoke`), so the recipe plumbing can be exercised
# end-to-end at zero LLM cost.
#
# Usage:
#   just submit-work "Implement pricing table + cost metric"
submit-work description: build
    #!/usr/bin/env bash
    set -euo pipefail
    template="${KATA_WORK_ITEM_TEMPLATE:-workflows/std/kata-work-item.star}"
    if [ ! -f "$template" ]; then
        echo "submit-work: template not found at $template" >&2
        exit 1
    fi
    out="/tmp/kata-work-item-$(date +%s%N).star"
    KATA_TEMPLATE="$template" \
        KATA_OUT="$out" \
        KATA_DESC={{quote(description)}} \
        python3 - <<'PY'
    import os, pathlib
    tpl = pathlib.Path(os.environ["KATA_TEMPLATE"]).read_text()
    desc = os.environ["KATA_DESC"]
    # Escape literal double-curlies in the description so minijinja
    # doesn't interpret them as template refs when the plan prompt
    # renders: an operator description containing `{ {id} }` (no
    # spaces) in a code example would fail plan-stage rendering with
    # "undefined value". Minijinja's literal-brace escape is the two-curly
    # block that renders the literal string.
    #
    # Source-level note: this file avoids literal `{` `{` and `}` `}`
    # sequences because just's own parser treats them as variable
    # interpolation. We build them from `chr()` so the substitution
    # logic is expressible here at all.
    OPEN = chr(123) * 2
    CLOSE = chr(125) * 2
    SENT_OPEN = "\x00KATA_OPEN\x00"
    SENT_CLOSE = "\x00KATA_CLOSE\x00"
    # Two-pass replace: (a) swap literals for sentinels, (b) swap
    # sentinels for the minijinja-escape sequence. Avoids the
    # single-pass footgun where the replacement itself contains the
    # pattern and re-matches.
    escape_open = OPEN + ' "' + OPEN + '" ' + CLOSE
    escape_close = OPEN + ' "' + CLOSE + '" ' + CLOSE
    tmp = desc.replace(OPEN, SENT_OPEN).replace(CLOSE, SENT_CLOSE)
    desc_safe = tmp.replace(SENT_OPEN, escape_open).replace(SENT_CLOSE, escape_close)
    out = []
    for line in tpl.splitlines(keepends=True):
        if line.lstrip().startswith("#"):
            out.append(line)
        else:
            out.append(line.replace("__WORK_DESCRIPTION__", desc_safe))
    pathlib.Path(os.environ["KATA_OUT"]).write_text("".join(out))
    PY
    echo "submit-work: wrote $out" >&2
    target/release/kata --api-url {{api_url}} run "$out" --submit

# Approve the single parked assignment. Handles the three cases:
#   - 0 parked   → prints "no pending approvals" and exits 0
#   - 1 parked   → approves it, printing the target first
#   - >1 parked  → lists every parked assignment and exits 1 with
#                  a hint pointing at `just api-approve`
#
# Use this when you're driving a single-track workflow and know
# there's only one gate at a time. For parallel branches or multi-
# execution traffic, reach for `just api-approvals` +
# `just api-approve <exec> <asn>` directly.
approve-latest: build
    #!/usr/bin/env bash
    set -euo pipefail
    approvals=$(target/release/kata --api-url {{api_url}} approvals)
    # NDJSON: one object per line, each starts with `{`. Empty stdout
    # is 0 parked; `grep -c` returns 1 on no match, so swallow it.
    count=$(printf '%s\n' "$approvals" | grep -c '^{' || true)
    if [ "$count" -eq 0 ]; then
        echo "approve-latest: no pending approvals"
        exit 0
    fi
    if [ "$count" -gt 1 ]; then
        echo "approve-latest: $count parked assignments — ambiguous" >&2
        printf '%s\n' "$approvals" | jq -r '"  \(.execution_id) \(.assignment_id) \(.stage_name)"' >&2
        echo "approve-latest: use \`just api-approve <exec> <asn>\` for a specific one" >&2
        exit 1
    fi
    exec_id=$(printf '%s\n' "$approvals" | jq -r '.execution_id')
    asn_id=$(printf '%s\n' "$approvals"  | jq -r '.assignment_id')
    stage=$(printf '%s\n' "$approvals"   | jq -r '.stage_name')
    echo "approve-latest: approving $exec_id / $asn_id (stage=$stage)" >&2
    exec target/release/kata --api-url {{api_url}} run approve "$exec_id" "$asn_id"

# ─── Process hygiene ─────────────────────────────────────────
#
# Always run `just pgrep-kata` before a commit or live smoke.
# If anything is listed, `just kill-kata` to clean up.
#
# The main authority uses a kernel-held data-directory lock, not PID files.
# Process hygiene therefore uses exact binary names; never `pgrep -f`, which
# can match and signal the invoking shell command line.

# Report stale processes that `pgrep-kata` structurally CANNOT see.
#
# `pgrep-kata` matches `pgrep -x kata` / `-x kata-worker` — exact binary names. It
# answers "is a kata daemon running", correctly, and nothing more. Read as "is the host
# clean" it misses idle processes that are invisible to it and burn zero CPU (so are
# invisible to `/proc/loadavg` too), for example:
#
#   cargo-clippy  5h25m  0 CPU  cwd <deleted>   — build-lock orphan
#   cargo         3h50m  0 CPU  cwd <deleted>   — build-lock orphan
#   3x zsh        ~42m   0 CPU  cwd <worktree>  — `until grep …; do sleep 30; done`
#                                                 waiters armed against a log their
#                                                 own run had already killed
#
# The build orphans are the class that WEDGES a worktree's cargo build lock
# indefinitely while looking like nothing at all. This recipe exists so detecting them
# is a maintained pattern rather than an ad-hoc grep written under time pressure — a
# pattern of `cargo|rustc|nextest|just` cannot match a `zsh` running `sleep`.
#
# FALSE-POSITIVE SAFETY, since this rides `gate`: class (2) requires zero CPU, an age
# over two minutes, AND a parent that is init or a cwd that is deleted. A cargo the gate
# itself is running has a live parent and accrues CPU, so it matches neither condition.
# Class (3) requires a sleep over two minutes old whose own or parent cwd is in THIS
# worktree; the gate spawns none.
pgrep-stale:
    #!/usr/bin/env bash
    set -uo pipefail
    any=0
    siblings=0

    # (1) kata daemons — same surface as `pgrep-kata`, kept here so this recipe is a
    # superset and a caller never needs both.
    #
    # A LIVE RUN'S NODE IS NOT RESIDUE, and this recipe has a way to tell. Every
    # recipe that boots an installed main holds
    # `/tmp/kata-installed-main-<uid>.lane.lock` for exactly as long as its node lives
    # (scripts/installed-main-lock.sh). If that lock is held RIGHT NOW, a live `kata` is
    # somebody's running smoke, not something left behind — report it and do not fail
    # the caller. This is the same discrimination the poll-loop branch below makes for
    # another worktree's waiter, and for the same reason: a check that fires on a
    # healthy process belonging to another run is a deadlock between runs, not
    # hygiene. Without it every concurrent gate would fail for the duration of a
    # containment run.
    #
    # This does NOT weaken the guarantee. The lock is released by the kernel when the
    # holder exits, including on a kill, so genuine residue — a node whose run is gone —
    # leaves the lock free and is still counted.
    # NOT when the CALLER holds the lock. `gate-containment` runs this as its own
    # opening hygiene check while holding the lane lock, and excusing a live kata there
    # would make the check vacuous against exactly the residue it is looking for.
    # `KATA_INSTALLED_MAIN_LOCK_HELD` is set only inside a holder's process tree, so it
    # is the precise "is this MY lock" discriminator.
    lane_lock="/tmp/kata-installed-main-$(id -u).lane.lock"
    lane_live=0
    if [ "${KATA_INSTALLED_MAIN_LOCK_HELD:-0}" != "1" ] \
       && command -v flock >/dev/null 2>&1 && [ -e "$lane_lock" ]; then
        flock -n "$lane_lock" true 2>/dev/null || lane_live=1
    fi
    for name in kata kata-worker; do
        if pids=$(pgrep -x "$name" 2>/dev/null); then
            if [ "$lane_live" -eq 1 ]; then
                echo "$pids  ($name — a LIVE installed-main run holds the lane lock; not residue)"
                siblings=1
            else
                echo "$pids  ($name)"
                any=1
            fi
        fi
    done

    # (2) BUILD-TOOL ORPHANS: reparented to init, or cwd deleted, and burning no CPU.
    #
    # The DISCRIMINATOR IS PARENTAGE. Zero CPU alone is useless: the suite's runner
    # supervises a whole run at ~0 CPU, and a freshly-spawned `rustc` sits at 0 CPU with no
    # children for its first moment. Both "0 CPU" and "0 CPU and childless" flag a
    # concurrent run's healthy build, so the gate that ran this would fail because of a
    # process it did not own.
    #
    # A genuine orphan is distinguishable structurally: when its parent dies it is
    # REPARENTED TO INIT (ppid 1), or the worktree it ran in has been removed so its cwd is
    # gone. A live build process always has a real, live parent. Observed orphans match
    # (a cargo at PPID 1, and two with deleted cwds).
    #
    # VERIFICATION STATUS, stated honestly rather than implied:
    #   VERIFIED  a clean host passes; a concurrent run's live build is not flagged (the
    #             critical false-positive case); a planted poll-loop waiter is detected
    #             and clears after reaping.
    #   UNVERIFIED BY PLANT  the ppid==1 branch. A ppid-1 orphan cannot be synthesized
    #             here because the spawning shell persists, so `setsid` yields a real
    #             parent. The branch is three lines and matches the observed orphans,
    #             but it has not been counterfactually fired. Treat a first real hit as
    #             also being this branch's first test.
    # ZOMBIES ARE EXCLUDED: already exited, holding no lock, and unkillable.
    # MATCH ON PROCESS NAME, NOT CMDLINE. A `pgrep -f` pattern of these names matches
    # `~/.cargo/bin/sccache` — the PATH contains "cargo" — so it would report the
    # sccache DAEMON as a build orphan: ppid 1, cwd /, 0 CPU, which is what a daemon looks
    # like by design and holds no build lock. That would fail `just gate` on every host
    # running sccache. Exact names cannot match a path.
    #
    # Only processes that can hold cargo's build lock belong here. `sccache` cannot: it is
    # a compile cache reached THROUGH rustc, never the lock holder.
    for pid in $(pgrep -x 'cargo' 2>/dev/null; pgrep -x 'rustc' 2>/dev/null; pgrep -x 'cargo-nextest' 2>/dev/null; pgrep -x 'cargo-clippy' 2>/dev/null; pgrep -x 'cargo-fmt' 2>/dev/null; true); do
        [ -d "/proc/$pid" ] || continue
        stat=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')
        case "$stat" in Z*) continue ;; esac
        cpu=$(ps -o time= -p "$pid" 2>/dev/null | tr -d ' ')
        [ "$cpu" = "00:00:00" ] || continue
        # AGE FLOOR. A genuinely wedged orphan is old; a transient rustc is seconds old.
        # Without it a 23-SECOND-OLD live suite run can be flagged, and most such pids exit
        # on their own within ~90s. Parentage already excludes those, but the floor is
        # cheap insurance against a reparenting race, and it makes
        # the recipe assert the property it exists for: nothing was LEFT BEHIND.
        secs=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
        [ -n "${secs:-}" ] || continue
        [ "$secs" -ge 120 ] 2>/dev/null || continue
        ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null || true)
        if [ "${ppid:-0}" = "1" ]; then
            echo "$pid  (build ORPHAN, reparented to init, 0 CPU: ${cwd:-<cwd deleted>})"
            any=1
        elif [ -z "$cwd" ]; then
            echo "$pid  (build ORPHAN, cwd DELETED, 0 CPU — may hold a stale build lock)"
            any=1
        fi
    done

    # (3) POLL-LOOP WAITERS: a shell whose cwd is a worktree, sleeping. These come from
    # runs arming `until grep <log>` against output they later kill.
    # Checks the SLEEPING PROCESS'S OWN cwd as well as its parent's: a shell `exec`s
    # `sleep` in place, so the sleep's parent is often the OUTER shell sitting in the
    # repo root while the sleep itself inherited the worktree cwd. Checking only the
    # parent misses exactly that (a counterfactual test shows it).
    # OWNERSHIP IS SCOPED TO THE INVOKING WORKTREE. A waiter in ANOTHER worktree of
    # this repository belongs to that worktree's run: failing this caller's gate on it
    # would leave the caller a recourse it cannot invoke (it may not reap another run's
    # process, and it cannot pass its own gate while the process lives), so it is
    # reported and not counted.
    #
    # `--show-toplevel` returns the WORKTREE path when run inside one, so a worktree
    # still flags its own waiters; only the other worktrees' waiters are excluded.
    # `siblings` is initialised ONCE at the top of the recipe, not here. Re-initialising
    # it at this point would silently discard a "live run's node" report from branch
    # (1) and print "no stale processes" instead of naming what is running.
    self_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
    # Every worktree of this repository, this one included: the LONGEST root that
    # contains a cwd owns it, so a worktree nested in the checkout (`.worktrees/*`, or
    # an agent tool's own worktree directory) is its own run's, not this caller's. A
    # directory that is NOT a registered worktree (a removed worktree's leftovers)
    # belongs to the registered root containing it: a leftover inside this checkout
    # is counted here.
    mapfile -t worktree_roots < <(git worktree list --porcelain 2>/dev/null | sed -n 's/^worktree //p')
    worktree_roots+=("$self_root")
    python3 scripts/is-idle-inhibitor.py --self-test
    for pid in $(pgrep -x sleep 2>/dev/null || true); do
        [ -d "/proc/$pid" ] || continue
        # A live harness's idle inhibitor is not a shell polling an abandoned
        # log. Verify its real parent executable and exact child argv; a name
        # in an arbitrary shell command must not exempt an actual waiter.
        if python3 scripts/is-idle-inhibitor.py "$pid"; then
            continue
        fi
        # AGE FLOOR, same 120s the build-orphan branch uses and for the same reason:
        # this recipe exists to find what was LEFT BEHIND, and a sleep that is seconds
        # old was not left behind — it is a live command still doing its job. Without
        # this, the `sleep 5` in the very shell that LAUNCHES a gate trips the gate's
        # own opening bookend. A check that fires on its caller is not a hygiene
        # check, it is a deadlock.
        secs=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
        [ -n "${secs:-}" ] || continue
        [ "$secs" -ge 120 ] 2>/dev/null || continue
        own=$(readlink "/proc/$pid/cwd" 2>/dev/null || true)
        ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        par=""
        if [ -n "${ppid:-}" ] && [ -d "/proc/$ppid" ]; then
            par=$(readlink "/proc/$ppid/cwd" 2>/dev/null || true)
        fi
        for cwd in "$own" "$par"; do
            [ -n "$cwd" ] || continue
            owner_root=""
            for wt in "${worktree_roots[@]}"; do
                case "$cwd" in
                    "$wt"|"$wt"/*) [ "${#wt}" -le "${#owner_root}" ] || owner_root="$wt" ;;
                esac
            done
            if [ "$owner_root" = "$self_root" ]; then
                echo "$pid  (poll-loop waiter in this checkout: $cwd)"
                any=1
                break
            elif [ -n "$owner_root" ]; then
                # A sibling worktree's waiter. Reported for the operator, NOT counted:
                # it is not this caller's to reap and must not fail this caller's gate.
                echo "$pid  (poll-loop waiter in a SIBLING worktree, not yours: $cwd)"
                siblings=1
                break
            fi
        done
    done

    if [ "$any" -eq 0 ]; then
        if [ "$siblings" -eq 1 ]; then
            echo "no stale processes OF YOUR OWN (the runs listed above are live, and theirs)"
        else
            echo "no stale processes"
        fi
    else
        echo "---"
        echo "BEFORE KILLING ANYTHING, confirm ownership:  readlink /proc/<pid>/cwd"
        echo "If the cwd is ANOTHER worktree, that process belongs to another run —"
        echo "it is that run's to reap, not yours; report it."
        exit 1
    fi

# Report every live Kata process.
pgrep-kata:
    #!/usr/bin/env bash
    set -euo pipefail
    any=0
    if stragglers=$(pgrep -x kata 2>/dev/null); then
        echo "$stragglers  (kata)"
        any=1
    fi
    if stragglers=$(pgrep -x kata-worker 2>/dev/null); then
        echo "$stragglers  (kata-worker)"
        any=1
    fi
    if [ "$any" -eq 0 ]; then
        echo "no stale kata processes"
    else
        exit 1
    fi

# Gracefully stop exact-name Kata processes, wait up to 3s, then escalate.
kill-kata:
    #!/usr/bin/env bash
    set -euo pipefail
    killed=0
    for name in kata kata-worker; do
        for pid in $(pgrep -x "$name" 2>/dev/null || true); do
            kill -TERM "$pid" 2>/dev/null || true
            for _ in $(seq 30); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid" 2>/dev/null || true
                sleep 0.2
            fi
            killed=$((killed+1))
        done
    done
    if [ "$killed" -gt 0 ]; then
        echo "killed $killed process(es)"
    else
        echo "no kata processes to kill"
    fi

# ─── Observability runbook ───────────────────────────────────

# Start a local Jaeger all-in-one container for OTLP trace
# ingestion. Prefers docker, falls back to podman. Point the
# `[telemetry]` section of the kata config at it (the echo below
# names the keys). Ports: 16686 UI, 4317 OTLP gRPC, 4318
# OTLP HTTP — all bound to 127.0.0.1 only.
jaeger-up:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v docker >/dev/null 2>&1; then
        engine=docker
    elif command -v podman >/dev/null 2>&1; then
        engine=podman
    else
        echo "ERROR: neither docker nor podman found" >&2
        exit 1
    fi
    if [ -n "$("$engine" ps --filter name=kata-jaeger -q 2>/dev/null)" ]; then
        echo "kata-jaeger already running (via $engine); skipping"
    else
        "$engine" run -d --rm \
            --name kata-jaeger \
            -p 127.0.0.1:16686:16686 \
            -p 127.0.0.1:4317:4317 \
            -p 127.0.0.1:4318:4318 \
            jaegertracing/all-in-one:latest
    fi
    echo
    echo "Jaeger UI : http://127.0.0.1:16686"
    echo "OTLP gRPC : http://127.0.0.1:4317"
    echo
    echo "Next: set [telemetry] in your kata config and run a workflow."
    echo "  export        = \"otlp\""
    echo "  otlp_endpoint = \"http://127.0.0.1:4317\""
    echo "The [telemetry] keys are documented in config/kata.example.toml."

# Stop the kata-jaeger container. No-op if it isn't running.
jaeger-down:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v docker >/dev/null 2>&1 && [ -n "$(docker ps --filter name=kata-jaeger -q 2>/dev/null)" ]; then
        docker stop kata-jaeger
    elif command -v podman >/dev/null 2>&1 && [ -n "$(podman ps --filter name=kata-jaeger -q 2>/dev/null)" ]; then
        podman stop kata-jaeger
    else
        echo "kata-jaeger is not running"
    fi

# ── The development loop ────────────────────────────────────────────────────
# Answers "I changed X — what do I re-run?" and then runs it: different changes
# need completely different re-run sets, and over a hundred recipes all look
# equally plausible. The routing table lives in ONE place —
# docs/development/verification.md, between the `routing:` fences — and
# `just dev-loop-check` (wired into `just gate`) proves it still describes
# reality. See that doc for the traps it routes around.

# Route the current diff to the checks it needs, and RUN them.
verify *paths:
    python3 scripts/dev-loop.py run {{ paths }}

# Same routing, printed and not run.
route *paths:
    python3 scripts/dev-loop.py route {{ paths }}

# Gate guard: the repo's description of its own development loop must be TRUE.
# Six assertions, each with a planted counterfactual in --self-test:
#   A1 every recipe the table names EXISTS;
#   A2 every path glob still matches a tracked file (no dead route);
#   A3 every tracked path is reachable — by the workspace crate that owns it, or
#      by a row; `workflows/`, `scripts/`, `config/`, `docs/`, the justfile and
#      the nextest config belong to no crate, so a row must claim them
#      explicitly, and a path under `crates/`/`bin/` that NO crate owns fails
#      here rather than leaning on the row that claims the territory;
#   A4 every row states a WHY — a rule nobody can audit is not a rule;
#   A5 every `just <recipe>` the doc names IN PROSE exists too — A1 read only
#      the table, and prose here is instruction, not commentary;
#   A6 every recipe the table names is INVOCABLE with the arguments the table
#      gives it. A1 proves only that the NAME resolves: a row naming
#      `workflows-check` — which takes a required argument — would make every
#      `just verify` over a Starlark or engine change die with an argument
#      error instead of a check result.
dev-loop-check:
    python3 -B scripts/test-dev-loop.py
    # It COMPILES NOTHING: every check below is python or bash over the tree, so a
    # docs-only `just verify` and the commit tier's preflight pay no Rust build
    # (`the_preflight_compiles_nothing_and_overlaps_the_build_group` in gate_exclusion
    # refuses a cargo compile reachable from here). The youki pin's refusal cells are
    # `youki-pin-cells`, below `agent-accept`.
    # Every test that takes the per-uid inspection lock must have a suite
    # slow-timeout that outlives the lock's blocking wait, or contention reads as a
    # TIMEOUT instead of the lock's named refusal — which is why this is checked
    # rather than remembered.
    python3 -B scripts/check-inspection-lock-timeouts.py --self-test
    python3 -B scripts/check-inspection-lock-timeouts.py
    # A message literal with its line joins collapsed renders prose with a
    # wall of whitespace mid-sentence, an easy defect to ship and hard to
    # see in review. The check lexes string literals (comments,
    # char and raw strings excluded) and flags a 3+-space run between two
    # prose characters; deliberate alignment carries `// kata-spacing:
    # intentional` on a line the literal touches.
    python3 -B scripts/check-message-whitespace.py --self-test
    python3 -B scripts/check-message-whitespace.py
    python3 -B scripts/test-smoke-discovery.py
    python3 -B scripts/test-regress.py
    python3 -B scripts/check-test-partition.py --self-test
    # The two gate checks that read the run instead of repeating it: the JUnit
    # "ran and passed" check behind agent-accept / test-conformance, and the
    # source-tree guard every tier ends on. Each proves its own refusals here.
    python3 -B scripts/check-junit-ran.py --self-test
    python3 -B scripts/source-tree-guard.py --self-test
    # The coordination scripts' host-free parts, each over scratch repositories and
    # flags; each script's header says what its `--self-test` proves. The four that
    # source scripts/gate-env.sh run with XDG_RUNTIME_DIR under a parent that cannot
    # exist: a self-test that touched the user's real runtime dir, or needed the host to
    # have one, would be refused there and red (each points KATA_RUNTIME_DIR at its own
    # scratch directory before sourcing).
    bash scripts/gate-snapshot.sh --self-test
    bash scripts/prune-target.sh --self-test
    XDG_RUNTIME_DIR=/nonexistent/kata-self-test bash scripts/gate-launch.sh --self-test
    XDG_RUNTIME_DIR=/nonexistent/kata-self-test bash scripts/lane-wait.sh --self-test
    XDG_RUNTIME_DIR=/nonexistent/kata-self-test bash scripts/lanes-prune.sh --self-test
    # The suite recipes' TMPDIR on a tmpfs: each refusal, the run directory's
    # removal (after a TERM too, never under the running suite) and the stale sweep.
    bash scripts/test-tmpfs.sh --self-test
    # The L2 nightly's two pure parts: first-parent bisect over a synthetic repository
    # and the flake-drift JUnit comparison (scripts/nightly.sh runs the second too).
    XDG_RUNTIME_DIR=/nonexistent/kata-self-test bash scripts/nightly.sh --self-test
    # The E9 VM script's host-free parts: the install plan it derives from a README;
    # push-token's refusals of the owner's token file; the API key leaving the
    # environment (nothing it starts inherits it, or any other operator variable);
    # login-anthropic's key refusals; e3-host's refusals (case, agent, funding, out
    # directory, the key only for the anthropic agent); block-providers' loopback-only
    # answer check; the dry-run stand-in provider served on the host's loopback (the
    # plan to a plan request on each family through its own CA only, `done` otherwise,
    # 404 off its path, each request logged); and, driving the real commands over
    # stubbed guest calls, install (reading a scratch repository's committed README, so
    # a reorder reaches its later guest calls), e3-prep and e3-host checking for the
    # guest's forge token before any other guest call, a dead e3-host arm copied out by
    # the EXIT trap without the node's worker secret, and standin-provider refused
    # before any other guest call unless every provider host is on loopback; and
    # push-token, login-anthropic and drop-token, run from one heredoc-fed bash over a
    # fake ssh that drains its stdin, leave the script's later lines to bash while the
    # token and the key still reach the guest.
    bash scripts/e9-vm.sh --self-test
    # The vendored nanocode engine is upstream at the pinned rev plus kata's patch,
    # and the check that says so refuses each planted divergence.
    python3 -B scripts/nanocode-vendor.py --self-test
    just nanocode-vendor-check
    # Fixtures and the committed evidence carry no credential or private data, and the
    # evidence page shows exactly its run records; each check proves its refusals first.
    just evidence-check
    # ADR 0003's checked model: the runner's verdicts and manifest audit against a fake
    # TLC, then the audit of the real manifest (`just model-check-0003` runs TLC).
    python3 -B scripts/model-check.py --self-test
    python3 -B scripts/model-check.py docs/architecture/models/0003 --audit
    python3 scripts/dev-loop.py check --self-test
    python3 scripts/dev-loop.py check

# Refuse credentials, auth headers, bearer/OAuth tokens, cookie values, private session
# data, email addresses and unsanitized provider payloads in the committed evidence and
# the test fixtures (the `Evidence and fixtures` routing row in
# docs/development/verification.md names the scanned set; the script's docstring states
# every rule). Pattern checks only: it verifies nothing against any service. The
# self-test plants one sample per rule. Then refuse an invalid evidence run record, or an
# evidence page (docs/evidence/README.md) whose rendered sections differ from the records.
evidence-check:
    python3 -B scripts/evidence-sanitize.py --self-test
    python3 -B scripts/evidence-sanitize.py check
    python3 -B scripts/evidence-page.py --self-test
    python3 -B scripts/evidence-page.py check

# Rewrite the evidence page's rendered sections from docs/evidence/runs/*/run.toml.
evidence-render:
    python3 -B scripts/evidence-page.py render

# Redact, in place, every value `evidence-check` refuses in the given raw artifacts,
# including inside JSON escaped in a JSONL transcript's strings. Idempotent (its output is
# a fixed point the check accepts); refuses, writing nothing, a symbolic link or a file
# that is not UTF-8.
evidence-sanitize +paths:
    python3 -B scripts/evidence-sanitize.py sanitize {{ paths }}

# Prove a regression test actually catches the bug it was written for.
# AGENTS.md says every bug fix needs a regression test watched failing first;
# this is the mechanism that watches it.
#
#   just regress /tmp/pre-fix 'test(my_new_test)' crates/worker/src/thing.rs
#
# The baseline directory must contain explicit pre-fix copies at the same
# relative paths. Run with exclusive access to those files. SHA256-verified
# backups restore on normal exits, INT and TERM; SIGKILL requires manual recovery.
# Requires identical nonempty test identities and nextest test-failure exit 100.
[positional-arguments]
regress baseline filter +paths:
    #!/usr/bin/env bash
    set -euo pipefail
    exec python3 -B scripts/regress.py "$@"

# ENOSPC WITH 2.9 TB FREE — the per-directory wall, named before it is hit.
#
# Measured on a 3.6 TB ext4 volume: `target/` at 207G, `target/debug/deps` at 129G
# across 1,488,310 directory entries, and the OLDEST entry in it 37.6 hours old
# (`find target/debug/deps -maxdepth 1 -printf '%T+\n' | sort | head -1`). That same
# directory has reached 4,482,673 entries, and the build failed ENOSPC while `df`
# reported terabytes free and `df -i` reported inodes at 2%: ext4's htree index for
# ONE directory was exhausted, not the filesystem. The kernel names the wrong
# subject, so the entire cost of the defect is spent looking at the disk.
#
# This is CHURN, not stale content — the whole 1.49M-entry directory accumulated in
# 37.6 hours (39,578 entries/hour) after a full sweep — so there is nothing to
# age-expire and no automatic remedy this recipe could safely take. It WARNS,
# names the subject, names the remedy, and exits 0 either way: a hard refusal that
# blocks work on a host with 2.9 TB free is worse than the defect it prevents.
#
# Runs its own `--self-test` first (~0.1s) and then the scan (2.21s over 16 churn
# directories, measured). The self-test drives the real scanner over synthetic
# roots and proves it FIRES over the line, counts truly, reaches nested per-recipe
# target dirs, stays quiet under the line, REPORTS a directory it cannot read
# instead of counting it as zero, and exits 0 in every arm — a check nobody has
# seen fire proves nothing, and neither does a check that greens by observing
# nothing.
htree-preflight *root:
    bash scripts/htree-preflight.sh --self-test
    bash scripts/htree-preflight.sh {{ root }}

# Can this host run the required steps at all? Answers in seconds instead of 25+ minutes,
# with each host requirement written down rather than learned by failing.
#
# TWO VERDICTS, REPORTED SEPARATELY, because they are two different questions: the
# tree-level gate is host-independent; the containment lane is entirely a statement
# about this kernel. An operator on a host that can gate but cannot certify containment
# needs to be told exactly that, not handed one word.
#
# Plus ONE ADVISORY, which is deliberately not a third verdict — see the block at the
# bottom of the body. "Can this host finish" is exactly the question the htree wall
# answers wrongly, so this is where it belongs; but a directory approaching a limit is
# a thing to schedule, not a thing to be blocked by, so it never touches the exit code.
host-check:
    #!/usr/bin/env bash
    set -uo pipefail
    bad=0
    echo "== gate + gate-push tree checks (host-independent, both tiers) =="
    # 1. PATH entries that are not directories — a stale entry (a tool's
    #    vanished per-session cache dir, say) would inject the cwd into a build.
    #    Report it HERE, where a human is looking.
    # NO PIPELINE HERE: `... | while ...` runs the loop in a SUBSHELL, so `bad=1`
    # set inside it is discarded and a PATH-only failure would print the problem
    # and still exit 0 — a check that reports and passes is worse than no check.
    IFS=':' read -r -a _path_entries <<< "$PATH"
    for p in "${_path_entries[@]}"; do
        [ -n "$p" ] || continue
        if [ ! -d "$p" ]; then
            echo "  PATH entry is not a directory: $p"
            bad=1
        fi
    done
    # 2. the dated audit toolchain fmt pins to.
    tc=$(tr -d ' \n' < .config/audit-nightly 2>/dev/null || true)
    toolchains="$(rustup toolchain list 2>/dev/null || true)"
    if [ -n "$tc" ] && ! grep -q -- "$tc" <<<"$toolchains"; then
        echo "  MISSING toolchain $tc — install it:  rustup toolchain install $tc"
        bad=1
    fi
    # 3. a stale attachment descriptor makes `kata run --wait` misreport, and
    #    `footprint-check` (which boots a real installed main) is in the gate.
    if [ -e "$HOME/.local/state/kata/main-attachment.json" ] && ! pgrep -x kata >/dev/null 2>&1; then
        echo "  STALE $HOME/.local/state/kata/main-attachment.json with no live kata — remove it"
        bad=1
    fi
    # 4. the gate's irreducible host tools. These are not designed away like
    #    model CLIs: Python drives repository checks and `just lint` requires the
    #    pinned ruff.
    #
    #    A missing-host-tool claim is only found by RUNNING `just test` with a
    #    scrubbed PATH, not by asserting the property.
    if ! command -v python3 >/dev/null 2>&1; then
        echo "  MISSING python3 — repository checks require it"
        bad=1
    fi
    if ! just _ruff-pin; then
        bad=1
    fi
    #    jj: kata-workflow's `workspace_effect` cells read the repository through
    #    the jj CLI (`jj_cli_workspace_names`, `jj_cli_log` in
    #    crates/workflow/tests/workspace_effect.rs), a reader sharing no code with
    #    kata, and `.expect()` the spawn. The floor is the jj-lib version Cargo.lock
    #    pins: jj promises a newer CLI reads an older repository, not the reverse,
    #    and the cells' repositories are written by that library. Only jj 0.46.0
    #    reading them is measured.
    jj_floor="$(awk '$0 == "name = \"jj-lib\"" { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)"
    if [ -z "$jj_floor" ]; then
        echo "  UNREADABLE jj-lib version in Cargo.lock — the jj CLI floor cannot be named"
        bad=1
    elif ! command -v jj >/dev/null 2>&1; then
        echo "  MISSING jj — the workspace_effect cells (crates/workflow/tests/workspace_effect.rs)"
        echo "      spawn the jj CLI (>= $jj_floor, the jj-lib Cargo.lock pins) and .expect() the spawn."
        echo "      'nix develop' provides it (pkgs.jujutsu)."
        bad=1
    else
        jj_have="$(jj --version | awk '{print $2}')"
        if [ "$(printf '%s\n%s\n' "$jj_floor" "$jj_have" | sort -V | head -n 1)" != "$jj_floor" ]; then
            echo "  OLD jj $jj_have first on PATH ($(command -v jj)); the workspace_effect cells read"
            echo "      repositories jj-lib $jj_floor writes, so they need jj >= $jj_floor."
            bad=1
        fi
    fi
    # 5. disk fill on every filesystem a gate writes: the checkout's `target/` (and
    #    its `.kata/`), `$TMPDIR` (every smoke data dir, and the soak, measurement and
    #    live rigs' tempdirs; the suite's are on the test tmpfs, item 8) and `$HOME`
    #    (the installed main's state). Refused at >= 80% used.
    #
    #    WHY A REFUSAL, NOT AN ADVISORY: every authoritative SQLite plane commits at
    #    synchronous=FULL, and the commit's fsync runs WHILE the write lock is held,
    #    so a waiting writer sits behind the device flush, bounded by the workspace
    #    5 s busy_timeout (BUSY_TIMEOUT_MS, crates/core/src/store/sqlite_backed.rs).
    #    On 2026-10-19 the root QLC NVMe at 88% full stalled those flushes past 5 s:
    #    the gate went red on rotating TIMEOUTs and a `cas insert (inline) failed:
    #    database is locked` — a product refusal that names SQLite, not the disk.
    #    At 40% the same disk's fsync p99 is 1.3 ms.
    #
    #    WHY 80: the one measured failure is 88%. The persistent targets are bounded
    #    by age (scripts/prune-target.sh), and the snapshot's summary.txt records each
    #    target's size, so the headroom 80 leaves below the fill at which flushes
    #    collapsed is read off the summary, not argued from one past figure. It is one
    #    observation on one drive class, not a device model: a smaller or
    #    non-QLC filesystem gets the same percentage, conservatively.
    #
    #    REFUSED SET: a filesystem holding one of those three paths (the nearest
    #    existing ancestor when the path does not exist yet) whose `df` Use% is >= 80,
    #    and a path whose filesystem `df` cannot report (unobserved is not healthy).
    disk_fill_refuse_pct=80
    declare -A _disk_fill_seen=()
    for _disk_path in target "${TMPDIR:-/tmp}" "$HOME"; do
        _probe="$_disk_path"
        while [ ! -e "$_probe" ]; do _probe="$(dirname -- "$_probe")"; done
        if ! _df="$(df --output=pcent,target -- "$_probe" 2>&1)"; then
            echo "  UNREADABLE disk fill for $_disk_path: $_df"
            bad=1
            continue
        fi
        read -r _pcent _mount <<<"$(tail -n 1 <<<"$_df")"
        _pcent="${_pcent%\%}"
        if ! [[ "$_pcent" =~ ^[0-9]+$ ]]; then
            echo "  UNREADABLE disk fill for $_disk_path: df reports '$_pcent' for $_mount"
            bad=1
            continue
        fi
        [ -z "${_disk_fill_seen[$_mount]:-}" ] || continue
        _disk_fill_seen[$_mount]=1
        if [ "$_pcent" -ge "$disk_fill_refuse_pct" ]; then
            echo "  DISK FULL $_mount is ${_pcent}% used (refused at >= ${disk_fill_refuse_pct}%), and a gate"
            echo "      writes there ($_disk_path). A filling flash disk stalls the fsync each SQLite commit"
            echo "      holds its write lock through, past the 5 s busy_timeout ('database is locked',"
            echo "      rotating TIMEOUTs). Free space on $_mount until it is below ${disk_fill_refuse_pct}% —"
            echo "      stale worktree target/ dirs and /tmp/.tmp* residue are the usual bulk — then re-run."
            bad=1
        fi
    done
    # 6. Yama's ptrace scope. The toolhost's kill cells (bin/kata-toolhost/tests/
    #    toolhost.rs, `Traced::seize`) PTRACE_SEIZE a descendant to make a zombie
    #    the toolhost cannot reap; a scope of 2 or 3 refuses that, so 'just test'
    #    would hard-FAIL them. No Yama at all leaves an ancestor's ptrace allowed.
    scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)
    if [ "$scope" -gt 1 ]; then
        echo "  kernel.yama.ptrace_scope is $scope — the toolhost's kill cells need 0 or 1"
        echo "      (sysctl kernel.yama.ptrace_scope=1; scope 3 needs a reboot to lower)"
        bad=1
    fi
    # 7. the Code Mode interpreter's syscall filter (`_code-mode-filter`): every Code
    #    Mode cell in kata-code-mode-host's and kata-agent-nanocode's suites runs in an
    #    interpreter that installs it, so a kernel that refuses it reds the commit tier.
    if ! just _code-mode-filter; then
        bad=1
    fi
    # 8. the test tmpfs: the suite recipes (`test`, `test-crate`, `test-one-crate`,
    #    `test-one`, `youki-pin-cells`) source scripts/test-tmpfs.sh, which refuses a host
    #    without one (its header states the refused set) rather than putting the suite's
    #    tempdirs back on a disk. `--check` writes nothing.
    if ! bash scripts/test-tmpfs.sh --check; then
        bad=1
    fi
    if [ "$bad" -eq 0 ]; then
        echo "  ok — PATH clean, audit toolchain present, no stale descriptor,"
        echo "       every filesystem the gate writes is below ${disk_fill_refuse_pct}% used,"
        echo "       python3 + the pinned ruff + jj present, Yama ptrace_scope ${scope} (<= 1),"
        echo "       the kernel installs Code Mode's interpreter filter (TSYNC, kill_process),"
        echo "       and the test tmpfs is there with room for a suite run."
        echo "       No model CLI is needed by EITHER"
        echo "       TIER: no spawn of the product they reach boots a config that"
        echo "       declares one — the push tier's 'footprint-check' boots a shell-only"
        echo "       config (scripts/footprint-config.sh). The guard"
        echo "       'the_gate_boots_no_config_that_needs_a_model_cli' (bin/kata-eval/"
        echo "       tests/gate_exclusion.rs) fails the gate if a new one appears."
    else
        echo "  BLOCKED — 'gate'/'gate-push' will fail on the above."
    fi

    echo
    echo "== gate-containment (this kernel's containment capabilities) =="
    just _containment-preconditions
    containment=$?

    echo
    echo "== advisory: build-directory headroom (NOT a verdict) =="
    # DELIBERATELY does not touch `bad` and cannot change this recipe's exit code.
    # The failure it anticipates is ENOSPC-with-terabytes-free: one directory's ext4
    # htree index filling while `df` and `df -i` both look healthy. That is squarely
    # "can this host finish", which is why it is reported here — but it is a thing to
    # schedule a sweep for, not a thing to be blocked by, and a hard refusal on a host
    # with 2.9 TB free would be worse than the defect. The script exits 0 on every
    # successful scan (its `--self-test` pins that in both arms), so this line cannot
    # red a host-check even if the warning fires.
    bash scripts/htree-preflight.sh

    echo
    if [ "$bad" -eq 0 ] && [ "$containment" -eq 0 ]; then
        echo "host-check: ok — this host can run BOTH required tiers."
        exit 0
    fi
    [ "$bad" -eq 0 ] && echo "host-check: the 'gate'/'gate-push' tree checks can run here." || echo "host-check: the 'gate'/'gate-push' tree checks are BLOCKED."
    if [ "$containment" -eq 0 ]; then
        echo "host-check: 'gate-containment' can run here."
    else
        echo "host-check: 'gate-containment' is BLOCKED — a skip is a FAILURE in that lane,"
        echo "  so this host cannot produce a containment green until the lines above are fixed."
    fi
    exit 1
