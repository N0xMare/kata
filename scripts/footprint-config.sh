#!/usr/bin/env bash
#
# Derive the shell-only config the gate boots, from `config/kata.example.toml`.
#
# WHY THIS EXISTS
# ---------------
# `just gate` is HOST-INDEPENDENT BY CONSTRUCTION, and the gate steps that boot
# or spawn the product must boot only the config the step exercises. Booting
# the example config verbatim breaks that property twice over: it declares
# `[agents.default]`/`[agents.reviewer]`/`[agents.gate]` model entries a
# footprint or shell-stage step never selects, and it declares no
# `[node] environment`, so a verbatim boot is refused
# `node_environment_undeclared` — a boot refusal, not a footprint finding.
#
# Dropping those entries is safe for what those steps EXERCISE. For
# `footprint-check` the floors are the release binary size (config-independent),
# the boot RSS of the main once its API accepts, and a ready-time budget —
# no declared agent entry is launched at boot either way (a model turn runs
# only when a stage dispatches one). Everything the RSS
# floor actually watches — `[runtime]` dispatch
# concurrency, `[workers]`, the supervised-node transport, `[api]`, prometheus
# `[telemetry]`, the `[containment]` policy — is untouched, and the ceiling is
# a ~5x shape guard, not a tripwire.
#
# `[agents.shell]` is kept explicitly: the packs these steps run select
# `agent = "shell"` stages, and under the `oci` route a stage selecting a
# label with no `[agents.<label>]` entry is `adapter_undeclared` at check.
# `kata init` writes the same `[agents.shell]` block, so the shape booted here
# is a shape the product genuinely ships, not a synthetic minimum.
#
# `oci` IS THE ONLY ENGINE, and it is what this config boots. The
# `[node] environment` an `oci` node is refused without
# (`node_environment_undeclared`) is declared over one real store path: the
# statically-linked busybox closure the live OCI rigs pin
# (`crates/workflow/tests/oci_stage_live.rs`'s `BUSYBOX`). The derivation is
# host-free — it emits the path the same way an operator declares theirs and
# never probes the store, so it runs on hosts with no Nix at all. A host where the closure
# is absent sees the bind refuse `node_environment_nix_unavailable` /
# `store does not contain` at BOOT, naming the realise command — exactly the
# operator-facing behaviour the pin exists to exercise.
#
# DERIVED, NOT COMMITTED. A committed `config/kata.footprint.toml` would be a
# hand-maintained twin of the file whose `[runtime]`/`[workers]`/`[telemetry]`
# values are exactly what the RSS floor measures, and the drift would be silent
# — the floor keeps passing while measuring a shape nobody ships. Deriving makes
# that drift impossible. Making `config/kata.example.toml` itself shell-only is
# excluded: it over-declares on purpose (its own header says why), and `just
# serve` boots it by default.
#
# THE SCRIPT VERIFIES ITS OWN OUTPUT, and that is not decoration. The keys are
# patched with literal `sed` expressions, and `sed` exits 0 when an expression
# matches nothing. Only `bind` would fail loudly on its own (the recipe's
# readiness poll waits on the port). The other three would fail SILENTLY:
# reformat `data_dir = "~/.kata/data"` to `data_dir="~/.kata/data"`, bump the
# metrics port off 9400, or change `jj_repo` off `".."` — all ordinary edits to
# a 300-line commented example — and the caller would boot a main pointed at the
# operator's live `~/.kata/data`, binding the host's 9400, op-log-GC-sweeping
# whatever `.jj` sat next to the config. That is the exact host-dependence this
# script exists to delete, so the check below reads the patched values — and the
# environment declaration's — BACK out of the derived TOML and refuses unless
# each equals what was emitted. A substitution that matches nothing is a loud
# failure at derivation time, naming the key.
#
# It is also the ONE predicate for "this config declares exactly [agents.shell]".
# The caller must not re-implement it: a line-oriented `grep -E '^\[agents\.'`
# and a TOML-key check are different predicates over one artifact — they
# disagree on an `[agents.shell.env]` sub-table and on an inline
# `agents.shell = {}` — and two predicates that agree today are
# a drift waiting to happen. Callers run this script and trust its exit code.
#
# Usage: footprint-config.sh <data_dir> <api_port> <metrics_port> <jj_repo> [source_config]
#   Writes the derived TOML to stdout. `source_config` defaults to
#   `config/kata.example.toml` and exists so the regression tests can drive the
#   derivation over fixtures that provoke each failure mode.
set -euo pipefail

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 <data_dir> <api_port> <metrics_port> <jj_repo> [source_config]" >&2
    exit 2
fi

data_dir="$1"
api_port="$2"
metrics_port="$3"
jj_repo="$4"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_config="${5:-$here/../config/kata.example.toml}"

if [ ! -f "$source_config" ]; then
    echo "footprint-config.sh: FAIL — source config not found: $source_config" >&2
    exit 1
fi

# The one store path the declared environment is over — the same pin the live
# OCI cells name (`crates/workflow/tests/oci_stage_live.rs`'s `BUSYBOX`). Keep
# them in agreement: a pin that drifts fails the gate on the store's answer,
# not on a guess.
busybox="/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0"

environment_block="environment = { label = \"footprint-gate\", system = \"x86_64-linux\", nixpkgs_attribute = \"nixpkgs#pkgsStatic.busybox\", store_paths = [\"$busybox\"], path_prepend = [\"$busybox/bin\"], integrity_policy = { verify = \"nar_hash_only\", sigs_needed = 0, required_signers = [], allow_unsigned_content_addressed = true, verify_contents_at_declare = true } }"

# `metrics_bind` and `jj_repo` are patched for the same reason `bind` is: both
# reach OUTSIDE this run's tempdir otherwise. A busy 9400 is only a soft
# degradation (the recorder and its thread are silently dropped), so an
# unpatched port would quietly change the shape being measured; and `jj_repo`
# resolves relative to the CONFIG FILE's directory, which for a `mktemp -d`
# config is `/tmp` — so boot would open, and op-log-GC-sweep, whatever `/tmp/.jj`
# happens to be on the host.
derived="$(
    sed -e "s#data_dir = \"~/.kata/data\"#data_dir = \"$data_dir\"#" \
        -e "s|^\[node\]|&\n$environment_block|" \
        -e "s#bind = \"127.0.0.1:8400\"#bind = \"127.0.0.1:$api_port\"#" \
        -e "s#^metrics_bind  *= \"127.0.0.1:9400\"#metrics_bind  = \"127.0.0.1:$metrics_port\"#" \
        -e "s#^jj_repo = \"\\.\\.\"#jj_repo = \"$jj_repo\"#" \
        "$source_config" \
    | awk '
        # Drop every `[agents.*]` table except the shell agent, up to the next
        # table header. The column-0 `^\[` boundary is what makes this safe: the
        # only bracket-bearing lines inside those blocks are comments (e.g.
        # `# [[pricing.models]]`), which never start at column 0.
        #
        # The shell arm matches `[agents.shell]` AND `[agents.shell.<sub>]`. An
        # exact `$0 != "[agents.shell]"` test looks equivalent and is not: it
        # drops every SUB-TABLE of the shell agent (`[agents.shell.env]`, …)
        # while the caller still sees exactly one `[agents.*]` line and one
        # `agents` key, so the boot would silently measure a shell agent
        # configured differently from the one the product ships — the same
        # silent drift deriving is supposed to make impossible.
        /^\[/ { drop = ($0 ~ /^\[agents\./ && $0 !~ /^\[agents\.shell(\.|\])/) }
        !drop
    '
)"

# Read the patched values — and the environment declaration — BACK out of the
# parsed result, and pin the agent table, before a single byte reaches stdout.
# See the header: every one of these was a silent no-op away from booting
# against host state.
printf '%s\n' "$derived" | python3 -c '
import sys, tomllib

want = dict(zip(
    ("node.data_dir", "api.bind", "telemetry.metrics_bind", "vcs.jj_repo"),
    sys.argv[1:5],
))
busybox = sys.argv[5]
busybox_bin = busybox + "/bin"

try:
    cfg = tomllib.loads(sys.stdin.read())
except Exception as exc:  # noqa: BLE001 - message is the whole point
    sys.exit(f"footprint-config.sh: FAIL - derived config is not valid TOML: {exc}")

def lookup(path):
    cur = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

problems = []
for path, expected in want.items():
    got = lookup(path)
    if got != expected:
        problems.append(
            f"  {path} = {got!r}, expected {expected!r} — the substitution for "
            f"this key matched NOTHING in the source config (its spacing or its "
            f"default value changed), so the derived config still points at host state"
        )

# The `[node] environment` declaration `node_environment_undeclared` refuses
# without must be the one emitted above, read back by value.
env = lookup("node.environment")
if not isinstance(env, dict):
    problems.append(
        "  node.environment is absent — an `oci` node without it refuses "
        "`node_environment_undeclared` at boot"
    )
else:
    store_paths = env.get("store_paths")
    if store_paths != [busybox]:
        problems.append(
            f"  node.environment.store_paths = {store_paths!r}, expected "
            f"[{busybox!r}] — the environment insertion matched nothing or declared "
            f"a different closure"
        )
    path_prepend = env.get("path_prepend")
    if path_prepend != [busybox_bin]:
        problems.append(
            f"  node.environment.path_prepend = {path_prepend!r}, expected "
            f"[{busybox_bin!r}]"
        )

agents = cfg.get("agents")
if not isinstance(agents, dict) or sorted(agents) != ["shell"]:
    names = sorted(agents) if isinstance(agents, dict) else agents
    problems.append(
        f"  [agents] declares {names!r}, expected exactly [\"shell\"] — the steps "
        f"that boot this config run shell stages only, any other entry is a model "
        f"agent they never select, and a config without [agents.shell] is not the "
        f"shape `kata init` writes."
    )
# The label decides the entry: [agents.shell] is the shell route, and the kata
# config parse refuses any key under it (shell_agent_block_keys), so there is no
# backend field left here to check.

if problems:
    sys.exit("footprint-config.sh: FAIL - the derived config is wrong:\n" + "\n".join(problems))
' "$data_dir" "127.0.0.1:$api_port" "127.0.0.1:$metrics_port" "$jj_repo" "$busybox"

printf '%s\n' "$derived"
