#!/usr/bin/env bash
#
# Shared OCI-node provisioning for the justfile live smokes (sourced, never
# executed). Three facts an `oci` node's config and process environment must
# carry, none of which a smoke recipe may silently skip:
#
#   1. `[node] environment` — a realised Nix closure; `kata serve` refuses
#      `node_environment_undeclared` without it. `oci_smoke_inject_environment`
#      writes the declaration into a derived config (usually a `kata init`
#      product); `oci_smoke_store_path` imports a directory (the kata tool
#      tree, a rustup toolchain — anything that is not already in the store)
#      so its programs can be declared like any other closure root.
#   2. `KATA_EXTERNAL_*` — the certified capsule provider. The route has no
#      PATH fallback, so `oci_smoke_provision_provider` drives the
#      operator verb (`kata sandbox install-external-provider`) the same way
#      `crates/test-utils/src/live.rs::provision_live_provider` does, and the
#      caller exports the three variables it prints.
#   3. A DELEGATED scope — rootless youki containers own a cgroup only inside
#      one, so `serve` runs under `systemd-run`. `oci_smoke_delegate_args`
#      is the argv prefix `delegated_scope::systemd_run_args` renders; keep
#      the two in agreement.
#
# THE ENVIRONMENT PINS ARE THE LIVE RIG'S PINS — the same busybox/getent/git
# store paths `crates/test-utils/src/live.rs::LIVE_ENVIRONMENT_STORE_PATHS`
# declares, re-spelled here because a bash recipe cannot read a Rust const.
# A pin that drifts fails on the store's answer at boot
# (`node_environment_nix_unavailable` / `store does not contain`), which is
# the behaviour the pin exists to exercise; a recipe whose pack needs more
# programs adds roots via the realisation calls its own body performs.

set -euo pipefail

# The checkout this helper belongs to: its flake.lock pins every `nixpkgs#…` realised here.
OCI_SMOKE_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# busybox + getent + git-minimal — identical strings to
# `LIVE_ENVIRONMENT_STORE_PATHS`. busybox carries `sh`, `printf`, `cat`,
# `grep`, `test`; getent covers the DNS arm; git-minimal covers stages that
# `requires = ["git"]` or exec it.
OCI_SMOKE_BUSYBOX="/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0"
OCI_SMOKE_GETENT="/nix/store/shwr4cipfr4ypvi7vjr20y4k6ziyzkqy-getent-getent-netbsd-static-x86_64-unknown-linux-musl-9.2"
OCI_SMOKE_GIT="/nix/store/3ba67bl61l0dxp1x4m9waqnvm5n5bkcs-git-minimal-2.55.0"

# The argv prefix `delegated_scope::systemd_run_args` renders, with
# `RuntimeMaxSec` a parameter: each recipe passes a bound above its own
# watchdog so the kernel — not the shell — owns a hung scope's residue.
# `delegated_scope.rs` documents why the ceiling is kernel-side.
oci_smoke_delegate_args() {
    local max_secs="${1:-330}"
    printf '%s\n' --user --scope --quiet -p Delegate=yes -p "RuntimeMaxSec=$max_secs" --
}

# `nix store add-path` a prepared directory and print the store path: the way
# a smoke declares programs that are not already store paths (the built
# `kata` binary, a rustup toolchain dir). Refuses a missing directory; the
# store's own verdict on the copy is the error an operator sees.
oci_smoke_store_path() {
    local dir="$1"
    [ -d "$dir" ] || {
        echo "oci-smoke-node: cannot add-path a directory that is not there: $dir" >&2
        return 1
    }
    nix store add-path "$dir"
}

# Realise each named flake attr and print its store path, one per line — the
# way a recipe declares a program it cannot pin: pins exist only where the
# live rig pins them, and every other program (`cargo`, `just`, `python3`) is
# derived on the host that runs the recipe, from the nixpkgs revision this
# checkout's flake.lock pins (`--inputs-from`), never the floating registry
# channel — a verdict must not move with the channel, and nothing is downloaded
# to resolve it. A dynamically-linked host binary CANNOT serve here regardless
# of where it is copied: the capsule rootfs carries only the declared closure,
# so a binary whose interpreter is `/lib64/ld-linux` has no loader in the guest
# — only a Nix-closed or a static binary can exec. `nix build` answers the
# cached path when the closure already exists.
oci_smoke_nix_paths() {
    nix build --no-link --print-out-paths --inputs-from "$OCI_SMOKE_REPO_ROOT" "$@"
}

# The in-capsule `kata`: the STATIC musl build of this tree (the caller runs
# `cargo build -p kata --bin kata --target x86_64-unknown-linux-musl` first, as it
# builds the static `kata-toolhost`), laid out as the flake's package lays out its
# tree — `bin/kata` beside `share/kata/{workflows,examples,kata-factory}`, which
# `WorkflowLibrary::default_roots` resolves relative to the binary — under `$2`,
# then added to the store and printed, so a recipe declares it like any other
# closure root. A static binary needs no loader in the guest, and no Nix build of
# the workspace is paid for it (the flake package is L2's `flake-checks`).
oci_smoke_kata_tool() {
    local repo="$1" dir="$2" built="$1/target/x86_64-unknown-linux-musl/debug/kata"
    [ -x "$built" ] || {
        echo "oci-smoke-node: the static kata is not built at $built — cargo build -p kata --bin kata --target x86_64-unknown-linux-musl first" >&2
        return 1
    }
    mkdir -p "$dir/bin" "$dir/share/kata"
    cp "$built" "$dir/bin/kata"
    cp -r "$repo/workflows/std" "$dir/share/kata/workflows"
    cp -r "$repo/workflows/examples" "$dir/share/kata/examples"
    cp -r "$repo/workflows/kata-factory" "$dir/share/kata/kata-factory"
    oci_smoke_store_path "$dir"
}

# Write the declaration a model agent needs under `oci` into a config's
# `[agents.<name>]` block: `adapter` and `credential`. The block must exist
# already — a recipe that invents a whole agent section instead of extending
# the derived one drifts on every other field. `$1` = config path, `$2` =
# agent name, `$3` = adapter (`nanocode_openai` or `nanocode_anthropic`),
# `$4` = credential inline table. Existing `adapter`/`credential` lines in the
# block are replaced, so a recipe may re-declare.
oci_smoke_agent_capsule() {
    local cfg="$1" name="$2" adapter="$3" credential_toml="$4"
    grep -q "^\[agents\.$name\]$" "$cfg" || {
        echo "oci-smoke-node: no [agents.$name] table in $cfg — extend the derived block, do not invent it" >&2
        return 1
    }
    python3 - "$cfg" "$name" "$adapter" "$credential_toml" <<'PY'
import sys

cfg, name, adapter, credential_toml = sys.argv[1:5]
with open(cfg) as fh:
    lines = fh.read().splitlines(keepends=True)
header = f"[agents.{name}]\n"
try:
    start = lines.index(header)
except ValueError:
    sys.exit(f"oci-smoke-node: {header.strip()} not found as a line in {cfg}")
end = len(lines)
for i in range(start + 1, len(lines)):
    line = lines[i]
    if line.startswith("["):
        end = i
        break
block = [
    line
    for line in lines[start + 1 : end]
    if not line.startswith(("adapter =", "credential ="))
]
addition = f'adapter = "{adapter}"\ncredential = {credential_toml}\n'
with open(cfg, "w") as fh:
    fh.write("".join(lines[: start + 1]) + addition + "".join(block) + "".join(lines[end:]))
PY
}

# Render one `[node] environment = { .. }` TOML line over the given store
# paths (each gets its `bin/` on `path_prepend`). ONE line — a TOML inline
# table cannot span lines, and the config is re-parsed.
oci_smoke_environment_block() {
    local label="$1"; shift
    local store_paths="" path_prepend="" root
    for root in "$@"; do
        store_paths+="\"$root\", "
        path_prepend+="\"$root/bin\", "
    done
    store_paths="${store_paths%, }"
    path_prepend="${path_prepend%, }"
    printf 'environment = { label = "%s", system = "x86_64-linux", nixpkgs_attribute = "nixpkgs#pkgsStatic.busybox", store_paths = [%s], path_prepend = [%s], integrity_policy = { verify = "nar_hash_only", sigs_needed = 0, required_signers = [], allow_unsigned_content_addressed = true, verify_contents_at_declare = true } }\n' \
        "$label" "$store_paths" "$path_prepend"
}

# Insert the environment declaration (and an optional `egress_allow` line)
# immediately under `[node]` in a derived config. `$1` = config path, `$2` =
# label, remaining args = store paths. `OCI_SMOKE_EGRESS_ALLOW` (space-joined
# `host:port` authorities) appends `egress_allow = [..]` after the
# environment line when non-empty — a pack authoring `net = "host"` is
# refused `egress_undeclared` on an empty set.
oci_smoke_inject_environment() {
    local cfg="$1" label="$2"; shift 2
    local block egress_line=""
    block="$(oci_smoke_environment_block "$label" "$@")"
    if [ -n "${OCI_SMOKE_EGRESS_ALLOW:-}" ]; then
        local list="" authority
        for authority in $OCI_SMOKE_EGRESS_ALLOW; do
            list+="\"$authority\", "
        done
        egress_line="egress_allow = [${list%, }]"
    fi
    grep -q '^\[node\]$' "$cfg" || {
        echo "oci-smoke-node: no [node] table in $cfg — cannot inject the environment it needs" >&2
        return 1
    }
    python3 - "$cfg" "$block" "$egress_line" <<'PY'
import sys

cfg, block, egress_line = sys.argv[1], sys.argv[2], sys.argv[3]
with open(cfg) as fh:
    text = fh.read()
idx = text.find("[node]\n")
if idx < 0:
    sys.exit("oci-smoke-node: [node] header not found as a line")
insert_at = idx + len("[node]\n")
# `$(oci_smoke_environment_block)` strips the block's own trailing newline —
# re-terminate it before anything is appended or `egress_allow` would land
# on the environment line and fail the TOML parse.
addition = block.rstrip("\n") + "\n"
if egress_line:
    addition += egress_line + "\n"
with open(cfg, "w") as fh:
    fh.write(text[:insert_at] + addition + text[insert_at:])
PY
}

# Provision the certified youki provider into a by-hash store under `$1` and
# export the three `KATA_EXTERNAL_*` variables the capsule route resolves.
# `$2` = the `kata` binary; `$3` = the directory the provider binaries were
# built into (`target/debug` or `target/release`). Mirrors
# `provision_live_provider`: `ip` is copied when the host has one — an
# `Egress`-free capsule never opens it, and an `Egress` capsule without it
# refuses `provider_unresolved` at admission.
oci_smoke_provision_provider() {
    local workdir="$1" kata_bin="$2" bin_dir="$3"
    local source="$workdir/provider-src" store="$workdir/provider-store"
    mkdir -p "$source"
    local name built
    for name in kata-provider-youki kata-oci-hook; do
        built="$bin_dir/$name"
        [ -x "$built" ] || {
            echo "oci-smoke-node: $name not built at $built — cargo build -p $name first" >&2
            return 1
        }
        cp "$built" "$source/"
    done
    local candidate
    for candidate in /usr/bin/ip /usr/sbin/ip /bin/ip /sbin/ip; do
        if [ -f "$candidate" ]; then
            cp "$candidate" "$source/ip"
            break
        fi
    done
    local out address
    # `KATA_EXTERNAL_PROVIDER_STORE` is the input as well as the export — the
    # verb creates the store where it names.
    if ! out="$(KATA_EXTERNAL_PROVIDER_STORE="$store" \
        "$kata_bin" sandbox install-external-provider --name youki "$source" 2>&1)"; then
        echo "oci-smoke-node: install-external-provider failed: $out" >&2
        return 1
    fi
    address="$(printf '%s\n' "$out" | sed -n 's/^export KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS=//p')"
    [ -n "$address" ] || {
        echo "oci-smoke-node: install-external-provider printed no content address: $out" >&2
        return 1
    }
    export KATA_EXTERNAL_PROVIDER_STORE="$store"
    export KATA_EXTERNAL_EXECUTION_PROVIDER="youki"
    export KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS="$address"
}
