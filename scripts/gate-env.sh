#!/usr/bin/env bash
#
# The coordination paths and the unattended PATH, spelled ONCE. Sourced, never executed,
# by every entry point that coordinates a gate, the nightly and lane work on one host:
# scripts/gate-launch.sh, scripts/lane-wait.sh, scripts/lanes-prune.sh, scripts/nightly.sh
# and `just nightly-install`.
#
# THE PATHS ARE KEYED ON THE MAIN CHECKOUT — the directory holding the repository's common
# git dir — never on the worktree a caller runs in, so a lane worktree anywhere on disk,
# the snapshot worktree and the checkout all find the same flag and lock:
#
#   KATA_RUNTIME_DIR      $XDG_RUNTIME_DIR/kata<main checkout path with '/' as '-'>. Per-user
#                         tmpfs: a flag a dead session left does not outlive a reboot, and
#                         neither does the directory, so sourcing this file creates it
#                         (`kata_runtime_dir_ensure`) before anyone flocks the lock in it.
#   KATA_QUIET_BOX        an L1 gate holds it (scripts/gate-launch.sh) from before it drains
#                         the box until its snapshot ends; lanes start no build or test
#                         while it is held (scripts/lane-wait.sh), and the nightly waits.
#   KATA_NIGHTLY_MARK     the L2 nightly holds it from its start (before it waits for a
#                         busy box) to its exit; lanes start nothing while it is held, so
#                         the in-flight work drains and the nightly can start; a gate
#                         launch waits for it.
#   KATA_LIVE_SUITE_LOCK  flock(1) over every live suite, L1 snapshot and L2 run of this
#                         user: whoever holds it owns the per-uid installed main and the
#                         timing-sensitive steps.
#
# A flag is HELD while it exists and either names no pid or names a live one: a flag left
# by a SIGKILLed holder (its pid gone) is stale and holds nothing (`kata_flag_held`). The
# holders write their pid; a maintainer's bare `touch` holds until removed.
#
# Each variable may be set by the caller first (the self-tests point them at scratch
# paths); unset, it is derived here.
#
# THE RUNTIME DIRECTORY is owner-only. Sourcing this file creates KATA_RUNTIME_DIR when
# nothing is at the path, with one `mkdir -m 0700` (never `-p`: its parent, logind's
# per-user runtime directory, must already exist), and then refuses — the sourcing script
# exits 1, naming the path and the recourse — unless what is there is a directory, not a
# symlink (dangling or not), that this uid owns at mode exactly 0700 (a setgid or sticky
# bit is refused too). So an absent parent, a plain file, a symlink, another owner and a
# group- or other-accessible mode are each refused. scripts/lane-wait.sh's self-test pins
# each of these in a cell of its own but ANOTHER OWNER: building that case needs a second
# uid (root), so its refusal — the uid half of the `stat` comparison — is not pinned by
# any test, only by reading. `kata_flag_take` creates nothing itself: it re-runs
# `kata_runtime_dir_ensure`, the one creator. An existing directory is refused and
# left as it is, never chmod'ed: a directory another account made or can write is not
# this user's to repair silently (the posture of scripts/test-tmpfs.sh's per-user
# parent). The mode is judged on what is there after the create, so no check precedes a
# create it could race. The derived path's parent is logind's 0700 runtime directory of
# this uid, so no other account can swap the path after the check; an overridden
# KATA_RUNTIME_DIR's parent is the caller's to choose.
#
# THE UNATTENDED PATH. A systemd unit's environment is not a login shell's, and a gate
# launched by an agent harness inherits whatever store paths that harness happened to
# carry — the class that produced false reds when a hand-kept PATH lost the pinned ruff.
# `just nightly-install` records the durable part of a maintainer's shell PATH once
# (`kata_durable_path`) in KATA_UNATTENDED_ENV, the nightly unit's EnvironmentFile; the
# gate launcher runs its gate on the same file (`kata_unattended_path`). `just host-check`,
# the first stage of every snapshot, then names any tool that PATH lacks.

_kata_gate_env_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
KATA_MAIN_CHECKOUT="${KATA_MAIN_CHECKOUT:-$(dirname -- "$(git -C "$_kata_gate_env_root" rev-parse --path-format=absolute --git-common-dir)")}"
KATA_RUNTIME_DIR="${KATA_RUNTIME_DIR:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/kata${KATA_MAIN_CHECKOUT//\//-}}"
KATA_QUIET_BOX="${KATA_QUIET_BOX:-$KATA_RUNTIME_DIR/QUIET_BOX}"
KATA_NIGHTLY_MARK="${KATA_NIGHTLY_MARK:-$KATA_RUNTIME_DIR/NIGHTLY}"
KATA_LIVE_SUITE_LOCK="${KATA_LIVE_SUITE_LOCK:-$KATA_RUNTIME_DIR/live-suite.lock}"
KATA_UNATTENDED_ENV="${KATA_UNATTENDED_ENV:-${XDG_CONFIG_HOME:-$HOME/.config}/kata-nightly/env}"
unset _kata_gate_env_root

# Create KATA_RUNTIME_DIR owner-only when absent; refuse anything else (the refused set
# is in the header). Exit status only, the reason on stderr.
kata_runtime_dir_ensure() {
    local dir="$KATA_RUNTIME_DIR" found
    [ -e "$dir" ] || [ -L "$dir" ] || mkdir -m 0700 -- "$dir" 2>/dev/null || true
    found="$(stat -c '%u %a' -- "$dir" 2>/dev/null)" || found=""
    if [ -L "$dir" ] || [ ! -d "$dir" ] || [ "$found" != "$(id -u) 700" ]; then
        echo "gate-env: REFUSED — the runtime dir '$dir' must be a directory owned by uid $(id -u) at mode 0700;" >&2
        echo "  it is $( [ -L "$dir" ] && echo 'a symlink' || { [ -e "$dir" ] && [ ! -d "$dir" ] && echo 'not a directory'; } || echo "'${found:-absent}' (uid mode)")." >&2
        echo "  The gate's flags and the live-suite lock live in it. Remove it if it is yours (or" >&2
        echo "  \`chmod 700\` it), or point KATA_RUNTIME_DIR (or XDG_RUNTIME_DIR) at a directory" >&2
        echo "  that is." >&2
        return 1
    fi
}
kata_runtime_dir_ensure || exit 1

# Is flag $1 held? Exit status only.
kata_flag_held() {
    local pid
    [ -e "$1" ] || return 1
    pid="$(head -c 32 "$1" 2>/dev/null | tr -dc 0-9)"
    [ -z "$pid" ] && return 0
    kill -0 "$pid" 2>/dev/null
}

# Hold flag $1 for this process: write our pid (or $2) into it. The runtime dir is
# ensured again first — `kata_runtime_dir_ensure` is its one creator — so a dir that
# vanished since sourcing comes back owner-only, and one widened since is refused (exit
# 1, nothing written). An overridden flag outside it needs its directory to exist.
kata_flag_take() {
    kata_runtime_dir_ensure || return 1
    echo "${2:-$$}" >"$1"
}

# The durable entries of $PATH: absolute, existing directories outside /run/user/ (tmpfs —
# a version manager's per-shell dirs vanish on reboot, and `host-check` then refuses
# "PATH entry is not a directory").
kata_durable_path() {
    local entry durable=""
    local -a entries
    IFS=':' read -r -a entries <<<"$PATH"
    for entry in "${entries[@]}"; do
        case "$entry" in
            /run/user/*) continue ;;
            /*) [ -d "$entry" ] || continue ;;
            *) continue ;;
        esac
        durable="${durable:+$durable:}$entry"
    done
    printf '%s\n' "$durable"
}

# The PATH `just nightly-install` recorded; fails, naming the recourse, when there is none.
kata_unattended_path() {
    local path
    path="$(sed -n 's/^PATH=//p' "$KATA_UNATTENDED_ENV" 2>/dev/null | tail -1)"
    if [ -z "$path" ]; then
        echo "gate-env: no unattended PATH recorded in $KATA_UNATTENDED_ENV; run \`just nightly-install\` from the main checkout in a shell whose PATH runs \`just host-check\` green" >&2
        return 1
    fi
    printf '%s\n' "$path"
}
