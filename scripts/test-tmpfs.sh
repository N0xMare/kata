#!/usr/bin/env bash
#
# The workspace test run's TMPDIR, on a tmpfs the recipe owns.
#
# ─ THE DEFECT THIS REMOVES ─
#
# On 2026-11-11 an L1 went red on one TIMEOUT that ran in 2 s alone. Summed per crate
# against the previous green L1, the crates whose cells commit SQLite and write
# repositories slowed 7-21x (kata-api x17, kata-workflow x13.5, kata-vcs x7) while the
# CPU-only crates stayed at x0.7-1.2. Nothing in the code had changed: the QLC NVMe
# holding `/tmp` had exhausted its SLC cache under a full relink (160 MB/s at 100%
# util, w_await ~250 ms), and every test tempdir — `tempfile::tempdir()` reads
# `TMPDIR`, and so does every `std::env::temp_dir()` — sat behind that device. A cell's
# wall clock measured the disk's cache state, not the code.
#
# ─ WHAT IT DOES ─
#
# Sourced by the nextest recipes (`test`, `test-crate`, `test-one-crate`, `test-one`,
# `youki-pin-cells`) before their `cargo nextest run` line:
#
#   1. refuses unless the root (`KATA_TEST_TMPFS`, default `$XDG_RUNTIME_DIR`) is a
#      tmpfs with at least MIN_FREE_MIB available, this uid owns it, and kata's
#      owner-only publication would accept every directory on its path;
#   2. refuses unless the per-user parent `<root>/kata-test-<uid>` is a real directory
#      this uid owns at mode 0700 (the sourced form creates it when absent; `--check`
#      writes nothing);
#   3. removes every run directory in that parent whose owning shell is gone;
#   4. creates `<parent>/<pid>.<starttime>` at 0700 for this shell and exports it as
#      `TMPDIR` (owner-only: kata's immutable SQLite inspection refuses a shared-mode
#      temp root);
#   5. removes it when the shell exits — after the foreground command has ended, never
#      under it: TERM, INT and HUP are trapped, and bash runs a trap only once its
#      foreground child is done (the self-test drives the TERM arm). So a TERM sent to
#      the recipe's shell alone stops nothing early: the suite runs to its end first.
#      A signal to the process group (Ctrl-C, `kill -- -<pgid>`, `timeout`) reaches the
#      suite itself and stops it.
#
# REFUSED SET of steps 1-2, each with exit 1 and the reason on stderr: no root (neither
# variable set); a root that is not a plain absolute path (relative, or with a `.` or
# `..` component); a root that is not a directory; a root whose `stat -f` type is not
# `tmpfs` (ramfs and every disk filesystem included); a tmpfs with less than
# MIN_FREE_MIB available to this uid; a root or ancestor that is a symlink; a root this
# uid does not own, or that group or other can write; an ancestor that is neither
# root's nor this uid's with no group/other write, nor root's sticky 1777 `/tmp` or
# `/var/tmp` (kata's owner-only publication rule, `owner_only_publication.rs`, for an
# existing ancestor — `/dev/shm` is refused here, as kata refuses it); a parent that is
# a symlink, not a directory, not owned by this uid, or not mode 0700. Nothing falls
# back to a disk directory: a silent fallback would put the run's timing back on the
# disk's cache state without saying so. The recourse is in the message.
#
# ─ WHY THE RUNTIME DIRECTORY, NOT /dev/shm ─
#
# Measured: with TMPDIR under `/dev/shm`, 78 `kata` cells fail, every one on kata's own
# owner-only publication refusing the path ("ancestor uid 0 mode 1777 ... it is not /tmp
# or /var/tmp; another account could replace the path beneath it"). That refusal is the
# product's, and right: `/dev/shm` is a shared sticky directory kata does not
# recognise. logind's `$XDG_RUNTIME_DIR` is a tmpfs this uid owns at 0700 under
# root-owned 0755 ancestors, which the same check accepts.
#
# ─ THE SIZE BOUND ─
#
# The bound on what a run may write is the tmpfs's own size (the kernel answers ENOSPC
# past it); logind sizes `$XDG_RUNTIME_DIR` at `RuntimeDirectorySize`, 10% of RAM by
# default. No per-run cap is enforced. The floor refuses a run that would start with
# less headroom than the suite's measured peak with a margin, which also keeps that
# headroom for the session's own sockets and locks in the same directory.
#
# ─ WHAT STAYS ON DISK ─
#
# A cell whose claim is about a real disk names its directory explicitly instead of
# reading TMPDIR — `operational_write_measurement` takes `CARGO_TARGET_TMPDIR`, because
# its number IS the disk's write latency. docs/development/verification.md ("Test
# TMPDIR") lists them and says why the rest of the suite's durability cells are
# indifferent to the backing store.
#
# Usage:
#   source scripts/test-tmpfs.sh        in a recipe body, ahead of `cargo nextest run`
#   bash scripts/test-tmpfs.sh --check  the precondition alone, writing nothing (`just host-check`)
#   bash scripts/test-tmpfs.sh --self-test
#
# Env:
#   KATA_TEST_TMPFS               the tmpfs root (default $XDG_RUNTIME_DIR)
#   KATA_TEST_TMPFS_MIN_FREE_MIB  override MIN_FREE_MIB (the self-test's seam)

# The floor, in MiB available on the root before a run starts: the workspace suite's
# measured peak (`just test` on 128 test threads, verification.md's "Test TMPDIR") with a
# margin for growth and for the other recipes that may share the root.
_KATA_TMPFS_MIN_FREE_MIB=2048

_kata_tmpfs_root() {
    printf '%s' "${KATA_TEST_TMPFS:-${XDG_RUNTIME_DIR:-}}"
}

_kata_tmpfs_parent() {
    printf '%s/kata-test-%s' "$(_kata_tmpfs_root)" "$(id -u)"
}

# The start time (clock ticks since boot, `/proc/<pid>/stat` field 22) of process $1, or
# nothing when it is gone. Field 2 may hold spaces and parentheses, so the fields are
# counted from after its LAST `)`.
_kata_tmpfs_starttime() {
    local stat rest fields
    stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 0
    rest="${stat##*) }"
    read -r -a fields <<<"$rest"
    printf '%s' "${fields[19]:-}"
}

# The recourse every refusal of steps 1-2 ends on.
_kata_tmpfs_recourse() {
    echo "  Point KATA_TEST_TMPFS at a tmpfs directory this uid owns at 0700, under ancestors" >&2
    echo "  only root or this uid can write, with ${1} MiB free (docs/development/verification.md," >&2
    echo "  'Test TMPDIR'). logind's XDG_RUNTIME_DIR is one." >&2
}

# Step 1's path rule, kata's owner-only publication rule for an EXISTING directory
# (`owner_only_publication.rs`): the root and each of its ancestors, `/` included, is
# no symlink; the root is this uid's with no group/other write; an ancestor is this
# uid's or root's with no group/other write, or root's sticky 1777 `/tmp` or `/var/tmp`.
# The root is held to the narrower rule because the parent is created in it.
_kata_tmpfs_path_check() {
    local root="$1" min="$2" uid prefix component path owner mode
    local -a components paths=(/)
    uid="$(id -u)"
    IFS=/ read -r -a components <<<"${root#/}"
    prefix=""
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        prefix="$prefix/$component"
        paths+=("$prefix")
    done
    for path in "${paths[@]}"; do
        if [ -L "$path" ]; then
            echo "test-tmpfs: REFUSED — '$path' on the test TMPDIR root's path is a symlink;" >&2
            echo "  kata's owner-only publication opens every component without following one." >&2
            _kata_tmpfs_recourse "$min"
            return 1
        fi
        read -r owner mode < <(stat -c '%u %a' -- "$path" 2>/dev/null) || true
        mode=$(( 8#${mode:-7777} ))
        if [ "$path" = "${paths[-1]}" ]; then
            [ "$owner" = "$uid" ] && [ $(( mode & 8#022 )) -eq 0 ] && continue
            printf 'test-tmpfs: REFUSED — the test TMPDIR root %s has uid %s mode %o; it must be
' "'$path'" "${owner:-?}" "$mode" >&2
            echo "  this uid's ($uid) with no group or other write: another account could replace" >&2
            echo "  the run's TMPDIR beneath it, and kata's owner-only publication refuses that." >&2
            _kata_tmpfs_recourse "$min"
            return 1
        fi
        if { [ "$owner" = "$uid" ] || [ "$owner" = 0 ]; } && [ $(( mode & 8#022 )) -eq 0 ]; then
            continue
        fi
        if [ "$owner" = 0 ] && [ "$mode" -eq $(( 8#1777 )) ] \
            && { [ "$path" = /tmp ] || [ "$path" = /var/tmp ]; }; then
            continue
        fi
        printf 'test-tmpfs: REFUSED — %s, an ancestor of the test TMPDIR root, has uid %s mode %o.
' "'$path'" "${owner:-?}" "$mode" >&2
        echo "  kata's owner-only publication accepts an ancestor only when root or this uid owns" >&2
        echo "  it and no group or other account can write it, or it is root's sticky /tmp or" >&2
        echo "  /var/tmp; under any other, 'kata' cells fail on that refusal." >&2
        _kata_tmpfs_recourse "$min"
        return 1
    done
    return 0
}

# Steps 1-2: the refusals. Prints the reason on stderr and returns 1. With `create`
# (the sourced form) an absent parent is made; without it (`--check`) nothing is
# written and an absent parent passes, since the first run creates it under a root the
# path rule has just accepted as this uid's.
_kata_tmpfs_check() {
    local mode_arg="${1:-}" root parent min avail_blocks block_size fs_type avail_mib owner_mode
    root="$(_kata_tmpfs_root)"
    parent="$(_kata_tmpfs_parent)"
    min="${KATA_TEST_TMPFS_MIN_FREE_MIB:-$_KATA_TMPFS_MIN_FREE_MIB}"
    case "$min" in
        '' | *[!0-9]*)
            echo "test-tmpfs: KATA_TEST_TMPFS_MIN_FREE_MIB='$min' is not a count of MiB." >&2
            return 1
            ;;
    esac
    if [ -z "$root" ]; then
        echo "test-tmpfs: REFUSED — no test TMPDIR root: neither KATA_TEST_TMPFS nor XDG_RUNTIME_DIR is set." >&2
        echo "  The test recipes put every test tempdir on a tmpfs, so that no test's SQLite" >&2
        echo "  commit waits on a disk's flush. Run from a login session (logind sets" >&2
        echo "  XDG_RUNTIME_DIR), or:" >&2
        _kata_tmpfs_recourse "$min"
        return 1
    fi
    if [[ "$root" != /* || "$root/" == */./* || "$root/" == */../* ]]; then
        echo "test-tmpfs: REFUSED — the test TMPDIR root '$root' is not a plain absolute path." >&2
        _kata_tmpfs_recourse "$min"
        return 1
    fi
    if [ ! -d "$root" ]; then
        echo "test-tmpfs: REFUSED — the test TMPDIR root '$root' is not a directory." >&2
        echo "  The test recipes put every test tempdir on a tmpfs, so that no test's SQLite" >&2
        echo "  commit waits on a disk's flush." >&2
        _kata_tmpfs_recourse "$min"
        return 1
    fi
    read -r avail_blocks block_size fs_type < <(stat -f -c '%a %S %T' -- "$root" 2>/dev/null) || true
    if [ "$fs_type" != "tmpfs" ]; then
        echo "test-tmpfs: REFUSED — the test TMPDIR root '$root' is ${fs_type:-unreadable}, not tmpfs." >&2
        echo "  Test tempdirs on a disk put every SQLite commit in the suite behind that" >&2
        echo "  disk's flush, and a cell's timing then measures the disk (2026-11-11: 7-21x" >&2
        echo "  on the fsync-heavy crates)." >&2
        _kata_tmpfs_recourse "$min"
        return 1
    fi
    avail_mib=$(( avail_blocks * block_size / 1048576 ))
    if [ "$avail_mib" -lt "$min" ]; then
        echo "test-tmpfs: REFUSED — the tmpfs at '$root' has ${avail_mib} MiB available; a test run" >&2
        echo "  needs ${min} MiB (the suite's measured peak with a margin). Free it, or:" >&2
        _kata_tmpfs_recourse "$min"
        return 1
    fi
    _kata_tmpfs_path_check "$root" "$min" || return 1
    if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then
        [ "$mode_arg" = create ] || return 0
        mkdir -m 0700 -- "$parent" 2>/dev/null || true
    fi
    owner_mode="$(stat -c '%u %a' -- "$parent" 2>/dev/null)" || owner_mode=""
    # `-L` is belt and braces: `stat` without `-L` reports a symlink's own 777, which
    # the mode comparison refuses anyway; the clause names the case in the message.
    if [ -L "$parent" ] || [ ! -d "$parent" ] || [ "$owner_mode" != "$(id -u) 700" ]; then
        echo "test-tmpfs: REFUSED — '$parent' must be a directory owned by uid $(id -u) at mode 0700;" >&2
        echo "  it is $( [ -L "$parent" ] && echo 'a symlink' || echo "'${owner_mode:-absent}' (uid mode)")." >&2
        echo "  Every run's TMPDIR lives under it. Remove it if it is yours; otherwise:" >&2
        _kata_tmpfs_recourse "$min"
        return 1
    fi
    return 0
}

# Step 3: remove every `<pid>.<starttime>` run directory whose owner is gone. A name of
# any other shape is left alone. Sealed (0555) trees are opened first.
_kata_tmpfs_sweep() {
    local parent entry name pid start
    parent="$(_kata_tmpfs_parent)"
    for entry in "$parent"/*; do
        [ -d "$entry" ] && [ ! -L "$entry" ] || continue
        name="${entry##*/}"
        [[ "$name" =~ ^([0-9]+)\.([0-9]+)$ ]] || continue
        pid="${BASH_REMATCH[1]}"
        start="${BASH_REMATCH[2]}"
        [ "$(_kata_tmpfs_starttime "$pid")" = "$start" ] && continue
        _kata_tmpfs_remove "$entry"
    done
}

_kata_tmpfs_remove() {
    chmod -R u+rwX -- "$1" 2>/dev/null || true
    rm -rf -- "$1" 2>/dev/null || true
    if [ -e "$1" ]; then
        echo "test-tmpfs: WARNING — could not remove '$1'; it holds RAM until removed." >&2
    fi
}

_kata_tmpfs_leave() {
    [ -n "${_KATA_TMPFS_RUN:-}" ] && _kata_tmpfs_remove "$_KATA_TMPFS_RUN"
}

# Steps 1-5, for the sourcing shell.
_kata_tmpfs_enter() {
    local start
    _kata_tmpfs_check create || return 1
    _kata_tmpfs_sweep
    start="$(_kata_tmpfs_starttime "$$")"
    [ -n "$start" ] || { echo "test-tmpfs: cannot read /proc/$$/stat" >&2; return 1; }
    _KATA_TMPFS_RUN="$(_kata_tmpfs_parent)/$$.$start"
    if ! mkdir -m 0700 -- "$_KATA_TMPFS_RUN"; then
        echo "test-tmpfs: REFUSED — cannot create the run directory '$_KATA_TMPFS_RUN'." >&2
        _KATA_TMPFS_RUN=""
        return 1
    fi
    trap '_kata_tmpfs_leave' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    trap 'exit 129' HUP
    export TMPDIR="$_KATA_TMPFS_RUN"
}

# ── self-test ────────────────────────────────────────────────────────────────
#
# Drives the real functions over a scratch root on the real tmpfs, and proves:
#   1. each refusal of the REFUSED SET fires, by its own message; the path rule accepts
#      root's sticky /tmp as an ancestor and refuses /dev/shm; and `--check` on an
#      accepted root writes nothing;
#   2. the SOURCED form refuses too — under `/proc` and under a disk directory whose
#      0700 parent already exists, so no parent-creation failure can stand in for the
#      refusal — and the command after `source` never runs;
#   3. a sourcing shell gets a 0700 TMPDIR on tmpfs under the parent, its command's
#      exit status survives, and the directory (a sealed 0555 tree in it included) is
#      gone after the shell exits;
#   4. a TERM to the shell alone, sent once its foreground `sleep` is a running child,
#      leaves the directory in place while that child runs, then removes it, exiting 143;
#   5. the sweep removes a directory whose owner is gone or whose pid was reused, and
#      keeps a live owner's directory and names of other shapes.
_kata_tmpfs_self_test() {
    local scratch disk="" sticky="" shm="" fails=0 out rc dir candidate
    local self="${BASH_SOURCE[0]}"
    scratch="$(mktemp -d "$(_kata_tmpfs_root)/kata-test-selftest.XXXXXX")" || {
        echo "test-tmpfs --self-test: cannot create a scratch root on $(_kata_tmpfs_root)" >&2
        return 1
    }
    # Arm 2's disk directory: the first writable non-tmpfs one of these.
    for candidate in /var/tmp "$(cd "$(dirname "$self")/.." && pwd)/target" "${HOME:-}"; do
        [ -n "$candidate" ] && [ -d "$candidate" ] && [ -w "$candidate" ] || continue
        [ "$(stat -f -c %T -- "$candidate" 2>/dev/null)" != tmpfs ] || continue
        disk="$(mktemp -d "$candidate/kata-test-tmpfs-selftest.XXXXXX")" && break
        disk=""
    done
    # Arm 1's sticky anchors: a directory of this uid's under root's sticky /tmp (which
    # kata accepts as an ancestor) and under /dev/shm (which it refuses).
    sticky="$(mktemp -d /tmp/kata-test-tmpfs-selftest.XXXXXX 2>/dev/null)" || sticky=""
    shm="$(mktemp -d /dev/shm/kata-test-tmpfs-selftest.XXXXXX 2>/dev/null)" || shm=""
    # shellcheck disable=SC2064 # the paths are fixed now, on purpose.
    trap "chmod -R u+rwX '$scratch' ${disk:+'$disk'} 2>/dev/null; rm -rf '$scratch' ${disk:+'$disk'} ${sticky:+'$sticky'} ${shm:+'$shm'}" EXIT
    fail() { printf '  FAIL: %b\n' "$*" >&2; fails=$((fails + 1)); }
    refused() { # label env-assignments... — expects exit 1 and the label in stderr
        local label="$1"; shift
        out="$(env "$@" bash "$self" --check 2>&1)" && rc=0 || rc=$?
        if [ "$rc" -ne 1 ] || ! grep -q -F -- "$label" <<<"$out"; then
            fail "expected a refusal naming '$label' (rc 1); got rc $rc:\n$out"
        fi
    }

    # 1. the refusals
    refused "neither KATA_TEST_TMPFS nor XDG_RUNTIME_DIR" -u KATA_TEST_TMPFS -u XDG_RUNTIME_DIR
    refused "is not a plain absolute path" KATA_TEST_TMPFS="relative/root"
    refused "is not a plain absolute path" KATA_TEST_TMPFS="$scratch/../${scratch##*/}"
    refused "is not a directory" KATA_TEST_TMPFS="$scratch/absent"
    refused "is proc, not tmpfs" KATA_TEST_TMPFS=/proc
    refused "a test run" KATA_TEST_TMPFS="$scratch" KATA_TEST_TMPFS_MIN_FREE_MIB=999999999999
    refused "not a count" KATA_TEST_TMPFS="$scratch" KATA_TEST_TMPFS_MIN_FREE_MIB=4g
    refused "the test TMPDIR root '/dev/shm' has uid 0 mode 1777" \
        KATA_TEST_TMPFS=/dev/shm KATA_TEST_TMPFS_MIN_FREE_MIB=0
    mkdir -m 0770 "$scratch/open"
    refused "the test TMPDIR root '$scratch/open' has uid $(id -u) mode 770" \
        KATA_TEST_TMPFS="$scratch/open" KATA_TEST_TMPFS_MIN_FREE_MIB=0
    mkdir -m 0700 "$scratch/open/root"
    refused "'$scratch/open', an ancestor of the test TMPDIR root, has uid $(id -u) mode 770" \
        KATA_TEST_TMPFS="$scratch/open/root" KATA_TEST_TMPFS_MIN_FREE_MIB=0
    mkdir -m 0700 "$scratch/fresh"
    ln -s "$scratch/fresh" "$scratch/alias"
    refused "'$scratch/alias' on the test TMPDIR root's path is a symlink" \
        KATA_TEST_TMPFS="$scratch/alias" KATA_TEST_TMPFS_MIN_FREE_MIB=0
    # The path rule's sticky-anchor clause, driven directly (here /tmp need not be a
    # tmpfs, so `--check` would refuse it first on its type).
    if [ -z "$sticky" ] || [ -z "$shm" ]; then
        fail "cannot create the sticky-anchor directories under /tmp ('$sticky') and /dev/shm ('$shm')"
    else
        out="$(_kata_tmpfs_path_check "$sticky" 0 2>&1)" \
            || fail "a 0700 directory of this uid's under root's sticky /tmp was refused:\n$out"
        out="$(_kata_tmpfs_path_check "$shm" 0 2>&1)" && rc=0 || rc=$?
        if [ "$rc" -ne 1 ] || ! grep -q -F -- "'/dev/shm', an ancestor of the test TMPDIR root, has uid 0 mode 1777" <<<"$out"; then
            fail "a directory under /dev/shm was not refused for its sticky ancestor (rc $rc):\n$out"
        fi
    fi
    out="$(KATA_TEST_TMPFS="$scratch/fresh" KATA_TEST_TMPFS_MIN_FREE_MIB=0 bash "$self" --check 2>&1)" \
        || fail "a fresh 0700 tmpfs root with no parent yet was refused:\n$out"
    [ ! -e "$scratch/fresh/kata-test-$(id -u)" ] || fail "--check wrote the parent under '$scratch/fresh'"
    local parent
    parent="$scratch/kata-test-$(id -u)"
    mkdir -m 0755 "$scratch/elsewhere"
    rm -rf "$parent"
    ln -s "$scratch/elsewhere" "$parent"
    refused "it is a symlink" KATA_TEST_TMPFS="$scratch" KATA_TEST_TMPFS_MIN_FREE_MIB=0
    rm "$parent"
    mkdir -m 0755 "$parent"
    refused "'$(id -u) 755'" KATA_TEST_TMPFS="$scratch" KATA_TEST_TMPFS_MIN_FREE_MIB=0
    chmod 0700 "$parent"
    out="$(KATA_TEST_TMPFS="$scratch" KATA_TEST_TMPFS_MIN_FREE_MIB=0 bash "$self" --check 2>&1)" \
        || fail "a tmpfs root with a 0700 parent was refused:\n$out"

    # 2. the sourced form refuses, and the command after `source` never runs
    local ran="$scratch/sourced-ran" root
    if [ -z "$disk" ]; then
        fail "no writable non-tmpfs directory (/var/tmp, target/, \$HOME) to source under"
    else
        mkdir -m 0700 "$disk/kata-test-$(id -u)"
    fi
    for root in /proc ${disk:+"$disk"}; do
        rm -f "$ran"
        out="$(KATA_TEST_TMPFS="$root" KATA_TEST_TMPFS_MIN_FREE_MIB=0 bash -c '
            set -euo pipefail
            source "$1"
            : >"$2"' _ "$self" "$ran" 2>&1)" && rc=0 || rc=$?
        if [ "$rc" -ne 1 ] || ! grep -q -F -- "not tmpfs" <<<"$out"; then
            fail "sourcing under '$root' did not refuse it as not tmpfs (rc $rc, expected 1):\n$out"
        fi
        [ ! -e "$ran" ] || fail "the command after \`source\` ran under the refused root '$root'"
    done
    if [ -n "$disk" ] && [ -n "$(ls -A "$disk/kata-test-$(id -u)")" ]; then
        fail "a refused source created a run directory on the disk under '$disk'"
    fi

    # 3. a sourcing shell: TMPDIR, exit status, removal
    out="$(KATA_TEST_TMPFS="$scratch" KATA_TEST_TMPFS_MIN_FREE_MIB=0 bash -c '
        set -euo pipefail
        source "$1"
        printf "%s %s %s\n" "$TMPDIR" "$(stat -f -c %T "$TMPDIR")" "$(stat -c %a "$TMPDIR")"
        mkdir -p "$TMPDIR/sealed/inner" && : >"$TMPDIR/sealed/inner/f" && chmod -R a-w "$TMPDIR/sealed"
        exit 7' _ "$self" 2>&1)" && rc=0 || rc=$?
    [ "$rc" -eq 7 ] || fail "the command's exit status 7 came back as $rc:\n$out"
    read -r dir type mode <<<"$out"
    [[ "$dir" =~ ^"$parent"/[0-9]+\.[0-9]+$ ]] || fail "TMPDIR '$dir' is not a run directory under $parent"
    [ "$type" = tmpfs ] || fail "TMPDIR is on '$type', not tmpfs"
    [ "$mode" = 700 ] || fail "TMPDIR has mode $mode, not 700"
    [ ! -e "$dir" ] || fail "the run directory '$dir' (with a sealed tree) survived its shell"

    # 4. TERM to the shell alone: removal waits for the foreground command. The TERM
    #    goes only once the shell's `sleep` child has exec'd (its comm reads `sleep`):
    #    a TERM before then is handled at once, correctly, and proves nothing here. The
    #    test ends the `sleep` itself, so no clock decides the verdict.
    local marker="$scratch/term-dir" pid child="" polls=0 c kids
    KATA_TEST_TMPFS="$scratch" KATA_TEST_TMPFS_MIN_FREE_MIB=0 bash -c '
        set -euo pipefail
        source "$1"
        printf "%s" "$TMPDIR" >"$2"
        sleep 300' _ "$self" "$marker" 2>"$scratch/term-arm.err" &
    pid=$!
    while [ -z "$child" ] && [ "$polls" -lt 100 ] && kill -0 "$pid" 2>/dev/null; do
        kids=()
        read -r -a kids <"/proc/$pid/task/$pid/children" 2>/dev/null || :
        for c in "${kids[@]}"; do
            [ "$(cat "/proc/$c/comm" 2>/dev/null)" = sleep ] && child="$c"
        done
        [ -n "$child" ] || { sleep 0.05; polls=$((polls + 1)); }
    done
    dir="$(cat "$marker" 2>/dev/null)"
    if [ -z "$child" ] || [ -z "$dir" ]; then
        fail "within 5 s the TERM arm's shell did not both report its TMPDIR ('$dir') and run its sleep (pid '$child'):\n$(cat "$scratch/term-arm.err" 2>/dev/null)"
        kill -TERM "$pid" 2>/dev/null
        [ -z "$child" ] || kill -TERM "$child" 2>/dev/null
        wait "$pid" 2>/dev/null
    else
        kill -TERM "$pid"
        sleep 0.5
        [ -d "$dir" ] || fail "a TERM to the shell removed '$dir' while its foreground command ran"
        kill -0 "$child" 2>/dev/null || fail "the foreground sleep $child ended under a TERM sent to its shell alone"
        kill -TERM "$child" 2>/dev/null
        wait "$pid" && rc=0 || rc=$?
        [ "$rc" -eq 143 ] || fail "a TERMed run exited $rc, not 143"
        [ ! -e "$dir" ] || fail "a TERMed run left '$dir' behind"
    fi

    # 5. the sweep
    local mine dead reused other
    mine="$parent/$$.$(_kata_tmpfs_starttime "$$")"
    dead="$parent/4194305.1"     # above PID_MAX_LIMIT: no live process has this pid
    reused="$parent/$$.1"        # a live pid with another start time: a reused pid
    other=("$parent/not-a-run" "$parent/4194305" "$parent/4194305.x" "$parent/4194305.1.2")
    mkdir -p "$mine" "$dead/sealed" "$reused" "${other[@]}"
    chmod a-w "$dead/sealed"
    KATA_TEST_TMPFS="$scratch" _kata_tmpfs_sweep
    [ -d "$mine" ] || fail "the sweep removed a live owner's directory"
    [ ! -e "$dead" ] || fail "the sweep kept a dead owner's directory (a sealed tree in it)"
    [ ! -e "$reused" ] || fail "the sweep kept a directory whose pid was reused"
    for c in "${other[@]}"; do
        [ -d "$c" ] || fail "the sweep removed '${c##*/}', which is not a run directory's name"
    done

    if [ "$fails" -ne 0 ]; then
        echo "test-tmpfs --self-test: $fails failure(s)" >&2
        return 1
    fi
    echo "test-tmpfs --self-test: ok — 13 refusals, the sticky anchors, the sourced refusal, the run directory's life, TERM, the sweep."
}

if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    _kata_tmpfs_enter || exit 1
    return 0
fi

set -uo pipefail
case "${1:-}" in
    --check)
        _kata_tmpfs_check || exit 1
        echo "test-tmpfs: ok — $(_kata_tmpfs_root) is a tmpfs this uid owns, with >= ${KATA_TEST_TMPFS_MIN_FREE_MIB:-$_KATA_TMPFS_MIN_FREE_MIB} MiB available, on a path kata publishes under."
        ;;
    --self-test)
        _kata_tmpfs_self_test
        ;;
    *)
        echo "usage: source scripts/test-tmpfs.sh | bash scripts/test-tmpfs.sh --check | --self-test" >&2
        exit 2
        ;;
esac
