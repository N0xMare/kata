#!/usr/bin/env bash
# Can a concurrent reader see a TORN `state.json` while `youki start` saves `running`?
#
#   scripts/youki-state-tear-probe.sh <youki-binary> [delay-microseconds]
#
# The question `nix/youki-0.7.0-atomic-state-save.patch` answers. youki 0.7.0's
# `State::save` truncated `state.json` in place and `Container::start` releases the
# init before it saves `running`, so `youki kill` / `state` / `list` could open a
# 0-byte document there. This probe holds that save open on purpose: it runs `youki
# start` under strace with EVERY `write(2)` delayed (`delay_enter`), so the release
# and the state document each take <delay> to land, and it reads the container's state
# inside the second delay three ways:
#
#   1. the FILE itself, with `wc -c` and `jq` — no youki code involved;
#   2. `youki state <id>`; and
#   3. `youki kill <id> SIGTERM` — the reader kata's teardown races.
#
# Every write is delayed, not a path-filtered one, because the patched save writes a
# pid-named temporary file (`state.json.<pid>.tmp`) whose name strace cannot be told
# in advance; the trace (`-y`, so each fd prints its path) shows which write was the
# state document. The probe refuses a run whose trace does not show the state document
# written inside the window it read in, so a timing slip cannot pass for INTACT.
#
# Verdict, last line: `INTACT` (exit 0) when all three readers saw a complete document,
# `TORN` (exit 1) when any one did not, `UNPROVEN` (exit 2) when the window was not
# observed. Measured on 2026-10-30: TORN on the 0.7.0 pin built without the patch
# (gs3ykqgl…), INTACT on the pin built with it.
#
# Host requirements: a static `busybox` (`BUSYBOX`, default /usr/bin/busybox), strace,
# jq, and a youki that may create a rootless container here. On a host with
# `kernel.apparmor_restrict_unprivileged_userns = 1` that is the binary the installed
# profile names; to measure a CANDIDATE pin before its profile is installed, set
# `YOUKI_PROBE_AA_PROFILE=youki` and every youki call runs through `aa-exec -p youki`
# (an unconfined user may change into any loaded profile — nothing on the host is
# written). It runs inside a delegated user scope bounded by `RuntimeMaxSec`, like the
# live rigs, so a failed teardown cannot outlive it.
set -uo pipefail

youki=${1:?usage: youki-state-tear-probe.sh <youki-binary> [delay-microseconds]}
delay=${2:-1500000}
busybox=${BUSYBOX:-/usr/bin/busybox}

if [ -z "${YOUKI_PROBE_IN_SCOPE:-}" ]; then
    exec systemd-run --user --scope --quiet -p Delegate=yes -p RuntimeMaxSec=120 \
        --setenv=YOUKI_PROBE_IN_SCOPE=1 -- env YOUKI_PROBE_IN_SCOPE=1 "$0" "$@"
fi

aa=()
[ -n "${YOUKI_PROBE_AA_PROFILE:-}" ] && aa=(aa-exec -p "$YOUKI_PROBE_AA_PROFILE" --)
y() { "${aa[@]}" "$youki" "$@"; }

work=$(mktemp -d "${TMPDIR:-/tmp}/youki-tear-probe.XXXXXX")
root=$work/root
bundle=$work/bundle
id=tear-probe-$$
# youki places the container in its OWN transient scope (`youki-<id>.scope`), outside
# the bounded scope this script runs in, so the teardown checks that scope itself.
cleanup() {
    if ! y --root "$root" delete --force "$id" > "$work/delete.out" 2>&1; then
        echo "teardown: youki delete --force failed: $(tail -1 "$work/delete.out")"
    fi
    if systemctl --user is-active --quiet "youki-$id.scope"; then
        echo "teardown: youki-$id.scope survived the delete; stopping it"
        systemctl --user stop "youki-$id.scope"
    fi
    chmod -R u+w "$work" 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

echo "youki: $youki ($(sha256sum "$youki" | cut -c1-16)…), write delay ${delay}us"
mkdir -p "$root" "$bundle/rootfs/bin"
cp "$busybox" "$bundle/rootfs/bin/busybox"
for applet in sh sleep; do ln -s busybox "$bundle/rootfs/bin/$applet"; done
(cd "$bundle" && y spec --rootless) || { echo "UNPROVEN: youki spec failed"; exit 2; }
jq '.process.terminal = false
    | .process.args = ["/bin/sh", "-c", "trap \"exit 3\" TERM; while :; do sleep 1; done"]' \
    "$bundle/config.json" > "$bundle/config.next" && mv "$bundle/config.next" "$bundle/config.json"

if ! y --root "$root" create --bundle "$bundle" "$id" > "$work/create.out" 2>&1; then
    echo "UNPROVEN: youki create failed:"; cat "$work/create.out"; exit 2
fi
state=$root/$id/state.json
echo "after create: state.json $(wc -c < "$state") bytes, status $(jq -r .status "$state")"

trace=$work/start.trace
# Under the profile, strace is what changes into it: it execs the binary itself.
"${aa[@]}" strace -f -qq -y -o "$trace" -e trace=openat,write,rename,fsync \
    -e inject=write:delay_enter="$delay" \
    "$youki" --root "$root" start "$id" > "$work/start.out" 2>&1 &
starter=$!

# The window opens when the save has opened its file for writing: `state.json` itself
# (truncated) on an in-place save, `state.json.<pid>.tmp` on an atomic one. strace logs
# the openat when it returns, before the delayed write's line.
for _ in $(seq 1 200); do
    grep -Eq "openat\(.*/$id/state\.json[^\"]*\", O_[A-Z_|]*O_CREAT" "$trace" 2>/dev/null && break
    sleep 0.02
done
grep -Eq "openat\(.*/$id/state\.json[^\"]*\", O_[A-Z_|]*O_CREAT" "$trace" 2>/dev/null || {
    wait "$starter"; echo "--- trace"; cat "$trace"; echo "UNPROVEN: the save never opened its file"; exit 2
}
window_opened=$(date +%s%N)
sleep 0.2

torn=0
bytes=$(wc -c < "$state")
if file_status=$(jq -er .status "$state" 2>/dev/null); then
    echo "inside the window: state.json is $bytes bytes, status $file_status (complete)"
else
    echo "inside the window: state.json is $bytes bytes and does NOT parse"; torn=1
fi
if state_out=$(y --root "$root" state "$id" 2>&1); then
    echo "inside the window: youki state rc=0, status $(printf '%s' "$state_out" | jq -r .status)"
else
    echo "inside the window: youki state FAILED: $(printf '%s' "$state_out" | tail -1)"; torn=1
fi
if kill_out=$(y --root "$root" kill "$id" SIGTERM 2>&1); then
    echo "inside the window: youki kill rc=0"
else
    echo "inside the window: youki kill FAILED: $(printf '%s' "$kill_out" | tail -1)"; torn=1
fi
window_closed=$(date +%s%N)

wait "$starter"; start_rc=$?
echo "youki start rc=$start_rc"
echo "--- trace of youki start (state directory only)"
grep -E "/$id/" "$trace"

# The readers must have run while the state document's write was still delayed: the
# write's line ends with `(DELAYED)` and strace stamps nothing, so bound it instead —
# the reads took less than the delay and began after the save opened its file.
elapsed_us=$(( (window_closed - window_opened) / 1000 ))
if [ "$elapsed_us" -ge "$delay" ]; then
    echo "UNPROVEN: the three reads took ${elapsed_us}us, longer than the ${delay}us write delay"
    exit 2
fi
grep -Eq "write\([0-9]+</[^>]*/$id/state\.json[^>]*>, .*\(DELAYED\)" "$trace" || {
    echo "UNPROVEN: the trace shows no delayed write of the state document"; exit 2
}

echo "after start: state.json status $(jq -r .status "$state" 2>&1)"
if [ "$torn" -ne 0 ]; then echo "TORN"; exit 1; fi
echo "INTACT"
