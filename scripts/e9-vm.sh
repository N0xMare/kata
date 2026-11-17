#!/usr/bin/env bash
# The clean-machine VM for evidence cell E9, and the machine the E3 host-kill column kills.
#
#   scripts/e9-vm.sh create                 a fresh VM: verified base image + its own qcow2 overlay
#   scripts/e9-vm.sh start | stop | status
#   scripts/e9-vm.sh ssh [ssh-option...] [-- command...]
#   scripts/e9-vm.sh push-bundle <rev>      the commit under test, as a git bundle (sha recorded)
#   scripts/e9-vm.sh install                README.md's install, run as written, each step timed
#   scripts/e9-vm.sh push-token <file>      after install: the owner's forge token file, as GH_TOKEN
#   scripts/e9-vm.sh drop-token             after E9's E1: delete the guest's token file (nothing exports it after)
#   scripts/e9-vm.sh login-anthropic        after install: this environment's ANTHROPIC_API_KEY, as the
#                                           guest's own `kata login anthropic --api-key`
#   scripts/e9-vm.sh kill-host              SIGKILL qemu: E3's "host crash"
#   scripts/e9-vm.sh e3-prep                after install, with no token: the guest's E3 rig toolchain and test build
#   scripts/e9-vm.sh e3-host <case> <out>   one E3 host cell, P1-host..P4-host: arm, kill-host, start, resume;
#                                           everything copied to a new <out>/e3-<case>-<UTC>/ on every exit path
#   scripts/e9-vm.sh e3-host --retire <case>  move a finished or VOID cell's guest state aside for a fresh try
#   scripts/e9-vm.sh block-providers        NO-SPEND DRY RUNS ONLY: every model provider host resolves to
#                                           loopback in the guest, on both address families, or it refuses
#   scripts/e9-vm.sh standin-provider       NO-SPEND DRY RUNS ONLY, after block-providers: a stand-in Anthropic
#                                           endpoint on the guest's loopback, trusted through a throwaway CA
#   scripts/e9-vm.sh destroy [--base]       delete the VM (and, with --base, the cached image)
#   scripts/e9-vm.sh --self-test            host-free: the README plan; the token, API-key and E3-host refusals;
#                                           block-providers' loopback-only answer check; the stand-in's answers
#                                           and control; and install, e3-prep, e3-host and standin-provider
#                                           driven over stubbed guest calls (the forge-token check before any
#                                           other guest call, a dead cell's EXIT-trap copy-out, the stand-in
#                                           refused before any copy unless every provider host is on loopback);
#                                           push-token, login-anthropic and drop-token run from one heredoc-fed
#                                           bash over a fake ssh, leaving the script's later lines unread
#
# One VM per state directory, `$KATA_E9_VM_DIR` (default `~/.local/state/kata/e9-vm`, created
# owner-only: kata refuses to publish under a group-writable directory of the user's). Sizing:
# `KATA_E9_VM_CPUS` (16), `KATA_E9_VM_MEM` (32G), `KATA_E9_VM_DISK` (96G, sparse).
#
# Host requirements: Nix with flakes (qemu and xorriso come from the nixpkgs this checkout's
# flake.lock pins, through `--inputs-from`), gpgv with the Ubuntu cloud-image keyring
# (`KATA_E9_VM_KEYRING`, default /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg), python3,
# ssh, git, and read-write /dev/kvm (otherwise qemu runs under TCG, which is many times slower).
# Nothing on the host is changed and nothing needs sudo; the guest network is qemu user-mode
# networking, with only the guest's sshd forwarded to a 127.0.0.1 port that `start` picks free
# each boot (the per-VM known_hosts is rewritten for it).
#
# The guest is a stock Ubuntu 24.04 cloud image, pinned by release serial and sha256. It is
# downloaded into a new empty directory and used only when the publisher's SHA256SUMS carries a
# good signature by the pinned key fingerprint, lists the pinned sha256, and the file hashes to it.
# It is the SERVER cloud image: it already carries git, curl and python3, so E9 measures the
# README on Ubuntu 24.04 Server as Canonical's cloud image installs it, not on a desktop or a
# minimal install.
# cloud-init (a NoCloud seed) creates user `e9` with passwordless sudo and a per-VM client key,
# and installs a per-VM host key, so ssh checks the guest's identity strictly. Passwordless sudo
# makes the README's `sudo` steps non-interactive; on a real host each one prompts.
#
# The disk is `-drive file=overlay.qcow2,if=virtio,cache=none,aio=native` and nothing else: guest
# writes bypass the host page cache (O_DIRECT) and guest flushes reach the host file and the qcow2
# metadata, so `kill-host` models a GUEST power loss (the guest page cache and the writes qemu
# had not completed are lost; what the guest flushed survives). There is no
# drive-mode setting, so `cache=unsafe` (which ignores flushes) and `-snapshot` (which discards
# the disk) cannot be selected. `start` after `kill-host` boots the SAME overlay. A host kill
# models neither host power loss nor a device that honours flushes.
#
# `install` does not carry its own copy of the install. It reads README.md AT THE BUNDLED COMMIT
# (`git show <commit>:README.md`) and runs every line of every ```sh block directly under the
# headings `## Requirements`, `## Install from source` and `## Quickstart` (a `###` heading ends
# its section's capture). Each section runs in one fresh login shell, as a reader pasting it into
# a new terminal would. Every line runs verbatim, except exactly these, each recorded in the plan
# as a deviation:
#   - `git clone https://github.com/N0xMare/kata` clones the pushed bundle instead (the repository
#     is private until the flip; owner decision 2026-10-29 #6);
#   - a line ending `# terminal 1` runs in the background in its own login shell;
#   - harness glue the README does not state: before the Quickstart, an empty-rooted git repo
#     `~/e9-demo` to run it in; before the first `# terminal 2` line, a wait (120 s) for the main
#     to answer `kata run list`; after it, `kata --version`, `kata doctor`, a check that the
#     checkout is the bundled commit, a read-only sqlite oracle (a second handle, python3's
#     sqlite3) that the newest execution is `completed`, and the `sqlite3` program installed for
#     E1's oracles (`sqlite3 -readonly`; kata itself needs none).
# Every line runs WITHOUT A TERMINAL: over ssh with no tty and stdin from /dev/null, and with the
# guest's passwordless sudo. That too is a declared deviation from a reader typing into a
# terminal: a program that asks only when stdin is a tty takes its non-interactive path.
# summary.txt states both. The README's Nix installer line passes `--yes`, so that installer
# takes the same path with a terminal or without one.
# A section stops at its first failing line; the run stops at its first failing section. The run
# directory `vm/install-<UTC>/` keeps the README read, the plan (section, kind, line), each
# section's log, the guest's timing.tsv, the guest journal's sudo commands, and summary.txt with
# per-line seconds and the time to first run (the first planned line's start to the end of the
# first `kata run` line).
#
# `push-bundle` records the commit and the bundle's sha256. The commit identifies what was tested;
# the bundle sha256 checks only that one transfer (the guest copy is compared with it), because two
# bundles of the same commit are not byte-identical.
#
# `push-token` refuses a symlink, a file that is not a regular file, one not owned by the invoking
# user, one whose mode is not exactly 0600, and an empty one. It never prints the content: the file
# is streamed over ssh stdin into the guest's ~/.config/e9/gh-token (0600) and the guest's
# ~/.profile exports GH_TOKEN from that file into every later login shell. The script prints only
# whether the guest copy's sha256 matches. Push it AFTER `install`, right before E1, and
# `drop-token` it right after E1 (its only consumer): `install`, `e3-prep` and `e3-host` refuse to
# run while the guest holds the token file, so no install step (the build scripts, the Nix
# installer, `kata host setup`, the main), no E3 rig build (cargo-nextest's and the workspace's
# build scripts) and no E3 cell runs with GH_TOKEN in its environment.
#
# The guest's agent logs in with kata's own login, after `install` and before E1, never by
# copying a login file between hosts. `nanocode_anthropic` needs no browser: `login-anthropic`
# streams ANTHROPIC_API_KEY from ITS OWN environment (the operator scopes it to the one command:
# `( set -a; . <the .env>; set +a; scripts/e9-vm.sh login-anthropic )`) over ssh stdin into the
# guest's `kata login anthropic --api-key`, which stores its owner-only login file; the key is on
# no command line (printf is a shell builtin) and is never printed, and ssh forwards no
# environment. It refuses a key that is unset, empty or holds whitespace, and accepts any other
# value: the provider is what refuses a wrong key, at the first turn. The script moves the key
# into a NON-exported variable before it starts anything, and starts every process that can
# outlive it (qemu, the ssh control master that ControlPersist keeps) and every ssh and nix
# client with an environment of PATH and HOME (and TERM, when set) only: no process it leaves
# running holds the key or any other variable of the operator's scoped environment. `nanocode_openai`'s
# login is the owner's `kata login openai` inside the guest over this script's ssh, for example
# `scripts/e9-vm.sh ssh -- 'cd ~/e9-demo && kata login openai --device-code'`, run by the owner in
# their own terminal (its output names the ChatGPT account and goes into no transcript).
#
# E3's host column (D2 §5.4, `bin/kata/tests/e3_crash_matrix_host_live.rs`) runs INSIDE the guest
# and, once its control holds, runs `KATA_E3_HOST_KILL_CMD` there; `e3-host <case>` is the host
# side of that kill. It runs the cell's arm phase over ssh with a kill command that only drops a
# request file in the guest and sleeps; on the request it copies the rig's OWN arm files (the
# state JSON, arm-oracle.txt, the SSE transcript) out of the guest, read from the guest's page
# cache with no fsync in the guest, runs `kill-host`, `start`s the same disk, copies those three
# files back (they are the rig's notes, not kata's state: kata's files stay exactly as the
# power loss left them), runs the resume phase, and copies the record and the kept node's data
# directory out. The cell refuses the mock, so `e3-host` spends: it requires KATA_E3_AGENT
# (`nanocode-openai`, whose guest login is the owner's `kata login openai`, or
# `nanocode-anthropic`, whose key it streams from this environment's ANTHROPIC_API_KEY over ssh
# stdin, as `login-anthropic` does; the openai agent is sent an empty line, never the key) and
# KATA_E3_FUNDED=1. Its second argument is the host directory the cell's copy goes under,
# `<out>/e3-<case>-<UTC>/`: the arm and resume logs, the arm files, `kill_utc`, and the guest's
# records of that case (`evidence/`) and the kept node's `data/`, copied on EVERY exit path (a
# VOID arm, a failed start, a refusal after the arm), never left only on the VM `destroy`
# deletes. A cell arms only on a fresh node root, so a second try of a case first runs
# `e3-host --retire <case>`: it refuses while any guest process names that root, then unseals
# it (kata seals store trees read-only) and moves the root, its state file and its records to
# `~/e3-retired/<case>-<UTC>/` in the guest. `e3-prep` builds the rig in the guest's checkout
# first (cargo-nextest, the workspace test build, the musl tool host, the rig's Nix store paths,
# every cargo step `--locked`); a running main in the guest is stopped first, one installed main
# per user.
# `block-providers` is for a NO-SPEND dry run's stand-in agent, never for a funded run: it appends
# each provider host (`provider_hosts`) to the guest's /etc/hosts as 127.0.0.1 AND ::1, flushes the
# file, and refuses unless the guest's `getent ahosts` answers each host with exactly those two
# addresses, so a dry run's model call cannot leave the guest on either family. (A resolver that
# skips /etc/hosts is not covered: the dry run's transport errors, recorded, show the call failed.)
# `standin-provider` is the same kind of NO-SPEND step, for the one cell such a dry run cannot
# reach otherwise: P3-host's point fires only in a COMPLETED turn's `/out` publication, so a
# stand-in agent that reaches no provider VOIDs it. It refuses unless every provider host is
# already on loopback (`block-providers`), copies `scripts/e9-standin-provider.py` into the guest,
# makes a throwaway CA and a leaf for api.anthropic.com there (2 days), adds the CA to the
# guest's system store, starts the stand-in on 127.0.0.1:443 and [::1]:443 unless both already
# listen, and refuses unless a plan request through the system store gets the plan stream on
# each family. kata's real `nanocode-anthropic` client, under a fake key and with the rig's
# endpoint door shut, then completes its turns inside the guest. A host kill ends the stand-in:
# run it again before each cell. The guest keeps the CA, so a guest that ran it is a dry-run
# guest only (`destroy` it; E9 runs on a fresh VM).
# Guest command lines and generated guest scripts are single-quoted ON PURPOSE: they expand in the
# guest, not here.
# shellcheck disable=SC2016,SC2029
set -euo pipefail

# The operator's key, when this environment carries one, leaves the environment before anything
# starts: it lives on in a NON-exported variable, read only by `login-anthropic` and by
# `e3-host` for the anthropic agent, each of which writes it to one ssh stdin.
api_key=${ANTHROPIC_API_KEY-}
unset ANTHROPIC_API_KEY

# Run "$@" with PATH and HOME (and TERM, when set) only: no other variable of the operator's
# environment (a scoped .env among them) reaches a process this script starts.
scrubbed() { env -i PATH="$PATH" HOME="$HOME" ${TERM:+TERM="$TERM"} "$@"; }

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state=${KATA_E9_VM_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/kata/e9-vm}
vm=$state/vm
cpus=${KATA_E9_VM_CPUS:-16}
mem=${KATA_E9_VM_MEM:-32G}
disk=${KATA_E9_VM_DISK:-96G}
keyring=${KATA_E9_VM_KEYRING:-/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg}
guest_user=e9

# The guest image pin: release serial, file, its sha256, and the primary key fingerprint that
# must sign SHA256SUMS (Ubuntu's "UEC Image Automatic Signing Key").
ubuntu_serial=20261017
image_url=https://cloud-images.ubuntu.com/releases/noble/release-$ubuntu_serial
image_name=ubuntu-24.04-server-cloudimg-amd64.img
image_sha256=04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94
signing_fpr=D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81
base=$state/base-$ubuntu_serial

readme_sections=("Requirements" "Install from source" "Quickstart")
provider_hosts=(api.anthropic.com api.openai.com chatgpt.com auth.openai.com)
readme_clone='git clone https://github.com/N0xMare/kata'

die() { printf 'e9-vm: %s\n' "$*" >&2; exit 1; }
note() { printf 'e9-vm: %s\n' "$*" >&2; }

# Scratch directories a failed command must not leave behind; a directory renamed into place no
# longer exists under its scratch name, so a success removes nothing.
scratch=()
e3_out='' e3_case='' e3_copied=''
trap 'e3_copy_out; rm -rf "${scratch[@]}"' EXIT

tools() {
    local out
    out=$(scrubbed nix build --no-link --print-out-paths --inputs-from "$repo" \
        'nixpkgs#qemu_kvm' 'nixpkgs#xorriso^out') || die "cannot realise qemu/xorriso from the pinned nixpkgs"
    qemu_dir=$(sed -n 1p <<<"$out")
    xorriso_dir=$(sed -n 2p <<<"$out")
}

# A nixpkgs binary resolves its libraries through its own RUNPATH; a host LD_LIBRARY_PATH would
# put other glibc-era libraries in front of them (scrubbed drops it with the rest).
nixbin() { scrubbed "$@"; }

load_vm() {
    [ -f "$vm/vm.env" ] || die "no VM at $vm: run 'create' first"
    # shellcheck source=/dev/null
    . "$vm/vm.env"
    ssh_opts=(-i "$vm/id_ed25519" -p "$port" -o IdentitiesOnly=yes -o BatchMode=yes
        -o UserKnownHostsFile="$vm/known_hosts" -o StrictHostKeyChecking=yes
        -o ControlMaster=auto -o ControlPath="$vm/ssh.ctl" -o ControlPersist=yes
        -o ConnectTimeout=10 -o ServerAliveInterval=15 -o LogLevel=ERROR)
}

# `guest_in` hands the guest this script's stdin, for a call that streams something in; `guest`
# gives it /dev/null, so a call reads nothing its caller's stdin still holds (the rest of a
# `bash <<'EOF'` script that runs this one).
guest_in() { scrubbed ssh "${ssh_opts[@]}" "$guest_user@127.0.0.1" "$@"; }
guest() { guest_in "$@" </dev/null; }

# The qemu pid, only when the pidfile names a live qemu running THIS VM's overlay: a recycled
# pid is never signalled.
qemu_pid() {
    local pid
    [ -f "$vm/qemu.pid" ] || return 1
    pid=$(tr -dc 0-9 <"$vm/qemu.pid")
    [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] || return 1
    grep -qF "file=$vm/overlay.qcow2," < <(tr '\0' '\n' <"/proc/$pid/cmdline") || return 1
    printf '%s\n' "$pid"
}

fetch_base() {
    if [ -f "$base/$image_name" ]; then
        printf '%s  %s\n' "$image_sha256" "$base/$image_name" | sha256sum -c --quiet - \
            || die "cached base $base/$image_name no longer hashes to the pin: delete $base"
        return
    fi
    [ -r "$keyring" ] || die "no Ubuntu cloud-image keyring at $keyring (set KATA_E9_VM_KEYRING)"
    local dl status listed
    dl=$(mktemp -d "$state/download.XXXXXX")
    scratch+=("$dl")
    note "downloading $image_url/$image_name into $dl"
    curl --proto '=https' -fsSL -o "$dl/SHA256SUMS" "$image_url/SHA256SUMS"
    curl --proto '=https' -fsSL -o "$dl/SHA256SUMS.gpg" "$image_url/SHA256SUMS.gpg"
    status=$(gpgv --status-fd 1 --keyring "$keyring" "$dl/SHA256SUMS.gpg" "$dl/SHA256SUMS" 2>/dev/null) \
        || die "SHA256SUMS has no good signature in $keyring"
    # VALIDSIG's last field is the primary key fingerprint.
    grep -qx "$signing_fpr" <<<"$(awk '$2 == "VALIDSIG" { print $NF }' <<<"$status")" \
        || die "SHA256SUMS is not signed by $signing_fpr"
    listed=$(awk -v f="*$image_name" '$2 == f { print $1 }' "$dl/SHA256SUMS")
    [ "$listed" = "$image_sha256" ] || die "signed SHA256SUMS lists '$listed' for $image_name, not the pin"
    curl --proto '=https' -fsSL -o "$dl/$image_name" "$image_url/$image_name"
    printf '%s  %s\n' "$image_sha256" "$dl/$image_name" | sha256sum -c --quiet - \
        || die "$image_name does not hash to the pin"
    chmod 0444 "$dl/$image_name"
    mv -T "$dl" "$base"
    note "verified base image $base/$image_name (signed by $signing_fpr)"
}

free_port() {
    python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

cmd_create() {
    [ -e "$vm" ] && die "a VM already exists at $vm: destroy it first"
    # qemu's QMP socket and ssh's control socket must fit a unix socket path.
    [ "${#vm}" -le 90 ] || die "state directory path too long for unix sockets: $vm"
    (umask 077 && mkdir -p "$state")
    tools
    fetch_base
    local stage
    stage=$(mktemp -d "$state/vm.XXXXXX")
    scratch+=("$stage")
    ssh-keygen -q -t ed25519 -N '' -C e9-vm-client -f "$stage/id_ed25519"
    ssh-keygen -q -t ed25519 -N '' -C e9-vm-host -f "$stage/host_ed25519"
    printf 'instance-id: e9-%s\nlocal-hostname: e9-vm\n' "$(date -u +%Y%m%dT%H%M%SZ)" >"$stage/meta-data"
    {
        printf '#cloud-config\n'
        printf 'users:\n  - name: %s\n    shell: /bin/bash\n    lock_passwd: true\n' "$guest_user"
        printf '    sudo: "ALL=(ALL) NOPASSWD:ALL"\n    ssh_authorized_keys:\n      - %s\n' "$(cat "$stage/id_ed25519.pub")"
        printf 'ssh_pwauth: false\ndisable_root: true\nssh_deletekeys: true\nssh_genkeytypes: [ed25519]\n'
        printf 'ssh_keys:\n  ed25519_private: |\n'
        sed 's/^/    /' "$stage/host_ed25519"
        printf '  ed25519_public: %s\n' "$(cat "$stage/host_ed25519.pub")"
    } >"$stage/user-data"
    nixbin "$xorriso_dir/bin/xorriso" -as mkisofs -quiet -o "$stage/seed.iso" -V cidata -J -R \
        "$stage/user-data" "$stage/meta-data" 2>/dev/null
    nixbin "$qemu_dir/bin/qemu-img" create -q -f qcow2 -F qcow2 -b "$base/$image_name" "$stage/overlay.qcow2" "$disk"
    {
        printf 'port=\ncpus=%s\nmem=%s\ndisk=%s\n' "$cpus" "$mem" "$disk"
        printf 'ubuntu_serial=%s\nimage_sha256=%s\ncreated_utc=%s\n' "$ubuntu_serial" "$image_sha256" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >"$stage/vm.env"
    mv -T "$stage" "$vm"
    note "created $vm; next: start"
}

cmd_start() {
    load_vm
    qemu_pid >/dev/null && die "the VM is already running"
    tools
    local accel=kvm cpu=host boot_secs=${KATA_E9_VM_BOOT_SECS:-600}
    if ! [ -r /dev/kvm ] || ! [ -w /dev/kvm ]; then
        note "WARNING: /dev/kvm is not read-write for $(id -un): running under TCG emulation, many times slower"
        note "  (the host step that enables KVM: sudo usermod -aG kvm $(id -un), then a new login)"
        accel=tcg cpu=max boot_secs=$((boot_secs * 6))
    fi
    rm -f "$vm/qmp.sock" "$vm/qemu.pid"
    scrubbed ssh -O exit "${ssh_opts[@]}" "$guest_user@127.0.0.1" 2>/dev/null || true
    # A port chosen now, not at create: one free then may be taken by the next boot.
    port=$(free_port)
    sed -i "s/^port=.*/port=$port/" "$vm/vm.env"
    printf '[127.0.0.1]:%s %s\n' "$port" "$(cut -d' ' -f1,2 "$vm/host_ed25519.pub")" >"$vm/known_hosts"
    load_vm
    nixbin "$qemu_dir/bin/qemu-system-x86_64" -name e9-vm \
        -machine "q35,accel=$accel" -cpu "$cpu" -smp "$cpus" -m "$mem" \
        -drive "file=$vm/overlay.qcow2,if=virtio,cache=none,aio=native,format=qcow2" \
        -drive "file=$vm/seed.iso,media=cdrom,readonly=on" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=n0 \
        -display none -serial "file:$vm/console-$(date -u +%Y%m%dT%H%M%SZ).log" \
        -qmp "unix:$vm/qmp.sock,server=on,wait=off" -pidfile "$vm/qemu.pid" -daemonize
    note "qemu started (pid $(qemu_pid), accel $accel, ssh 127.0.0.1:$port); waiting for sshd"
    local deadline=$((SECONDS + boot_secs))
    until guest true 2>/dev/null; do
        qemu_pid >/dev/null || die "qemu exited during boot (see $vm/console-*.log)"
        [ "$SECONDS" -lt "$deadline" ] || die "no ssh after ${boot_secs}s (see $vm/console-*.log)"
        sleep 3
    done
    local rc=0
    guest cloud-init status --wait >/dev/null || rc=$?
    case $rc in
        0) ;;
        2) note "WARNING: cloud-init finished with recoverable errors (guest: cloud-init status --long)" ;;
        *) die "cloud-init failed (rc $rc; guest: cloud-init status --long)" ;;
    esac
    note "up: scripts/e9-vm.sh ssh"
}

qmp() {
    python3 -I - "$vm/qmp.sock" "$1" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
f = s.makefile("rw")
f.readline()
for cmd in ("qmp_capabilities", sys.argv[2]):
    f.write(json.dumps({"execute": cmd}) + "\n")
    f.flush()
    reply = json.loads(f.readline())
    while "event" in reply:
        reply = json.loads(f.readline())
    if "error" in reply:
        sys.exit("qmp %s: %s" % (cmd, reply["error"]))
EOF
}

wait_gone() {
    local pid=$1 deadline=$((SECONDS + $2))
    while [ -e "/proc/$pid" ]; do
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 1
    done
}

cmd_stop() {
    load_vm
    local pid
    pid=$(qemu_pid) || die "the VM is not running"
    qmp system_powerdown
    wait_gone "$pid" 180 || die "the guest did not power off within 180s (kill-host forces it)"
    scrubbed ssh -O exit "${ssh_opts[@]}" "$guest_user@127.0.0.1" 2>/dev/null || true
    note "stopped"
}

cmd_kill_host() {
    load_vm
    local pid
    pid=$(qemu_pid) || die "the VM is not running"
    kill -KILL "$pid"
    note "SIGKILL qemu pid $pid at $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
    wait_gone "$pid" 30 || die "qemu pid $pid survived SIGKILL for 30s"
    scrubbed ssh -O exit "${ssh_opts[@]}" "$guest_user@127.0.0.1" 2>/dev/null || true
    note "killed; 'start' boots the same overlay"
}

cmd_status() {
    load_vm
    local pid
    if pid=$(qemu_pid); then echo "running: qemu pid $pid, ssh 127.0.0.1:$port"; else echo "stopped"; fi
    cat "$vm/vm.env"
    if [ -f "$vm/bundle.env" ]; then cat "$vm/bundle.env"; fi
}

cmd_ssh() {
    load_vm
    local opts=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do opts+=("$1"); shift; done
    [ "$#" -gt 0 ] && shift
    exec env -i PATH="$PATH" HOME="$HOME" ${TERM:+TERM="$TERM"} ssh "${ssh_opts[@]}" "${opts[@]}" "$guest_user@127.0.0.1" "$@"
}

cmd_destroy() {
    local purge_base=0
    [ "${1:-}" = "--base" ] && purge_base=1
    if [ -f "$vm/vm.env" ]; then
        load_vm
        qemu_pid >/dev/null && die "the VM is running: stop or kill-host it first"
        scrubbed ssh -O exit "${ssh_opts[@]}" "$guest_user@127.0.0.1" 2>/dev/null || true
    fi
    rm -rf "$vm"
    note "removed $vm"
    if [ "$purge_base" = 1 ]; then
        chmod -R u+w "$base" 2>/dev/null || true
        rm -rf "$base"
        note "removed $base"
    fi
}

cmd_push_bundle() {
    local rev=${1:?usage: e9-vm.sh push-bundle <rev>}
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    local commit tmp bundle bundle_sha guest_sha
    commit=$(git -C "$repo" rev-parse --verify --end-of-options "$rev^{commit}") || die "no commit $rev"
    # A scratch bare repository borrowing the checkout's objects: the bundle carries one branch
    # `main` at the commit, and no ref of the checkout is written.
    tmp=$(mktemp -d "$vm/bundle.XXXXXX")
    scratch+=("$tmp")
    git init -q --bare "$tmp/repo"
    git -C "$repo" rev-parse --path-format=absolute --git-common-dir | sed 's|$|/objects|' \
        >"$tmp/repo/objects/info/alternates"
    git -C "$tmp/repo" update-ref refs/heads/main "$commit"
    git -C "$tmp/repo" symbolic-ref HEAD refs/heads/main
    bundle=$vm/kata-$commit.bundle
    git -C "$tmp/repo" bundle create -q "$bundle" HEAD refs/heads/main
    git -C "$tmp/repo" bundle verify -q "$bundle" >/dev/null 2>&1
    rm -rf "$tmp"
    bundle_sha=$(sha256sum "$bundle" | cut -d' ' -f1)
    guest_in 'mkdir -p ~/e9 && cat > ~/e9/kata.bundle' <"$bundle"
    guest_sha=$(guest 'sha256sum ~/e9/kata.bundle' | cut -d' ' -f1)
    [ "$guest_sha" = "$bundle_sha" ] || die "the guest's bundle hashes to $guest_sha, not $bundle_sha"
    printf 'commit=%s\nbundle_sha256=%s\npushed_utc=%s\n' "$commit" "$bundle_sha" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$vm/bundle.env"
    note "pushed commit $commit as ~/e9/kata.bundle (sha256 $bundle_sha)"
}

# Refuse anything but a non-empty regular file, owned by the invoking user, mode exactly 0600.
# The checks read the OPENED file (fd), so a swap after the check is not what gets sent.
validate_token_file() {
    local file=$1 fd uid mode
    [ -L "$file" ] && die "refused: $file is a symlink"
    [ -f "$file" ] || die "refused: $file is not a regular file"
    exec {fd}<"$file"
    read -r uid mode < <(stat -L -c '%u %a' "/dev/fd/$fd")
    [ "$uid" = "$(id -u)" ] || die "refused: $file is owned by uid $uid, not $(id -u)"
    [ "$mode" = 600 ] || die "refused: $file has mode $mode, not 0600"
    [ -s "/dev/fd/$fd" ] || die "refused: $file is empty"
    token_fd=$fd
}

cmd_push_token() {
    local file=${1:?usage: e9-vm.sh push-token <owner-file>}
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    validate_token_file "$file"
    local host_sha guest_sha
    host_sha=$(sha256sum <"/dev/fd/$token_fd" | cut -d' ' -f1)
    # shellcheck disable=SC2016 # expanded by the guest shell
    guest_in 'umask 077 && mkdir -p ~/.config/e9 && cat > ~/.config/e9/gh-token && chmod 600 ~/.config/e9/gh-token
line='\''if [ -r "$HOME/.config/e9/gh-token" ]; then export GH_TOKEN="$(cat "$HOME/.config/e9/gh-token")"; fi'\''
grep -qxF "$line" ~/.profile || printf "%s\n" "$line" >> ~/.profile' <"/dev/fd/$token_fd"
    guest_sha=$(guest 'sha256sum < ~/.config/e9/gh-token' | cut -d' ' -f1)
    [ "$guest_sha" = "$host_sha" ] || die "the guest copy differs from $file"
    note "token copied to the guest's ~/.config/e9/gh-token (0600; matches); login shells export GH_TOKEN"
}

# The guest's forge-token check: `test -e` of the file's rc, read as held (0), absent (1) or
# unknown (anything else, an ssh failure); `what` names the step refused while it is held.
token_verdict() {
    case $1 in
        0) die "refused: the guest holds the forge token (~/.config/e9/gh-token), which every login shell exports; $2 never runs with it (drop-token first)" ;;
        1) ;;
        *) die "cannot check the guest for a forge token (ssh rc $1)" ;;
    esac
}

refuse_guest_token() {
    local held=0
    guest 'test -e ~/.config/e9/gh-token' || held=$?
    token_verdict "$held" "$1"
}

cmd_drop_token() {
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    guest 'rm -f ~/.config/e9/gh-token && test ! -e ~/.config/e9/gh-token' \
        || die "could not delete the guest's ~/.config/e9/gh-token"
    note "deleted the guest's forge token file; login shells export no GH_TOKEN from now on"
}

# Refuse an ANTHROPIC_API_KEY (as this script took it from its environment, `api_key`) that is
# unset, empty, or holds whitespace (a line break would end the key early on the guest's stdin),
# without printing it.
validate_api_key_env() {
    [ -n "$api_key" ] \
        || die "refused: ANTHROPIC_API_KEY is unset or empty here (scope it to this command: ( set -a; . <the .env>; set +a; scripts/e9-vm.sh login-anthropic ))"
    case $api_key in
        *[[:space:]]*) die "refused: ANTHROPIC_API_KEY holds whitespace" ;;
    esac
}

cmd_login_anthropic() {
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    validate_api_key_env
    printf '%s\n' "$api_key" | guest_in 'bash -l -c "kata login anthropic --api-key"' >&2 \
        || die "the guest's kata login anthropic --api-key failed"
    guest 'bash -l -c "kata login status"' | grep -F anthropic >&2 \
        || die "the guest's kata login status names no anthropic login"
    note "the guest holds kata's own anthropic-api-key login; its agent block reads it with credential = { mode = \"api_key\", source = \"kata_login\" }"
}

# The E3 host cell's test, by case: `e3_crash_matrix_host_live`'s four cells.
e3_test_of() {
    case $1 in
        P1-host) echo e3_p1_host_live ;;
        P2-host) echo e3_p2_host_live ;;
        P3-host) echo e3_p3_host_live ;;
        P4-host) echo e3_p4_host_live ;;
        *) die "refused: '$1' is no E3 host case (P1-host, P2-host, P3-host, P4-host)" ;;
    esac
}

# The funded agent the host column needs, refused as the rig refuses it, before anything runs.
e3_host_agent() {
    case ${KATA_E3_AGENT-} in
        nanocode-anthropic) validate_api_key_env ;;
        nanocode-openai) ;;
        *) die "refused: KATA_E3_AGENT must be nanocode-openai or nanocode-anthropic (the host column refuses the mock)" ;;
    esac
    [ "${KATA_E3_FUNDED-}" = 1 ] || die "refused: an E3 host cell spends model budget; set KATA_E3_FUNDED=1"
    printf '%s\n' "$KATA_E3_AGENT"
}

# The guest's E3 runner: phase arm|resume, the case, its test and the agent; the API key, when
# there is one, arrives as the first line of stdin and is exported only into this process.
e3_guest_script() {
    cat <<'GUEST'
set -uo pipefail
phase=$1 case=$2 test=$3 agent=$4
IFS= read -r key || true
if [ -n "$key" ]; then export ANTHROPIC_API_KEY=$key; fi
unset key
pid=$(ss -ltnpH 'sport = :8400' | sed -n 's/.*pid=\([0-9]*\),.*/\1/p' | head -n 1)
if [ -n "$pid" ]; then kill -TERM "$pid"; for _ in $(seq 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done; fi
mkdir -p ~/e3-state ~/e3-evidence
export KATA_E2E_KEEP=1 KATA_E3_AGENT=$agent KATA_E3_FUNDED=1 KATA_E3_HOST_STATE_DIR=$HOME/e3-state \
    KATA_E3_EVIDENCE_DIR=$HOME/e3-evidence
if [ "$phase" = arm ]; then
    rm -f ~/e3-state/kill.request
    export KATA_E3_HOST_KILL_CMD='touch "$KATA_E3_HOST_STATE_DIR/kill.request"; exec sleep infinity'
else
    export KATA_E3_HOST_RESUME=$HOME/e3-state/$case.json
fi
cd ~/kata || exit 1
exec cargo nextest run --locked -p kata -P live-smoke --test-threads=1 --run-ignored all --success-output final \
    -E "binary(e3_crash_matrix_host_live) & test(=$test)"
GUEST
}

# The line `e3-host` writes to the guest runner's stdin: the key for the anthropic agent, an empty
# line for any other.
e3_key_line() {
    if [ "$1" = nanocode-anthropic ]; then printf '%s\n' "$api_key"; else printf '\n'; fi
}

cmd_e3_prep() {
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    refuse_guest_token "the E3 rig's build (cargo-nextest's and the workspace's build scripts)"
    guest_in 'bash -l -s' <<'GUEST'
set -euo pipefail
cd ~/kata
cargo install --locked cargo-nextest --version 0.9.126
cargo build --locked --workspace --bins --examples
cargo build --locked -p kata-provider-youki --bin kata-provider-youki
cargo build --locked -p kata-oci-hook --bin kata-oci-hook
cargo build --locked -p kata-toolhost --target x86_64-unknown-linux-musl
# The store paths the rig's node environment names (agent_change_rig BUSYBOX, GIT_MINIMAL).
nix-store --realise $(grep -o '/nix/store/[0-9a-z]\{32\}-[^"]*' bin/kata/tests/agent_change_rig/mod.rs | sort -u) >/dev/null
cargo nextest run --locked -p kata -P live-smoke --run-ignored all --no-run
cargo nextest list --locked -p kata -P live-smoke --run-ignored all -E 'binary(e3_crash_matrix_host_live)' | grep -c _host_live
GUEST
    note "the guest's rig is built (cargo-nextest, the test build, the musl tool host, the rig's store paths)"
}

# Copy the cell's guest side into $e3_out: the records of $e3_case (`evidence/`) and the kept
# node's data directory (`data/`) but its worker secret (`local-worker.secret`; the round's
# readers read only the databases). Called on every exit path once the cell has a directory; a
# VM that is not up is noted, not fatal.
e3_copy_out() {
    [ -n "${e3_out:-}" ] && [ -z "${e3_copied:-}" ] || return 0
    e3_copied=1
    if ! qemu_pid >/dev/null; then
        note "$e3_case: the VM is not running: nothing copied out of the guest into $e3_out"
        return 0
    fi
    mkdir -p "$e3_out/evidence" "$e3_out/data"
    guest "cd ~/e3-evidence 2>/dev/null && tar -cf - --ignore-failed-read e3-$e3_case-*" 2>/dev/null \
        | tar -C "$e3_out/evidence" -xf - 2>/dev/null || note "$e3_case: no record of the case in the guest's ~/e3-evidence"
    guest "test -d ~/e3-state/$e3_case/data && tar -C ~/e3-state/$e3_case/data --exclude=./local-worker.secret -cf - ." 2>/dev/null \
        | tar -C "$e3_out/data" -xf - 2>/dev/null || note "$e3_case: no kept node data in the guest's ~/e3-state/$e3_case"
    note "$e3_case: copied the guest's record(s) to $e3_out/evidence, the kept node's data to $e3_out/data"
}

cmd_e3_host() {
    if [ "${1:-}" = --retire ]; then
        cmd_e3_retire "${2:?usage: e9-vm.sh e3-host --retire <P1-host|P2-host|P3-host|P4-host>}"
        return
    fi
    local case=${1:?usage: e9-vm.sh e3-host <P1-host|P2-host|P3-host|P4-host> <out-dir>} \
        parent=${2:?usage: e9-vm.sh e3-host <case> <out-dir>, the host directory the copy of the cell goes under} \
        test agent armpid rc deadline
    test=$(e3_test_of "$case")
    agent=$(e3_host_agent)
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    refuse_guest_token "an E3 host cell"
    guest "test ! -e ~/e3-state/$case && test ! -e ~/e3-state/$case.json" \
        || die "the guest already holds ~/e3-state/$case: a host cell arms on a fresh node root (e3-host --retire $case)"
    mkdir -p "$parent"
    e3_case=$case
    e3_out=$parent/e3-$case-$(date -u +%Y%m%dT%H%M%SZ)
    mkdir "$e3_out"
    e3_guest_script | guest_in 'cat > ~/e9/e3-host.sh'
    note "$case: arm phase ($agent); log $e3_out/arm.log"
    e3_key_line "$agent" | guest_in "bash -l ~/e9/e3-host.sh arm $case $test $agent" >"$e3_out/arm.log" 2>&1 &
    armpid=$!
    deadline=$((SECONDS + 3600))
    until guest 'test -e ~/e3-state/kill.request' 2>/dev/null; do
        kill -0 "$armpid" 2>/dev/null || { tail -n 20 "$e3_out/arm.log" >&2; die "$case: the arm phase ended without asking for the kill (see $e3_out/arm.log)"; }
        [ "$SECONDS" -lt "$deadline" ] || die "$case: no kill request within 3600 s"
        sleep 0.2
    done
    guest "cd ~/e3-state && tar -cf - $case.json $case/arm-oracle.txt $case/sse-transcript.txt" >"$e3_out/arm-files.tar" \
        || die "$case: could not copy the rig's arm files out before the kill"
    date -u +%Y-%m-%dT%H:%M:%S.%NZ >"$e3_out/kill_utc"
    cmd_kill_host
    wait "$armpid" 2>/dev/null || true
    cmd_start
    guest_in "cd ~/e3-state && tar -xf - && rm -f kill.request" <"$e3_out/arm-files.tar" \
        || die "$case: could not restore the rig's arm files"
    note "$case: resume phase; log $e3_out/resume.log"
    rc=0
    e3_key_line "$agent" | guest_in "bash -l ~/e9/e3-host.sh resume $case $test $agent" >"$e3_out/resume.log" 2>&1 || rc=$?
    e3_copy_out
    tail -n 5 "$e3_out/resume.log" >&2
    note "$case: resume rc $rc; everything under $e3_out"
    return "$rc"
}

# Move a cell's guest state aside so the case can arm again: its node root, its state file and
# its records, to ~/e3-retired/<case>-<UTC>/. Refused while a guest process names the root.
cmd_e3_retire() {
    local case=$1
    e3_test_of "$case" >/dev/null
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    guest "set -eu
root=\$HOME/e3-state/$case
for f in /proc/[0-9]*/cmdline; do
    if tr '\\0' ' ' < \"\$f\" 2>/dev/null | grep -qF \"\$root\"; then
        echo \"e9-vm: refused: process \$(basename \$(dirname \$f)) still names \$root\" >&2; exit 3
    fi
done
to=\$HOME/e3-retired/$case-\$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p \"\$to\"
if [ -e \"\$root\" ]; then chmod -R u+w \"\$root\"; mv \"\$root\" \"\$to/root\"; fi
if [ -e \"\$root.json\" ]; then mv \"\$root.json\" \"\$to/\"; fi
for r in \$HOME/e3-evidence/e3-$case-*; do if [ -e \"\$r\" ]; then mv \"\$r\" \"\$to/\"; fi; done
rm -f \$HOME/e3-state/kill.request
echo \"e9-vm: retired $case to \$to\" >&2" || die "$case: could not retire the guest's state"
}

# Refuse unless `getent ahosts` output ($2, for host $1) names exactly 127.0.0.1 and ::1.
loopback_only() {
    local addrs
    addrs=$(awk 'NF { print $1 }' <<<"$2" | LC_ALL=C sort -u | tr '\n' ' ')
    [ "$addrs" = '127.0.0.1 ::1 ' ] \
        || die "refused: the guest resolves $1 to [${addrs% }], not exactly 127.0.0.1 and ::1"
}

# Refuse unless the guest resolves every provider host to exactly 127.0.0.1 and ::1.
providers_on_loopback() {
    local host answer
    for host in "${provider_hosts[@]}"; do
        answer=$(guest "getent ahosts $host") || die "the guest cannot resolve $host"
        loopback_only "$host" "$answer"
        note "the guest resolves $host to 127.0.0.1 and ::1 only"
    done
}

cmd_block_providers() {
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    guest "for h in ${provider_hosts[*]}; do printf '127.0.0.1 %s\\n::1 %s\\n' \$h \$h; done | sudo tee -a /etc/hosts >/dev/null && sudo sync /etc/hosts /etc" \
        || die "could not append the provider hosts to the guest's /etc/hosts"
    providers_on_loopback
}

# The stand-in's throwaway CA and its leaf for api.anthropic.com, made in the current directory
# unless they exist; `chain.crt` is the leaf then the CA, `leaf.key` its key.
standin_certs_script() {
    cat <<'CERTS'
set -eu
if [ ! -s chain.crt ] || [ ! -s leaf.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=e3-standin-ca \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj /CN=api.anthropic.com 2>/dev/null
    printf '%s\n' subjectAltName=DNS:api.anthropic.com extendedKeyUsage=serverAuth \
        basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature,keyEncipherment >leaf.ext
    openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out leaf.crt -days 2 \
        -extfile leaf.ext 2>/dev/null
    cat leaf.crt ca.crt >chain.crt
fi
CERTS
}

# The positive control, run where the stand-in serves: a plan request answered with the plan, on
# each family; $1 is curl's extra arguments (none in the guest, whose system store and /etc/hosts
# carry the CA and the name).
standin_control_script() {
    cat <<'CONTROL'
set -u
port=$1 extra=$2
for family in -4 -6; do
    # shellcheck disable=SC2086
    out=$(curl "$family" -sS -m 10 $extra "https://api.anthropic.com:$port/v1/messages" \
        -H 'content-type: application/json' -d '{"probe": "produce a plan for the task"}') \
        || { echo "stand-in control: curl $family failed" >&2; exit 1; }
    case $out in
        *'"text_delta"'*'Replace the line in src/app.txt.'*) echo "stand-in control: curl $family got the plan stream" ;;
        *) echo "stand-in control: curl $family got no plan stream: $out" >&2; exit 1 ;;
    esac
done
CONTROL
}

cmd_standin_provider() {
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    providers_on_loopback
    guest_in 'mkdir -p ~/e9/standin && cat >~/e9/standin/standin.py' <"$repo/scripts/e9-standin-provider.py" \
        || die "could not copy the stand-in into the guest"
    guest_in "cd ~/e9/standin && bash -s" <<<"$(standin_certs_script)" || die "could not make the stand-in's CA and leaf"
    guest 'sudo cp ~/e9/standin/ca.crt /usr/local/share/ca-certificates/e3-standin.crt && sudo update-ca-certificates >/dev/null' \
        || die "could not add the stand-in's CA to the guest's system store"
    local listening='[ "$(ss -ltnH "sport = :443" | wc -l)" -ge 2 ]'
    guest "cd ~/e9/standin && { $listening || (sudo setsid nohup python3 -I standin.py chain.crt leaf.key \$PWD/req.log 443 >>server.out 2>&1 </dev/null &); }; for _ in \$(seq 50); do $listening && exit 0; sleep 0.1; done; echo 'the stand-in is not listening on 127.0.0.1:443 and [::1]:443' >&2; exit 1" \
        || die "the stand-in did not come up"
    guest_in "bash -s 443 ''" <<<"$(standin_control_script)" || die "the stand-in's positive control failed"
    note "the stand-in answers api.anthropic.com on 127.0.0.1:443 and [::1]:443 in the guest (dry runs only)"
}

# README.md's command lines: "<section>\t<line>" for every line of every ```sh block directly
# under the wanted `##` headings, blank and comment-only lines dropped, continuations joined.
readme_lines() {
    local wanted
    wanted=$(printf '%s|' "${readme_sections[@]}")
    awk -v wanted="${wanted%|}" '
        BEGIN { n = split(wanted, w, "|"); for (i = 1; i <= n; i++) want[w[i]] = 1 }
        fence == 0 && /^#+ / {
            h = $0; sub(/^#+ /, "", h)
            sec = ($0 ~ /^## / && (h in want)) ? h : ""
            next
        }
        fence == 0 && /^```/ { fence = ($0 ~ /^```sh[[:space:]]*$/ && sec != "") ? 1 : 2; next }
        fence != 0 && /^```[[:space:]]*$/ { fence = 0; next }
        fence == 1 {
            line = cont $0
            if (line ~ /\\$/) { cont = substr(line, 1, length(line) - 1); next }
            cont = ""
            if (line ~ /^[[:space:]]*(#.*)?$/) next
            print sec "\t" line
        }' "$1"
}

# The install plan: "<section>\t<kind>\t<line>", kind one of readme | readme-bg | substituted | glue.
plan() {
    local readme=$1 commit=$2 sec line seen_t2=0 cur=""
    while IFS=$'\t' read -r sec line; do
        if [ "$sec" != "$cur" ]; then
            cur=$sec
            if [ "$sec" = "Quickstart" ]; then
                printf '%s\tglue\t%s\n' "$sec" "mkdir -p ~/e9-demo && cd ~/e9-demo && git init -q -b main && git commit -q --allow-empty -m 'e9: empty root'"
            fi
        fi
        if [ "$line" = "$readme_clone" ]; then
            printf '%s\tsubstituted\t%s\n' "$sec" "git clone ~/e9/kata.bundle kata"
        elif [[ $line == *"# terminal 1" ]]; then
            printf '%s\treadme-bg\t%s\n' "$sec" "$line"
        else
            if [[ $line == *"# terminal 2" ]] && [ "$seen_t2" = 0 ]; then
                seen_t2=1
                printf '%s\tglue\t%s\n' "$sec" 'for _ in $(seq 120); do kata run list >/dev/null 2>&1 && break; sleep 1; done; kata run list >/dev/null'
            fi
            printf '%s\treadme\t%s\n' "$sec" "$line"
        fi
    done < <(readme_lines "$readme")
    printf 'Checks\tglue\t%s\n' 'cd ~/e9-demo' 'kata --version' 'kata doctor --config .kata/kata.toml' \
        "test \"\$(git -C ~/kata rev-parse HEAD)\" = $commit" 'python3 -I ~/e9/run/oracle.py .kata/kata.toml' \
        'sudo apt-get install -y sqlite3 && sqlite3 --version'
}

# The guest-side oracle, independent of kata's own report: the newest execution's lifecycle row
# through a read-only sqlite handle on the data_dir the project config names.
oracle_py() {
    cat <<'EOF'
import pathlib, sqlite3, sys, tomllib
config = pathlib.Path(sys.argv[1]).resolve()
data_dir = pathlib.Path(tomllib.loads(config.read_text())["node"]["data_dir"])
if not data_dir.is_absolute():
    data_dir = config.parent / data_dir
db = sqlite3.connect("file:%s?mode=ro" % (data_dir / "operational.db"), uri=True)
row = db.execute("select execution_id, state, terminal_outcome from execution_lifecycle order by created_at_ms desc limit 1").fetchone()
if row is None:
    sys.exit("oracle: no execution")
stages = db.execute("select stage_id, count(*) from attempts where execution_id = ? group by stage_id", (row[0],)).fetchall()
print("oracle: newest execution state=%s outcome=%s; attempts per stage %s" % (row[1], row[2], dict(stages)))
sys.exit(0 if row[1] == "completed" else 1)
EOF
}

# One section's guest script: each line timed into ~/e9/run/timing.tsv, the section stopping at
# its first failing line.
section_script() {
    local plan_file=$1 want=$2 idx=0 sec kind line
    printf 'cd ~\n'
    while IFS=$'\t' read -r sec kind line; do
        idx=$((idx + 1))
        [ "$sec" = "$want" ] || continue
        printf 'printf "%%s\\tstart\\t%%s\\n" %d "$(date +%%s)" >> ~/e9/run/timing.tsv\n' "$idx"
        printf 'printf "%%s\\n" %q\n' "[e9 $idx $kind] \$ $line"
        if [ "$kind" = readme-bg ]; then
            printf '%s\n' "$line" >"$run/bg-$idx.sh"
            printf 'setsid nohup bash -l ~/e9/run/bg-%d.sh > ~/e9/run/bg-%d.log 2>&1 < /dev/null &\n' "$idx" "$idx"
        else
            printf '%s\n' "$line"
        fi
        printf '__rc=$?; printf "%%s\\tend\\t%%s\\t%%s\\n" %d "$(date +%%s)" "$__rc" >> ~/e9/run/timing.tsv\n' "$idx"
        printf 'if [ "$__rc" -ne 0 ]; then exit "$__rc"; fi\n'
    done <"$plan_file"
}

summarize() {
    local plan_file=$1 timing=$2
    awk -F'\t' '
        NR == FNR { sec[NR] = $1; kind[NR] = $2; line[NR] = $3; n = NR; next }
        $2 == "start" { start[$1] = $3 }
        $2 == "end" { end_[$1] = $3; rc[$1] = $4 }
        END {
            for (i = 1; i <= n; i++) {
                if (i in end_) printf "%5ds rc=%-3s %-11s %-19s %s\n", end_[i] - start[i], rc[i], kind[i], sec[i], line[i]
                else if (i in start) printf "  ...  rc=?   %-11s %-19s %s\n", kind[i], sec[i], line[i]
                else printf "  -    not run %-11s %-19s %s\n", kind[i], sec[i], line[i]
                if (first == "" && (i in start)) first = start[i]
                if (firstrun == "" && kind[i] == "readme" && line[i] ~ /^kata run / && rc[i] == "0") firstrun = end_[i]
            }
            if (firstrun != "") printf "time to first run: %ds (first planned line start -> first kata run end)\n", firstrun - first
            else print "time to first run: not reached"
            dev = 0
            for (i = 1; i <= n; i++) if (kind[i] != "readme") dev++
            printf "deviations from README as written: %d planned line(s) of kind substituted/readme-bg/glue\n", dev
        }' "$plan_file" "$timing"
}

cmd_install() {
    load_vm
    qemu_pid >/dev/null || die "the VM is not running"
    [ -f "$vm/bundle.env" ] || die "no bundle pushed: run 'push-bundle <rev>' first"
    refuse_guest_token "an install step (install on a VM without it, and push the token after)"
    local commit
    commit=$(sed -n 's/^commit=//p' "$vm/bundle.env")
    run=$vm/install-$(date -u +%Y%m%dT%H%M%SZ)
    mkdir "$run"
    git -C "$repo" show "$commit:README.md" >"$run/README.md"
    plan "$run/README.md" "$commit" >"$run/plan.tsv"
    local sec
    for sec in "${readme_sections[@]}"; do
        grep -q "^$sec	readme" "$run/plan.tsv" \
            || printf 'README defect: section "## %s" has no ```sh command line\n' "$sec" >>"$run/defects.txt"
    done
    oracle_py >"$run/oracle.py"
    local n=0 rc=0 sections=("${readme_sections[@]}" Checks)
    for sec in "${sections[@]}"; do
        n=$((n + 1))
        section_script "$run/plan.tsv" "$sec" >"$run/section-$n.sh"
    done
    guest 'rm -rf ~/e9/run && mkdir -p ~/e9/run'
    local since
    since=$(guest 'date +%s')
    tar -C "$run" -cf - . | guest_in 'tar -C ~/e9/run -xf -'
    n=0
    for sec in "${sections[@]}"; do
        n=$((n + 1))
        note "section $n: $sec (log $run/section-$n.log)"
        rc=0
        guest "bash -l ~/e9/run/section-$n.sh" >"$run/section-$n.log" 2>&1 || rc=$?
        printf '%s\t%s\n' "$sec" "$rc" >>"$run/sections.tsv"
        if [ "$rc" != 0 ]; then
            note "section '$sec' FAILED (rc $rc); last lines:"
            tail -n 15 "$run/section-$n.log" >&2
            break
        fi
    done
    guest 'cat ~/e9/run/timing.tsv' >"$run/timing.tsv" || true
    guest 'for f in ~/e9/run/bg-*.log; do [ -f "$f" ] && { echo "== $f"; tail -n 40 "$f"; }; done' >"$run/bg-logs.txt" 2>&1 || true
    guest "sudo journalctl --no-pager -o short-iso --since @$since _COMM=sudo | grep -F COMMAND=" >"$run/guest-sudo.txt" 2>&1 || true
    summarize "$run/plan.tsv" "$run/timing.tsv" >"$run/summary.txt"
    {
        echo "commit: $commit"
        echo "run without a terminal (ssh, no tty, stdin /dev/null) and with passwordless guest sudo: a prompt that asks only on a tty took its non-interactive path"
        cat "$run/sections.tsv"
        [ -f "$run/defects.txt" ] && cat "$run/defects.txt"
        echo "planned lines that run sudo:"
        awk -F'\t' '$3 ~ /(^|[^[:alnum:]_-])sudo / { print "  " $2 ": " $3; n++ } END { if (!n) print "  (none)" }' "$run/plan.tsv"
        echo "sudo commands the guest journal recorded during the run (incl. sudo run by kata itself, and this script's journalctl):"
        sed 's/^/  /' "$run/guest-sudo.txt"
    } >>"$run/summary.txt"
    cat "$run/summary.txt"
    note "run directory: $run"
    [ "$rc" = 0 ]
}

cmd_self_test() {
    # The key leaves the environment at the script's start: the self-test runs itself again with a
    # canary key and a canary variable exported, and that run checks neither reaches a child.
    if [ -z "${E9_SELFTEST_CHILD:-}" ]; then
        E9_SELFTEST_CHILD=1 E9_SELFTEST_CANARY=canary-variable ANTHROPIC_API_KEY=sk-ant-selftest-canary \
            exec bash "${BASH_SOURCE[0]}" --self-test
    fi
    [ "$api_key" = sk-ant-selftest-canary ] || die "self-test: the key was not taken from the environment"
    [ -z "${ANTHROPIC_API_KEY+x}" ] || die "self-test: ANTHROPIC_API_KEY is still in this script's environment"
    [ "$(env | grep -c canary)" = 1 ] || die "self-test: a child sees the key (env names canary $(env | grep -c canary) times, the variable alone is 1)"
    local scrubbed_names
    scrubbed_names=$(scrubbed env | cut -d= -f1 | grep -vx TERM | sort | tr '\n' ' ')
    [ "$scrubbed_names" = "HOME PATH " ] || die "self-test: a scrubbed child sees $scrubbed_names, not HOME PATH (TERM)"
    local t
    t=$(mktemp -d)
    scratch+=("$t")
    # The plan, against a fixture README: sections, kinds, and the dropped sub-section.
    cat >"$t/README.md" <<'EOF'
# x
## Requirements
```sh
sudo apt-get install -y git   # a comment
# a comment-only line
```
## Install from source
```sh
git clone https://github.com/N0xMare/kata
cargo build \
  --release
```
### Alternative: install with Nix
```sh
nix profile install github:N0xMare/kata
```
## Quickstart
```text
## not a heading
```
```sh
kata serve   # terminal 1
kata run std.hello   # terminal 2
```
## Documentation
```sh
not-run
```
EOF
    local got want
    got=$(plan "$t/README.md" 0123 | cut -f1,2)
    want=$(printf '%s\n' "Requirements	readme" "Install from source	substituted" "Install from source	readme" \
        "Quickstart	glue" "Quickstart	readme-bg" "Quickstart	glue" "Quickstart	readme" \
        "Checks	glue" "Checks	glue" "Checks	glue" "Checks	glue" "Checks	glue" "Checks	glue")
    [ "$got" = "$want" ] || { printf 'plan kinds:\n%s\nwanted:\n%s\n' "$got" "$want" >&2; die "self-test: plan"; }
    # A here-string, not a pipe: under pipefail an early-exiting grep -q would SIGPIPE the plan.
    grep -qxF "Install from source	readme	cargo build   --release" <<<"$(plan "$t/README.md" 0123)" \
        || die "self-test: continuation"
    # The token-file refusals: each case must be refused for its own reason; a valid file passes.
    printf 'x' >"$t/ok" && chmod 600 "$t/ok"
    printf 'x' >"$t/wide" && chmod 644 "$t/wide"
    : >"$t/empty" && chmod 600 "$t/empty"
    ln -s "$t/ok" "$t/link"
    mkdir "$t/dir"
    local case expect out
    for case in "wide:mode 644, not 0600" "empty:is empty" "link:is a symlink" "dir:not a regular file" \
        "/etc/passwd:owned by uid 0"; do
        expect=${case#*:} case=${case%%:*}
        [ "${case#/}" = "$case" ] && case=$t/$case
        out=$( (validate_token_file "$case") 2>&1) && die "self-test: $case was accepted"
        [[ $out == *"$expect"* ]] || die "self-test: $case refused for the wrong reason: $out"
    done
    (validate_token_file "$t/ok") || die "self-test: a valid 0600 file was refused"
    # The API-key refusals: unset, empty and whitespace-holding values, each for its own
    # reason, and never echoing the value; a plain value passes.
    local key
    for case in "unset:is unset or empty" ":is unset or empty" "sk test:holds whitespace" \
        $'sk\ntest:holds whitespace' $'sk\ttest:holds whitespace'; do
        expect=${case##*:} key=${case%:*}
        if [ "$key" = unset ]; then
            out=$( (api_key=''; validate_api_key_env) 2>&1) && die "self-test: an unset key was accepted"
        else
            out=$( (api_key=$key; validate_api_key_env) 2>&1) && die "self-test: key ${case%%:*} was accepted"
        fi
        [[ $out == *"$expect"* ]] || die "self-test: key refused for the wrong reason: $out"
        [ -z "$key" ] || [ "$key" = unset ] || [[ $out != *"$key"* ]] || die "self-test: a refusal printed the key"
    done
    (api_key=sk-ant-selftest; validate_api_key_env) || die "self-test: a plain key was refused"
    # The E3 host cell's refusals, before anything runs: an unknown case, the mock or no agent,
    # a funded agent without KATA_E3_FUNDED=1, the anthropic agent without a key.
    out=$( (e3_test_of P5-host) 2>&1) && die "self-test: case P5-host was accepted"
    [[ $out == *"is no E3 host case"* ]] || die "self-test: P5-host refused for the wrong reason: $out"
    [ "$(e3_test_of P3-host)" = e3_p3_host_live ] || die "self-test: P3-host does not name its test"
    for case in ":must be nanocode-openai or nanocode-anthropic" "nanocode-mock:must be nanocode-openai" \
        "nanocode-openai:set KATA_E3_FUNDED=1"; do
        expect=${case#*:} key=${case%%:*}
        out=$( (unset KATA_E3_FUNDED; KATA_E3_AGENT=$key e3_host_agent) 2>&1) && die "self-test: agent '$key' was accepted"
        [[ $out == *"$expect"* ]] || die "self-test: agent '$key' refused for the wrong reason: $out"
    done
    out=$( (api_key=''; KATA_E3_AGENT=nanocode-anthropic KATA_E3_FUNDED=1 e3_host_agent) 2>&1) \
        && die "self-test: the anthropic host agent was accepted without a key"
    [[ $out == *"is unset or empty"* ]] || die "self-test: a keyless anthropic agent refused for the wrong reason: $out"
    [ "$(KATA_E3_AGENT=nanocode-openai KATA_E3_FUNDED=1 e3_host_agent)" = nanocode-openai ] \
        || die "self-test: a funded nanocode-openai host agent was refused"
    # The key goes to the anthropic agent's stdin only; the openai agent gets an empty line.
    [ "$(api_key=sk-ant-selftest; e3_key_line nanocode-anthropic)" = sk-ant-selftest ] \
        || die "self-test: the anthropic agent was not sent the key"
    [ "$(api_key=sk-ant-selftest; e3_key_line nanocode-openai | od -An -c | tr -d ' ')" = '\n' ] \
        || die "self-test: the openai agent was sent more than an empty line"
    # E3-host's own refusals before anything runs: no out directory; --retire of an unknown case.
    out=$( (KATA_E3_AGENT=nanocode-openai KATA_E3_FUNDED=1 cmd_e3_host P1-host) 2>&1) \
        && die "self-test: e3-host without an out directory was accepted"
    [[ $out == *"<out-dir>"* ]] || die "self-test: e3-host without an out directory refused for the wrong reason: $out"
    out=$( (cmd_e3_host --retire P5-host) 2>&1) && die "self-test: --retire P5-host was accepted"
    [[ $out == *"is no E3 host case"* ]] || die "self-test: --retire P5-host refused for the wrong reason: $out"
    # The forge-token check: held refuses, naming the step; absent passes; an ssh failure refuses.
    out=$( (token_verdict 0 "an E3 host cell") 2>&1) && die "self-test: a held token was accepted"
    [[ $out == *"an E3 host cell never runs with it (drop-token first)"* ]] \
        || die "self-test: a held token refused for the wrong reason: $out"
    (token_verdict 1 x) || die "self-test: an absent token was refused"
    out=$( (token_verdict 255 x) 2>&1) && die "self-test: an unanswered token check was accepted"
    [[ $out == *"cannot check the guest for a forge token (ssh rc 255)"* ]] \
        || die "self-test: an unanswered token check refused for the wrong reason: $out"
    # block-providers' answer check: exactly loopback on both families; one family, a routable
    # address or no answer each refuse.
    loopback_only h $'127.0.0.1 STREAM h\n127.0.0.1 DGRAM\n::1 STREAM\n::1 RAW' \
        || die "self-test: a loopback-only answer was refused"
    for case in $'127.0.0.1 STREAM h' $'127.0.0.1 STREAM h\n::1 STREAM\n2606:4700::1 STREAM' \
        $'160.79.104.10 STREAM h' ''; do
        out=$( (loopback_only h "$case") 2>&1) && die "self-test: the answer [$case] was accepted"
        [[ $out == *"not exactly 127.0.0.1 and ::1"* ]] || die "self-test: [$case] refused for the wrong reason: $out"
    done
    # The stand-in itself, served here on a free loopback port under a CA its own cert script made:
    # through that CA, on each family, the control gets the plan; any other messages request gets
    # `done`, any other path or method 404, each logged; without the CA the control refuses.
    mkdir "$t/standin"
    (cd "$t/standin" && bash -s) <<<"$(standin_certs_script)" || die "self-test: the stand-in's cert script failed"
    local port standin_pid standin_rc=0
    port=$(free_port)
    python3 -I "$repo/scripts/e9-standin-provider.py" "$t/standin/chain.crt" "$t/standin/leaf.key" \
        "$t/standin/req.log" "$port" >"$t/standin/server.out" 2>&1 &
    standin_pid=$!
    (
        set -euo pipefail
        for _ in $(seq 100); do grep -qs '"started"' "$t/standin/req.log" && break; sleep 0.1; done
        grep -qs '"started"' "$t/standin/req.log" || die "self-test: the stand-in did not start: $(cat "$t/standin/server.out")"
        trust="--cacert $t/standin/ca.crt --resolve api.anthropic.com:$port:127.0.0.1,[::1]"
        out=$(bash -s "$port" "$trust" <<<"$(standin_control_script)" 2>&1) \
            || die "self-test: the control refused the stand-in: $out"
        [ "$(grep -c 'got the plan stream' <<<"$out")" = 2 ] || die "self-test: the control did not pass both families: $out"
        out=$(bash -s "$port" "--resolve api.anthropic.com:$port:127.0.0.1,[::1]" <<<"$(standin_control_script)" 2>&1) \
            && die "self-test: the control passed a stand-in it does not trust: $out"
        [[ $out == *"curl -4 failed"* ]] || die "self-test: the untrusted control refused for the wrong reason: $out"
        # shellcheck disable=SC2086
        out=$(curl -sS -m 10 $trust "https://api.anthropic.com:$port/v1/messages" -d '{}')
        [[ $out == *'"text": "done"'* && $out != *src/app.txt* ]] || die "self-test: a non-plan request got: $out"
        # shellcheck disable=SC2086
        for probe in "-X GET https://api.anthropic.com:$port/v1/messages" "-d {} https://api.anthropic.com:$port/v1/other"; do
            code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 $trust $probe)
            [ "$code" = 404 ] || die "self-test: the stand-in answered [$probe] $code, not 404"
        done
        [ "$(grep -c '"plan": true' "$t/standin/req.log")" = 2 ] && [ "$(grep -c '"plan": false' "$t/standin/req.log")" = 1 ] \
            && [ "$(grep -c '"answer": 404' "$t/standin/req.log")" = 2 ] \
            || die "self-test: the stand-in's log is not the requests made: $(cat "$t/standin/req.log")"
    ) || standin_rc=$?
    kill "$standin_pid"
    wait "$standin_pid" 2>/dev/null || true   # its TERM status
    [ "$standin_rc" = 0 ] || die "self-test: the stand-in (above)"
    # The real commands, driven in a copy of this script whose VM-facing functions are stubs that
    # log each guest call (every other byte, the EXIT trap included, is this script's own):
    # install, e3-prep and e3-host check for the forge token BEFORE any other guest call, and
    # an e3-host cell that dies before its resume is still copied out by the EXIT trap, without
    # the node's worker secret. The copy sits in a scratch repository whose commit holds the
    # fixture README, so install could reach every guest call past its README read.
    local copy=$t/repo/scripts/e9-vm-stubbed.sh calls=$t/calls commit
    mkdir -p "$t/repo/scripts"
    cp "$repo/scripts/e9-standin-provider.py" "$t/repo/scripts/"   # standin-provider copies it from beside the script
    git -C "$t/repo" init -q
    cp "$t/README.md" "$t/repo/README.md"
    git -C "$t/repo" add README.md
    git -C "$t/repo" -c user.name=e9 -c user.email=e9@self-test -c commit.gpgsign=false commit -qm fixture
    commit=$(git -C "$t/repo" rev-parse HEAD)
    cat >"$t/stubs.sh" <<'EOF'
load_vm() { :; }
qemu_pid() { echo 1; }
cmd_kill_host() { echo kill-host >>"$E9_STUB_CALLS"; }
cmd_start() { echo start >>"$E9_STUB_CALLS"; }
guest_in() {
    cat >/dev/null
    printf 'guest %s\n' "$*" >>"$E9_STUB_CALLS"
    case $* in
        *'getent ahosts'*) if [ -n "${E9_STUB_LOOPBACK:-}" ]; then printf '127.0.0.1 STREAM h\n::1 STREAM\n'; fi ;;
        *'.config/e9/gh-token'*) return "$E9_STUB_TOKEN" ;;
        *kill.request* | *'e3-host.sh arm'*) return 1 ;;
    esac
}
EOF
    awk -v stubs="$t/stubs.sh" '/^case \$\{1:-\} in$/ { while ((getline line < stubs) > 0) print line } { print }' \
        "${BASH_SOURCE[0]}" >"$copy"
    grep -qx 'qemu_pid() { echo 1; }' "$copy" || die "self-test: the stubs did not go in before the dispatch"
    mkdir -p "$t/state/vm" && printf 'commit=%s\n' "$commit" >"$t/state/vm/bundle.env"
    stubbed() {
        : >"$calls"
        E9_STUB_CALLS=$calls E9_STUB_TOKEN=$1 KATA_E9_VM_DIR=$t/state KATA_E3_AGENT=nanocode-openai \
            KATA_E3_FUNDED=1 bash "$copy" "${@:2}" </dev/null 2>&1
    }
    for case in install e3-prep e3-host; do
        local args=("$case")
        [ "$case" = e3-host ] && args+=(P1-host "$t/out")
        out=$(stubbed 0 "${args[@]}") && die "self-test: $case ran while the guest held the forge token"
        [[ $out == *"refused: the guest holds the forge token"* ]] || die "self-test: $case refused for the wrong reason: $out"
        [ "$(cat "$calls")" = 'guest test -e ~/.config/e9/gh-token' ] \
            || die "self-test: $case called the guest before (or beside) its token check: $(tr '\n' ';' <"$calls")"
    done
    out=$(stubbed 1 e3-host P1-host "$t/out") && die "self-test: an arm phase that never asked for the kill was accepted"
    [[ $out == *"the arm phase ended without asking for the kill"* ]] || die "self-test: the dead arm refused for the wrong reason: $out"
    if ! grep -q '^guest cd ~/e3-evidence' "$calls" || ! grep -q '^guest test -d ~/e3-state/P1-host/data' "$calls"; then
        die "self-test: the EXIT trap did not copy the dead cell out: $(tr '\n' ';' <"$calls")"
    fi
    grep '^guest test -d ~/e3-state/P1-host/data' "$calls" | grep -qF -- '--exclude=./local-worker.secret' \
        || die "self-test: the copy-out carries the node's local-worker.secret: $(grep '/data' "$calls")"
    ! grep -qx kill-host "$calls" || die "self-test: the dead arm still killed the VM"
    compgen -G "$t/out/e3-P1-host-*/evidence" >/dev/null || die "self-test: no copy-out directory for the dead cell"
    # standin-provider: refused before any other guest call unless every provider host is on
    # loopback; once they are, the copy, the certs, the CA, the start and the control, in order.
    out=$(stubbed 1 standin-provider) && die "self-test: standin-provider ran with the provider hosts unblocked"
    [[ $out == *"not exactly 127.0.0.1 and ::1"* ]] || die "self-test: the unblocked stand-in refused for the wrong reason: $out"
    [ "$(cat "$calls")" = 'guest getent ahosts api.anthropic.com' ] \
        || die "self-test: standin-provider called the guest past its loopback check: $(tr '\n' ';' <"$calls")"
    out=$(E9_STUB_LOOPBACK=1 stubbed 1 standin-provider) || die "self-test: standin-provider refused loopback providers: $out"
    want=$(printf 'guest getent ahosts %s\n' api.anthropic.com api.openai.com chatgpt.com auth.openai.com)
    [ "$(head -n 4 "$calls")" = "$want" ] && sed -n 5p "$calls" | grep -qF 'cat >~/e9/standin/standin.py' \
        && sed -n 6p "$calls" | grep -qF 'cd ~/e9/standin && bash -s' \
        && sed -n 7p "$calls" | grep -qF 'update-ca-certificates' \
        && sed -n 8p "$calls" | grep -qF 'standin.py chain.crt leaf.key' \
        && [ "$(sed -n '9,$p' "$calls")" = "guest bash -s 443 ''" ] \
        || die "self-test: standin-provider's guest calls are not check, copy, certs, CA, start, control: $(tr '\n' ';' <"$calls")"
    # The RUNBOOK's E9 block runs as ONE `bash <<'EOF'`, so the commands' stdin is the rest of
    # that script: push-token, login-anthropic and drop-token, through the real `guest` and a
    # fake `ssh` that drains its stdin as ssh forwards it, must leave the script's later lines to
    # bash, while each call that feeds the guest still delivers what it feeds.
    local hcopy=$t/repo/scripts/e9-vm-heredoc.sh ssh_calls=$t/ssh-calls
    mkdir -p "$t/fakessh"
    cat >"$t/fakessh/ssh" <<EOF
#!/usr/bin/env bash
cmd=\${!#}
head -n 1 <<<"\$cmd" >>"$ssh_calls"
case \$cmd in
    *'cat > ~/.config/e9/gh-token'*) sha256sum | cut -d' ' -f1 >"$t/fake-token.sha" ;;
    *'kata login anthropic --api-key'*) cat >"$t/fake-key" ;;
    *'sha256sum < ~/.config/e9/gh-token'*) cat >/dev/null; printf '%s  -\n' "\$(cat "$t/fake-token.sha")" ;;
    *'kata login status'*) cat >/dev/null; echo 'anthropic-api-key: an API key is stored' ;;
    *) cat >/dev/null ;;
esac
EOF
    chmod +x "$t/fakessh/ssh"
    printf '%s\n' 'load_vm() { ssh_opts=(); }' 'qemu_pid() { echo 1; }' >"$t/vmstubs.sh"
    awk -v stubs="$t/vmstubs.sh" '/^case \$\{1:-\} in$/ { while ((getline line < stubs) > 0) print line } { print }' \
        "${BASH_SOURCE[0]}" >"$hcopy"
    : >"$ssh_calls"
    out=$(PATH="$t/fakessh:$PATH" KATA_E9_VM_DIR=$t/state ANTHROPIC_API_KEY=sk-ant-selftest-heredoc bash 2>&1 <<EOF
bash "$hcopy" push-token "$t/ok"
echo "heredoc: after push-token"
bash "$hcopy" login-anthropic
echo "heredoc: after login-anthropic"
bash "$hcopy" drop-token
echo "heredoc: after drop-token"
EOF
    ) || die "self-test: the heredoc-driven push-token, login-anthropic, drop-token failed: $out"
    [ "$(grep -c '^heredoc: after ' <<<"$out")" = 3 ] \
        || die "self-test: a guest call swallowed the rest of a heredoc-fed script: $out"
    [ "$(cat "$t/fake-token.sha")" = "$(sha256sum <"$t/ok" | cut -d' ' -f1)" ] \
        || die "self-test: push-token did not stream the token file to the guest"
    [ "$(cat "$t/fake-key")" = sk-ant-selftest-heredoc ] || die "self-test: login-anthropic did not stream the key to the guest"
    want=$(printf '%s\n' 'umask 077 && mkdir -p ~/.config/e9 && cat > ~/.config/e9/gh-token && chmod 600 ~/.config/e9/gh-token' \
        'sha256sum < ~/.config/e9/gh-token' 'bash -l -c "kata login anthropic --api-key"' 'bash -l -c "kata login status"' \
        'rm -f ~/.config/e9/gh-token && test ! -e ~/.config/e9/gh-token')
    [ "$(cat "$ssh_calls")" = "$want" ] || die "self-test: the heredoc run's guest calls are not push, check, login, status, drop: $(tr '\n' ';' <"$ssh_calls")"
    echo "e9-vm self-test: ok"
}

case ${1:-} in
    create) cmd_create ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    ssh) shift; cmd_ssh "$@" ;;
    push-bundle) shift; cmd_push_bundle "$@" ;;
    push-token) shift; cmd_push_token "$@" ;;
    login-anthropic) cmd_login_anthropic ;;
    e3-prep) cmd_e3_prep ;;
    e3-host) shift; cmd_e3_host "$@" ;;
    drop-token) cmd_drop_token ;;
    install) cmd_install ;;
    kill-host) cmd_kill_host ;;
    block-providers) cmd_block_providers ;;
    standin-provider) cmd_standin_provider ;;
    destroy) shift; cmd_destroy "$@" ;;
    --self-test) cmd_self_test ;;
    *) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
