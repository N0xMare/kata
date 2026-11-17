#!/usr/bin/env bash
# e2-oracles.sh EV: the E2 oracles, read from outside kata (RUNBOOK §4, §4b).
# Run from the clone AFTER `kata run wait <exec>` returned (EV/exec names the
# execution, EV/trunk-before.txt the trunk tip the run started from).
# E2_VARIANT (optional) is the variant the round runs: `refine-addendum` for a
# counted parity run, `refine-cell` for the refine cell (RUNBOOK §4, §4b).
#
# One PASS/FAIL line per oracle into EV/oracles.txt; exit 0 only when all pass:
#   terminal-completed  the execution is `completed` (second read-only handle)
#   variant             the invocation's task text is a kit variant
#                       (`ledger.py variant`), equal to E2_VARIANT when set
#   commit-subject      trunk's tip is kata's commit for this execution
#   parent-is-trunk     its parent is trunk-before
#   tip-not-empty       its tree differs from its parent's
#   remote-branch       origin's refs/heads/kata/<exec> == the tip
#   one-open-pr         exactly one open PR has kata/<exec> as head and main as base
#   clone-check         a fresh clone at the tip (E2_CLONES/<run>, outside EV)
#                       passes `sh tests/check.sh`
#   oracle-e2           the held-out wrap oracle passes (capped scope, HOME=/tmp)
# and, only when the variant is `refine-cell` (the refine cell, RUNBOOK §4b):
#   gate-bound, gate-unseen, refined, final-gate
#                       `ledger.py refinecheck` (the held-out gate reached the
#                       test stage; no prompt holds its source in a form
#                       `gate_leaks` names; the loop refined; the last
#                       iteration passed the whole gate, its house
#                       conventions C1..C3 and functional checks G1..G22)
#   gate-unnamed        no member of the tip's tree names the gate's capsule
#                       path literally (a file's text, a symlink's target, the
#                       member's path) or holds its source (`ledger.py
#                       --leakscan --tree`: at least one member scanned, none
#                       with a leak); a path assembled at run time passes it
#   clone-gate          the gate (conventions + functional), run here on the
#                       tip's tree, passes
#   oracle-align        the held-out align SCORING set passes (capped scope)
# and last, always:
#   kit-intact          no candidate run changed the kit (below)
#
# CANDIDATE CODE RUNS ON THIS HOST AS THIS USER (clone-check, and inside
# oracle-e2, clone-gate and oracle-align), with resource caps but no
# filesystem isolation: neither bwrap (no unprivileged user namespace here)
# nor a user service's ReadOnlyPaths= is available (both probed 2026-11-02).
# So the kit scripts are never read from the kit itself after candidate code
# has run: they run from a SNAPSHOT copied before the first candidate run,
# whose sha256 manifest is held in this process's memory. After every capped
# run its scope is stopped (killing anything it left behind) and the
# snapshot, the live kit and the clone's HEAD are re-checked against the
# manifest and the tip; once one differs, no later kit oracle runs (each
# reads FAIL) and `kit-intact` FAILs. Each kit oracle gets its own fresh
# clone of the tip, made after the previous run was stopped (a clone at a
# sha is content-pinned by fetch's object hashing); oracle-e2 or oracle-align
# whose clone fails (the clone, its checkout at the tip or its HEAD check)
# reads `FAIL <oracle>: clone failed`, never no line, and leaves no half-made
# clone for intact() to read as a moved HEAD (the first clone, `check`,
# failing stops the script: exit 2, no oracles.txt; prove.sh §4 forces both
# later clones, and oracle-e2's checkout, to fail). This file is parsed whole
# before it runs (main below), so rewriting it on disk changes nothing.
# Refused: a PERSISTENT change, by a candidate run, to any kit file or to the
# clone's HEAD. Not refused: same-user code that changes a file and restores it
# within its own run, or moves itself out of its scope's cgroup first.
#
# The tree checks (clone-check, oracle-e2, clone-gate, oracle-align) run on
# the CAPSULE's tool set, not the host's: PATH is the clone's
# `[node.environment] path_prepend` (.kata/kata.toml), so `sh` and every
# utility is the capsule's BusyBox, as in kata's test stage. The host `sh`
# here is dash, whose `printf "$1"` reads a format that starts with `-` as an
# option: the fixture's own `run`/`check` helpers then feed and expect nothing,
# so a test whose stdin starts with `-` passes VACUOUSLY on dash (measured
# 2026-11-02: t_align's `run '-1.5\n20\n'` -> "Illegal option -1", and the
# B3 mutants survived) while it is real in the capsule.
#
# EV/observed.toml holds the record's OBSERVED fields, which are never pass
# conditions of a parity run: `variant` and `refined` (`ledger.py refined`:
# "yes" when test#iter-0 failed and a later iteration ran).
#
# EV/stages.txt, EV/turns.txt and EV/spend.toml hold `ledger.py stages`,
# `turns` and `record` (the record's spend lines). When one of those exits
# non-zero (e.g. `record` refuses a charge kata priced that evidence-page.py
# PRICED does not admit; `turns` a missing session-evidence blob) its file
# holds ONE line, `FAIL stages-read|turns-read|spend-read: ledger.py VERB
# exit N: <its last stderr line>`, printed too, and the script exits 3
# whatever the oracles said: STOP, no record is written until ledger.py
# reads the kept data dir (RUNBOOK §4). These are not oracles.txt lines: the
# evidence page judges an E2 run by exactly 10 (pr) or 18 (refine) oracle
# lines, and a ledger read judges the evidence, not the candidate.
#
# Exit: 0 every oracle passed; 1 an oracle failed; 2 usage or setup (no
# oracles.txt); 3 a ledger read of the record failed (oracles.txt written).
set -uo pipefail

main() {
	[ $# -eq 1 ] || { echo "usage: e2-oracles.sh EV" >&2; return 2; }
	local EV=$1 KLIVE D EXEC REPO CL K MANIFEST CAPSULE_PATH CAPSULE_SH C n=0 broken= fails=0 ORACLES=
	KLIVE=$(cd -P -- "$(dirname -- "$0")" && pwd)
	D=$PWD/.kata/data
	EXEC=$(cat "$EV/exec")
	REPO=N0xMare/kata-e2-fixture
	# The fresh clones live OUTSIDE the run directory (every file there is a listed
	# artifact of the record): under E2_CLONES (default ~/ke/oracle-clones), one
	# directory per run, one clone per kit oracle in it.
	CL=${E2_CLONES:-$HOME/ke/oracle-clones}/$(basename "$EV")
	[ ! -e "$CL" ] || { echo "e2-oracles: $CL exists; remove it or set E2_CLONES" >&2; return 2; }
	[ ! -e "$EV/oracles.txt" ] || { echo "e2-oracles: $EV/oracles.txt exists; one judgement per run" >&2; return 2; }
	mkdir -p "$CL"
	CAPSULE_PATH=$(python3 -I -c 'import sys, tomllib; print(":".join(tomllib.load(open(sys.argv[1], "rb"))["node"]["environment"]["path_prepend"]))' .kata/kata.toml) ||
		{ echo "e2-oracles: no [node.environment] path_prepend in .kata/kata.toml" >&2; return 2; }
	CAPSULE_SH=$(PATH=$CAPSULE_PATH command -v sh)
	case $CAPSULE_SH in */nix/store/*busybox*/bin/sh) ;; *) echo "e2-oracles: the capsule PATH's sh is $CAPSULE_SH, not BusyBox" >&2; return 2 ;; esac
	echo "PATH=$CAPSULE_PATH" >"$EV/capsule-path.txt"

	# The kit snapshot (above): every kit file but backups and caches, read-only.
	K=$CL/kit
	mkdir "$K"
	tar -C "$KLIVE" --exclude='*.bak-*' --exclude=__pycache__ -cf - . | tar -C "$K" -xf - || { echo "e2-oracles: cannot snapshot the kit" >&2; return 2; }
	chmod -R a-w "$K"
	MANIFEST=$(cd "$K" && find . -type f -print0 | sort -z | xargs -0 sha256sum)
	printf '%s\n' "$MANIFEST" >"$EV/kit-sha256.txt"

	oracle() {
		local line
		if [ "$2" = 0 ]; then line="PASS $1"; else line="FAIL $1${3:+: $3}"; fails=$((fails + 1)); fi
		echo "$line"
		ORACLES+="$line"$'\n'
	}
	# intact: the snapshot and the live kit match the manifest, the clones' HEADs the tip.
	intact() {
		local d
		[ -z "$broken" ] || return 1 # the first change found is the one reported
		(cd "$K" && printf '%s\n' "$MANIFEST" | sha256sum -c --quiet --strict) >/dev/null 2>&1 || { broken="the kit snapshot changed after $1"; return 1; }
		(cd "$KLIVE" && printf '%s\n' "$MANIFEST" | sha256sum -c --quiet --strict) >/dev/null 2>&1 || { broken="the live kit changed after $1"; return 1; }
		for d in "$CL"/c-*; do
			[ -d "$d" ] || continue
			[ "$(git -C "$d" rev-parse HEAD 2>/dev/null)" = "$C" ] || { broken="clone $(basename "$d")'s HEAD moved after $1"; return 1; }
		done
	}
	# capped LABEL DIR CMD...: CMD in DIR in its own scope; the scope is stopped
	# after, then intact. Never in a subshell: `broken` must reach main.
	capped() {
		local label=$1 dir=$2 unit rc
		shift 2
		n=$((n + 1))
		unit=e2-oracles-$$-$n
		systemd-run --user --scope -q --unit="$unit" -p TasksMax=64 -p MemoryMax=512M -p RuntimeMaxSec=900 \
			env -C "$dir" HOME=/tmp PATH="$CAPSULE_PATH" "$@"
		rc=$?
		systemctl --user stop "$unit.scope" >/dev/null 2>&1
		intact "$label"
		return $rc
	}
	# fresh NAME: a new clone of origin at the tip, under CL; prints its path. A clone
	# whose checkout or HEAD check fails is removed, so intact() never reads a
	# half-made clone as a moved HEAD; a c-NAME that already exists is no clone of
	# ours and is left for intact() to judge.
	fresh() {
		[ ! -e "$CL/c-$1" ] || return 1
		git clone -q "$(git remote get-url origin)" "$CL/c-$1" || return 1
		if git -C "$CL/c-$1" checkout -q --detach "$C" &&
			[ "$(git -C "$CL/c-$1" rev-parse HEAD)" = "$C" ]; then
			printf '%s\n' "$CL/c-$1"
			return 0
		fi
		rm -rf "$CL/c-$1"
		return 1
	}
	# guard NAME: refuse a kit oracle once the kit or a clone changed.
	guard() {
		[ -z "$broken" ] && return 0
		oracle "$1" 1 "not run: $broken"
		return 1
	}

	local state variant subject c rest line
	state=$(python3 -I "$K/ledger.py" "$D" execs | awk -v e="$EXEC" '$1 == e {print $4}')
	[ "$state" = completed ]
	oracle terminal-completed $? "state $state"
	variant=$(python3 -I "$K/ledger.py" "$D" variant "$EXEC" | sed -n 's/^variant = "\(.*\)"$/\1/p')
	if [ -n "${E2_VARIANT:-}" ]; then [ "$variant" = "$E2_VARIANT" ]; else [ -n "$variant" ] && [ "$variant" != unknown ]; fi
	oracle variant $? "variant ${variant:-unreadable}${E2_VARIANT:+, want $E2_VARIANT}"
	C=$(git rev-parse main)
	echo "$C" >"$EV/tip.txt"
	subject=$(git log -1 --format=%s "$C")
	[ "$subject" = "kata workspace_effect commit for execution $EXEC" ]
	oracle commit-subject $? "$subject"
	[ "$(git rev-parse "$C^")" = "$(cat "$EV/trunk-before.txt")" ]
	oracle parent-is-trunk $?
	[ "$(git rev-parse "$C^{tree}")" != "$(git rev-parse "$C^^{tree}")" ]
	oracle tip-not-empty $?
	git ls-remote origin "refs/heads/kata/$EXEC" >"$EV/remote-branch.txt"
	[ "$(cut -f1 "$EV/remote-branch.txt")" = "$C" ]
	oracle remote-branch $? "$(cat "$EV/remote-branch.txt")"
	gh pr list --repo "$REPO" --state open --head "kata/$EXEC" --json number,baseRefName,headRefOid >"$EV/pr.json"
	python3 -I -c 'import json,sys; prs=json.load(open(sys.argv[1])); sys.exit(0 if len(prs) == 1 and prs[0]["baseRefName"] == "main" and prs[0]["headRefOid"] == sys.argv[2] else 1)' "$EV/pr.json" "$C"
	oracle one-open-pr $? "$(cat "$EV/pr.json")"
	echo "$CL" >"$EV/clone-path.txt"
	# Everything the host reads OF the tip is read before any candidate code runs.
	c=$(fresh check) || { echo "e2-oracles: cannot clone the tip" >&2; return 2; }
	git -C "$c" archive --format=tar -o "$CL/tip.tar" "$C"
	python3 -I "$K/ledger.py" "$D" iterations "$EXEC" >"$EV/test-iterations.txt"
	python3 -I "$K/ledger.py" "$D" refined "$EXEC" >"$EV/refined.txt"
	if [ "$variant" = refine-cell ]; then
		python3 -I "$K/ledger.py" "$D" refinecheck "$EXEC" "$(python3 -I "$K/refine-pack.py" --test-command)" >"$EV/refinecheck.txt"
		python3 -I "$K/ledger.py" --leakscan --tree "$CL/tip.tar" >"$EV/gate-unnamed.txt"
	fi

	capped clone-check "$c" sh tests/check.sh >"$EV/clone-check.txt" 2>&1
	oracle clone-check $? "$(tail -n 1 "$EV/clone-check.txt")"
	if guard oracle-e2; then
		if c=$(fresh oracle-e2); then
			capped oracle-e2 "$PWD" sh "$K/oracle-e2.sh" "$c" >"$EV/oracle.txt" 2>&1
			oracle oracle-e2 $? "$(grep '^oracle-e2: [0-9]' "$EV/oracle.txt")"
		else
			oracle oracle-e2 1 "clone failed"
		fi
	fi
	if [ "$variant" = refine-cell ]; then
		# Its `variant` line repeats the oracle above; every other PASS/FAIL line is an oracle.
		while IFS= read -r line; do
			case $line in
			'PASS variant' | 'FAIL variant'*) ;;
			PASS\ *) oracle "${line#PASS }" 0 ;;
			FAIL\ *) rest=${line#FAIL }; oracle "${rest%%:*}" 1 "${rest#*: }" ;;
			esac
		done <"$EV/refinecheck.txt"
		grep -q '^refinecheck: ' "$EV/refinecheck.txt"
		oracle refinecheck-ran $? "ledger.py refinecheck printed no summary (see refinecheck.txt)"
		grep -q '^leakscan: [1-9][0-9]* text(s) scanned, 0 with a leak$' "$EV/gate-unnamed.txt"
		oracle gate-unnamed $? "$(head -n 1 "$EV/gate-unnamed.txt")"
		if guard clone-gate; then
			mkdir "$CL/gate-tree"
			tar -C "$CL/gate-tree" -xf "$CL/tip.tar"
			chmod -R a-w "$CL/gate-tree"
			capped clone-gate "$CL/gate-tree" sh "$K/gate/align-gate.sh" >"$EV/clone-gate.txt" 2>&1
			oracle clone-gate $? "$(tail -n 1 "$EV/clone-gate.txt")"
		fi
		if guard oracle-align; then
			if c=$(fresh oracle-align); then
				capped oracle-align "$PWD" sh "$K/oracle-align.sh" "$c" >"$EV/oracle-align.txt" 2>&1
				oracle oracle-align $? "$(grep '^oracle-align: [0-9]' "$EV/oracle-align.txt")"
			else
				oracle oracle-align 1 "clone failed"
			fi
		fi
	fi
	intact "the last oracle"
	[ -z "$broken" ]
	oracle kit-intact $? "$broken"
	{
		echo "# e2-oracles.sh: the record's OBSERVED fields, read through ledger.py's read-only handle"
		echo "variant = \"${variant:-unknown}\""
		grep '^refined = ' "$EV/refined.txt"
		sed -n 's/^\(iterations\|final_test\) = /# &/p' "$EV/refined.txt"
		sed -n 's/^INFO \(\(refine_cause\|iter0_gate_fails\) = .*\)$/# \1/p' "$EV/refinecheck.txt" 2>/dev/null
	} >"$EV/observed.toml"
	# The record's ledger reads. A failed read never leaves its file empty: the file holds
	# `FAIL NAME-read: ...` instead (spend.toml's is not TOML, so no field can be copied from
	# it), and the script exits 3 whatever the oracles said (header: no record until ledger.py
	# reads the kept data dir).
	local read_fails=
	# ledger_read NAME VERB FILE: `ledger.py VERB EXEC` into EV/FILE, or its FAIL line.
	ledger_read() {
		local rc line
		python3 -I "$K/ledger.py" "$D" "$2" "$EXEC" >"$CL/$2.out" 2>"$CL/$2.err"
		rc=$?
		if [ "$rc" = 0 ]; then
			cp "$CL/$2.out" "$EV/$3"
			return 0
		fi
		# The last stderr line names the error: a refusal's one line, a traceback's exception.
		line="FAIL $1-read: ledger.py $2 exit $rc: $(tail -n 1 "$CL/$2.err" | tr -d '\r')"
		printf '%s\n' "$line" >"$EV/$3"
		read_fails+="$line"$'\n'
	}
	ledger_read stages stages stages.txt
	ledger_read turns turns turns.txt
	ledger_read spend record spend.toml
	# Written last, in one piece, from memory: nothing a candidate run wrote into EV survives here.
	printf '%s' "$ORACLES" >"$EV/oracles.txt"
	printf '%s' "$read_fails"
	echo "e2-oracles: $fails oracle(s) failed ($(grep -c . "$EV/oracles.txt") oracles; observed: $(grep -v '^#' "$EV/observed.toml" | tr '\n' ' '))"
	[ -z "$read_fails" ] || return 3
	[ "$fails" = 0 ]
}
main "$@"
exit $?
