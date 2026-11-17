#!/usr/bin/env bash
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf 'a\nb\n'        > "$work/alpha.txt"
printf 'x\ny\nz\n'     > "$work/two words.txt"
printf 'q\n'           > "$work/zeta.txt"
got="$(bash count.sh "$work")"
want="alpha.txt: 2
two words.txt: 3
zeta.txt: 1"
if [ "$got" != "$want" ]; then
  echo "MISMATCH" >&2; echo "--- got ---" >&2; echo "$got" >&2
  echo "--- want ---" >&2; echo "$want" >&2; exit 1
fi
