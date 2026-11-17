#!/usr/bin/env bash
set -euo pipefail
# Syntax must parse...
bash -n deploy.sh
# ...AND the behavior must survive (bash -n alone passes on a
# truncated-to-empty file — a destructive "fix" must not count as solved).
out="$(bash -c 'source ./deploy.sh && run go')"
[ "$out" = "going" ] || { echo "expected 'going' from run go, got: $out" >&2; exit 1; }
