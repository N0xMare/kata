#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/dev/null
source ./lib.sh
got="$(add 2 3)"
[ "$got" = "5" ]  || { echo "add 2 3 = $got, want 5" >&2; exit 1; }
got="$(add 10 20)"
[ "$got" = "30" ] || { echo "add 10 20 = $got, want 30" >&2; exit 1; }
echo ok
