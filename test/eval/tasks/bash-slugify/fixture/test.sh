#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/dev/null
source ./slug.sh
got="$(slugify 'Hello World')"
[ "$got" = "hello-world" ] || { echo "slugify 'Hello World' = $got, want hello-world" >&2; exit 1; }
got="$(slugify 'Kata Rocks!')"
[ "$got" = "kata-rocks" ] || { echo "slugify 'Kata Rocks!' = $got, want kata-rocks" >&2; exit 1; }
echo ok
