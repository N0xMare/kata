#!/usr/bin/env bash
# Print "<name>: <line count>" for every .txt file in the given directory,
# sorted by name. Must handle names containing spaces.
set -euo pipefail
dir=$1
shopt -s nullglob
files=("$dir"/*.txt)
IFS=$'\n' sorted=($(printf '%s\n' "${files[@]}" | sort))
unset IFS
for f in "${sorted[@]}"; do
  printf '%s: %s\n' "$(basename "$f")" "$(wc -l < "$f")"
done
