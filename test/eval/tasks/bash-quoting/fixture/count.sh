#!/usr/bin/env bash
# Print "<name>: <line count>" for every .txt file in the given directory,
# sorted by name. Must handle names containing spaces.
set -euo pipefail
dir=$1
for f in $(ls $dir/*.txt); do
  echo "$(basename $f): $(wc -l < $f)"
done
