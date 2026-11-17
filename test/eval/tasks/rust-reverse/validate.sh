#!/usr/bin/env bash
set -euo pipefail
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
rustc --edition 2021 --test lib.rs -o "$out/t" 2>&1
"$out/t"
