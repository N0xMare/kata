#!/usr/bin/env bash
set -euo pipefail

run() {
  if [ "$1" = "go" ]; then
    echo "going"
  fi
}

run "${1:-stop}"
