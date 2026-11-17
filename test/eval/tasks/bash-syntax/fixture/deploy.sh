#!/usr/bin/env bash
set -euo pipefail

run() {
  if [ "$1" = "go" ]
    echo "going"
  fi
}

run "${1:-stop}"
