#!/usr/bin/env bash
#
# The source-tree baseline a required tier compares against at `just
# source-tree-unchanged` (scripts/source-tree-guard.py states what that refuses).
#
# Sourced, for gate-timing.sh's reason: the baseline must be visible to every child
# `just` process of the tier, so the tier ROOT takes it and exports its path, and a
# nested tier (`gate-hosted` running both cores) reuses the outer one rather than
# re-baselining mid-run — a second baseline would silently absorb whatever the first
# half of the run wrote.
#
# The file lives at a FIXED path under `target/`, overwritten by each tier root: one
# checkout runs one tier at a time (its cargo build dir already forbids more), and a
# fixed path cannot leak a temp file per run.
#
#     source scripts/gate-source-tree.sh      # in a tier root, before any step
kata_source_tree_baseline() {
    [ -z "${KATA_SOURCE_TREE_BASELINE:-}" ] || return 0
    mkdir -p "$PWD/target"
    KATA_SOURCE_TREE_BASELINE="$PWD/target/source-tree.baseline"
    export KATA_SOURCE_TREE_BASELINE
    python3 -B scripts/source-tree-guard.py baseline "$KATA_SOURCE_TREE_BASELINE"
}

kata_source_tree_baseline
