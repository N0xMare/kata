#!/usr/bin/env python3
"""The workspace crate graph, read ONCE from `cargo metadata`, for every caller.

WHY THIS MODULE EXISTS. The verification router (`dev-loop.py`) needs three facts
— which crate owns a path, which crates depend on a crate, and in what order they
must be built — and `cargo metadata` is the only source that answers them the way
cargo does (it sees `exclude`, path deps and dev-dependency edges). The router used
to glob `crates/*/Cargo.toml` with a hand-rolled `name =` regex, which cannot see a
dependency edge at all and silently disagrees with cargo about workspace membership.

It is a module (underscore, importable) so a second consumer imports it rather than
re-deriving the graph; a second reading of one graph is the ambiguous-name defect.

REFUSAL IS THE DEFAULT ON IGNORANCE. Every path out of here either returns the
real graph or raises `Refusal`. A caller must fail rather than derive a narrower
verification set from a graph it could not read — a routing answer computed from an
empty graph looks exactly like "nothing to do".
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class Refusal(Exception):
    """A graph fact could not be derived. Never degrades into a default."""


# Where a workspace member's manifest can live in this repo. Used to find any
# EXCLUDED sibling workspaces: a manifest under one of these globs that the root
# `cargo metadata` did not report is its own workspace, and the path->crate
# question must still answer for it. Discovered rather than listed, so an
# excluded crate is covered the day it appears instead of the day somebody
# remembers this constant.
MEMBER_MANIFEST_GLOBS = ("crates/*/Cargo.toml", "crates/*/*/Cargo.toml", "bin/*/Cargo.toml")


@dataclass(frozen=True)
class WorkspaceGraph:
    """The workspace as three indexes, all keyed by cargo package name.

    `dirs` maps a package to its repo-relative manifest directory; `dependents`
    and `dependencies` are the two directions of the same edge set, kept together
    so a caller never has to invert one by hand and get the direction wrong.
    """

    dirs: dict[str, str]
    dependents: dict[str, set[str]]
    dependencies: dict[str, set[str]]


def workspace_graph(cargo: str = "cargo", *, root: Path = ROOT) -> WorkspaceGraph:
    """Read the workspace graph from `cargo metadata`.

    `--no-deps` keeps this to the workspace and off the network. Dependency KINDS
    are not filtered: a dev-dependency edge is a real reverse edge here, because
    `kata-test-utils` changing is how a worker TEST changes, and a routing answer
    that ignored dev-dependencies would skip exactly the target that broke.
    """
    proc = subprocess.run(
        [cargo, "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(root),
    )
    if proc.returncode != 0:
        tail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "no stderr"
        raise Refusal(f"cargo metadata failed: {tail}")
    try:
        meta = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal(f"cargo metadata emitted unparseable JSON: {exc}") from exc
    packages = meta.get("packages")
    if not packages:
        raise Refusal("cargo metadata reported no workspace packages")

    dirs: dict[str, str] = {}
    for pkg in packages:
        manifest = Path(pkg["manifest_path"]).resolve().parent
        try:
            rel = manifest.relative_to(root)
        except ValueError as exc:
            raise Refusal(f"package {pkg['name']} sits outside {root}: {manifest}") from exc
        dirs[pkg["name"]] = "" if str(rel) == "." else str(rel)

    dependents: dict[str, set[str]] = {name: set() for name in dirs}
    dependencies: dict[str, set[str]] = {name: set() for name in dirs}
    for pkg in packages:
        for dep in pkg.get("dependencies", []):
            if dep["name"] in dependents:
                dependents[dep["name"]].add(pkg["name"])
                dependencies[pkg["name"]].add(dep["name"])

    # The excluded sibling workspaces. They are islands: nothing in the root
    # workspace can depend on a non-member, so they carry no reverse edges and can
    # only ever be seeded by a path of their own. Leaving them out of `dirs` would
    # silently route their paths to no crate at all.
    claimed = {d for d in dirs.values() if d}
    for pattern in MEMBER_MANIFEST_GLOBS:
        for manifest in sorted(root.glob(pattern)):
            rel = str(manifest.parent.relative_to(root))
            if rel in claimed:
                continue
            for name in _island_packages(cargo, manifest.parent):
                dirs[name] = rel
                dependents.setdefault(name, set())
                dependencies.setdefault(name, set())
    return WorkspaceGraph(dirs=dirs, dependents=dependents, dependencies=dependencies)


def _island_packages(cargo: str, directory: Path) -> list[str]:
    """Package names of the workspace rooted at `directory`, whose own root it is.

    Only the packages whose manifest lives AT `directory` — a sibling workspace with
    members of its own has those members discovered by the same glob walk, and
    attributing them to the parent directory would make the longest-prefix match
    lie about which crate owns a path.
    """
    proc = subprocess.run(
        [cargo, "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(directory),
    )
    if proc.returncode != 0:
        tail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "no stderr"
        raise Refusal(f"cargo metadata failed for the excluded workspace {directory}: {tail}")
    try:
        meta = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal(f"cargo metadata emitted unparseable JSON for {directory}: {exc}") from exc
    here = directory.resolve()
    return [
        pkg["name"]
        for pkg in meta.get("packages", [])
        if Path(pkg["manifest_path"]).resolve().parent == here
    ]


def crate_of(path: str, dirs: dict[str, str]) -> str | None:
    """The workspace crate owning `path`, by EXACT manifest-directory prefix.

    Longest match wins and the match must end at a path boundary, so
    `crates/core-extra/src/lib.rs` is not attributed to `crates/core`. The
    workspace-root package (an empty directory, if one ever exists) claims nothing:
    it would claim every path and make every derivation meaningless.
    """
    best: tuple[int, str] | None = None
    for name, directory in dirs.items():
        if not directory:
            continue
        if path == directory or path.startswith(directory + "/"):
            if best is None or len(directory) > best[0]:
                best = (len(directory), name)
    return None if best is None else best[1]


def direct_dependents(seeds: set[str], dependents: dict[str, set[str]]) -> set[str]:
    """Every crate that depends on a seed DIRECTLY, excluding the seeds themselves.

    One level, not the transitive closure: the transitive closure of a leaf type
    crate here is most of the workspace, which is `just test` wearing per-crate
    clothes. One level is the set whose COMPILE can break from a signature change
    the changed crate's own tests never exercise.
    """
    reached: set[str] = set()
    for seed in seeds:
        reached |= dependents.get(seed, set())
    return reached - seeds


def dependency_order(names: set[str], dependencies: dict[str, set[str]]) -> list[str]:
    """`names` in dependency order — a crate after every `names` member it needs.

    Kahn over the subgraph induced by `names`, alphabetical among ready crates so
    the plan is byte-stable run to run (a plan that reorders itself cannot be
    diffed against the last one). A cycle cannot happen in a cargo workspace's
    normal edges but CAN through dev-dependencies, which cargo permits; the
    remainder is appended alphabetically rather than dropped, because dropping a
    crate from a verification plan to keep a sort total is the wrong trade.
    """
    remaining = set(names)
    ordered: list[str] = []
    while remaining:
        ready = sorted(
            name for name in remaining if not (dependencies.get(name, set()) & remaining)
        )
        if not ready:
            ordered.extend(sorted(remaining))
            return ordered
        ordered.extend(ready)
        remaining -= set(ready)
    return ordered
