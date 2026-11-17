#!/usr/bin/env python3
"""Route a change to the checks it needs, and prove the routing table is true.

The routing table lives in ONE place — `docs/development/verification.md`,
between `<!-- routing:begin -->` and `<!-- routing:end -->`. This script is its
only reader, so there is exactly one artifact and one parser.

    dev-loop.py route [paths...]   print the plan, run nothing
    dev-loop.py run   [paths...]   print the plan, then run it
    dev-loop.py check              gate guard: the table describes reality
    dev-loop.py check --self-test  prove the guard can fail

A path under `crates/**` or `bin/**` gets its row's recipes AND the lanes the
workspace crate graph derives: `validate-crate` for the changed crate and for each
crate that DIRECTLY depends on it. See `CRATE_FAN_OUT_CAP` for the breadth at which
that becomes one workspace run instead.

WHY `route` REFUSES. A changed path that matches no row and no crate exits non-zero,
naming the path — including a path inside `crates/**` or `bin/**` that a row claims
but no crate owns, which is the typo case. A routing table that silently ignores what
it does not know is worse than no table, because it will be trusted: it would report a
clean plan for a change nobody thought about. `check` enforces the same property ahead
of time over the whole tree, so the refusal is rare in practice.

Git discovery failures and an unreadable crate graph also refuse: an unreadable
change set is not an empty one, and an empty graph is not a workspace without
crates. Every tracked path must have an explicit table row or an owning crate;
there is no implicit exemption for a newly introduced top-level directory.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The path->crate mapping, the reverse edges and the dependency order come from
# `crate_graph.py`, i.e. from `cargo metadata`. Globbing `crates/*/Cargo.toml` and
# regexing out `name =` instead cannot see a dependency edge and disagrees with cargo
# about workspace membership; two readings of one graph is the ambiguous-name defect,
# and the narrower reading wins silently.
import crate_graph  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TABLE_DOC = "docs/development/verification.md"
BEGIN = "<!-- routing:begin -->"
END = "<!-- routing:end -->"

# Recipes that run for EVERY routed change, ahead of whatever the table matched.
#
# WHY `fmt` IS HERE AND NOT IN A ROW. Every explicit row names `lint-crate` / `test-crate`;
# only the crate FALLBACK routes to `validate-crate`, which is the one recipe that runs
# `just fmt`. So a change that MATCHED a row — the common case, and the whole point of
# having rows — would never be format-checked, `just verify` would report green, and the
# gate would die on a `fmt` diff twenty minutes in. `lint-crate` runs clippy under the
# pinned stable; the gate's `fmt` runs rustfmt under the dated audit nightly — different
# tool, different opinion, and no crate-scoped recipe would reach it.
#
# WORKSPACE `--check`, NOT CRATE-SCOPED, deliberately. `just fmt` is byte-for-byte the
# command the gate runs, so a change that is green here is green there on this axis; that
# equality IS the property being bought. A `cargo fmt -p <crate>` variant would be a
# SECOND format surface with a narrower opinion — a new ambiguous-name defect introduced
# inside the fix for a feedback-loop defect — and it would buy nothing measurable, since
# the full workspace check is seconds (rustfmt parses, it does not build).
#
# Unconditional, including for a docs-only change: making it conditional would need a
# judgment call ("does this change count as Rust?") that a wrong answer turns into a hole.
ALWAYS = ("fmt",)

# Territories whose every path belongs to a workspace crate. A path here that maps
# to NO crate is a refusal, not a `check`-only route: that is the typo case (a
# misspelled crate directory, a stale path in an explicit `just route` argument),
# and routing it to a workspace type-check while claiming the change was verified
# is exactly the silent-drop this router exists to not do.
CRATE_TERRITORIES = ("crates/", "bin/")

# One level of REVERSE dependencies per changed crate, and the breadth at which
# per-crate lanes stop being the cheaper answer.
#
# WHY ONE LEVEL. A changed crate's own tests do not compile its consumers, so a
# signature change that type-checks here breaks a direct dependent's test target
# with nothing red until the gate. The TRANSITIVE closure would be the wrong fix:
# for a leaf like `kata-types` it is most of the workspace, i.e. `just test` wearing
# per-crate clothes, paying the per-crate overhead N times for the same build.
#
# WHY THE CAP IS 6, MEASURED warm on the reference host (128 cores, one NVMe; the
# table and the per-lane numbers are in docs/development/verification.md):
#
#   a five-crate lane set (kata-provider-protocol + 4 dependents then)     364 s
#   just check + just lint + just test (one workspace run)                 467 s
#   one `validate-crate`, mean over 7 measured lanes                        75 s
#   the kata-types set (15 crates), extrapolated at that mean           ~ 1125 s
#
# Each lane re-runs the workspace `just fmt` and starts its own clippy and nextest
# process, so the per-crate arm grows ~75 s per crate while the workspace arm is
# flat: the curves cross at 467/75 ~= 6.2 crates. 6 is the last breadth where
# per-crate lanes are still cheaper AND still name what they verified. Changing this
# number owes a fresh measurement — the self-test asserts the 6 by name, because a
# cap fixture derived from the constant passes for any value.
CRATE_FAN_OUT_CAP = 6

# Above the cap: one workspace run instead of N crate runs. `just test` IS
# `cargo nextest run --workspace` (the justfile is the source of truth for the
# flags), and `just lint` is the clippy the crate lanes would each have run.
OVER_CAP_RECIPES = ("check", "lint", "test")

# A crate whose suite execs a workspace BINARY it does not build, and the recipe that
# builds that binary, run ahead of the crate's lane. A crate-scoped test build makes
# only the selected package's targets: `kata-agent-nanocode`'s `toolhost_backpressure`
# execs `target/<profile>/kata-toolhost`, which only `cargo build -p kata-toolhost`
# (or the workspace build `just test` runs first) produces. The over-cap arm needs no
# entry: `just test` builds every workspace binary before it runs.
LANE_PREREQUISITES: dict[str, tuple[str, ...]] = {
    "kata-agent-nanocode": ("build-toolhost",),
}

# Every crate-lane recipe this router can emit, for the A1/A6 name and arity checks.
# These names live in CODE rather than in a table row, so the table audit would not
# have covered them — and an unrunnable recipe name in the router is the same class
# of defect whether it came from a row or from a constant.
CRATE_LANE_RECIPES = (
    "validate-crate <crate>",
    *OVER_CAP_RECIPES,
    *(recipe for recipes in LANE_PREREQUISITES.values() for recipe in recipes),
)


class Row:
    __slots__ = ("name", "globs", "recipes", "why")

    def __init__(self, name: str, globs: list[str], recipes: list[str], why: str) -> None:
        self.name = name
        self.globs = globs
        self.recipes = recipes
        self.why = why

    def matches(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, g) for g in self.globs)


def _expand_braces(pattern: str) -> list[str]:
    """`a/{b,c}.rs` -> ['a/b.rs', 'a/c.rs']. One level is enough for this table."""
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        return [pattern]
    out: list[str] = []
    for alt in m.group(1).split(","):
        out.extend(_expand_braces(pattern[: m.start()] + alt.strip() + pattern[m.end() :]))
    return out


def _split_outside_braces(cell: str) -> list[str]:
    """Split on commas that are NOT inside `{...}` — `a/{b,c}.rs, d.rs` is TWO globs."""
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in cell:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p for p in parts if p.strip()]


def workspace_graph() -> crate_graph.WorkspaceGraph:
    """The workspace crate graph, from `cargo metadata` via the shared module.

    A failure REFUSES (`crate_graph.Refusal` -> `SystemExit`) instead of yielding an
    empty graph: an empty graph routes every crate path to nothing and reads as a
    clean plan, which is the one outcome this router may never produce.
    """
    try:
        return crate_graph.workspace_graph(root=ROOT)
    except crate_graph.Refusal as refusal:
        raise SystemExit(f"dev-loop: crate graph unavailable — {refusal}") from refusal


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def parse_table(text: str) -> list[Row]:
    if BEGIN not in text or END not in text:
        raise SystemExit(f"dev-loop: {TABLE_DOC} has no routing fences")
    body = text.split(BEGIN, 1)[1].split(END, 1)[0]
    rows: list[Row] = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = _cells(line)
        if len(cells) < 4 or cells[0] in ("Change class",) or set(cells[0]) <= set("- "):
            continue
        globs: list[str] = []
        for raw in _split_outside_braces(cells[1]):
            raw = raw.strip().strip("`")
            if raw:
                globs.extend(_expand_braces(raw))
        recipes = [r.strip().strip("`") for r in cells[2].split(",") if r.strip()]
        rows.append(Row(cells[0], globs, recipes, cells[3]))
    if not rows:
        raise SystemExit(f"dev-loop: parsed ZERO rows from {TABLE_DOC} — the fences moved")
    return rows


def _git(*args: str, allow_missing: bool = False) -> str | None:
    """Bounded discovery; only an explicitly optional missing ref may exit 1."""
    try:
        result = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True,
            errors="surrogateescape", timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"dev-loop: Git discovery failed for {args!r}: {error}") from error
    if allow_missing and result.returncode == 1:
        return None
    if result.returncode != 0:
        raise SystemExit(
            f"dev-loop: Git discovery failed for {args!r} (exit {result.returncode})"
        )
    return result.stdout


def _git_paths(*args: str) -> list[str]:
    output = _git(*args)
    assert output is not None
    if not output:
        return []
    if not output.endswith("\0"):
        raise SystemExit("dev-loop: Git discovery failed: expected NUL-delimited paths")
    return output[:-1].split("\0")


def tracked_files() -> list[str]:
    return _git_paths("ls-files", "-z")


def _upstream() -> str | None:
    """The branch this work will land against, for the committed half of the diff."""
    branch = _git("symbolic-ref", "--quiet", "HEAD", allow_missing=True)
    if branch:
        upstream = _git("for-each-ref", "--format=%(upstream)", branch.strip())
        if upstream and upstream.strip():
            # A configured but unavailable upstream is an error, not permission
            # to compare against another branch and silently lose committed work.
            resolved = _git("rev-parse", "--verify", "--quiet", upstream.strip() + "^{commit}")
            if not resolved or not resolved.strip():
                raise SystemExit("dev-loop: Git discovery failed: empty upstream identity")
            return resolved.strip()
    for ref in ("origin/main", "main"):
        resolved = _git("rev-parse", "--verify", "--quiet", ref + "^{commit}", allow_missing=True)
        if resolved:
            return resolved.strip()
    return None


def changed_paths() -> list[str]:
    """Working tree AND committed-but-unlanded work.

    THE WORKING TREE ALONE IS NOT ENOUGH: a contributor who commits first and gates
    second would get `no changes — nothing to route` and exit 0 from a tool whose
    whole purpose is to be trusted. A verification satisfiable by observing nothing
    is the defect class this guard exists to catch.

    So: staged + unstaged + untracked, UNION the diff against upstream (or
    origin/main), so committed-and-unpushed work still routes.
    """
    seen: list[str] = []
    cmds: list[tuple[str, ...]] = [
        ("diff", "--name-only", "-z", "HEAD"),
        ("ls-files", "--others", "--exclude-standard", "-z"),
    ]
    up = _upstream()
    if not up:
        raise SystemExit(
            "dev-loop: Git discovery failed: no comparison base; configure an upstream "
            "or supply explicit paths (which verify only those paths)"
        )
    cmds.append(("diff", "--name-only", "-z", f"{up}...HEAD"))
    for args in cmds:
        for path in _git_paths(*args):
            if path not in seen:
                seen.append(path)
    return seen


def just_recipes() -> set[str]:
    out = subprocess.run(
        ["just", "--summary"], cwd=ROOT, capture_output=True, text=True
    )
    if out.returncode != 0:
        raise SystemExit(f"dev-loop: `just --summary` failed: {out.stderr.strip()}")
    return set(out.stdout.split())


def just_recipe_params() -> dict[str, list[dict]]:
    """Every recipe's parameter list, from `just`'s own machine-readable dump."""
    out = subprocess.run(
        ["just", "--dump", "--dump-format", "json"], cwd=ROOT, capture_output=True, text=True
    )
    if out.returncode != 0:
        raise SystemExit(f"dev-loop: `just --dump` failed: {out.stderr.strip()}")
    recipes = json.loads(out.stdout).get("recipes", {})
    return {name: r.get("parameters", []) for name, r in recipes.items()}


def arity_complaint(params: list[dict], argc: int) -> str | None:
    """Why `argc` arguments cannot invoke a recipe with these parameters — or None."""
    required = 0
    unbounded = False
    for p in params:
        kind = p.get("kind", "singular")
        if kind in ("plus", "star"):
            unbounded = True
            if kind == "plus" and p.get("default") is None:
                required += 1
            continue
        if p.get("default") is None:
            required += 1
    if argc < required:
        return f"needs at least {required} argument(s); the table passes {argc}"
    if not unbounded and argc > len(params):
        return f"takes at most {len(params)} argument(s); the table passes {argc}"
    return None


def in_crate_territory(path: str) -> bool:
    return any(path == t.rstrip("/") or path.startswith(t) for t in CRATE_TERRITORIES)


@dataclass
class CrateRoute:
    """What the crate graph derived, and why — the thing `just route` must SHOW.

    A plan that says `validate-crate kata-core` without saying that `kata-core` was
    pulled in as a direct dependent of `kata-types` is unauditable: the reader
    cannot tell an intended lane from a mapping bug.
    """

    changed: list[str] = field(default_factory=list)
    pulled_in: dict[str, list[str]] = field(default_factory=dict)
    ordered: list[str] = field(default_factory=list)
    lanes: list[str] = field(default_factory=list)
    over_cap: bool = False


def derive_crate_route(seeds: dict[str, str], graph: crate_graph.WorkspaceGraph) -> CrateRoute:
    """Changed crates plus ONE level of reverse dependencies, in dependency order.

    Dev-dependency edges count (`crate_graph.workspace_graph` does not filter kinds):
    a `kata-test-utils` change is how a worker TEST changes, and a reverse set that
    ignored dev-dependencies would skip exactly the target that breaks.

    Above `CRATE_FAN_OUT_CAP` crates the per-crate arm stops paying: each lane
    re-runs the workspace `fmt` and starts its own clippy and nextest, so one
    workspace run is both cheaper and strictly wider. The cap therefore does not
    DROP anything — it widens.
    """
    route = CrateRoute(changed=sorted(seeds))
    pulled = crate_graph.direct_dependents(set(seeds), graph.dependents)
    for name in sorted(pulled):
        route.pulled_in[name] = sorted(
            seed for seed in seeds if name in graph.dependents.get(seed, set())
        )
    route.ordered = crate_graph.dependency_order(set(seeds) | pulled, graph.dependencies)
    if len(route.ordered) > CRATE_FAN_OUT_CAP:
        route.over_cap = True
        route.lanes = list(OVER_CAP_RECIPES)
    else:
        for name in route.ordered:
            for prerequisite in LANE_PREREQUISITES.get(name, ()):
                if prerequisite not in route.lanes:
                    route.lanes.append(prerequisite)
            route.lanes.append(f"validate-crate {name}")
    return route


def plan(
    paths: list[str],
    rows: list[Row],
    graph: crate_graph.WorkspaceGraph | None = None,
    exempt: frozenset[str] = frozenset(),
) -> tuple[list[str], list[str], list[Row], CrateRoute]:
    """Explicit rows, PLUS the crate lanes the graph derives; only then a refusal.

    A path under `crates/**` or `bin/**` carries two independent answers and needs
    both. The row answers the cross-cutting question (`check`, because a library
    change can break workspace integration). The crate graph answers the local one:
    validate the crate that changed AND its direct dependents, which is the set whose
    compile can break from a change whose own crate is green. Before this, the
    `crates/**` row SHADOWED the crate fallback, so every library change routed to
    `fmt` + `check` — a type-check, no clippy for the crate, and not one test.

    A crate-territory path that maps to no crate is UNROUTED, even though a row
    claims it: that is a typo or a stale path, and answering it with a workspace
    type-check would report a clean plan for a file nobody verified. `exempt` holds
    the auto-discovered deletions, whose crate is legitimately gone.
    """
    graph = graph if graph is not None else workspace_graph()
    matched: list[Row] = []
    unrouted: list[str] = []
    seeds: dict[str, str] = {}
    for p in paths:
        hit = [r for r in rows if r.matches(p)]
        for r in hit:
            if r not in matched:
                matched.append(r)
        pkg = crate_graph.crate_of(p, graph.dirs)
        if pkg:
            seeds.setdefault(pkg, p)
            continue
        if p in exempt:
            continue
        if hit and not in_crate_territory(p):
            continue
        unrouted.append(p)
    route = derive_crate_route(seeds, graph)
    ordered: list[str] = list(ALWAYS)
    for r in matched:
        for rec in r.recipes:
            if rec not in ordered:
                ordered.append(rec)
    for rec in route.lanes:
        if rec not in ordered:
            ordered.append(rec)
    return ordered, unrouted, matched, route


def cmd_route(args: argparse.Namespace, run: bool) -> int:
    rows = parse_table((ROOT / TABLE_DOC).read_text())
    paths = args.paths or changed_paths()
    if not paths:
        print("dev-loop: no changes — nothing to route.")
        return 0
    if not args.paths:
        # A retired top-level territory cannot match the current routing table:
        # keeping a dead glob solely to route its deletion would violate A2 and
        # preserving its old name in code would turn migration scaffolding into
        # permanent architecture. Auto-discovered deletions take the conservative
        # workspace route. Explicit nonexistent paths still refuse as typos.
        deleted = [path for path in paths if not (ROOT / path).exists()]
        if deleted:
            rows.append(
                Row(
                    "Deleted paths",
                    deleted,
                    ["check", "dev-loop-check"],
                    "Deleted territory receives workspace and routing checks.",
                )
            )
    deleted_exempt = frozenset() if args.paths else frozenset(
        path for path in paths if not (ROOT / path).exists()
    )
    recipes, unrouted, matched, route = plan(paths, rows, exempt=deleted_exempt)

    print(f"dev-loop: {len(paths)} changed path(s), {len(matched)} class(es) matched\n")
    if ALWAYS:
        print("  [always — the gate runs these regardless of what matched]")
        for rec in ALWAYS:
            print(f"      just {rec}")
    for r in matched:
        print(f"  [{r.name}]")
        for rec in r.recipes:
            print(f"      just {rec}")
        if r.why:
            print(f"      why: {r.why[:160]}")
    if not matched:
        print("  (no cross-cutting class matched)")
    if route.changed:
        print("  [crate lanes — derived from the workspace graph]")
        print(f"      changed crate(s): {', '.join(route.changed)}")
        if route.pulled_in:
            pulled = ", ".join(
                f"{name} (depends on {', '.join(seeds)})"
                for name, seeds in route.pulled_in.items()
            )
            print(f"      direct dependent(s), dev-dependencies included: {pulled}")
        else:
            print("      direct dependent(s): (none — nothing in the workspace depends on it)")
        print("      why: a changed crate's own tests do not compile its consumers, so one "
              "level of reverse\n           dependencies is the set whose COMPILE can break "
              "while the changed crate is green.")
        if route.over_cap:
            print(
                f"      {len(route.ordered)} crate(s) EXCEEDS the cap of {CRATE_FAN_OUT_CAP} "
                f"({', '.join(route.ordered)})\n"
                f"      why: each per-crate lane re-runs the workspace `fmt` and starts its own "
                f"clippy and\n           nextest, so at this breadth one workspace run is both "
                f"cheaper and strictly wider."
            )
        else:
            print(f"      dependency order: {' -> '.join(route.ordered)}")
        for rec in route.lanes:
            print(f"      just {rec}")
    print()

    exit_code = 0
    if unrouted:
        print("dev-loop: UNROUTED — no row claims these paths:")
        for p in unrouted:
            print(f"    {p}")
        print(
            "\n  Add an explicit verification row to docs/development/verification.md.\n"
            "  This refuses rather than reporting a clean plan\n"
            "  for a change nobody thought about."
        )
        exit_code = 1

    if exit_code:
        return exit_code  # Unknown scope must not launch any verification command.

    if not run:
        return exit_code

    print(f"\ndev-loop: running {len(recipes)} recipe(s)\n")
    for rec in recipes:
        print(f"=== just {rec} ===", flush=True)
        rc = subprocess.run(["just", *rec.split()], cwd=ROOT).returncode
        if rc != 0:
            print(f"\ndev-loop: `just {rec}` FAILED (exit {rc})")
            return rc
    if exit_code:
        print("\ndev-loop: recipes passed, but UNROUTED paths remain — see above.")
    return exit_code


def audit(doc: str) -> tuple[list[Row], list[str]]:
    """Six assertions over the table. Returns the rows and every failure, tagged `A<n>:`.

    Split out of `cmd_check` so `--self-test` can assert WHICH assertion fired: a
    counterfactual that only required a non-zero exit, which any OTHER assertion
    also produces, would prove that the guard failed, not that the named check works.
    """
    rows = parse_table(doc)
    failures: list[str] = []

    # (1) every recipe the table names EXISTS — and so does every ALWAYS recipe, which
    # is table-adjacent code and would otherwise be the one unchecked name in the router.
    known = just_recipes()
    for rec in ALWAYS:
        if rec.split()[0] not in known:
            failures.append(f"A1: ALWAYS names `just {rec}`, which does not exist")
    for rec in CRATE_LANE_RECIPES:
        if rec.split()[0] not in known:
            failures.append(f"A1: the crate router emits `just {rec}`, which does not exist")
    for r in rows:
        for rec in r.recipes:
            head = rec.split()[0]
            if head not in known:
                failures.append(f"A1: row [{r.name}] names `just {head}`, which does not exist")

    # (2) every glob still matches a tracked file — no dead route.
    files = tracked_files()
    for r in rows:
        for g in r.globs:
            if not any(fnmatch.fnmatch(f, g) for f in files):
                failures.append(f"A2: row [{r.name}] glob `{g}` matches no tracked file")

    # (3) every tracked path is reachable — by an owning crate, or by a row. A path
    # inside a crate territory that NO crate owns fails here rather than leaning on
    # the row that claims the territory: the crate lanes would skip it, so the row
    # alone would verify the territory and not the file.
    graph = workspace_graph()
    for f in files:
        crate = crate_graph.crate_of(f, graph.dirs)
        if crate:
            continue
        if in_crate_territory(f):
            failures.append(
                f"A3: tracked path `{f}` sits under {CRATE_TERRITORIES} but no workspace "
                "crate owns it, so the crate lanes would skip it"
            )
            continue
        if any(r.matches(f) for r in rows):
            continue
        failures.append(f"A3: tracked path `{f}` has no crate fallback and no row claims it")

    # (4) every row states a WHY. A row without one is a rule nobody can audit.
    for r in rows:
        if not r.why.strip():
            failures.append(f"A4: row [{r.name}] has an empty why-cell")

    # (5) every `just <recipe>` the doc names IN PROSE exists too.
    #
    # A1 checks the table; prose can still instruct a recipe that does not exist, and
    # a named recourse nobody can invoke is a defect of its own. The table is not the
    # only place this doc makes a promise, so the guard reads the whole file.
    for m in re.finditer(r"`just ([a-z][a-z0-9-]*)", doc):
        name = m.group(1)
        if name not in known:
            failures.append(f"A5: the doc names `just {name}` in prose, which does not exist")

    # (6) every recipe the table names is INVOCABLE with the arguments the table gives.
    #
    # A1 proves the name resolves and stops there, so a row could name a recipe that
    # takes a required argument — `workflows-check` takes a `workflow` — and every
    # `just verify` it routes would die with "got 0 positional arguments but takes 1":
    # not a check result, an argument error, from the tool a contributor is told to
    # trust after every change.
    params = just_recipe_params()
    for rec in list(ALWAYS) + list(CRATE_LANE_RECIPES) + [
        r for row in rows for r in row.recipes
    ]:
        parts = rec.split()
        head, argc = parts[0], len(parts) - 1
        if head not in params:
            continue  # A1 already reported the missing name.
        complaint = arity_complaint(params[head], argc)
        if complaint:
            failures.append(f"A6: `just {rec}` cannot run — `{head}` {complaint}")

    return rows, failures


def cmd_check(_args: argparse.Namespace, *, text: str | None = None, quiet: bool = False) -> int:
    doc = text if text is not None else (ROOT / TABLE_DOC).read_text()
    rows, failures = audit(doc)
    if failures:
        if not quiet:
            print(f"dev-loop-check: FAIL ({len(failures)})")
            for f in sorted(set(failures))[:40]:
                print(f"  {f}")
        return 1
    if quiet:
        return 0
    print(
        f"dev-loop-check: ok — {len(rows)} classes, every recipe exists, "
        f"every glob live, every tracked path routed"
    )
    return 0


def self_test() -> int:
    """Plant each failure and require THE NAMED assertion to catch it.

    Each case carries the `A<n>` tag it must produce. Requiring only a non-zero
    exit would let an unrelated assertion satisfy the case, so an assertion with
    no counterfactual of its own could stop covering what it claims and stay green.
    """
    doc = (ROOT / TABLE_DOC).read_text()
    checks = [
        ("A1", "unknown recipe", doc.replace("| `check` |", "| `no-such-recipe-xyz` |", 1)),
        ("A2", "dead glob", doc.replace("`crates/**`", "`does-not-exist/**`", 1)),
        # A3: remove every explicit justfile route, including overlapping
        # measurement routing. Removing only one row does not unclaim the path.
        ("A3", "unrouted territory", doc.replace("`justfile`, ", "").replace(", `justfile`", "")),
        ("A3", "unrouted canonical agent rules", doc.replace(", `AGENTS.md`", "", 1)),
        ("A4", "empty why", re.sub(r"(\| Rust libraries \|[^|]*\|[^|]*\|)[^|]*\|", r"\1 |", doc, count=1)),
        ("A5", "fictional prose recipe", doc.replace("`just verify`", "`just no-such-prose-recipe`", 1)),
        # A6: a real recipe named with the WRONG NUMBER of arguments. This is the shape
        # that actually shipped — `workflows-check` with none — so the counterfactual
        # uses the same failure, not an invented one.
        (
            "A6",
            "recipe invoked with too few arguments",
            doc.replace("`config-check`", "`workflows-check`", 1),
        ),
    ]
    for code, name, mutated in checks:
        if mutated == doc:
            print(f"dev-loop self-test: FAIL — counterfactual '{code} {name}' did not mutate the doc")
            return 1
        _, failures = audit(mutated)
        if not any(f.startswith(f"{code}:") for f in failures):
            got = sorted({f.split(":", 1)[0] for f in failures}) or ["nothing"]
            print(
                f"dev-loop self-test: FAIL — counterfactual '{code} {name}' did not trip {code}; "
                f"tripped {', '.join(got)}"
            )
            return 1
        print(f"  counterfactual caught by {code}: {name}")
    # And the real table must pass.
    if cmd_check(argparse.Namespace()) != 0:
        print("dev-loop self-test: FAIL — the real table does not pass")
        return 1
    print(
        "dev-loop self-test: PASS (A1 unknown-recipe / A2 dead-glob / A3 unrouted-territory / "
        "A4 empty-why / A5 fictional-prose-recipe / A6 wrong-arity — each tripping ITS OWN assertion)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for verb in ("route", "run"):
        p = sub.add_parser(verb)
        p.add_argument("paths", nargs="*")
    c = sub.add_parser("check")
    c.add_argument("--self-test", action="store_true")

    args = ap.parse_args()
    if args.cmd == "route":
        return cmd_route(args, run=False)
    if args.cmd == "run":
        return cmd_route(args, run=True)
    return self_test() if args.self_test else cmd_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
