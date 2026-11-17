#!/usr/bin/env python3
"""Independent routing controls: discovery failure cannot become a green plan."""

import argparse
import contextlib
import io
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE = runpy.run_path(str(Path(__file__).with_name("dev-loop.py")))
GLOBALS = MODULE["changed_paths"].__globals__
crate_graph = GLOBALS["crate_graph"]

EMPTY_GRAPH = crate_graph.WorkspaceGraph(dirs={}, dependents={}, dependencies={})


def graph(edges: dict[str, set[str]], dirs: dict[str, str]) -> crate_graph.WorkspaceGraph:
    """A fixture graph from `crate -> its dependents`, with the reverse filled in.

    Both directions are derived from ONE table so a fixture cannot describe an
    edge in one direction and not the other — an inconsistency that would make a
    dependency-order assertion pass for the wrong reason.
    """
    dependents = {name: set(v) for name, v in edges.items()}
    dependencies: dict[str, set[str]] = {name: set() for name in edges}
    for name, deps in edges.items():
        for dependent in deps:
            dependencies.setdefault(dependent, set()).add(name)
            dependents.setdefault(dependent, set())
    return crate_graph.WorkspaceGraph(dirs=dirs, dependents=dependents, dependencies=dependencies)


# The workspace's SHAPE: a leaf type crate with a wide fan-out, a mid crate, a
# dev-dependency-only consumer, and one crate nothing depends on.
FIXTURE_DIRS = {
    "kata-types": "crates/types",
    "kata-core": "crates/core",
    "kata-crypto": "crates/crypto",
    "kata-test-utils": "crates/test-utils",
    "kata-worker": "crates/worker",
    "kata-worker-bin": "bin/kata-worker",
    "kata-eval": "bin/kata-eval",
}
FIXTURE_EDGES = {
    # `kata-test-utils` is a DEV-dependency consumer of kata-types; it must still
    # appear, because a dev-dependency edge is how a test target breaks.
    "kata-types": {"kata-core", "kata-crypto", "kata-test-utils"},
    "kata-core": {"kata-worker"},
    "kata-crypto": {"kata-core"},
    "kata-test-utils": set(),
    "kata-worker": {"kata-worker-bin"},
    "kata-worker-bin": set(),
    "kata-eval": set(),
}
FIXTURE = graph(FIXTURE_EDGES, FIXTURE_DIRS)
LIBRARY_ROW = MODULE["Row"]("Rust libraries", ["crates/**"], ["check"], "why")
BINARY_ROW = MODULE["Row"]("Rust applications", ["bin/**"], ["check"], "why")
ROWS = [LIBRARY_ROW, BINARY_ROW]


class DiscoveryTests(unittest.TestCase):
    def test_failed_git_diff_is_not_an_empty_change_set(self):
        def run(args, **_kwargs):
            return subprocess.CompletedProcess(
                args, 128 if args[1] == "diff" else 0, "", "injected Git failure"
            )

        with patch.dict(GLOBALS, {"_upstream": lambda: "origin/main"}):
            with patch.object(subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(SystemExit, "Git discovery failed"):
                    MODULE["changed_paths"]()

    def test_failed_untracked_discovery_is_not_ignored(self):
        def run(args, **_kwargs):
            return subprocess.CompletedProcess(
                args, 128 if args[1] == "ls-files" else 0, "", "injected Git failure"
            )

        with patch.dict(GLOBALS, {"_upstream": lambda: "origin/main"}):
            with patch.object(subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(SystemExit, "Git discovery failed"):
                    MODULE["changed_paths"]()

    def test_discovery_timeout_and_os_error_refuse(self):
        for error in (subprocess.TimeoutExpired(["git"], 30), OSError("injected")):
            with self.subTest(error=type(error).__name__):
                with patch.object(subprocess, "run", side_effect=error):
                    with self.assertRaisesRegex(SystemExit, "Git discovery failed"):
                        MODULE["tracked_files"]()

    def test_malformed_path_stream_refuses(self):
        with patch.dict(GLOBALS, {"_git": lambda *_args: "not-nul-terminated\n"}):
            with self.assertRaisesRegex(SystemExit, "NUL-delimited"):
                MODULE["tracked_files"]()

    def test_no_comparison_base_refuses_auto_discovery(self):
        with patch.dict(GLOBALS, {"_upstream": lambda: None}):
            with self.assertRaisesRegex(SystemExit, "comparison base"):
                MODULE["changed_paths"]()

    def test_committed_comparison_failure_refuses(self):
        def run(args, **_kwargs):
            return subprocess.CompletedProcess(
                args, 128 if any("...HEAD" in arg for arg in args) else 0, "", ""
            )

        with patch.dict(GLOBALS, {"_upstream": lambda: "origin/main"}):
            with patch.object(subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(SystemExit, "Git discovery failed"):
                    MODULE["changed_paths"]()

    def test_configured_missing_upstream_refuses_even_with_main_fallback(self):
        with tempfile.TemporaryDirectory(prefix="kata-routing-upstream-") as temporary:
            root = Path(temporary)
            def git(*args):
                subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)

            git("init", "-q", "-b", "main")
            git("config", "commit.gpgsign", "false")
            git("config", "core.hooksPath", "/dev/null")
            git("-c", "user.name=Routing Test", "-c", "user.email=route@example.invalid",
                "commit", "-q", "--allow-empty", "-m", "base")
            git("config", "remote.origin.url", "https://example.invalid/repo.git")
            git("config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
            git("config", "branch.main.remote", "origin")
            git("config", "branch.main.merge", "refs/heads/missing")
            with patch.dict(GLOBALS, {"ROOT": root}):
                with self.assertRaisesRegex(SystemExit, "Git discovery failed"):
                    MODULE["changed_paths"]()

    def test_unknown_path_outside_old_territory_is_refused(self):
        recipes, unknown, _, _ = MODULE["plan"](
            ["new-build-system/config.toml"], [], EMPTY_GRAPH
        )
        self.assertEqual(unknown, ["new-build-system/config.toml"])
        self.assertEqual(recipes, ["fmt"])

    def test_auto_discovered_deletion_gets_conservative_workspace_route(self):
        doc = (
            f"{MODULE['BEGIN']}\n"
            "| sample | `scripts/**` | `fmt` | check |\n"
            f"{MODULE['END']}"
        )
        with tempfile.TemporaryDirectory(prefix="kata-routing-deletion-") as temporary:
            root = Path(temporary)
            (root / "routing.md").write_text(doc)
            args = argparse.Namespace(paths=[])
            replacements = {
                "ROOT": root,
                "TABLE_DOC": "routing.md",
                "changed_paths": lambda: ["retired/old-file"],
                "workspace_graph": lambda: EMPTY_GRAPH,
            }
            with patch.dict(GLOBALS, replacements):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(MODULE["cmd_route"](args, run=False), 0)
            self.assertIn("Deleted paths", output.getvalue())
            self.assertIn("just check", output.getvalue())

    def test_refused_plan_executes_no_checks(self):
        doc = f"{MODULE['BEGIN']}\n| sample | `scripts/**` | `fmt` | check |\n{MODULE['END']}"
        args = argparse.Namespace(paths=["crates/unowned/code.rs"])
        with patch.object(Path, "read_text", return_value=doc):
            with patch.dict(GLOBALS, {"workspace_graph": lambda: EMPTY_GRAPH}):
                with patch.object(subprocess, "run") as run:
                    run.return_value = subprocess.CompletedProcess(["just", "fmt"], 0)
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(MODULE["cmd_route"](args, run=True), 1)
                    run.assert_not_called()

    def test_real_git_preserves_special_path_bytes_and_unpushed_work(self):
        with tempfile.TemporaryDirectory(prefix="kata-routing-") as temporary:
            root = Path(temporary)
            def git(*args):
                return subprocess.run(
                    ["git", *args], cwd=root, text=True, capture_output=True, check=True
                )

            git("init", "-q", "-b", "main")
            git("config", "commit.gpgsign", "false")
            git("config", "core.hooksPath", "/dev/null")
            git("-c", "user.name=Routing Test", "-c", "user.email=route@example.invalid",
                "commit", "-q", "--allow-empty", "-m", "base")
            git("update-ref", "refs/remotes/origin/main", "HEAD")
            committed = "committed with space.txt"
            special = "untracked\nquoted\"file.txt"
            (root / committed).touch()
            git("add", "--", committed)
            git("-c", "user.name=Routing Test", "-c", "user.email=route@example.invalid",
                "commit", "-q", "-m", "unpublished")
            (root / special).touch()
            with patch.dict(GLOBALS, {"ROOT": root}):
                self.assertEqual(set(MODULE["changed_paths"]()), {committed, special})


class CrateRoutingTests(unittest.TestCase):
    """The crate lanes `just verify` derives, and the four ways they can be wrong.

    Before this routing existed the `crates/**` row SHADOWED the crate fallback, so
    every library change routed to `fmt` + `check`: no clippy for the crate, not one
    test, and nothing at all for the consumers whose compile the change can break.
    """

    def plan(self, paths, rows=None):
        return MODULE["plan"](paths, ROWS if rows is None else rows, FIXTURE)

    def test_single_crate_validates_itself_and_its_direct_dependents(self):
        recipes, unrouted, matched, route = self.plan(["crates/worker/src/lib.rs"])
        self.assertEqual(unrouted, [])
        self.assertEqual([r.name for r in matched], ["Rust libraries"])
        self.assertEqual(route.changed, ["kata-worker"])
        self.assertEqual(sorted(route.pulled_in), ["kata-worker-bin"])
        # fmt and check are KEPT, and the dependency precedes its dependent.
        self.assertEqual(
            recipes,
            ["fmt", "check", "validate-crate kata-worker", "validate-crate kata-worker-bin"],
        )

    def test_a_types_change_fans_out_one_level_only(self):
        # `kata-worker` depends on `kata-core`, which depends on `kata-types` — it is
        # TWO levels out and must NOT appear: the transitive closure of a leaf here is
        # most of the workspace, which is `just test` wearing per-crate clothes.
        recipes, unrouted, _, route = self.plan(["crates/types/src/lib.rs"])
        self.assertEqual(unrouted, [])
        self.assertEqual(route.changed, ["kata-types"])
        self.assertEqual(
            sorted(route.pulled_in), ["kata-core", "kata-crypto", "kata-test-utils"]
        )
        self.assertNotIn("kata-worker", route.ordered)
        self.assertFalse(route.over_cap)
        # A DEV-dependency consumer is in the set: that edge is how a test breaks.
        self.assertIn("validate-crate kata-test-utils", recipes)
        # Dependency order: a crate never precedes something it needs.
        position = {name: i for i, name in enumerate(route.ordered)}
        self.assertLess(position["kata-types"], position["kata-crypto"])
        self.assertLess(position["kata-crypto"], position["kata-core"])
        self.assertEqual(route.pulled_in["kata-core"], ["kata-types"])

    @staticmethod
    def fan_out(width):
        """A seed with `width` direct dependents: `width + 1` crates in the set."""
        edges = {f"dep{i}": set() for i in range(width)}
        edges["seed"] = set(edges)
        dirs = {name: f"crates/{name}" for name in edges}
        return graph(edges, dirs)

    def test_the_cap_is_the_measured_six_and_is_not_scaled_by_the_fixture(self):
        # The constant is a MEASUREMENT (see docs/development/verification.md and
        # `CRATE_FAN_OUT_CAP`'s comment), so the boundary cases below use literal
        # widths. A fixture derived from the constant would move with it and pass for
        # any value, including a cap so high the workspace arm is never taken.
        self.assertEqual(MODULE["CRATE_FAN_OUT_CAP"], 6)

    def test_six_crates_still_take_per_crate_lanes(self):
        recipes, unrouted, _, route = MODULE["plan"](
            ["crates/seed/src/lib.rs"], ROWS, self.fan_out(5)
        )
        self.assertEqual(unrouted, [])
        self.assertFalse(route.over_cap)
        self.assertEqual(len(route.ordered), 6)
        self.assertEqual(len([r for r in recipes if r.startswith("validate-crate")]), 6)
        self.assertNotIn("test", recipes)

    def test_over_cap_takes_one_workspace_run_and_names_no_crate_lane(self):
        recipes, unrouted, _, route = MODULE["plan"](
            ["crates/seed/src/lib.rs"], ROWS, self.fan_out(6)
        )
        self.assertEqual(unrouted, [])
        self.assertTrue(route.over_cap)
        self.assertEqual(len(route.ordered), 7)
        self.assertEqual(recipes, ["fmt", "check", "lint", "test"])
        self.assertFalse([r for r in recipes if r.startswith("validate-crate")])
        # The cap WIDENS. `just test` is the workspace nextest run, so nothing the
        # per-crate lanes would have tested is dropped to save time.
        self.assertEqual(MODULE["OVER_CAP_RECIPES"], ("check", "lint", "test"))

    def test_crate_territory_path_owned_by_no_crate_refuses(self):
        # The `crates/**` row MATCHES this path. It must still refuse: a misspelled
        # crate directory answered with a workspace type-check is a clean plan for a
        # file nobody verified.
        recipes, unrouted, matched, route = self.plan(["crates/typo-xyz/src/lib.rs"])
        self.assertEqual(unrouted, ["crates/typo-xyz/src/lib.rs"])
        self.assertEqual([r.name for r in matched], ["Rust libraries"])
        self.assertEqual(route.changed, [])
        self.assertNotIn("test", recipes)
        for path in ("bin/kata-typo/src/main.rs", "bin/stray.rs"):
            with self.subTest(path=path):
                _, unrouted, _, _ = self.plan([path])
                self.assertEqual(unrouted, [path])

    def test_a_docs_path_claimed_by_a_row_still_routes(self):
        # The territory refusal must be scoped to `crates/**` and `bin/**`; a path a
        # row claims outside them has no crate and needs none.
        row = MODULE["Row"]("Docs", ["docs/**"], ["dev-loop-check"], "why")
        recipes, unrouted, _, route = self.plan(["docs/development/verification.md"], [row])
        self.assertEqual(unrouted, [])
        self.assertEqual(route.changed, [])
        self.assertEqual(recipes, ["fmt", "dev-loop-check"])

    def test_deleted_crate_path_is_exempt_from_the_territory_refusal(self):
        _, unrouted, _, _ = MODULE["plan"](
            ["crates/retired/src/lib.rs"], ROWS, FIXTURE,
            frozenset({"crates/retired/src/lib.rs"}),
        )
        self.assertEqual(unrouted, [])


class ToolhostRoutingTests(unittest.TestCase):
    """The routes that reach the cells a `kata-toolhost` source change can red.

    `crates/toolhost-protocol/build.rs` hashes the toolhost's, its wire's and the
    frame codec's source into `TOOLHOST_SOURCE_DIGEST`, which kata-worker's pinned
    executor term folds, yet nothing depends on `kata-toolhost`: the crate graph
    alone routed a toolhost-only edit to `check` and its own crate lane. And
    `kata-agent-nanocode`'s `toolhost_backpressure` execs `target/<profile>/
    kata-toolhost`, which no crate-scoped test build produces. These read the
    REAL table and the REAL workspace graph, because the property is about them.
    """

    PIN_CELL = "test-one-crate kata-worker the_node_term_is_pinned_and_carries_no_version_string"

    @staticmethod
    def real_plan(paths):
        rows = MODULE["parse_table"]((MODULE["ROOT"] / MODULE["TABLE_DOC"]).read_text())
        return MODULE["plan"](paths, rows)

    def assert_toolhost_built_before(self, recipes, consumer):
        self.assertIn("build-toolhost", recipes)
        self.assertIn(consumer, recipes)
        self.assertLess(recipes.index("build-toolhost"), recipes.index(consumer))

    def test_a_toolhost_source_change_reaches_the_term_pin_and_the_real_toolhost_cells(self):
        for path in (
            "bin/kata-toolhost/src/main.rs",
            "crates/provider-protocol/src/lib.rs",
            "crates/toolhost-protocol/src/lib.rs",
        ):
            with self.subTest(path=path):
                recipes, unrouted, _, _ = self.real_plan([path])
                self.assertEqual(unrouted, [])
                self.assertIn(self.PIN_CELL, recipes)
                self.assert_toolhost_built_before(recipes, "test-crate agent-nanocode")

    def test_a_vendored_engine_change_reaches_the_term_pin(self):
        # `crates/agent-nanocode/build.rs` hashes the vendored engine and its patch
        # into the harness identity the term folds, and the workspace excludes the
        # copy, so no crate lane reaches kata-worker from `vendor/`.
        for path in (
            "vendor/nanocode-code-mode-engine.patch",
            "vendor/nanocode-code-mode-engine/src/native.rs",
        ):
            with self.subTest(path=path):
                recipes, unrouted, _, _ = self.real_plan([path])
                self.assertEqual(unrouted, [])
                self.assertIn(self.PIN_CELL, recipes)

    def test_an_interpreter_host_change_reaches_the_worker_that_pins_the_term(self):
        # `crates/agent-nanocode/build.rs` hashes kata-code-mode-host's manifest and
        # source into the same digest; that crate's lanes reach the pin through
        # kata-worker, which depends on it directly.
        for path in (
            "crates/code-mode-host/Cargo.toml",
            "crates/code-mode-host/src/syscall_filter.rs",
        ):
            with self.subTest(path=path):
                recipes, unrouted, _, route = self.real_plan([path])
                self.assertEqual(unrouted, [])
                self.assertFalse(route.over_cap)
                self.assertIn("validate-crate kata-worker", recipes)

    def test_every_route_into_the_nanocode_suite_builds_the_toolhost_first(self):
        recipes, _, _, _ = self.real_plan(["vendor/nanocode-code-mode-engine.patch"])
        self.assert_toolhost_built_before(recipes, "test-crate agent-nanocode")
        # A derived crate lane: kata-agent-nanocode changed, or pulled in as a
        # direct dependent of kata-agent.
        for path in ("crates/agent-nanocode/src/lib.rs", "crates/agent/src/lib.rs"):
            with self.subTest(path=path):
                recipes, _, _, route = self.real_plan([path])
                self.assertFalse(route.over_cap)
                self.assert_toolhost_built_before(
                    recipes, "validate-crate kata-agent-nanocode"
                )


class FlakeRoutingTests(unittest.TestCase):
    """The flake's own files route to `flake-checks`, the only runner of its checks.

    `dev-loop-check` evaluates no Nix, so a route that reached only the Build and
    release row would leave a `flake.nix` or `nix/**` edit unbuilt. Reads the REAL
    table, because the property is about it.
    """

    def test_the_flake_inputs_route_to_the_flake_checks(self):
        rows = MODULE["parse_table"]((MODULE["ROOT"] / MODULE["TABLE_DOC"]).read_text())
        for path in ("flake.nix", "flake.lock", "nix/youki.nix", "config/youki-pin.toml"):
            with self.subTest(path=path):
                recipes, unrouted, _, _ = MODULE["plan"]([path], rows)
                self.assertEqual(unrouted, [])
                self.assertIn("flake-checks", recipes)


class CrateGraphTests(unittest.TestCase):
    """The crate mapping the router reads, from `cargo metadata`."""

    def test_reverse_edges_and_order_come_from_the_real_workspace(self):
        real = crate_graph.workspace_graph(root=GLOBALS["ROOT"])
        self.assertIn("kata-types", real.dirs)
        self.assertEqual(real.dirs["kata-types"], "crates/types")
        # Both directions of every edge agree.
        for name, deps in real.dependencies.items():
            for dep in deps:
                self.assertIn(name, real.dependents[dep])

    def test_an_unreadable_graph_refuses_instead_of_returning_an_empty_one(self):
        with self.assertRaises(crate_graph.Refusal):
            crate_graph.workspace_graph("/bin/false", root=GLOBALS["ROOT"])
        with self.assertRaisesRegex(SystemExit, "crate graph unavailable"):
            with patch.dict(
                crate_graph.__dict__,
                {"workspace_graph": lambda **_k: (_ for _ in ()).throw(
                    crate_graph.Refusal("injected")
                )},
            ):
                MODULE["workspace_graph"]()

    def test_dependency_order_survives_a_dev_dependency_cycle(self):
        # cargo permits a dev-dependency cycle. Dropping a crate to keep the sort
        # total would drop it from a VERIFICATION plan; the remainder is appended.
        order = crate_graph.dependency_order({"a", "b"}, {"a": {"b"}, "b": {"a"}})
        self.assertEqual(sorted(order), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
