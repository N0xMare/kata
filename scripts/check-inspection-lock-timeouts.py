#!/usr/bin/env python3
"""Every test holding the per-uid inspection lock must outlive nextest's kill.

THE DEFECT THIS EXISTS FOR. `kata_test_utils::inspection_lock::hold()` BLOCKS while
another process on this uid is inside its own immutable-SQLite inspection window. The
default nextest profile kills a test after `period = 10s` x `terminate-after = 6` = 60s,
so the first real wait longer than that does not produce the lock's named refusal — it
produces a TIMEOUT — in a concurrent commit tier, for example
(`recovery_capture::tests::*`, `data_dir_lock::recovery_tests::*`), while a holder holds
the lock for 90 seconds. "This test hangs" for "another suite held a shared lock" is the
same substitution of a harness artifact for a scheduling fact that the lock itself was
written to remove, so it cannot be left to whoever remembers to edit two files together.

WHAT IT CHECKS, deriving both sides rather than trusting a list:

  * the guarded set is read off the TREE — every `inspection_lock::hold` call site;
  * the covered set is read off `.config/nextest.toml` — the `slow-timeout` override
    whose period is long enough for the lock's `WAIT_BUDGET`;
  * each guarded call site maps to the nextest selector that must name it: a unit test
    under `<crate>/src/**` maps to its MODULE PREFIX (`cli::recovery_capture::tests::`),
    an integration test under `<crate>/tests/<name>.rs` maps to `binary(<name>)`.

A new guarded test in a new module therefore fails this check instead of quietly
inheriting the 60s kill. It does not evaluate nextest's filter language — it asserts the
selector text is present in the override — which is the narrow claim it can actually
make; the wider "nextest really applies it" is left to nextest.

It also pins the ORDER the two numbers must keep: the lock's budget must be smaller than
the kill of the FIRST override that matches (nextest resolves each setting from the
earliest matching override), or the refusal never fires.

    python3 -B scripts/check-inspection-lock-timeouts.py [--self-test]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

NEXTEST_CONFIG = ROOT / ".config/nextest.toml"
LOCK_SOURCE = ROOT / "crates/test-utils/src/inspection_lock.rs"

GUARD_CALL = re.compile(r"inspection_lock::hold\s*\(")
# Only the guard's own module may define it; every other hit is a caller.
DEFINING_FILE = "crates/test-utils/src/inspection_lock.rs"

SEARCH_ROOTS = ("crates", "bin")


def guarded_call_sites() -> list[Path]:
    """Repo-relative files that call the guard, the tree being the authority."""
    sites: list[Path] = []
    for root in SEARCH_ROOTS:
        for path in sorted((ROOT / root).rglob("*.rs")):
            relative = path.relative_to(ROOT)
            if str(relative) == DEFINING_FILE or "target" in relative.parts:
                continue
            if GUARD_CALL.search(path.read_text()):
                sites.append(relative)
    return sites


def selector_for(relative: Path) -> tuple[str, str]:
    """The nextest selector that must cover this file, and why it is that one.

    `<crate>/tests/<name>.rs` is its own test binary, so `binary(<name>)` names it.
    Anything under `<crate>/src/**` is a unit test inside the crate's lib/bin binary,
    where the only stable selector is the MODULE PATH the file contributes — see
    `module_path`, which follows a `#[path]` mount to the module name it declares.
    """
    parts = list(relative.parts)
    if "tests" in parts:
        index = parts.index("tests")
        if index + 1 < len(parts) and index > 0 and parts[index - 1] != "src":
            return f"binary({Path(parts[-1]).stem})", "integration test binary"
    if "src" not in parts:
        raise AssertionError(f"cannot classify guarded file {relative}")
    return f"test({'::'.join(module_path(relative))}::", "unit-test module prefix"


# `#[path = "<file>"]`, any further attributes, then `[pub(...)] mod <name>;`.
PATH_MOUNT = re.compile(
    r'#\[path\s*=\s*"([^"]+)"\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;'
)


def module_path(relative: Path) -> list[str]:
    """The module path a file under `src/` contributes to its crate's test names.

    A file mounted with `#[path = "..."] mod <name>;` is the module `<name>` of the
    file that mounts it, whatever the file itself is called:
    `crates/core/src/store/backup_tests.rs` is mounted by `store/backup.rs` as
    `mod tests`, so its tests run as `store::backup::tests::*`. Deriving that path
    from the file name instead gives `store::backup_tests::`, a selector that matches
    nothing while its text still sits in the config. The mounting file is searched
    for beside the file and one directory up, which is where a non-inline `#[path]`
    resolves from; a mount inside an inline `mod { }` block is not modelled.
    Otherwise the path is the segments after `src/`, with `mod.rs`/`lib.rs`/`main.rs`
    contributing nothing of their own.
    """
    file = ROOT / relative
    if file.is_file():
        for directory in (file.parent, file.parent.parent):
            for mounting in sorted(directory.glob("*.rs")):
                if mounting == file:
                    continue
                for match in PATH_MOUNT.finditer(mounting.read_text()):
                    if (mounting.parent / match.group(1)).resolve() == file.resolve():
                        return module_path(mounting.relative_to(ROOT)) + [match.group(2)]
    parts = list(relative.parts)
    modules = parts[parts.index("src") + 1 :]
    modules[-1] = Path(modules[-1]).stem
    return [m for m in modules if m not in {"mod", "lib", "main"}]


def override_blocks() -> list[tuple[str, int]]:
    """Each `[[profile.default.overrides]]` block that sets a slow-timeout, with the
    second at which nextest kills a test it matches (`period` x `terminate-after`).

    Blocks with no slow-timeout only change scheduling (a test-group) and cannot satisfy
    this check; every other override in this file is somebody else's cap and is judged
    only if it names a guarded selector.
    """
    config = NEXTEST_CONFIG.read_text()
    blocks: list[tuple[str, int]] = []
    for block in config.split("[[profile.default.overrides]]")[1:]:
        match = re.search(
            r'slow-timeout\s*=\s*\{\s*period\s*=\s*"(\d+)s"\s*,\s*terminate-after\s*=\s*(\d+)',
            block,
        )
        if match:
            blocks.append((block, int(match.group(1)) * int(match.group(2))))
    return blocks


def wait_budget_seconds() -> int:
    source = LOCK_SOURCE.read_text()
    match = re.search(
        r"WAIT_BUDGET:\s*Duration\s*=\s*Duration::from_secs\((\d+)\)", source
    )
    if not match:
        raise AssertionError("cannot read WAIT_BUDGET from the lock module")
    return int(match.group(1))


def check(
    sites: list[Path], blocks: list[tuple[str, int]], budget: int
) -> list[str]:
    failures: list[str] = []
    if not sites:
        failures.append(
            "found NO caller of inspection_lock::hold — either the guard was removed "
            "from every test (say so deliberately) or this scan stopped reading the tree"
        )
    if not blocks:
        failures.append(
            "no slow-timeout override parsed out of .config/nextest.toml; a guarded "
            "test would inherit the default 60s kill"
        )
    for relative in sites:
        selector, kind = selector_for(relative)
        naming = [(block, kill) for block, kill in blocks if selector in block]
        if not naming:
            failures.append(
                f"{relative} holds the inspection lock, but no slow-timeout override in "
                f".config/nextest.toml names its {kind} `{selector}`. Without it the "
                f"blocking wait is killed at nextest's default 60s and reported as a "
                f"TIMEOUT instead of the lock's named refusal."
            )
            continue
        # The ORDER is the property: the refusal must fire before the kill. Only the
        # FIRST matching override decides it — nextest resolves each setting from the
        # earliest override that matches — so a later, shorter cap in this file (the
        # heavy-io inspection group carries one) is none of this check's business, and
        # judging it would demand edits to blocks that no longer decide anything.
        for _, kill in naming[:1]:
            if kill <= budget:
                failures.append(
                    f"the override covering {relative} kills at {kill}s but the lock "
                    f"waits up to {budget}s: nextest would kill the test before the "
                    f"refusal fires, which is the defect this check exists for"
                )
    return failures


def self_test() -> int:
    """Plant each failure and require THIS check to catch it."""
    failures: list[str] = []

    # 1. An uncovered guarded file must be named.
    planted = check(
        [Path("crates/nowhere/src/unlisted_module/tests.rs")],
        override_blocks(),
        wait_budget_seconds(),
    )
    if not any("unlisted_module" in f for f in planted):
        failures.append("an uncovered guarded module was not reported")

    # 2. An override that kills before the budget must be refused, even though every
    #    file is covered — the two numbers are a pair, not two independent settings.
    ordered = check(
        [Path("bin/kata/src/cli/recovery_capture/tests.rs")],
        [
            (
                'filter = test(cli::recovery_capture::tests::)\n'
                'slow-timeout = { period = "10s", terminate-after = 6 }',
                60,
            )
        ],
        wait_budget_seconds(),
    )
    if not any("before the refusal fires" in f for f in ordered):
        failures.append("an override killing before the budget was accepted")

    # 3. Selector derivation, both shapes, since everything above rests on it.
    cases = {
        "bin/kata/src/cli/recovery_capture/tests.rs": "test(cli::recovery_capture::tests::",
        "crates/core/src/store/backup_tests.rs": "test(store::backup::tests::",
        "crates/core/src/sqlite_immutable.rs": "test(sqlite_immutable::",
        "crates/core/tests/backup_durability_tests.rs": "binary(backup_durability_tests)",
    }
    for path, want in cases.items():
        got, _ = selector_for(Path(path))
        if got != want:
            failures.append(f"selector_for({path}) = {got}, expected {want}")

    # 4. NON-VACUITY: the real tree must pass, or the arms above prove nothing about it.
    real = check(guarded_call_sites(), override_blocks(), wait_budget_seconds())
    if real:
        failures.append(f"the real tree does not pass its own check: {real[0]}")

    if failures:
        print(f"inspection-lock timeout check --self-test: FAIL ({len(failures)})")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print(
        "inspection-lock timeout check --self-test: ok — uncovered module, "
        "kill-before-refusal, both selector shapes, and the real tree."
    )
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    sites = guarded_call_sites()
    failures = check(sites, override_blocks(), wait_budget_seconds())
    if failures:
        print(f"inspection-lock timeout check: FAIL ({len(failures)})")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print(
        f"inspection-lock timeout check: ok — {len(sites)} guarded file(s) covered by a "
        f"slow-timeout that outlives the lock's {wait_budget_seconds()}s wait."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
