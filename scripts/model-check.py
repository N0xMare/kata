#!/usr/bin/env python3
"""Model-check a directory of TLA+ specifications against its `checks.toml`.

A models directory (today only `docs/architecture/models/0003/`) carries TLA+
modules and one manifest, `checks.toml`, that names every TLC run the directory
owes and the verdict each run must reach:

* `expect = "pass"`: TLC must explore the whole bounded state space with no
  violation (exit 0, "No error has been found", and a state count).
* `expect = "<Name>"`: TLC must stop on a violation of exactly the invariant or
  property `<Name>` (exit 12 or 13, an `Error:` line naming it, and a state
  count). Two kinds, told apart by the check's `finding` field:
  - a MUTANT (`MUTANT = "<mutant>"`, no `finding`): the RED half. The invariant
    is not vacuous, and the mechanism the mutant removes is the one it rests on.
  - a FINDING (`finding = "<id>"`, `MUTANT = "none"`): the design as written, at
    the constants named, breaks a property it claims; the check pins the
    counterexample until the design or the model changes.

A run that reaches any other verdict fails the whole check: a mutant that
passes, a real model that fails, a violation of another invariant than the
one expected, a TLC error, or a run whose output names no state count. Each
run's full TLC output is kept under `--out` (default
`target/model-check/<directory name>/`), and the summary prints every run's
states generated, distinct states and depth.

THE AUDIT (`--audit`, and before every run) refuses, without TLC: a check
naming an unknown spec, an invariant or property its spec does not list, a
constant its spec does not declare, a mutant its module's `Mutants` set does
not hold, or a symmetry its module does not define; a spec invariant or
property the module does not define; a mutant or finding check that runs any
invariant but the one it expects; a finding whose MUTANT is not "none", or a
mutant check with a `finding`; a mutant the module declares that no check runs;
any spec invariant or property, other than one its spec lists under `typing` or
`refuted`, that no passing check runs or that no mutant check expects; a
`refuted` one that no finding check expects or that a passing check runs; and,
against the directory's README.md, a missing README, a spec invariant or
property its module's row does not name in backticks, a finding id with no
row in the README's Findings table or whose row does not name the check, and
a Findings row whose id no check carries. It cannot see whether a mutant
changes the mechanism its comment names, whether the bounds reach the
behaviours an invariant is about, or whether the README's prose is right.

Every run executes in its own scratch directory under `--out`, holding a copy
of the modules and the generated `.cfg`, so TLC writes nothing into the source
tree; an interrupted run kills its TLC. TLC is resolved by the caller (`just
model-check-0003` builds it from the flake's pinned nixpkgs) and passed as
`--tlc`.

Manifest shape::

    [spec.LeaseOrder]                 # one table per module
    file = "LeaseOrder.tla"
    invariants = ["TypeOK", ...]      # run, less `refuted`, by a check naming none
    properties = ["VerdictsOnlyForward"]
    typing = ["TypeOK"]               # optional: owes no mutant
    refuted = ["NoForwardPastTheBound"]  # optional: a finding refutes it
    [spec.LeaseOrder.constants]       # the real model's constants
    Nodes = "{n1}"                    # a string starting with { or << is raw TLA+
    MUTANT = "none"                   # any other string is a TLA+ string
    L = 5                             # integers and booleans map to TLA+

    [[check]]
    name = "lease-order-mutant-no-slack"
    spec = "LeaseOrder"
    expect = "NoCapsuleAfterSettlement"
    invariants = ["NoCapsuleAfterSettlement"]  # replaces the spec's list
    properties = []                            # replaces the spec's list
    symmetry = "Symmetry"             # optional: a definition TLC reduces by
    [check.constants]                 # overrides of the spec's constants
    MUTANT = "no_slack"

`--self-test` proves the verdict logic and the audit against a fake TLC.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

PASS_LINE = "Model checking completed. No error has been found."
STATES_RE = re.compile(
    r"([\d,]+) states generated, ([\d,]+) distinct states found, ([\d,]+) states left on queue"
)
DEPTH_RE = re.compile(r"The depth of the complete state graph search is (\d+)")
VIOLATION_RE = re.compile(
    r"^Error: (?:Invariant|Action property|Temporal property) (\w+) is violated",
    re.MULTILINE,
)
# TLC's exit codes for a safety violation and a temporal violation.
VIOLATION_EXITS = {12, 13}


class AuditError(Exception):
    pass


def tla_value(value: object) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        if value.startswith("{") or value.startswith("<<"):
            return value
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise AuditError(f"constant value {value!r} is not an int, bool or string")


def checked_names(spec: dict, check: dict) -> tuple[list[str], list[str]]:
    """What a check runs: its own lists, else its spec's, less what a finding refutes."""
    refuted = set(spec.get("refuted", []))
    return (
        check.get("invariants", [n for n in spec.get("invariants", []) if n not in refuted]),
        check.get("properties", [n for n in spec.get("properties", []) if n not in refuted]),
    )


def render_cfg(spec: dict, check: dict) -> str:
    constants = dict(spec["constants"])
    constants.update(check.get("constants", {}))
    invariants, properties = checked_names(spec, check)
    lines = ["CONSTANTS"]
    lines += [f"    {name} = {tla_value(value)}" for name, value in constants.items()]
    lines += ["INIT Init", "NEXT Next"]
    lines += [f"INVARIANT {name}" for name in invariants]
    lines += [f"PROPERTY {name}" for name in properties]
    if "symmetry" in check:
        lines.append(f"SYMMETRY {check['symmetry']}")
    return "\n".join(lines) + "\n"


def module_mutants(source: str) -> set[str]:
    """The strings of the module's `Mutants == {...}` set, its line comments dropped."""
    found = re.search(r"^Mutants == \{(.*?)\}", source, re.MULTILINE | re.DOTALL)
    if not found:
        return set()
    return set(re.findall(r'"(\w+)"', re.sub(r"\\\*[^\n]*", "", found.group(1))))


def readme_rows(readme: str) -> tuple[dict[str, str], dict[str, str]]:
    """The Modules table's rows by module file, and the Findings table's check cells by id."""
    modules: dict[str, str] = {}
    findings: dict[str, str] = {}
    section = ""
    for line in readme.splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if not cells or not line.startswith("|") or set(line) <= set("|-: "):
            continue
        module = re.fullmatch(r"`(\w+\.tla)`", cells[0])
        if module:
            modules[module.group(1)] = line
        elif section == "Findings" and cells[0] != "Id" and len(cells) > 1:
            findings[cells[0]] = cells[1]
    return modules, findings


def audit(models: Path, manifest: dict) -> None:
    """Refuse, by name, every manifest defect the module docstring lists."""
    specs = manifest.get("spec", {})
    checks = manifest.get("check", [])
    problems: list[str] = []
    sources: dict[str, str] = {}
    for name, spec in specs.items():
        path = models / spec["file"]
        if not path.is_file():
            problems.append(f"spec {name}: no module {spec['file']}")
            continue
        sources[name] = path.read_text()
        for symbol in spec.get("invariants", []) + spec.get("properties", []):
            if not re.search(rf"^{symbol} ==", sources[name], re.MULTILINE):
                problems.append(f"spec {name}: {spec['file']} defines no `{symbol}`")
        for constant in spec.get("constants", {}):
            if not re.search(rf"\b{constant}\b", sources[name].split("VARIABLE")[0]):
                problems.append(f"spec {name}: {spec['file']} declares no constant `{constant}`")
    names = [c.get("name", "?") for c in checks]
    for dup in sorted({n for n in names if names.count(n) > 1}):
        problems.append(f"check {dup}: named twice")
    passing: dict[str, set[str]] = {n: set() for n in specs}
    reds: dict[str, set[str]] = {n: set() for n in specs}
    found: dict[str, set[str]] = {n: set() for n in specs}
    mutants_run: dict[str, set[str]] = {n: set() for n in specs}
    for check in checks:
        name = check.get("name", "?")
        spec_name = check.get("spec")
        if spec_name not in specs:
            problems.append(f"check {name}: no spec `{spec_name}`")
            continue
        spec = specs[spec_name]
        listed = spec.get("invariants", []) + spec.get("properties", [])
        invariants, properties = checked_names(spec, check)
        for symbol in invariants + properties:
            if symbol not in listed:
                problems.append(f"check {name}: `{symbol}` is not one of {spec_name}'s")
        overrides = check.get("constants", {})
        for constant in overrides:
            if constant not in spec.get("constants", {}):
                problems.append(f"check {name}: no constant `{constant}` in {spec_name}")
        symmetry = check.get("symmetry")
        if symmetry and not re.search(rf"^{symmetry} ==", sources.get(spec_name, ""),
                                      re.MULTILINE):
            problems.append(f"check {name}: {spec['file']} defines no symmetry `{symmetry}`")
        mutant = overrides.get("MUTANT", spec.get("constants", {}).get("MUTANT", "none"))
        declared = module_mutants(sources.get(spec_name, ""))
        if mutant != "none" and mutant not in declared:
            problems.append(f"check {name}: `{mutant}` is not in {spec_name}'s Mutants")
        expect = check.get("expect")
        if expect == "pass":
            if mutant != "none" or "finding" in check:
                problems.append(f"check {name}: a passing check runs no mutant and no finding")
            passing[spec_name].update(invariants + properties)
            continue
        if expect not in listed:
            problems.append(f"check {name}: expects `{expect}`, not one of {spec_name}'s")
        if invariants + properties != [expect]:
            problems.append(f"check {name}: runs {invariants + properties}, not only `{expect}`")
        if "finding" in check:
            found[spec_name].add(expect)
            if mutant != "none":
                problems.append(f"check {name}: a finding runs the model as written, no mutant")
        elif mutant == "none":
            problems.append(f"check {name}: expects a violation with no mutant and no finding")
        else:
            reds[spec_name].add(expect)
            mutants_run[spec_name].add(mutant)
    for spec_name, spec in specs.items():
        typing = set(spec.get("typing", []))
        refuted = set(spec.get("refuted", []))
        for symbol in spec.get("invariants", []) + spec.get("properties", []):
            if symbol in refuted:
                if symbol not in found[spec_name]:
                    problems.append(f"spec {spec_name}: no finding check refutes `{symbol}`")
                if symbol in passing[spec_name]:
                    problems.append(f"spec {spec_name}: a passing check runs refuted `{symbol}`")
                continue
            if symbol not in passing[spec_name]:
                problems.append(f"spec {spec_name}: no passing check runs `{symbol}`")
            if symbol not in typing and symbol not in reds[spec_name]:
                problems.append(f"spec {spec_name}: no mutant check breaks `{symbol}`")
        for mutant in sorted(module_mutants(sources.get(spec_name, "")) - {"none"}):
            if mutant not in mutants_run[spec_name]:
                problems.append(f"spec {spec_name}: no check runs mutant `{mutant}`")
    readme = models / "README.md"
    if not readme.is_file():
        problems.append(f"{models.name}: no README.md")
    else:
        modules, findings = readme_rows(readme.read_text())
        for spec in specs.values():
            row = modules.get(spec["file"])
            if row is None:
                problems.append(f"README: no row for `{spec['file']}`")
                continue
            for symbol in spec.get("invariants", []) + spec.get("properties", []):
                if f"`{symbol}`" not in row:
                    problems.append(f"README: the `{spec['file']}` row names no `{symbol}`")
        pinned = set()
        for check in checks:
            if "finding" not in check:
                continue
            finding, name = check["finding"], check.get("name", "?")
            pinned.add(finding)
            if finding not in findings:
                problems.append(f"finding {finding}: no README row")
            elif f"`{name}`" not in findings[finding]:
                problems.append(f"README finding {finding}: does not name check `{name}`")
        for finding in sorted(set(findings) - pinned):
            problems.append(f"README finding {finding}: no check pins it")
    if problems:
        raise AuditError("\n".join(problems))


def judge(check: dict, returncode: int, output: str) -> tuple[bool, str, str]:
    counts = STATES_RE.findall(output)
    depth = DEPTH_RE.search(output)
    states = (
        f"{counts[-1][0]} generated, {counts[-1][1]} distinct, depth "
        f"{depth.group(1) if depth else '?'}"
        if counts
        else "no state count"
    )
    expect = check["expect"]
    violated = VIOLATION_RE.findall(output)
    if expect == "pass":
        ok = returncode == 0 and PASS_LINE in output and bool(counts) and not violated
        verdict = "passed" if ok else f"rc {returncode}, violated {violated or '?'}"
    else:
        ok = returncode in VIOLATION_EXITS and violated == [expect] and bool(counts)
        verdict = (
            f"violated {expect} as expected"
            if ok
            else f"rc {returncode}, violated {violated or 'nothing'}, expected {expect}"
        )
    return ok, verdict, states


def run_check(
    check: dict, specs: dict, models: Path, out: Path, tlc: str, workers: str
) -> tuple[bool, str]:
    name = check["name"]
    spec = specs[check["spec"]]
    scratch = out / name
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    for module in models.glob("*.tla"):
        shutil.copy2(module, scratch / module.name)
    cfg = scratch / f"{name}.cfg"
    cfg.write_text(render_cfg(spec, check))
    env = dict(os.environ)
    # TLC extracts its standard modules into java.io.tmpdir; keep that inside the run.
    (scratch / "tmp").mkdir()
    env["JAVA_TOOL_OPTIONS"] = f"-Djava.io.tmpdir={scratch / 'tmp'}"
    command = [tlc, "-workers", workers, "-deadlock", "-cleanup",
               "-metadir", str(scratch / "states"), "-config", cfg.name, spec["file"]]
    started = time.monotonic()
    log = out / f"{name}.log"
    with log.open("w") as sink:
        proc = subprocess.Popen(command, cwd=scratch, env=env, stdout=sink,
                                stderr=subprocess.STDOUT)
        try:
            returncode = proc.wait()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    seconds = time.monotonic() - started
    output = log.read_text()
    shutil.rmtree(scratch / "states", ignore_errors=True)
    shutil.rmtree(scratch / "tmp", ignore_errors=True)
    ok, verdict, states = judge(check, returncode, output)
    finding = f" [{check['finding']}]" if "finding" in check else ""
    line = f"{'ok  ' if ok else 'FAIL'} {name:<52} {verdict}{finding}; {states}; {seconds:.1f}s"
    return ok, line


# ─── self-test ────────────────────────────────────────────────────────────────

FAKE_TLC = r'''#!/usr/bin/env python3
import re, sys
cfg = open(sys.argv[sys.argv.index("-config") + 1]).read()
mode = re.search(r'FAKE = "(\w+)"', cfg).group(1)
counts = "7 states generated, 5 distinct states found, 0 states left on queue."
depth = "The depth of the complete state graph search is 3."
if mode == "pass":
    print("Model checking completed. No error has been found."); print(counts); print(depth)
elif mode.startswith("violate_"):
    print(f"Error: Invariant {mode[len('violate_'):]} is violated."); print(counts)
    sys.exit(12)
elif mode == "nocount":
    print("Model checking completed. No error has been found.")
elif mode == "error":
    print("Error: TLC threw an unexpected exception."); sys.exit(75)
'''

TOY = """---- MODULE Toy ----
CONSTANTS FAKE, MUTANT
Mutants == {"none", "m1"}
VARIABLE x
Init == x = 0
Next == x' = x
InvA == TRUE
InvB == TRUE
Sym == {}
====
"""

TOY_README = """# Toy

| Module | Invariants |
|---|---|
| `Toy.tla` | `InvA`; `InvB` |

## Findings

| Id | Check | What breaks |
|---|---|---|
"""

TOY_MANIFEST = """
[spec.Toy]
file = "Toy.tla"
invariants = ["InvA", "InvB"]
properties = []
[spec.Toy.constants]
FAKE = "pass"
MUTANT = "none"

[[check]]
name = "real"
spec = "Toy"
expect = "pass"

[[check]]
name = "red-a"
spec = "Toy"
expect = "InvA"
invariants = ["InvA"]
[check.constants]
MUTANT = "m1"
FAKE = "violate_InvA"

[[check]]
name = "red-b"
spec = "Toy"
expect = "InvB"
invariants = ["InvB"]
[check.constants]
MUTANT = "m1"
FAKE = "violate_InvB"
"""


def self_test() -> int:
    failures: list[str] = []
    refusals = 0

    def expect_audit(label: str, manifest_text: str, fragment: str | None) -> None:
        nonlocal refusals
        refusals += fragment is not None
        try:
            audit(models, tomllib.loads(manifest_text))
        except AuditError as error:
            if fragment is None or fragment not in str(error):
                failures.append(f"audit {label}: refused with {error!s}")
            return
        if fragment is not None:
            failures.append(f"audit {label}: accepted; expected a refusal naming {fragment!r}")

    with tempfile.TemporaryDirectory() as root:
        base = Path(root)
        models = base / "models"
        models.mkdir()
        (models / "Toy.tla").write_text(TOY)
        (models / "README.md").write_text(TOY_README)
        tlc = base / "fake-tlc"
        tlc.write_text(FAKE_TLC)
        tlc.chmod(0o755)
        out = base / "out"
        out.mkdir()
        before = sorted(p.name for p in models.iterdir())

        expect_audit("a complete manifest", TOY_MANIFEST, None)
        expect_audit("an unknown invariant",
                     TOY_MANIFEST + '\n[[check]]\nname = "x"\nspec = "Toy"\nexpect = "pass"\n'
                     'invariants = ["InvC"]\n', "`InvC` is not one of Toy's")
        expect_audit("an unknown constant",
                     TOY_MANIFEST + '\n[[check]]\nname = "x"\nspec = "Toy"\nexpect = "pass"\n'
                     '[check.constants]\nNOPE = 1\n', "no constant `NOPE`")
        expect_audit("an undeclared mutant",
                     TOY_MANIFEST + '\n[[check]]\nname = "x"\nspec = "Toy"\nexpect = "InvA"\n'
                     'invariants = ["InvA"]\n[check.constants]\nMUTANT = "m9"\n',
                     "`m9` is not in Toy's Mutants")
        expect_audit("an invariant with no mutant",
                     TOY_MANIFEST.split('[[check]]\nname = "red-b"')[0],
                     "no mutant check breaks `InvB`")
        expect_audit("a red check running two invariants",
                     TOY_MANIFEST.replace('expect = "InvA"\ninvariants = ["InvA"]',
                                          'expect = "InvA"\ninvariants = ["InvA", "InvB"]'),
                     "not only `InvA`")
        expect_audit("a finding with a mutant",
                     TOY_MANIFEST + '\n[[check]]\nname = "f"\nspec = "Toy"\nexpect = "InvA"\n'
                     'finding = "F9"\ninvariants = ["InvA"]\n[check.constants]\nMUTANT = "m1"\n',
                     "a finding runs the model as written")
        expect_audit("a violation with no mutant and no finding",
                     TOY_MANIFEST + '\n[[check]]\nname = "v"\nspec = "Toy"\nexpect = "InvA"\n'
                     'invariants = ["InvA"]\n', "with no mutant and no finding")
        expect_audit("a mutant no check runs",
                     TOY_MANIFEST.replace('MUTANT = "m1"', 'MUTANT = "none"', 2)
                     .replace('expect = "InvA"', 'expect = "InvA"\nfinding = "F1"')
                     .replace('expect = "InvB"', 'expect = "InvB"\nfinding = "F2"'),
                     "no check runs mutant `m1`")
        refuted_b = (TOY_MANIFEST.replace('properties = []\n[spec.Toy.constants]',
                                          'properties = []\nrefuted = ["InvB"]\n'
                                          '[spec.Toy.constants]')
                     .replace('expect = "InvB"', 'expect = "InvB"\nfinding = "F2"')
                     .replace('MUTANT = "m1"\nFAKE = "violate_InvB"', 'FAKE = "violate_InvB"'))
        (models / "README.md").write_text(TOY_README + "| F2 | `red-b` | InvB |\n")
        expect_audit("a refuted invariant left out of a passing check's default", refuted_b,
                     None)
        expect_audit("a refuted invariant a passing check runs",
                     refuted_b.replace('name = "real"\nspec = "Toy"\nexpect = "pass"',
                                       'name = "real"\nspec = "Toy"\nexpect = "pass"\n'
                                       'invariants = ["InvA", "InvB"]'),
                     "a passing check runs refuted `InvB`")
        (models / "README.md").write_text(TOY_README)
        expect_audit("an undefined spec invariant",
                     TOY_MANIFEST.replace('invariants = ["InvA", "InvB"]',
                                          'invariants = ["InvA", "InvB", "InvZ"]'),
                     "defines no `InvZ`")
        expect_audit("an undefined symmetry",
                     TOY_MANIFEST + '\n[[check]]\nname = "s"\nspec = "Toy"\nexpect = "pass"\n'
                     'symmetry = "Perms"\n', "defines no symmetry `Perms`")
        expect_audit("a defined symmetry",
                     TOY_MANIFEST + '\n[[check]]\nname = "s"\nspec = "Toy"\nexpect = "pass"\n'
                     'symmetry = "Sym"\n', None)
        expect_audit("a finding with no README row",
                     TOY_MANIFEST + '\n[[check]]\nname = "f"\nspec = "Toy"\nexpect = "InvA"\n'
                     'finding = "F1"\ninvariants = ["InvA"]\n', "finding F1: no README row")
        (models / "README.md").write_text(TOY_README + "| F1 | `f` | InvA, as written |\n")
        expect_audit("a finding whose README row names another check",
                     TOY_MANIFEST + '\n[[check]]\nname = "g"\nspec = "Toy"\nexpect = "InvA"\n'
                     'finding = "F1"\ninvariants = ["InvA"]\n', "does not name check `g`")
        expect_audit("a README finding no check pins", TOY_MANIFEST,
                     "README finding F1: no check pins it")
        (models / "README.md").write_text(TOY_README.replace("`InvA`; `InvB`", "`InvA`"))
        expect_audit("an invariant with no README row", TOY_MANIFEST,
                     "README: the `Toy.tla` row names no `InvB`")
        (models / "README.md").write_text(TOY_README.replace("| `Toy.tla` |", "| Toy |"))
        expect_audit("a module with no README row", TOY_MANIFEST, "README: no row for `Toy.tla`")
        (models / "README.md").unlink()
        expect_audit("no README", TOY_MANIFEST, "no README.md")
        (models / "README.md").write_text(TOY_README)

        spec = tomllib.loads(TOY_MANIFEST)["spec"]
        cases = [
            ("a real model that passes", "pass", "pass", True),
            ("a real model that violates", "pass", "violate_InvA", False),
            ("a pass with no state count", "pass", "nocount", False),
            ("a TLC error", "pass", "error", False),
            ("a mutant that breaks its invariant", "InvA", "violate_InvA", True),
            ("a mutant that breaks another invariant", "InvA", "violate_InvB", False),
            ("a mutant that passes", "InvA", "pass", False),
            ("a mutant whose run errors", "InvA", "error", False),
        ]
        verdicts = len(cases)
        for label, expect, mode, want in cases:
            check = {"name": "case", "spec": "Toy", "expect": expect,
                     "constants": {"FAKE": mode}}
            if expect != "pass":
                check["invariants"] = [expect]
            ok, line = run_check(check, spec, models, out, str(tlc), "1")
            if ok != want:
                failures.append(f"verdict {label}: got {'ok' if ok else 'FAIL'} ({line})")

        if sorted(p.name for p in models.iterdir()) != before:
            failures.append("a run wrote into the models directory")

    for failure in failures:
        print(f"model-check self-test: FAIL {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"model-check self-test: OK — {refusals} audit refusals and {verdicts} verdicts, "
          "against a fake TLC")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("models", type=Path, nargs="?", help="a directory holding checks.toml")
    parser.add_argument("--tlc", help="the TLC launcher (tlaplus's bin/tlc)")
    parser.add_argument("--out", type=Path, help="where logs and scratch runs go")
    parser.add_argument("--workers", default="16", help="TLC worker threads per run")
    parser.add_argument("--only", action="append", default=[], help="run only these checks")
    parser.add_argument("--audit", action="store_true", help="audit the manifest; run nothing")
    parser.add_argument("--self-test", action="store_true", help="prove this script's refusals")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.models is None:
        parser.error("a models directory is required")

    models = args.models.resolve()
    manifest = tomllib.loads((models / "checks.toml").read_text())
    try:
        audit(models, manifest)
    except AuditError as error:
        print(f"model-check {args.models}: the manifest is refused:\n{error}", file=sys.stderr)
        return 1
    checks = manifest["check"]
    if args.audit:
        print(f"model-check {args.models}: manifest audit OK — {len(checks)} checks")
        return 0
    if not args.tlc:
        parser.error("--tlc is required to run the checks")
    unknown = set(args.only) - {c["name"] for c in checks}
    if unknown:
        print(f"model-check: --only names no check: {sorted(unknown)}", file=sys.stderr)
        return 1
    selected = [c for c in checks if not args.only or c["name"] in args.only]

    # A TERM (the gate's timeout, a cancelled recipe) unwinds through run_check's
    # `finally`, which kills the TLC it started.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    out = (args.out or Path("target/model-check") / models.name).resolve()
    out.mkdir(parents=True, exist_ok=True)
    failures = 0
    started = time.monotonic()
    for check in selected:
        ok, line = run_check(check, manifest["spec"], models, out, args.tlc, args.workers)
        print(line, flush=True)
        failures += not ok
    print(
        f"model-check {args.models}: {len(selected) - failures}/{len(selected)} runs reached "
        f"their expected verdict in {time.monotonic() - started:.0f}s; logs in {out}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
