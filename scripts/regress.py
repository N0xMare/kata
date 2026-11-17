#!/usr/bin/env python3
"""Prove the same nonempty tests fail on explicit baseline bytes and pass on fix bytes.

Run with exclusive access to the named files. SIGINT/SIGTERM restore them;
SIGKILL/power loss cannot run cleanup, so the printed backup directory survives.
No git index, HEAD, or stash is read or changed.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


def listing_parser(text):
    spec = importlib.util.spec_from_file_location(
        "test_partition", Path(__file__).with_name("check-test-partition.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.selected_tests(module.parse_listing(text))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install(source, target):
    shutil.copyfile(source, target)
    shutil.copymode(source, target)
    # Cargo freshness keys on mtimes. Preserving the pre-fix mtime can run the
    # already-built fixed binary against baseline bytes and fabricate a green.
    os.utime(target, None)


def safe_file(root, relative):
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(
        part in ("..", ".git", ".jj") for part in path.parts
    ):
        raise ValueError("paths must be relative files outside VCS metadata")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink paths are refused")
    if not current.is_file() or current.stat().st_nlink != 1:
        raise ValueError("paths must be existing regular files without hard links")
    return current


def bounded_command(command, root, timeout=900):
    process = subprocess.Popen(command, cwd=root, text=True, stdout=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, _ = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, stdout)
    except BaseException:
        # Our fresh process group only: stop Cargo, nextest and their ordinary
        # descendants before restoring source files. Detached children are not
        # covered; tests must obey nextest's process lifecycle contract.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise


def cargo_runner(root, expression, operation):
    command = [
        "cargo", "nextest", operation, "--workspace", "--ignore-default-filter",
        "-P", "default", "-E", expression,
    ]
    if operation == "list":
        command += ["--message-format", "json"]
        return bounded_command(command, root)
    # Preserve the repository's timeout/override policy, changing only its JUnit
    # destination. A private fresh report cannot be confused with another run.
    with tempfile.TemporaryDirectory(prefix="kata-regress-report-") as directory:
        report = Path(directory) / "junit.xml"
        config = Path(directory) / "nextest.toml"
        source = (root / ".config/nextest.toml").read_text()
        def replace_report(match):
            block, count = re.subn(r'^path\s*=.*$', "path = " + json.dumps(str(report)),
                                   match.group(0), flags=re.M)
            if count != 1:
                raise ValueError("expected one default JUnit report path")
            return block
        source, count = re.subn(r'^\[profile\.default\.junit\]\n.*?(?=^\[|\Z)',
                                replace_report, source, flags=re.M | re.S)
        if count != 1:
            raise ValueError("expected default JUnit configuration")
        config.write_text(source)
        command += ["--retries", "0", "--no-fail-fast", "--config-file", str(config)]
        result = bounded_command(command, root)
        return subprocess.CompletedProcess(command, result.returncode,
                                           report.read_text() if report.is_file() else "")


def verify_run(result, selected, red):
    expected = 100 if red else 0
    if result.returncode != expected:
        raise ValueError(f"{'baseline' if red else 'fixed tests'} must exit {expected}, got {result.returncode}")
    try:
        document = ET.fromstring(result.stdout)
    except ET.ParseError as error:
        raise ValueError("missing or invalid fresh JUnit run report") from error
    if document.tag != "testsuites":
        raise ValueError("unrecognized JUnit report")
    seen, failed = set(), set()
    for suite in document:
        if suite.tag != "testsuite":
            raise ValueError("unrecognized JUnit suite")
        for case in suite.findall("testcase"):
            identity = (suite.get("name"), case.get("name"))
            if identity in seen or case.get("classname") != identity[0]:
                raise ValueError("duplicate or inconsistent JUnit identity")
            seen.add(identity)
            for child in case:
                if child.tag in ("system-out", "system-err"):
                    continue
                if child.tag != "failure" or child.get("type") not in (
                    "test failure", "test failure with exit code 101"
                ):
                    raise ValueError(f"run contains timeout, abort, skip, retry or unknown outcome: {child.tag} {child.get('type')}")
                failed.add(identity)
    if seen != selected:
        raise ValueError("JUnit executed identities differ from selected tests")
    if bool(failed) != red:
        raise ValueError("JUnit does not confirm expected test failure/pass")


def prove(root, baseline, expression, paths, runner=cargo_runner):
    root = Path(root).resolve(strict=True)
    baseline = Path(baseline).resolve(strict=True)
    if not expression.strip() or not paths or len(set(paths)) != len(paths):
        raise ValueError("supply a filter and distinct source paths")
    targets = [safe_file(root, path) for path in paths]
    sources = [safe_file(baseline, path) for path in paths]
    if len(set(targets)) != len(targets) or set(targets) & set(sources):
        raise ValueError("baseline and fix must be distinct files")
    original = [digest(path) for path in targets]
    before = [digest(path) for path in sources]
    if original == before:
        raise ValueError("baseline is byte-identical to the fix")

    def selected():
        result = runner(root, expression, "list")
        if result.returncode != 0:
            raise ValueError(f"nextest list failed with exit {result.returncode}")
        tests = listing_parser(result.stdout)
        if not tests:
            raise ValueError("zero runnable tests selected")
        return tests

    fixed_tests = selected()
    backup = Path(tempfile.mkdtemp(prefix="kata-regress-backup-"))
    print(f"regress: recovery backup {backup}", flush=True)
    for index, target in enumerate(targets):
        shutil.copy2(target, backup / str(index))
        if digest(backup / str(index)) != original[index]:
            raise ValueError(f"backup verification failed; retained {backup}")
    (backup / "manifest.json").write_text(json.dumps({
        "root": str(root), "paths": paths, "sha256": original,
    }, indent=2) + "\n")
    try:
        for index, (source, target) in enumerate(zip(sources, targets)):
            if digest(source) != before[index] or digest(target) != original[index]:
                raise ValueError("file changed during baseline preparation")
            install(source, target)
            if digest(target) != before[index]:
                raise ValueError("baseline copy verification failed")
        if selected() != fixed_tests:
            raise ValueError("baseline and fix select different test identities")
        print(f"regress: baseline must FAIL ({len(fixed_tests)} tests)", flush=True)
        result = runner(root, expression, "run")
        verify_run(result, fixed_tests, red=True)
    finally:
        # Verify EVERY backup before touching ANY target, and refuse to erase
        # concurrent edits. A refused restore leaves the manifest and backups.
        for index, target in enumerate(targets):
            safe_file(root, paths[index])
            if digest(backup / str(index)) != original[index]:
                raise ValueError(f"backup corrupted; manual recovery from {backup}")
            if digest(target) not in (before[index], original[index]):
                raise ValueError(f"concurrent edit; manual recovery from {backup}")
        for index, target in enumerate(targets):
            install(backup / str(index), target)
            if digest(target) != original[index]:
                raise ValueError(f"restore verification failed; retained {backup}")
        shutil.rmtree(backup)
    if selected() != fixed_tests:
        raise ValueError("restored fix changed the selected test identities")
    print(f"regress: fix must PASS ({len(fixed_tests)} tests)", flush=True)
    result = runner(root, expression, "run")
    verify_run(result, fixed_tests, red=False)
    print(f"regress: PASS — same {len(fixed_tests)} tests fail then pass", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="directory containing explicit pre-fix files")
    parser.add_argument("filter", help="nextest filterset expression")
    parser.add_argument("paths", nargs="+", help="repository-relative implementation files")
    args = parser.parse_args()

    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        prove(Path.cwd(), args.baseline, args.filter, args.paths)
    except (ValueError, OSError, KeyboardInterrupt, subprocess.TimeoutExpired) as error:
        print(f"regress: FAIL — {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
