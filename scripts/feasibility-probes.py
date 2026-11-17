#!/usr/bin/env python3
"""Run kata's non-model-spending host feasibility probes.

The output is evidence, not certification. Every row is one of passed, failed,
unsupported, or not_run; absent prerequisites are never converted into a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Result:
    probe: str
    status: str
    evidence: str


# ── The youki pin ────────────────────────────────────────────────────────────
# The probe is the only Python reader of `config/youki-pin.toml` since the
# AppArmor install moved into `kata host apparmor-install`; the Rust half is
# `kata_types::youki_pin`, embedded at build time. The two parse one file and
# refuse the same fields, so an operator sees whichever fires first.
PIN_FILE = Path(__file__).resolve().parent.parent / "config" / "youki-pin.toml"
PIN_REQUIRED = ("realised_by", "version", "store_path", "sha256", "profile_name", "pinned_on")


class PinError(Exception):
    """The pin, or the host state it names, disagreed with what was claimed."""


@dataclass(frozen=True)
class Pin:
    realised_by: str
    version: str
    store_path: str
    sha256: str
    profile_name: str
    pinned_on: str


def load_pin(path: Path = PIN_FILE) -> Pin:
    """Parse the pin. Every refusal names the field, so an operator can fix one line."""
    try:
        document = tomllib.loads(path.read_text())
    except OSError as error:
        raise PinError(f"cannot read the pin {path}: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise PinError(f"{path} is not valid TOML: {error}") from error
    table = document.get("youki")
    if not isinstance(table, dict):
        raise PinError(f"{path} has no [youki] table")
    missing = [field for field in PIN_REQUIRED if not isinstance(table.get(field), str)]
    if missing:
        raise PinError(f"{path} [youki] is missing string field(s): {', '.join(missing)}")
    pin = Pin(**{field: table[field] for field in PIN_REQUIRED})
    if not pin.store_path.startswith("/"):
        raise PinError(f"store_path must be absolute, got {pin.store_path!r}")
    if len(pin.sha256) != 64 or any(c not in "0123456789abcdef" for c in pin.sha256):
        raise PinError(f"sha256 must be 64 lowercase hex characters, got {pin.sha256!r}")
    if "/" in pin.profile_name or pin.profile_name in ("", ".", ".."):
        raise PinError(f"profile_name must be one path-free name, got {pin.profile_name!r}")
    return pin


def verify_pinned_binary(pin: Pin) -> str:
    """Refuse unless the pinned path holds exactly the pinned bytes.

    Refused set: an absent or unreadable `store_path`, and a readable one whose
    sha256 differs from the pin. Nothing else — this says nothing about whether
    the binary runs, which only the probe observes.
    """
    path = Path(pin.store_path)
    if not path.is_file():
        raise PinError(
            f"the pinned youki is absent: {pin.store_path} is not a file. Realise it from the "
            f"kata checkout with `{pin.realised_by}`, then re-pin {PIN_FILE} if the store path "
            "moved. A plain "
            "`nix profile install nixpkgs#youki` is NOT a substitute: that build has no "
            "libseccomp and silently ignores linux.seccomp."
        )
    try:
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise PinError(f"cannot read {pin.store_path} to digest it: {error}") from error
    if observed != pin.sha256:
        raise PinError(
            f"DIGEST MISMATCH at {pin.store_path}: pin says sha256 {pin.sha256}, the bytes on "
            f"disk are sha256 {observed}. A Nix store path is immutable, so this means the pin "
            f"is stale or the store is damaged — refusing to treat these bytes as the pinned "
            f"containment binary."
        )
    return observed


def run(
    argv: list[str],
    *,
    input_text: str | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 15,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=input_text,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def version(executable: str, *args: str) -> str:
    completed = run([executable, *args])
    text = (completed.stdout or completed.stderr).splitlines()
    return text[0].strip() if completed.returncode == 0 and text else "version unavailable"






def probe_portable_artifact() -> Result:
    with tempfile.TemporaryDirectory(prefix="kata-artifact-probe-") as temporary:
        root = Path(temporary)
        source = root / "source" / "payload"
        source.parent.mkdir()
        payload = b"kata portable artifact probe\n"
        source.write_bytes(payload)
        identity = hashlib.sha256(payload).digest()
        first = root / "layout-a" / "objects" / identity.hex()
        first.parent.mkdir(parents=True)
        shutil.copyfile(source, first)
        source.unlink()
        second = root / "different-layout" / "materialized"
        second.parent.mkdir(parents=True)
        shutil.copyfile(first, second)
        relocated = hashlib.sha256(second.read_bytes()).digest()
        second.write_bytes(second.read_bytes() + b"corrupt")
        corrupt = hashlib.sha256(second.read_bytes()).digest()
        if relocated != identity or corrupt == identity:
            return Result("portable artifact relocation", "failed", "identity check disagreed")
    return Result(
        "portable artifact relocation",
        "passed",
        "bytes survived source removal and host-layout change; corruption changed identity",
    )


def probe_nix() -> list[Result]:
    nix = shutil.which("nix")
    nix_store = shutil.which("nix-store")
    if nix is None or nix_store is None:
        return [Result("Nix local store", "unsupported", "nix and nix-store are required")]
    try:
        with tempfile.TemporaryDirectory(prefix="kata-nix-probe-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            payload = b"kata nix feasibility probe\n"
            (source / "payload").write_bytes(payload)
            added = run([nix, "store", "add-path", str(source)], timeout=30)
            if added.returncode != 0:
                return [Result("Nix local store", "failed", "nix store add-path refused")]
            store_path = Path(added.stdout.strip())
            source.rename(root / "source-relocated")
            if (store_path / "payload").read_bytes() != payload:
                return [Result("Nix local store", "failed", "store bytes changed after relocation")]
            closure = run([nix, "path-info", "--recursive", str(store_path)], timeout=30)
            verify = run([nix, "store", "verify", "--no-trust", str(store_path)], timeout=30)
            root_link = root / "gc-root"
            rooted = run(
                [nix_store, "--add-root", str(root_link), "--indirect", "-r", str(store_path)],
                timeout=30,
            )
            if closure.returncode != 0 or verify.returncode != 0 or rooted.returncode != 0:
                return [Result("Nix local store", "failed", "closure, integrity, or root command refused")]
            if not root_link.is_symlink() or root_link.resolve() != store_path:
                return [Result("Nix local store", "failed", "indirect root did not bind store path")]
        return [
            Result(
                "Nix import/closure/integrity/root",
                "passed",
                f"{version(nix, '--version')}; local path survived relocation and was verified/rooted",
            ),
            Result(
                "Nix concurrent GC and restart reconciliation",
                "not_run",
                "not probed here: proved in crates/core/tests/nix_environment_plane.rs against a "
                "disposable --store, which this script must not create on the host store",
            ),
        ]
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return [Result("Nix local store", "failed", type(error).__name__)]



def sanitized(text: str) -> str:
    """Replace this machine's home directory with `~` so evidence stays portable."""
    home = os.environ.get("HOME")
    return text.replace(home, "~") if home else text


def pinned_version(version: str) -> tuple[int, ...]:
    """The pin's `version` as a comparable tuple; an unreadable one is (0,)."""
    parts = version.split(".")
    if len(parts) >= 3 and all(part.isdigit() for part in parts[:3]):
        return tuple(int(part) for part in parts[:3])
    return (0,)


def youki_identification(executable: str) -> tuple[tuple[int, ...], str, str]:
    """youki's parsed version, its first line, and its WHOLE identification.

    Three values out of ONE exec, because two facts are read off it and a second
    `--version` would be a second measurement of one binary's self-description,
    able to disagree with the first — the same reason
    `kata_worker::oci_runtime::certify_youki` folds one captured output twice.

    The shared `version()` helper keeps only the first line, which is the right
    shape for a one-row evidence table and the wrong shape for the `libseccomp:`
    line three lines below it. So the full text is returned beside it rather than
    read again. An unparsable version reads as (0,).
    """
    completed = run([executable, "--version"])
    text = completed.stdout or completed.stderr
    if completed.returncode != 0 or not text.splitlines():
        return (0,), "version unavailable", text
    reported = text.splitlines()[0].strip()
    for token in reported.replace(":", " ").split():
        parts = token.split(".")
        if len(parts) >= 3 and all(part.isdigit() for part in parts[:3]):
            return tuple(int(part) for part in parts[:3]), reported, text
    return (0,), reported, text


def youki_libseccomp(reported: str) -> str | None:
    """The libseccomp version `youki --version` reported, or None if it reported none.

    `youki --version` prints a `libseccomp: <version>` line under
    `#[cfg(feature = "seccomp")]`, and that feature's only effect is to turn on
    `libcontainer/libseccomp` — the `cfg` gating every seccomp call in the
    runtime's init. So the line is present if and only if the runtime will honour
    `linux.seccomp` at all; without it the section is DROPPED in silence and the
    stage fence would be absent while every surface reported it present.

    NOT read off `youki features`: youki 0.7.0's `commands/features.rs` never
    populates the OCI-features document's `linux.seccomp` field (it carries a
    literal `// TODO: Expose seccomp support information`), so it reports null on
    a libseccomp build and a non-libseccomp build alike. The same discipline and
    the same line `kata_worker::oci_runtime::fold_seccomp_support` folds, so the
    two surfaces refuse the same binaries.
    """
    for line in reported.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() == "libseccomp" and value.strip():
            return value.strip()
    return None


def static_payload() -> Path | None:
    """A binary that runs in a rootfs holding nothing else, or None if none is static."""
    file_tool = shutil.which("file")
    candidates = ["/bin/true", "/usr/bin/busybox-static", "/bin/busybox-static", "/usr/bin/busybox"]
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_file() or file_tool is None:
            continue
        described = run([file_tool, "--brief", str(path)])
        if described.returncode == 0 and "statically linked" in described.stdout:
            return path
    return None


def build_rootfs(rootfs: Path) -> str:
    """Populate `rootfs` so that `/bin/true` is executable inside it."""
    rootfs.mkdir(parents=True)
    (rootfs / "bin").mkdir()
    target = rootfs / "bin" / "true"
    static = static_payload()
    if static is not None:
        # busybox dispatches on argv[0], so a static busybox copied to `true` IS `true`.
        shutil.copyfile(static, target)
        target.chmod(0o755)
        return f"static rootfs payload {static}"
    # Standard fallback: the dynamic binary plus the loader and libraries `ldd` names.
    shutil.copyfile("/bin/true", target)
    target.chmod(0o755)
    linked = run(["ldd", "/bin/true"])
    copied = 0
    for line in linked.stdout.splitlines():
        for token in line.split():
            if not token.startswith("/") or not Path(token).is_file():
                continue
            destination = rootfs / Path(token).relative_to("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(token, destination)
            destination.chmod(0o755)
            copied += 1
    return f"dynamic /bin/true with {copied} ldd dependencies"


def bundle_config(bundle: Path, youki: str) -> None:
    """Write a rootless OCI config whose only process is `/bin/true`.

    The pinned youki's own `spec --rootless` generates it, as
    `kata_worker::oci_runtime` does: a host without `runc` (a fresh Ubuntu) must
    probe the same container as one with it.
    """
    generated = run([youki, "spec", "--rootless"], cwd=bundle, timeout=30)
    if generated.returncode != 0:
        raise ValueError(f"`youki spec --rootless` exited {generated.returncode}")
    config = json.loads((bundle / "config.json").read_text())
    config["process"] = {
        "args": ["/bin/true"],
        "cwd": "/",
        "terminal": False,
        "user": {"uid": 0, "gid": 0},
        "env": ["PATH=/bin"],
    }
    (bundle / "config.json").write_text(json.dumps(config, indent=2))


def denial_note(stderr: str) -> str:
    lowered = stderr.lower()
    if "apparmor" in lowered:
        return "AppArmor denial named in stderr"
    if "operation not permitted" in lowered or "eperm" in lowered:
        return (
            "capability denial (EPERM) — consistent with an unprofiled binary transitioning "
            "into the unprivileged_userns AppArmor profile, which audit-denies capability"
        )
    return ""


def probe_youki() -> Result:
    probe = "rootless Youki OCI containment"
    try:
        pin = load_pin()
    except PinError as error:
        return Result(probe, "failed", f"the youki pin could not be read: {error}")
    # THE PINNED PATH IS THE SUBJECT, and it is resolved DIRECTLY rather than
    # through `$PATH` — the same discipline `kata_worker::oci_runtime::certify_youki`
    # follows, so the two surfaces speak about one file. `$PATH` is consulted only
    # to REPORT a mismatch, because "some other youki is first on your PATH" is the
    # most likely explanation an operator needs when the pinned one is absent, and
    # a probe that silently ran the PATH binary would certify bytes the exact-path
    # AppArmor profile does not cover.
    youki = pin.store_path
    if not Path(youki).is_file():
        on_path = shutil.which("youki")
        note = (
            f"; `youki` on $PATH resolves to {sanitized(str(Path(on_path).resolve()))}, which is "
            "NOT the pinned path — the exact-path AppArmor profile covers the pinned path only"
            if on_path is not None
            else ""
        )
        return Result(
            probe,
            "unsupported",
            f"the pinned youki {sanitized(pin.store_path)} is absent; realise it from the kata "
            f"checkout with `{pin.realised_by}`, then re-pin config/youki-pin.toml "
            f"if the store path moved{note}",
        )
    parsed, reported, identification = youki_identification(youki)
    floor = pinned_version(pin.version)
    if parsed < floor:
        minimum = ".".join(str(part) for part in floor)
        return Result(probe, "failed", f"{reported}; the OCI adapter requires youki >= {minimum} (pinned)")
    try:
        digest = verify_pinned_binary(pin)
    except PinError as error:
        return Result(probe, "failed", f"{reported}; {error}")
    libseccomp = youki_libseccomp(identification)
    if libseccomp is None:
        return Result(
            probe,
            "failed",
            f"{reported}; {sanitized(pin.store_path)} reports no `libseccomp:` line, so it was "
            "built without libcontainer/libseccomp and will DROP the linux.seccomp section of "
            "every bundle kata writes — silently. The stage fence would be absent while every "
            "surface reported it present. Realise a runtime that has it, from the kata checkout, "
            f"with `{pin.realised_by}`, "
            "then re-pin config/youki-pin.toml and re-install the AppArmor profile "
            "with `sudo kata host apparmor-install`",
        )
    identity = (
        f"{reported}; {sanitized(pin.store_path)}; sha256 {digest} matches config/youki-pin.toml; "
        f"libseccomp {libseccomp}"
    )
    container = f"kata-feasibility-{os.getpid()}"
    try:
        with tempfile.TemporaryDirectory(prefix="kata-youki-probe-") as temporary:
            bundle = Path(temporary) / "bundle"
            bundle.mkdir()
            payload = build_rootfs(bundle / "rootfs")
            bundle_config(bundle, youki)
            # A login session's cgroup is not delegated on this class of host, so the
            # run goes through the repository's zero-privilege delegated scope (see
            # `_containment-preconditions`). `--wait` is rejected alongside `--scope`;
            # a scope already runs synchronously and propagates the child's status.
            try:
                completed = run(
                    [
                        "systemd-run", "--user", "--scope", "-p", "Delegate=yes", "--quiet", "--collect",
                        youki, "run", "--bundle", str(bundle), container,
                    ],
                    timeout=30,
                )
            finally:
                run([youki, "delete", "--force", container], timeout=15)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return Result(probe, "failed", f"{identity}; probe harness raised {type(error).__name__}")
    if completed.returncode == 0:
        return Result(probe, "passed", f"{identity}; {payload}; rootless `/bin/true` container ran in a delegated scope")
    tail = " / ".join(sanitized(completed.stderr).splitlines()[-10:]) or "no stderr"
    note = denial_note(completed.stderr)
    suffix = f"; {note}" if note else ""
    return Result(probe, "failed", f"{identity}; exit {completed.returncode}{suffix}; stderr tail: {tail}")


# The probes `--only` can select, by the short name an operator types. A closed
# table rather than a substring match on `Result.probe`: a selector that silently
# matched nothing would print an empty list and exit 0, which is the "green with no
# subject" failure this repository refuses.
SELECTABLE: dict[str, Any] = {
    "youki": lambda: [probe_youki()],
    "nix": probe_nix,
    "artifact": lambda: [probe_portable_artifact()],
}


def all_results() -> list[Result]:
    results = [probe_portable_artifact()]
    results.extend(probe_nix())
    results.append(probe_youki())
    return results


def print_markdown(results: list[Result]) -> None:
    print("| Probe | Status | Evidence |")
    print("|---|---|---|")
    for result in results:
        print(f"| {result.probe} | **{result.status}** | {result.evidence} |")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--only",
        action="append",
        choices=sorted(SELECTABLE),
        help="run only the named probe group (repeatable). Default: every probe.",
    )
    args = parser.parse_args()
    if args.only:
        results = [row for name in args.only for row in SELECTABLE[name]()]
    else:
        results = all_results()
    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2, sort_keys=True))
    else:
        print_markdown(results)
    return 1 if any(result.status == "failed" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
