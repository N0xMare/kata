#!/usr/bin/env python3
"""The vendored nanocode Code Mode engine: derive it, check it, record its patch, bump it.

kata tracks nanocode (github.com/nanocodexyz/nanocode) by git rev, with exactly one
crate vendored in-tree: `nanocode-code-mode-engine`, the Code Mode host over djs,
because kata patches its seams into it (a backend that runs every cell out of
process, a stored-value loader, the tool catalog's encoding and the heap's
report) and nanocode has no public seam for those. The workspace
`Cargo.toml` routes every dependency on that crate to `vendor/` with a
`[patch."https://github.com/nanocodexyz/nanocode"]` entry, so the copy is built from
a fresh clone with no network path kata does not already take.

THE VENDORED TREE IS A FUNCTION OF THREE INPUTS. `vendor/nanocode-code-mode-engine/`
must be byte for byte, file for file, mode for mode:

  1. the upstream copy: every file under `crates/runtime/code-mode-engine` at the
     rev the workspace pins its four direct nanocode dependencies to, plus the
     repository's `LICENSE-MIT` and `LICENSE-APACHE`, read from git objects (so
     no `.gitattributes` export rule and no checkout state can change a byte);
  2. with its `Cargo.toml` workspace-inherited fields resolved against
     nanocode's root `Cargo.toml` at that rev (`resolve_manifest`), sibling path
     dependencies becoming `git` + `rev` dependencies on the same repository and
     rev, so they unify with the git packages the rest of nanocode resolves to;
  3. then `vendor/nanocode-code-mode-engine.patch` applied (`git apply -p1`):
     the kata delta, kept as one reviewable file.

`check` REFUSES (exit 1, every difference named) a vendored tree that differs
from that derivation in any way: a changed, missing or extra file, a changed
executable bit, a symlink, a patch file that does not apply, or a workspace whose
four direct nanocode pins disagree, are not on the nanocode repository, or whose
`[patch]` entry does not route the crate to `vendor/`. It refuses when it cannot
derive the expectation at all (an upstream rev it cannot fetch): a check that
cannot look is a refusal, never a pass. It does not see what cargo resolves
(`crates/agent-nanocode/tests/nanocode_seam.rs` reads that out of `Cargo.lock`).

Subcommands:

    check            refuse a vendored tree that is not upstream@rev + the patch
    vendor           re-derive the tree at the pinned rev and re-apply the patch
    record           rewrite the patch file as the diff from upstream@rev to the tree
    bump <rev>       move the four direct pins and NANOCODE_REV to <rev> (a commit
                     sha, branch or tag) and re-vendor; `just nanocode-bump` then
                     updates the lock and runs flake-hash
    flake-hash       point flake.nix's `nanocodeHash` at the locked rev
    --self-test      prove every refusal above against a synthetic upstream

Upstream objects are fetched once into `$XDG_CACHE_HOME/kata/nanocode.git`
(`~/.cache/...` without it), a bare repository outside the checkout.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REPOSITORY = "https://github.com/nanocodexyz/nanocode"
CRATE = "nanocode-code-mode-engine"
UPSTREAM_PATH = "crates/runtime/code-mode-engine"
LICENCE_FILES = ("LICENSE-MIT", "LICENSE-APACHE")
# The three crates the workspace depends on from nanocode's git source; their
# shared `rev` is the one rev the vendored copy must come from.
DIRECT_CRATES = (
    "nanocode-backend-codex",
    "nanocode-backend-claude",
    "nanocode-process-contracts",
    "nanocode-sync",
)
VENDOR_REL = f"vendor/{CRATE}"
PATCH_REL = f"vendor/{CRATE}.patch"
REV_CONST_REL = "crates/agent-nanocode/src/lib.rs"
FLAKE_REL = "flake.nix"
DEP_SECTION = re.compile(r"^(?:target\..+\.)?(?:dev-|build-)?dependencies$")
BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
SHA = re.compile(r"^[0-9a-f]{40}$")
# `.gitattributes` attributes that cannot change what `git archive` writes (no
# export rule, filter or end-of-line conversion), so `flake-hash` may hash a rev
# that sets them.
ARCHIVE_NEUTRAL_ATTRIBUTES = frozenset({"whitespace", "diff", "merge", "binary"})


class Refusal(Exception):
    """A fact the vendored tree stands on is false or could not be read."""


@dataclass(frozen=True)
class Layout:
    """Where one run reads and writes: the real checkout, or a self-test fixture."""

    root: Path
    repository: str
    cache: Path

    @property
    def vendor(self) -> Path:
        return self.root / VENDOR_REL

    @property
    def patch(self) -> Path:
        return self.root / PATCH_REL


def default_layout() -> Layout:
    cache_home = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return Layout(ROOT, REPOSITORY, cache_home / "kata" / "nanocode.git")


# ── git, isolated from the user's configuration ──────────────────────────────


def _git_env(ceiling: Path | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    if ceiling is not None:
        # `git apply` outside a repository is a plain patch tool; inside one it
        # resolves paths against that repository's root. The ceiling keeps a
        # temporary directory under the checkout from being read as part of it.
        env["GIT_CEILING_DIRECTORIES"] = str(ceiling)
    return env


def git(*args: str, cwd: Path | None = None, ceiling: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["git", "-c", "core.quotepath=off", "-c", "core.autocrlf=false", *args],
        cwd=cwd,
        env=_git_env(ceiling),
        capture_output=True,
        check=False,
    )
    if check and proc.returncode != 0:
        raise Refusal(f"`git {' '.join(args)}` failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc


def ensure_commit(layout: Layout, rev: str) -> None:
    """Have `rev`'s commit in the cache, fetching it from the repository if absent."""
    if not SHA.match(rev):
        raise Refusal(f"`{rev}` is not a full 40-hex commit sha")
    if not (layout.cache / "HEAD").exists():
        layout.cache.mkdir(parents=True, exist_ok=True)
        git("init", "--bare", "--quiet", str(layout.cache))
    if git("cat-file", "-e", f"{rev}^{{commit}}", cwd=layout.cache, check=False).returncode == 0:
        return
    fetched = git("fetch", "--quiet", "--depth=1", layout.repository, rev, cwd=layout.cache, check=False)
    if fetched.returncode != 0:
        raise Refusal(
            f"cannot fetch {layout.repository} at {rev} into {layout.cache}: "
            f"{fetched.stderr.decode(errors='replace').strip()}"
        )
    git("cat-file", "-e", f"{rev}^{{commit}}", cwd=layout.cache)


def resolve_rev(layout: Layout, name: str) -> str:
    """A commit sha for `name`: itself when it is one, else the remote's answer for it."""
    if SHA.match(name):
        return name
    listed = git("ls-remote", layout.repository, name).stdout.decode().split()
    shas = sorted({word for word in listed if SHA.match(word)})
    if len(shas) != 1:
        raise Refusal(f"`{name}` names {len(shas)} commits on {layout.repository}; pass a sha")
    return shas[0]


def blobs(layout: Layout, rev: str, path: str) -> dict[str, tuple[bytes, bool]]:
    """Every file under `path` at `rev`, keyed by its path relative to `path`."""
    listing = git("ls-tree", "-r", "-z", "--full-tree", rev, "--", path, cwd=layout.cache).stdout
    files: dict[str, tuple[bytes, bool]] = {}
    for entry in filter(None, listing.split(b"\0")):
        meta, name = entry.decode().split("\t", 1)
        mode, kind, oid = meta.split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise Refusal(f"{name} at {rev} is a {kind} (mode {mode}); only regular files can be vendored")
        relative = name[len(path) :].lstrip("/") if name != path else Path(name).name
        files[relative] = (git("cat-file", "blob", oid, cwd=layout.cache).stdout, mode == "100755")
    if not files:
        raise Refusal(f"{path} holds no files at {rev}")
    return files


# ── the manifest's workspace inheritance, resolved ───────────────────────────


def toml_key(key: str) -> str:
    return key if BARE_KEY.match(key) else json.dumps(key)


def toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{toml_key(k)} = {toml_value(v)}" for k, v in value.items()) + " }"
    raise Refusal(f"cannot render {value!r} as TOML")


def resolve_dependency(name: str, local: dict, workspace: dict, repository: str, rev: str) -> dict:
    """One `name = { workspace = true, ... }` entry, as cargo would inherit it."""
    if name not in workspace:
        raise Refusal(f"`{name}` inherits from [workspace.dependencies], which has no `{name}`")
    inherited = workspace[name]
    base = {"version": inherited} if isinstance(inherited, str) else dict(inherited)
    resolved: dict = {}
    for key, value in base.items():
        if key == "path":
            # A sibling crate of the nanocode workspace: the same package the git
            # source resolves to everywhere else in kata's lock.
            resolved["git"] = repository
            resolved["rev"] = rev
        else:
            resolved[key] = value
    unknown = set(local) - {"workspace", "features", "optional"}
    if unknown:
        raise Refusal(f"`{name}` sets {sorted(unknown)} beside `workspace = true`; only features/optional resolve")
    features = list(resolved.get("features", []))
    features += [feature for feature in local.get("features", []) if feature not in features]
    if features:
        resolved["features"] = features
    if "optional" in local:
        resolved["optional"] = local["optional"]
    return resolved


def resolve_manifest(crate_toml: str, root_toml: str, repository: str, rev: str) -> str:
    """The crate manifest with every `workspace = true` replaced by its value.

    Line by line, so the upstream layout survives for review; any spelling of
    inheritance this does not know is refused rather than copied through.
    """
    workspace = tomllib.loads(root_toml).get("workspace", {})
    package_fields = workspace.get("package", {})
    dependencies = workspace.get("dependencies", {})
    lines = crate_toml.splitlines()
    out: list[str] = []
    section = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        header = re.match(r"^\[([^\[\]]+)\]\s*(#.*)?$", stripped)
        if header:
            section = header.group(1).strip().replace(" ", "")
            if section == "lints":
                end = index + 1
                while end < len(lines) and not lines[end].strip().startswith("["):
                    end += 1
                body = [candidate.strip() for candidate in lines[index + 1 : end] if candidate.strip()]
                if body != ["workspace = true"]:
                    raise Refusal(f"[lints] is {body}; only `workspace = true` alone resolves")
                tables = [
                    [f"[lints.{toml_key(tool)}]"]
                    + [f"{toml_key(key)} = {toml_value(value)}" for key, value in table.items()]
                    for tool, table in workspace.get("lints", {}).items()
                ]
                out.extend("\n\n".join("\n".join(table) for table in tables).splitlines())
                if end < len(lines) and not lines[end - 1].strip():
                    out.append("")
                index = end
                continue
            out.append(line)
            index += 1
            continue
        if "workspace" in stripped.split("#", 1)[0]:
            dotted = re.match(r"^([A-Za-z0-9_-]+)\.workspace\s*=\s*true$", stripped)
            inline = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(\{.*\})$", stripped)
            if section == "package" and dotted:
                key = dotted.group(1)
                if key not in package_fields:
                    raise Refusal(f"package.{key} inherits from [workspace.package], which has no `{key}`")
                out.append(f"{key} = {toml_value(package_fields[key])}")
            elif DEP_SECTION.match(section) and dotted:
                name = dotted.group(1)
                resolved = resolve_dependency(name, {"workspace": True}, dependencies, repository, rev)
                out.append(f"{name} = {toml_value(resolved)}")
            elif DEP_SECTION.match(section) and inline:
                name = inline.group(1)
                local = tomllib.loads(f"x = {inline.group(2)}")["x"]
                if local.get("workspace") is not True:
                    raise Refusal(f"[{section}] `{name}` names `workspace` without `workspace = true`")
                resolved = resolve_dependency(name, local, dependencies, repository, rev)
                out.append(f"{name} = {toml_value(resolved)}")
            else:
                raise Refusal(f"[{section}] line `{stripped}` inherits in a form this resolver does not know")
        else:
            out.append(line)
        index += 1
    text = "\n".join(out) + "\n"
    if _names_workspace(tomllib.loads(text)):
        raise Refusal("the resolved manifest still names `workspace`")
    return text


def _names_workspace(value: object) -> bool:
    if isinstance(value, dict):
        return "workspace" in value or any(_names_workspace(item) for item in value.values())
    if isinstance(value, list):
        return any(_names_workspace(item) for item in value)
    return False


# ── the expectation, and the tree on disk ────────────────────────────────────

Tree = dict[str, tuple[bytes, bool]]


def pristine(layout: Layout, rev: str) -> Tree:
    """Upstream@rev with its manifest resolved: the tree before kata's patch."""
    ensure_commit(layout, rev)
    tree = blobs(layout, rev, UPSTREAM_PATH)
    root_files = {}
    for licence in LICENCE_FILES:
        root_files.update(blobs(layout, rev, licence))
    clash = set(root_files) & set(tree)
    if clash:
        raise Refusal(f"{UPSTREAM_PATH} at {rev} already holds {sorted(clash)}")
    tree.update(root_files)
    root_toml = git("cat-file", "blob", f"{rev}:Cargo.toml", cwd=layout.cache).stdout.decode()
    crate_toml, executable = tree["Cargo.toml"]
    tree["Cargo.toml"] = (
        resolve_manifest(crate_toml.decode(), root_toml, layout.repository, rev).encode(),
        executable,
    )
    return tree


def write_tree(tree: Tree, directory: Path) -> None:
    for relative, (content, executable) in sorted(tree.items()):
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o755 if executable else 0o644)


def read_tree(directory: Path) -> Tree:
    if not directory.is_dir():
        raise Refusal(f"{directory} does not exist")
    tree: Tree = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise Refusal(f"{relative} is a symlink; the vendored tree holds regular files only")
        if path.is_file():
            tree[relative] = (path.read_bytes(), os.access(path, os.X_OK))
    return tree


def apply_patch(tree: Tree, patch: Path, scratch: Path) -> Tree:
    """`tree` with `patch` applied by `git apply -p1`, or a Refusal naming the conflict."""
    work = scratch / "apply"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    write_tree(tree, work)
    if patch.stat().st_size:
        applied = git("apply", "-p1", "--whitespace=nowarn", str(patch), cwd=work, ceiling=scratch, check=False)
        if applied.returncode != 0:
            raise Refusal(f"{patch.name} does not apply:\n{applied.stderr.decode(errors='replace').strip()}")
    return read_tree(work)


def expected(layout: Layout, rev: str, scratch: Path) -> Tree:
    if not layout.patch.is_file():
        raise Refusal(f"{PATCH_REL} does not exist (an empty file means no kata delta)")
    return apply_patch(pristine(layout, rev), layout.patch, scratch)


def differences(want: Tree, have: Tree) -> list[str]:
    found: list[str] = []
    for relative in sorted(set(want) | set(have)):
        if relative not in have:
            found.append(f"{relative}: missing from {VENDOR_REL}")
        elif relative not in want:
            found.append(f"{relative}: not in upstream + {PATCH_REL}")
        elif want[relative][0] != have[relative][0]:
            found.append(f"{relative}: content differs ({_first_difference(want[relative][0], have[relative][0])})")
        elif want[relative][1] != have[relative][1]:
            found.append(f"{relative}: executable bit is {have[relative][1]}, expected {want[relative][1]}")
    return found


def _first_difference(want: bytes, have: bytes) -> str:
    wanted, had = want.decode(errors="replace").splitlines(), have.decode(errors="replace").splitlines()
    for number, (left, right) in enumerate(zip(wanted, had), start=1):
        if left != right:
            return f"line {number}: expected {left[:120]!r}, found {right[:120]!r}"
    return f"expected {len(wanted)} lines, found {len(had)}"


# ── the workspace's pins ─────────────────────────────────────────────────────


def pinned_rev(layout: Layout) -> str:
    """The one rev the workspace's direct nanocode dependencies name, checked."""
    manifest = tomllib.loads((layout.root / "Cargo.toml").read_text())
    dependencies = manifest.get("workspace", {}).get("dependencies", {})
    revs = set()
    for name in DIRECT_CRATES:
        entry = dependencies.get(name)
        if not isinstance(entry, dict) or entry.get("git") != REPOSITORY or "rev" not in entry:
            raise Refusal(f"[workspace.dependencies] {name} is not a `git = \"{REPOSITORY}\"` + `rev` dependency")
        revs.add(entry["rev"])
    if len(revs) != 1:
        raise Refusal(f"the direct nanocode dependencies name {len(revs)} revs: {sorted(revs)}")
    patch = manifest.get("patch", {}).get(REPOSITORY, {}).get(CRATE)
    if patch != {"path": VENDOR_REL}:
        raise Refusal(f'[patch."{REPOSITORY}"] {CRATE} is {patch!r}, not {{ path = "{VENDOR_REL}" }}')
    return revs.pop()


# ── subcommands ──────────────────────────────────────────────────────────────


def check(layout: Layout) -> list[str]:
    rev = pinned_rev(layout)
    with tempfile.TemporaryDirectory(prefix="nanocode-vendor-") as scratch:
        return differences(expected(layout, rev, Path(scratch)), read_tree(layout.vendor))


def vendor(layout: Layout) -> str:
    """Rewrite the vendored tree from upstream@rev + the patch; returns the rev.

    On a patch that no longer applies the tree is left as the PRISTINE upstream
    copy, so the delta can be ported by hand and recorded, and this refuses.
    """
    rev = pinned_rev(layout)
    with tempfile.TemporaryDirectory(prefix="nanocode-vendor-") as scratch:
        base = pristine(layout, rev)
        try:
            patched = apply_patch(base, layout.patch, Path(scratch))
        except Refusal:
            _replace(layout.vendor, base)
            raise
        _replace(layout.vendor, patched)
    return rev


def _replace(directory: Path, tree: Tree) -> None:
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    write_tree(tree, directory)


def record(layout: Layout) -> None:
    """Write the patch file as the diff from upstream@rev to the vendored tree."""
    rev = pinned_rev(layout)
    with tempfile.TemporaryDirectory(prefix="nanocode-vendor-") as scratch:
        scratch_path = Path(scratch)
        write_tree(pristine(layout, rev), scratch_path / "a")
        write_tree(read_tree(layout.vendor), scratch_path / "b")
        diff = git(
            "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false", "-c", "diff.algorithm=myers",
            "diff", "--no-index", "--no-color", "--no-ext-diff", "--no-renames", "--binary", "--full-index",
            "--no-prefix", "a", "b",
            cwd=scratch_path, ceiling=scratch_path.parent, check=False,
        )
        if diff.returncode not in (0, 1):
            raise Refusal(f"`git diff --no-index` failed: {diff.stderr.decode(errors='replace').strip()}")
        layout.patch.write_bytes(diff.stdout)


def bump(layout: Layout, name: str) -> str:
    """Move the four direct pins and `NANOCODE_REV` to `name`'s commit and re-vendor.

    The lock and the flake hash follow (`just nanocode-bump` runs cargo, then
    `flake-hash`). A patch that no longer applies refuses with the pins moved and
    the tree left as the pristine upstream copy, ready for the delta to be ported.
    """
    rev = resolve_rev(layout, name)
    old = pinned_rev(layout)
    manifest = layout.root / "Cargo.toml"
    names = "|".join(map(re.escape, DIRECT_CRATES))
    pin = re.compile(rf'^((?:{names})\s*=\s*\{{\s*git = "{re.escape(REPOSITORY)}", rev = ")[0-9a-f]{{40}}(" \}})$', re.M)
    text, count = pin.subn(rf"\g<1>{rev}\g<2>", manifest.read_text())
    if count != len(DIRECT_CRATES):
        raise Refusal(f"found {count} of the {len(DIRECT_CRATES)} direct nanocode pins in Cargo.toml to rewrite")
    const = layout.root / REV_CONST_REL
    source, consts = re.subn(
        r'(pub const NANOCODE_REV: &str = ")[0-9a-f]{40}(";)', rf"\g<1>{rev}\g<2>", const.read_text()
    )
    if consts != 1:
        raise Refusal(f"{REV_CONST_REL} has {consts} `NANOCODE_REV` definitions")
    manifest.write_text(text)
    const.write_text(source)
    print(f"nanocode-bump: pins and NANOCODE_REV {old} -> {rev}")
    vendor(layout)
    return rev


def flake_hash(layout: Layout) -> None:
    """Point flake.nix's `nanocodeHash` at the locked rev.

    The flake fetches nanocode's whole tree at the rev `Cargo.lock` locks
    (`fetchgit`) and vendors every nanocode package inside it; this hashes the
    rev the way `fetchgit` stores it: `nix hash path` over `git archive` of the
    commit. That equality holds only for a rev with no `.gitmodules` (fetchgit
    fetches submodules) and no `.gitattributes` attribute that changes archived
    bytes (`ARCHIVE_NEUTRAL_ATTRIBUTES` lists the ones that cannot); for any
    other rev this refuses and names the recompute step instead of writing a
    hash it cannot vouch for.
    """
    rev = pinned_rev(layout)
    locked = tomllib.loads((layout.root / "Cargo.lock").read_text()).get("package", [])
    source = f"git+{REPOSITORY}?rev={rev}#{rev}"
    recompute = (
        f"set `nanocodeHash` in {FLAKE_REL} to lib.fakeHash, run "
        "`nix build .#kata`, and paste the hash it reports as `got:`"
    )
    if not any(package.get("source") == source for package in locked):
        raise Refusal(f"Cargo.lock has no package from {source}; run cargo first")
    ensure_commit(layout, rev)
    paths = git("ls-tree", "-r", "--name-only", "-z", rev, cwd=layout.cache).stdout.decode().split("\0")
    if any(Path(path).name == ".gitmodules" for path in paths):
        raise Refusal(f"{rev} has submodules; {recompute}")
    for path in (path for path in paths if Path(path).name == ".gitattributes"):
        rules = git("cat-file", "blob", f"{rev}:{path}", cwd=layout.cache).stdout.decode()
        for line in rules.splitlines():
            for attribute in line.split()[1:] if line.strip() and not line.startswith("#") else []:
                name = attribute.lstrip("-!").split("=", 1)[0]
                if name not in ARCHIVE_NEUTRAL_ATTRIBUTES and not name.startswith("linguist-"):
                    raise Refusal(f"{rev}:{path} sets `{attribute}`, which can change archived bytes; {recompute}")
    if shutil.which("nix") is None:
        raise Refusal(f"nix is not on PATH; {recompute}")
    with tempfile.TemporaryDirectory(prefix="nanocode-flake-") as scratch:
        tree = Path(scratch) / "tree"
        tree.mkdir()
        archive = git("archive", "--format=tar", rev, cwd=layout.cache).stdout
        subprocess.run(["tar", "-x", "-C", str(tree)], input=archive, check=True)
        hashed = subprocess.run(["nix", "hash", "path", str(tree)], capture_output=True, text=True, check=False)
    if hashed.returncode != 0:
        raise Refusal(f"`nix hash path` failed ({hashed.stderr.strip()}); {recompute}")
    flake = layout.root / FLAKE_REL
    entry = f'nanocodeHash = "{hashed.stdout.strip()}";'
    text, count = re.subn(r'^(\s*)nanocodeHash = "sha256-[A-Za-z0-9+/=]+";$', rf"\g<1>{entry}", flake.read_text(), flags=re.M)
    if count != 1:
        raise Refusal(f"{FLAKE_REL} has {count} `nanocodeHash` definitions, not one; {recompute}")
    flake.write_text(text)
    print(f"nanocode-bump: {FLAKE_REL} {entry}")


# ── self-test ────────────────────────────────────────────────────────────────


def self_test() -> int:
    """Every refusal `check` claims, each against its own planted defect."""
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="nanocode-vendor-self-test-") as scratch:
        base = Path(scratch)
        upstream = base / "upstream"
        crate = upstream / UPSTREAM_PATH
        (crate / "src").mkdir(parents=True)
        (upstream / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/runtime/code-mode-engine"]\n\n'
            '[workspace.package]\nversion = "0.1.0"\nedition = "2024"\nlicense = "MIT OR Apache-2.0"\n\n'
            '[workspace.dependencies]\nsibling = { version = "0.1.0", path = "crates/sibling" }\n'
            'serde = { version = "1", features = ["derive"] }\ntokio = "1.48.0"\n\n'
            '[workspace.lints.rust]\nunsafe_code = "forbid"\n\n[workspace.lints.clippy]\n'
            'all = { level = "warn", priority = -1 }\n'
        )
        (crate / "Cargo.toml").write_text(
            f'[package]\nname = "{CRATE}"\nversion.workspace = true\nedition.workspace = true\n'
            'license.workspace = true\n\n[dependencies]\nsibling.workspace = true\n'
            'serde = { workspace = true, features = ["rc"] }\n\n'
            "[target.'cfg(not(target_family = \"wasm\"))'.dependencies]\n"
            'tokio = { workspace = true, features = ["rt"] }\n\n[lints]\nworkspace = true\n\n'
            "[lib]\ntest = false\n"
        )
        (crate / "src" / "lib.rs").write_text("pub fn one() -> u32 {\n    1\n}\n\npub fn two() -> u32 {\n    2\n}\n")
        (crate / "build.rs").write_text("fn main() {}\n")
        (crate / "build.rs").chmod(0o755)
        for licence in LICENCE_FILES:
            (upstream / licence).write_text(f"{licence} text\n")
        git("init", "--quiet", str(upstream))
        git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=upstream)
        git("add", "-A", cwd=upstream)
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "--quiet", "-m", "one", cwd=upstream)
        rev = git("rev-parse", "HEAD", cwd=upstream).stdout.decode().strip()

        root = base / "kata"
        layout = Layout(root, f"file://{upstream}", base / "cache.git")
        (root / "vendor").mkdir(parents=True)
        (root / "crates/agent-nanocode/src").mkdir(parents=True)

        def write_manifest(pin: str, patch_path: str = VENDOR_REL, first_dep: str | None = None) -> None:
            deps = "".join(f'{name} = {{ git = "{REPOSITORY}", rev = "{pin}" }}\n' for name in DIRECT_CRATES)
            if first_dep is not None:
                deps = f"{DIRECT_CRATES[0]} = {first_dep}\n" + deps.split("\n", 1)[1]
            (root / "Cargo.toml").write_text(
                f'[workspace]\nmembers = []\n\n[workspace.dependencies]\n{deps}\n'
                f'[patch."{REPOSITORY}"]\n{CRATE} = {{ path = "{patch_path}" }}\n'
            )

        write_manifest(rev)
        (root / REV_CONST_REL).write_text(f'pub const NANOCODE_REV: &str = "{rev}";\n')
        layout.patch.write_bytes(b"")

        def expect(label: str, needle: str | None) -> None:
            """`needle is None` means check passes; else a refusal naming `needle`."""
            try:
                found = check(layout)
            except Refusal as refusal:
                found = [str(refusal)]
            if needle is None and found:
                failures.append(f"{label}: expected a clean check, got {found}")
            elif needle is not None and not any(needle in line for line in found):
                failures.append(f"{label}: expected a refusal naming {needle!r}, got {found}")

        vendor(layout)
        manifest = (layout.vendor / "Cargo.toml").read_text()
        for wanted in (
            'version = "0.1.0"',
            f'sibling = {{ version = "0.1.0", git = "file://{upstream}", rev = "{rev}" }}',
            'serde = { version = "1", features = ["derive", "rc"] }',
            'tokio = { version = "1.48.0", features = ["rt"] }',
            '[lints.rust]\nunsafe_code = "forbid"\n\n[lints.clippy]\nall = { level = "warn", priority = -1 }\n\n[lib]',
        ):
            if wanted not in manifest:
                failures.append(f"resolve: the vendored manifest lacks {wanted!r}:\n{manifest}")
        expect("pristine copy, empty patch", None)

        lib = layout.vendor / "src" / "lib.rs"
        lib.write_text(lib.read_text().replace("    1\n", "    10\n"))
        expect("an edit not yet recorded", "src/lib.rs: content differs")
        record(layout)
        expect("the edit, recorded", None)

        saved = lib.read_text()
        lib.write_text(saved.replace("    2\n", "    20\n"))
        expect("a line changed outside the patch", "src/lib.rs: content differs (line 6")
        lib.write_text(saved)
        (layout.vendor / "src" / "extra.rs").write_text("\n")
        expect("an extra file", "src/extra.rs: not in upstream")
        (layout.vendor / "src" / "extra.rs").unlink()
        (layout.vendor / "LICENSE-MIT").unlink()
        expect("a missing licence", "LICENSE-MIT: missing")
        vendor(layout)
        (layout.vendor / "build.rs").chmod(0o644)
        expect("a lost executable bit", "build.rs: executable bit")
        vendor(layout)
        (layout.vendor / "src" / "link.rs").symlink_to("lib.rs")
        expect("a symlink", "src/link.rs is a symlink")
        (layout.vendor / "src" / "link.rs").unlink()
        expect("re-vendored", None)

        patch_text = layout.patch.read_text()
        layout.patch.write_text(patch_text.replace("+    10", "+    11"))
        expect("a patch file edited past the tree", "src/lib.rs: content differs")
        layout.patch.write_text(patch_text.replace("-    1\n", "-    7\n"))
        expect("a patch that does not apply", "does not apply")
        layout.patch.write_text(patch_text)

        write_manifest("0" * 40)
        expect("a pin the copy is not from", "cannot fetch")
        write_manifest(rev, patch_path="vendor/elsewhere")
        expect("a [patch] routed elsewhere", "[patch.")
        write_manifest(rev, first_dep=f'{{ git = "{REPOSITORY}", rev = "{"1" * 40}" }}')
        expect("direct pins that disagree", "the direct nanocode dependencies name 2 revs")
        write_manifest(rev, first_dep=f'{{ git = "file:///elsewhere", rev = "{rev}" }}')
        expect("a direct pin on another repository", f"{DIRECT_CRATES[0]} is not a `git")
        write_manifest(rev)
        expect("restored", None)

        # Upstream moves outside the patch: the bump re-vendors and keeps the delta.
        (crate / "build.rs").write_text("fn main() { println!(); }\n")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "--quiet", "-am", "clean", cwd=upstream)
        clean = git("rev-parse", "HEAD", cwd=upstream).stdout.decode().strip()
        try:
            bump(layout, clean)
        except Refusal as refusal:
            failures.append(f"bump: a patch that still applies refused: {refusal}")
        expect("a clean bump", None)
        if "    10\n" not in lib.read_text() or "println" not in (layout.vendor / "build.rs").read_text():
            failures.append("bump: the clean bump lost the delta or the upstream change")
        if behind := [p for p in ("Cargo.toml", REV_CONST_REL) if clean not in (root / p).read_text()]:
            failures.append(f"bump: the clean bump left {behind} behind")

        # The upstream moves under the patch: the bump re-vendors, and a patch
        # whose context moved fails loudly and leaves the pristine copy.
        source = crate / "src" / "lib.rs"
        source.write_text(source.read_text().replace("    1\n", "    3\n"))
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "--quiet", "-am", "two", cwd=upstream)
        moved = git("rev-parse", "HEAD", cwd=upstream).stdout.decode().strip()
        try:
            bump(layout, moved)
            failures.append("bump: a conflicting patch did not refuse")
        except Refusal as refusal:
            if "does not apply" not in str(refusal):
                failures.append(f"bump: refused for the wrong reason: {refusal}")
        if f'rev = "{moved}"' not in (root / "Cargo.toml").read_text():
            failures.append("bump: the Cargo.toml pins did not move")
        if moved not in (root / REV_CONST_REL).read_text():
            failures.append("bump: NANOCODE_REV did not move")
        if "    3\n" not in lib.read_text():
            failures.append("bump: the conflicted tree is not the pristine upstream copy")

        # The delta ported by hand onto the pristine copy, recorded, and the bump
        # re-run at the same rev: it keeps the port and the check passes.
        lib.write_text(lib.read_text().replace("    3\n", "    30\n"))
        record(layout)
        try:
            bump(layout, moved)
        except Refusal as refusal:
            failures.append(f"bump: the re-run after a recorded hand port refused: {refusal}")
        if "    30\n" not in lib.read_text():
            failures.append("bump: the re-run after a recorded hand port lost the port")
        expect("a recorded hand port, bumped again", None)

    if failures:
        print("nanocode-vendor self-test: FAIL\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1
    print(
        "nanocode-vendor self-test: ok — manifest resolution; refusals for an unrecorded edit, a line "
        "changed outside the patch, an extra file, a missing licence, a lost executable bit, a symlink, an "
        "edited patch, a patch that does not apply, an unfetchable pin, a misrouted [patch], direct pins "
        "that disagree and a direct pin on another repository; a clean bump "
        "keeps the delta, a bump whose patch conflicts refuses and leaves the pristine copy, and the "
        "same bump re-run after the delta is ported by hand and recorded keeps the port"
    )
    return 0


def main() -> int:
    args = sys.argv[1:]
    layout = default_layout()
    try:
        if args == ["--self-test"]:
            return self_test()
        if args == ["check"]:
            found = check(layout)
            if found:
                print(
                    f"nanocode-vendor check: REFUSED — {VENDOR_REL} is not upstream@{pinned_rev(layout)} "
                    f"+ {PATCH_REL}:\n  " + "\n  ".join(found),
                    file=sys.stderr,
                )
                return 1
            print(f"nanocode-vendor check: ok — {VENDOR_REL} is upstream@{pinned_rev(layout)} + {PATCH_REL}")
            return 0
        if args == ["vendor"]:
            print(f"nanocode-vendor: {VENDOR_REL} re-derived at {vendor(layout)} with {PATCH_REL} applied")
            return 0
        if args == ["record"]:
            record(layout)
            print(f"nanocode-vendor: {PATCH_REL} recorded against upstream@{pinned_rev(layout)}")
            return 0
        if len(args) == 2 and args[0] == "bump":
            print(f"nanocode-bump: {VENDOR_REL} re-derived at {bump(layout, args[1])} with {PATCH_REL} applied")
            return 0
        if args == ["flake-hash"]:
            flake_hash(layout)
            return 0
    except Refusal as refusal:
        print(f"nanocode-vendor: REFUSED — {refusal}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
