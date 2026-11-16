"""Lay out nanocode's vendored crates inside the repository they come from.

    nanocode-vendor-dir.py <repository> <crates> <out>

<repository> is nanocode's tree at the locked rev (fetchgit). <crates> is
importCargoLock's vendor directory for that rev's packages alone: one copy per
package, its manifest's workspace-inherited fields resolved and a
`.cargo-checksum.json` added. A crate copied out of the repository loses every
path it reads outside its own directory (djs-core `include_str!`s
`../../../../builtins/gen/*.js`; its build script walks `../djs-libm/src`), so
<out> is a cargo directory source whose entries stay in place:

  <out>/.repository/                 the whole tree, each package's directory
                                     carrying its resolved `Cargo.toml` and
                                     `.cargo-checksum.json` from <crates>
  <out>/<name>-<version> -> .repository/<path of that package>

Cargo reads a directory source one level deep and skips dot entries, so it sees
exactly the packages; the kernel resolves `..` from the symlink's target, so
every relative read lands where it does in a git checkout. Refuses a package of
<crates> that no manifest of the tree names, or that two manifests name.
"""

import shutil
import stat
import sys
import tomllib
from pathlib import Path


def package_name(manifest: Path) -> str | None:
    try:
        return tomllib.loads(manifest.read_text()).get("package", {}).get("name")
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        # A fixture that is not a manifest; it names no package cargo resolved.
        return None


def main(repository: Path, crates: Path, out: Path) -> None:
    tree = out / ".repository"
    shutil.copytree(repository, tree, symlinks=True)
    for path in [tree, *tree.rglob("*")]:
        if not path.is_symlink():
            path.chmod(path.stat().st_mode | stat.S_IWUSR)

    homes: dict[str, list[Path]] = {}
    for manifest in tree.rglob("Cargo.toml"):
        if (name := package_name(manifest)) is not None:
            homes.setdefault(name, []).append(manifest.parent)

    for crate in sorted(p for p in crates.iterdir() if not p.name.startswith(".") and p.is_dir()):
        name = tomllib.loads((crate / "Cargo.toml").read_text())["package"]["name"]
        found = homes.get(name, [])
        if len(found) != 1:
            sys.exit(f"nanocode-vendor-dir: {crate.name}: {len(found)} manifests in the tree name `{name}`, not one")
        home = found[0]
        for file in ("Cargo.toml", ".cargo-checksum.json"):
            shutil.copyfile(crate / file, home / file)
        (out / crate.name).symlink_to(home.relative_to(out))


if __name__ == "__main__":
    main(*map(Path, sys.argv[1:]))
