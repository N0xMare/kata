#!/usr/bin/env python3
"""Refuse a gate run that changed the source tree it was judging.

A required tier builds, tests and boots the product IN a checkout. If anything in that
run writes into the SOURCE tree -- a test that creates its temp dir under
`CARGO_MANIFEST_DIR`, a stray `git init` in a package directory -- two things go
wrong at once: the verdict is about a tree nobody committed, and `bin/kata/build.rs`
(which watches the git index and the tracked tree) re-runs and recompiles `kata` in
every profile for every later cargo step. Both have happened: a nested repository at
`bin/kata/.git` in the snapshot worktree, and a measurement temp dir inside
`crates/core` mid-run.

TWO RULES, and each refuses exactly this:

1. RELATIVE -- the run changed git's view of the tree. `baseline FILE` records every
   entry `git status --porcelain=v1 -z --untracked-files=all` reports (modified,
   staged, deleted, untracked-and-not-ignored) with a SHA-256 of each such file's
   bytes; `verify FILE` recomputes and refuses any entry that appeared, vanished or
   whose bytes changed. It is RELATIVE because `just gate` is required before a
   COMMIT, i.e. in a checkout that legitimately holds uncommitted edits and
   untracked new files. It does NOT see a write into an ignored path (`target/`,
   `.jj/`, `.kata/` ...) or a file that was created and removed again within the
   run -- git cannot see either.
2. ABSOLUTE -- a nested git repository below the checkout root (`.git` anywhere but
   the root, outside `target/`, `.worktrees/` -- the gate snapshot's and the
   nightly's linked worktrees -- and `.claude/`, where Claude Code keeps its agents'
   worktrees). git status never reports one, so rule 1 is blind to it, and it is
   exactly what points `bin/kata/build.rs`'s `git` commands at the wrong repository.
   No baseline can make one acceptable.

`pristine` is the stricter form scripts/gate-snapshot.sh applies to its DETACHED
worktree before a run: any git-visible entry at all (a detached checkout of a commit
holds no legitimate edit or untracked file), plus rule 2.
"""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile

PRUNED = ("target", ".worktrees", ".claude", ".git")


def status_entries(root):
    """Return {(code, path)} for every git-visible change, fail closed on git errors.

    `--no-optional-locks`: a read must not refresh a stat-dirty index into `.git/index`,
    which bin/kata/build.rs watches (the self-test holds it)."""
    out = subprocess.run(
        ["git", "-C", root, "--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    fields = out.split(b"\0")
    entries = set()
    index = 0
    while index < len(fields):
        field = fields[index]
        index += 1
        if not field:
            continue
        if len(field) < 4 or field[2:3] != b" ":
            raise ValueError(f"unparseable git status entry: {field!r}")
        code = field[:2].decode()
        path = os.fsdecode(field[3:])
        entries.add((code, path))
        if code[0] in "RC":
            # A rename/copy carries its source path as the NEXT NUL field.
            if index >= len(fields) or not fields[index]:
                raise ValueError(f"rename entry without a source path: {field!r}")
            entries.add(("<-", os.fsdecode(fields[index])))
            index += 1
    return entries


def digest(root, path):
    full = os.path.join(root, path)
    if os.path.islink(full):
        return "symlink:" + os.readlink(full)
    if not os.path.isfile(full):
        return "-"
    sha = hashlib.sha256()
    with open(full, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


def snapshot(root):
    return sorted(
        f"{code}\t{digest(root, path)}\t{path}" for code, path in status_entries(root)
    )


def nested_repositories(root):
    found = []
    for directory, subdirs, files in os.walk(root):
        relative = os.path.relpath(directory, root)
        if relative == ".":
            subdirs[:] = [d for d in subdirs if d not in PRUNED]
            continue
        if ".git" in subdirs or ".git" in files:
            found.append(os.path.join(relative, ".git"))
        subdirs[:] = [d for d in subdirs if d != ".git"]
    return sorted(found)


def pristine(root):
    """Return the refusal lines for a checkout that must equal its commit exactly."""
    problems = [f"  not in the commit: [{code}] {path}" for code, path in sorted(status_entries(root))]
    problems += [f"  nested git repository: {nested}" for nested in nested_repositories(root)]
    return problems


def write_baseline(root, path):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(line + "\n" for line in snapshot(root)))


def verify(root, path):
    """Return the list of refusal lines; empty means the tree is unchanged."""
    with open(path, encoding="utf-8") as handle:
        before = set(line.rstrip("\n") for line in handle if line.strip())
    after = set(snapshot(root))
    problems = []
    for line in sorted(after - before):
        code, sha, name = line.split("\t", 2)
        problems.append(f"  changed during the run: [{code}] {name}  (sha256 {sha})")
    for line in sorted(before - after):
        code, sha, name = line.split("\t", 2)
        if not any(entry.endswith("\t" + name) for entry in after):
            problems.append(f"  changed during the run: [{code}] {name} is no longer reported")
    for nested in nested_repositories(root):
        problems.append(f"  nested git repository: {nested}")
    return problems


def self_test():
    def git(repo, *args):
        subprocess.run(["git", "-C", repo, *args], check=True, stdout=subprocess.DEVNULL)

    with tempfile.TemporaryDirectory() as work:
        repo = os.path.join(work, "repo")
        os.makedirs(os.path.join(repo, "pkg", "src"))
        with open(os.path.join(repo, ".gitignore"), "w") as f:
            f.write("target/\n.jj/\n")
        for name, text in (("pkg/src/lib.rs", "a\n"), ("pkg/Cargo.toml", "b\n")):
            with open(os.path.join(repo, name), "w") as f:
                f.write(text)
        git(repo, "init", "-q")
        git(repo, "add", ".")
        git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "i")
        base = os.path.join(work, "baseline")

        # A checkout that is ALREADY dirty (the pre-commit case) and stays so: clean.
        with open(os.path.join(repo, "pkg/src/lib.rs"), "w") as f:
            f.write("edited before the run\n")
        with open(os.path.join(repo, "new_file.rs"), "w") as f:
            f.write("untracked before the run\n")
        write_baseline(repo, base)
        assert verify(repo, base) == [], verify(repo, base)

        # Ignored writes are outside rule 1 by construction.
        os.makedirs(os.path.join(repo, "target", "x"))
        os.makedirs(os.path.join(repo, "pkg", ".jj"))
        assert verify(repo, base) == []

        def refused(mutate, expect):
            write_baseline(repo, base)
            undo = mutate()
            problems = verify(repo, base)
            undo()
            assert any(expect in p for p in problems), (expect, problems)
            assert verify(repo, base) == [], "undo did not restore the tree"

        def new_untracked():
            p = os.path.join(repo, "pkg", "measurement-tmp", "db")
            os.makedirs(os.path.dirname(p))
            open(p, "w").close()
            return lambda: (os.remove(p), os.rmdir(os.path.dirname(p)))

        def modify_clean_tracked():
            p = os.path.join(repo, "pkg/Cargo.toml")
            with open(p, "w") as f:
                f.write("rewritten\n")
            return lambda: open(p, "w").write("b\n")

        def modify_dirty_tracked():
            p = os.path.join(repo, "pkg/src/lib.rs")
            with open(p, "w") as f:
                f.write("rewritten by the run\n")
            return lambda: open(p, "w").write("edited before the run\n")

        def delete_untracked():
            p = os.path.join(repo, "new_file.rs")
            os.remove(p)
            return lambda: open(p, "w").write("untracked before the run\n")

        def nested_repo():
            git(os.path.join(repo, "pkg"), "init", "-q")
            return lambda: subprocess.run(["rm", "-rf", os.path.join(repo, "pkg", ".git")], check=True)

        refused(new_untracked, "pkg/measurement-tmp/db")
        refused(modify_clean_tracked, "pkg/Cargo.toml")
        refused(modify_dirty_tracked, "pkg/src/lib.rs")
        refused(delete_untracked, "new_file.rs")
        refused(nested_repo, "nested git repository: pkg/.git")

        # A linked worktree under the pruned `.worktrees/` root carries a `.git` file and
        # is the gate snapshot's and the nightly's own checkout, never a nested repository.
        os.makedirs(os.path.join(repo, ".worktrees", "gate-snapshot"))
        with open(os.path.join(repo, ".worktrees", "gate-snapshot", ".git"), "w") as f:
            f.write("gitdir: elsewhere\n")
        assert nested_repositories(repo) == [], nested_repositories(repo)
        subprocess.run(["rm", "-rf", os.path.join(repo, ".worktrees")], check=True)

        # Rule 2 is absolute: a baseline taken WITH the nested repo still refuses it.
        git(os.path.join(repo, "pkg"), "init", "-q")
        write_baseline(repo, base)
        assert verify(repo, base) == ["  nested git repository: pkg/.git"], verify(repo, base)

        # `pristine` refuses every git-visible entry and the nested repository, and
        # accepts a checkout equal to its commit with ignored build output beside it.
        found = pristine(repo)
        for expect in ("[ M] pkg/src/lib.rs", "[??] new_file.rs", "nested git repository: pkg/.git"):
            assert any(expect in line for line in found), (expect, found)
        subprocess.run(["rm", "-rf", os.path.join(repo, "pkg", ".git"), os.path.join(repo, "new_file.rs")], check=True)
        git(repo, "checkout", "-q", "--", "pkg/src/lib.rs")
        assert pristine(repo) == [], pristine(repo)

        # Reading the tree never WRITES the index: a plain `git status` refreshes the
        # stat of a stat-dirty tracked file into `.git/index`, and bin/kata/build.rs
        # re-runs on `index`, so a guard that wrote it would make the next build
        # recompile `kata` for nothing.
        index = os.path.join(repo, ".git", "index")
        os.utime(index, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
        lib = os.path.join(repo, "pkg/src/lib.rs")
        later = 1_000_000_100_000_000_000
        os.utime(lib, ns=(later, later))
        assert pristine(repo) == [], pristine(repo)
        assert os.stat(index).st_mtime_ns == 1_000_000_000_000_000_000, "the guard rewrote the index"
    print(
        "source-tree-guard self-test: PASS (dirty-at-start accepted, ignored writes out of scope; "
        "new untracked, modified clean, modified dirty, deleted untracked and nested repository refused; "
        "pristine refuses edits, untracked files and nested repositories; the index is never written)"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("mode", nargs="?", choices=("baseline", "verify", "pristine"))
    parser.add_argument("file", nargs="?")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], check=True, stdout=subprocess.PIPE, text=True
    ).stdout.strip()
    if args.mode == "pristine":
        problems = pristine(root)
        if problems:
            print("\n".join(problems))
            return 1
        return 0
    if not args.mode or not args.file:
        parser.error("usage: source-tree-guard.py baseline|verify FILE, or pristine")
    if args.mode == "baseline":
        write_baseline(root, args.file)
        return 0
    problems = verify(root, args.file)
    if problems:
        print("source-tree-unchanged: FAIL — the source tree changed during this gate run:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print(
            "  Something in the run (or an edit made while it ran) wrote into the tree it was\n"
            "  judging, so the verdict is about a tree nobody committed. A test must write\n"
            "  under a temp dir or CARGO_TARGET_TMPDIR, never under its package. A nested\n"
            "  repository makes bin/kata/build.rs read the wrong git; remove it.",
            file=sys.stderr,
        )
        return 1
    print(f"source-tree-unchanged: ok — {root} is as the run found it, and holds no nested repository.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.SubprocessError, OSError) as error:
        print(f"source-tree-guard: FAIL — {error}", file=sys.stderr)
        sys.exit(1)
