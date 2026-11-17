//! The bounded text diff between two recorded commits (`{{ target.diff }}`),
//! checked against `git diff` itself over the same two commits.

use std::path::Path;

use kata_effects_contract::ExecutionWorkspaceProvider;
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_vcs::{JjBackend, VcsBackend};

/// `git <args>` in `repo`, asserted successful, stdout verbatim.
fn git(repo: &Path, args: &[&str]) -> String {
    let output = hermetic_git_in(repo).args(args).output().expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// git's own diff of `base..head`, in the format the module doc names: no
/// rename detection, no external or textconv driver, ten-digit object ids.
fn git_diff(repo: &Path, base: &str, head: &str) -> String {
    git(
        repo,
        &[
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--abbrev=10",
            base,
            head,
        ],
    )
}

/// A repository whose second commit modifies, adds, deletes, re-modes,
/// strips a trailing newline from and binary-edits files of its first, and
/// edits a long file in two places far enough apart to be two hunks under
/// three lines of context and one under more. No line starts with a letter,
/// `_` or `$`, so git writes no function-name context after an `@@`.
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    let write = |name: &str, body: &[u8]| std::fs::write(repo.join(name), body).unwrap();
    write("kept.txt", b"one\ntwo\nthree\nfour\n");
    write("gone.txt", b"bye\n");
    write("mode.sh", b"echo hi\n");
    write("tail.txt", b"line\n");
    write("blob.bin", b"\0\x01\x02");
    let long: Vec<String> = (1..=20).map(|n| format!("{n:02}")).collect();
    write("long.txt", format!("{}\n", long.join("\n")).as_bytes());
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]).trim().to_owned();

    write("kept.txt", b"one\ntwo and a half\nthree\nfour\nfive\n");
    std::fs::remove_file(repo.join("gone.txt")).unwrap();
    write("new.txt", b"hello\nworld\n");
    write("tail.txt", b"line\nno newline");
    write("blob.bin", b"\0\x01\x03");
    let mut long = long;
    "02 changed".clone_into(&mut long[1]);
    "15 changed".clone_into(&mut long[14]);
    write("long.txt", format!("{}\n", long.join("\n")).as_bytes());
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["update-index", "--chmod=+x", "mode.sh"]);
    run_git(&repo, &["commit", "-q", "-m", "head"]);
    let head = git(&repo, &["rev-parse", "HEAD"]).trim().to_owned();
    (tmp, repo, base, head)
}

/// The rendered text is byte for byte the diff git writes for the same two
/// commits, across every section shape the renderer has.
#[test]
fn the_text_diff_is_the_diff_git_writes() {
    let (_tmp, repo, base, head) = fixture();
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    let diff = backend
        .recorded_commit_text_diff(&base, &head, 1024 * 1024)
        .expect("the diff renders");
    let expected = git_diff(&repo, &base, &head);
    assert!(!diff.truncated, "a small diff is whole");
    assert_eq!(diff.text, expected);
    for shape in [
        "new file mode 100644",
        "deleted file mode 100644",
        "old mode 100644\nnew mode 100755",
        "\\ No newline at end of file",
        "Binary files a/blob.bin and b/blob.bin differ",
        "@@ -1,5 +1,5 @@",
        "@@ -12,7 +12,7 @@",
    ] {
        assert!(expected.contains(shape), "the fixture exercises {shape:?}");
    }
}

/// Paths a pull request's author chooses, each one a byte git quotes or a
/// line that reads like a diff header: a newline (alone, and opening a fake
/// `+++` header in a directory name), a tab, a quote, a backslash, a C0
/// control byte with DEL, a multi-byte UTF-8 character, a space (git appends a
/// tab to a `---`/`+++` label holding one) and a name that is itself a `diff
/// --git` line, and git's named escapes (`\a \b \v \f`) and ESC. Each is
/// modified, added or deleted between the two commits; the fixture also
/// deletes, re-modes and binary-edits quoted names.
const HOSTILE_PATHS: &[&str] = &[
    "new\nline.txt",
    "x\n+++ b/evil.txt",
    "tab\there.txt",
    "quote\"d.txt",
    "back\\slash.txt",
    "ctl\u{1}del\u{7f}.txt",
    "caf\u{e9}.txt",
    "sp ace.txt",
    "diff --git a b",
    "esc\u{1b}[31m.txt",
    "bell\u{7}bs\u{8}vt\u{b}ff\u{c}.txt",
];

/// A repository whose head modifies, adds and deletes [`HOSTILE_PATHS`].
fn hostile_fixture() -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    let write = |name: &str, body: &[u8]| {
        let path = repo.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    };
    // Even entries exist at the base and are modified; odd ones are added.
    for (index, name) in HOSTILE_PATHS.iter().enumerate() {
        if index % 2 == 0 {
            write(name, b"before\n");
        }
    }
    write("gone with space.txt", b"bye\n");
    write("del\tx.txt", b"bye\n");
    write("bin ary.bin", b"\0\x01\x02");
    write("bin\"q.bin", b"\0\x01\x02");
    write("mode\nx.sh", b"echo hi\n");
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]).trim().to_owned();

    for name in HOSTILE_PATHS {
        write(name, b"after\n");
    }
    std::fs::remove_file(repo.join("gone with space.txt")).unwrap();
    std::fs::remove_file(repo.join("del\tx.txt")).unwrap();
    write("bin ary.bin", b"\0\x01\x03");
    write("bin\"q.bin", b"\0\x01\x03");
    write("new bin\u{e9}.bin", b"\0\x01\x04");
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["update-index", "--chmod=+x", "mode\nx.sh"]);
    run_git(&repo, &["commit", "-q", "-m", "head"]);
    let head = git(&repo, &["rev-parse", "HEAD"]).trim().to_owned();
    (tmp, repo, base, head)
}

/// Paths the PR author chose are written exactly as git writes them under
/// its default `core.quotePath=true`: C-quoted (`"a/…" "b/…"`, `\n` `\t` `\"`
/// `\\` escapes, octal for other control and non-ASCII bytes) when a byte
/// needs it, and a `---`/`+++` label holding a space followed by a tab. git
/// is the oracle: the whole text equals `git diff` over the same commits, so
/// no path can open a line the reader takes for a header git did not write.
#[test]
fn a_hostile_path_is_quoted_exactly_as_git_quotes_it() {
    let (_tmp, repo, base, head) = hostile_fixture();
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    let diff = backend
        .recorded_commit_text_diff(&base, &head, 1024 * 1024)
        .expect("the diff renders");
    let expected = git(
        &repo,
        &[
            "-c",
            "core.quotePath=true",
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--abbrev=10",
            &base,
            &head,
        ],
    );
    assert_eq!(diff.text, expected);
    for shape in [
        "diff --git \"a/new\\nline.txt\" \"b/new\\nline.txt\"\n",
        "+++ \"b/x\\n+++ b/evil.txt\"\t\n",
        "--- \"a/tab\\there.txt\"\n",
        "\"b/quote\\\"d.txt\"",
        "\"b/back\\\\slash.txt\"",
        "\"b/ctl\\001del\\177.txt\"",
        "\"b/caf\\303\\251.txt\"",
        "+++ b/sp ace.txt\t\n",
        "--- a/gone with space.txt\t\n",
        "diff --git a/diff --git a b b/diff --git a b\n",
        "Binary files a/bin ary.bin and b/bin ary.bin differ\n",
        "\"b/esc\\033[31m.txt\"",
        "\"b/bell\\abs\\bvt\\vff\\f.txt\"",
        "diff --git \"a/del\\tx.txt\" \"b/del\\tx.txt\"\ndeleted file mode 100644\n",
        "--- \"a/del\\tx.txt\"\n+++ /dev/null\n",
        "Binary files \"a/bin\\\"q.bin\" and \"b/bin\\\"q.bin\" differ\n",
        "Binary files /dev/null and \"b/new bin\\303\\251.bin\" differ\n",
        "diff --git \"a/mode\\nx.sh\" \"b/mode\\nx.sh\"\nold mode 100644\nnew mode 100755\n",
    ] {
        assert!(expected.contains(shape), "the fixture exercises {shape:?}");
    }
}

/// Under a bound the text is a whole-line prefix of git's diff, and marked
/// truncated; at exactly git's length it is whole.
#[test]
fn a_bounded_text_diff_is_a_whole_line_prefix_of_gits() {
    let (_tmp, repo, base, head) = fixture();
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    let expected = git_diff(&repo, &base, &head);
    let bound = expected.len() / 2;
    let diff = backend
        .recorded_commit_text_diff(&base, &head, bound)
        .expect("the diff renders");
    assert!(diff.truncated);
    assert!(diff.text.len() <= bound, "{} > {bound}", diff.text.len());
    assert!(expected.starts_with(&diff.text));
    assert!(diff.text.ends_with('\n'), "cut at a whole line");
    let next_line = expected[diff.text.len()..]
        .split_inclusive('\n')
        .next()
        .unwrap();
    assert!(
        diff.text.len() + next_line.len() > bound,
        "the next whole line would not have fit"
    );

    let whole = backend
        .recorded_commit_text_diff(&base, &head, expected.len())
        .expect("the diff renders");
    assert!(!whole.truncated);
    assert_eq!(whole.text, expected);
}

/// A repository whose two commits each hold `bad\xffname.txt` (a name that is
/// not UTF-8, which git quotes as `"b/bad\377name.txt"`) in directory `where_`
/// (`""` for the root), the head
/// adding it when `changed` and leaving it as the base has it otherwise, and
/// modifying `kept.txt` at the root either way.
fn non_utf8_fixture(
    where_: &str,
    changed: bool,
) -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    use std::os::unix::ffi::OsStrExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("project");
    std::fs::create_dir_all(repo.join(where_)).unwrap();
    init_git_repo_at(&repo);
    let bad = repo
        .join(where_)
        .join(std::ffi::OsStr::from_bytes(b"bad\xffname.txt"));
    std::fs::write(repo.join("kept.txt"), b"before\n").unwrap();
    std::fs::write(repo.join(where_).join("other.txt"), b"other\n").unwrap();
    if !changed {
        std::fs::write(&bad, b"bad\n").unwrap();
    }
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]).trim().to_owned();
    std::fs::write(repo.join("kept.txt"), b"after\n").unwrap();
    if changed {
        std::fs::write(&bad, b"bad\n").unwrap();
    }
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "head"]);
    let head = git(&repo, &["rev-parse", "HEAD"]).trim().to_owned();
    (tmp, repo, base, head)
}

/// THE REFUSAL: a path whose name is not UTF-8 is never rendered. jj-lib
/// refuses to read a tree holding such an entry name, so when the diff reads
/// that tree — the root, or a directory that differs between the two commits
/// — both `target.diff` and `target.changed_files` fail (the render reading
/// either fails, naming the read) rather than write the path in any spelling,
/// though git would quote it. Outside the refused set: a directory that holds
/// such a name but is identical in both commits is not read, and the diff is
/// git's byte for byte.
#[test]
fn a_path_that_is_not_utf8_fails_the_read_unless_its_tree_is_unchanged() {
    for (where_, changed) in [("", true), ("", false), ("sub", true)] {
        let (_tmp, repo, base, head) = non_utf8_fixture(where_, changed);
        let backend = JjBackend::open(&repo).expect("adopt the repository");
        if changed {
            let dir = if where_.is_empty() { "" } else { "sub/" };
            assert!(
                git_diff(&repo, &base, &head).contains(&format!("\"b/{dir}bad\\377name.txt\"")),
                "git quotes the name kata refuses"
            );
        }
        let text = backend
            .recorded_commit_text_diff(&base, &head, 1024 * 1024)
            .expect_err("the text diff refuses a tree holding a non-UTF-8 name");
        assert!(
            text.to_string().contains(&format!("{base}..{head}")),
            "the refusal names the range: {text}"
        );
        backend
            .recorded_commit_diff(&base, &head)
            .expect_err("the file list refuses a tree holding a non-UTF-8 name");
    }

    let (_tmp, repo, base, head) = non_utf8_fixture("sub", false);
    let backend = JjBackend::open(&repo).expect("adopt the repository");
    let diff = backend
        .recorded_commit_text_diff(&base, &head, 1024 * 1024)
        .expect("an unchanged directory is not read");
    assert_eq!(diff.text, git_diff(&repo, &base, &head));
    assert_eq!(
        backend
            .recorded_commit_diff(&base, &head)
            .expect("an unchanged directory is not read")
            .len(),
        1
    );
}
