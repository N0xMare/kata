//! The `oci` admission repository census, exercised
//! against REAL git fixtures: a repository the `git` CLI itself built
//! (submodule gitlinks, committed `.gitattributes`, `info/attributes`,
//! `$GIT_DIR/shallow`, partial-clone config keys), adopted by
//! [`JjBackend::open`] into a colocated jj repo, then censused through
//! [`ExecutionWorkspaceProvider::refuse_unsupported_repository_features`] on a just-created
//! execution workspace — exactly the call the executor's submit path makes.
//!
//! Every refusal asserts the COMPLETE finding set by rebuilding the expected
//! message through [`oci_unsupported_features_refusal`]: a census that
//! under-reports would leave the operator remediating one feature at a time,
//! and a census that over-reports would refuse repositories it claims not to.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use kata_effects_contract::{
    ExecutionWorkspaceKey, ExecutionWorkspaceProvider, OCI_UNSUPPORTED_REPOSITORY_FEATURES,
    UnsupportedRepositoryFeature, oci_unsupported_features_refusal,
};
use kata_test_utils::git::{hermetic_git, hermetic_git_in, init_git_repo_at, run_git};
use kata_types::KataError;
use kata_vcs::{JjBackend, VcsBackend};
use ulid::Ulid;

/// Open `repo` (a directory `git init` already seeded) through
/// [`JjBackend::open`]'s adoption path, create an execution workspace, and run
/// the census on its handle — the submit path's exact call shape. The
/// workspace is removed before returning so no fixture state outlives the
/// test. `Err` carries the refusal's full durable message.
fn census(repo: &Path) -> Result<(), String> {
    let backend = JjBackend::open(repo).expect("adopt the fixture repository");
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("the census presumes a created execution workspace");
    let verdict =
        ExecutionWorkspaceProvider::refuse_unsupported_repository_features(&backend, &handle)
            .map_err(|error| error.to_string());
    ExecutionWorkspaceProvider::remove_workspace(&backend, &key)
        .expect("remove the census's execution workspace");
    verdict
}

/// Assert the census refused, and that its durable message IS the one
/// [`oci_unsupported_features_refusal`] builds for exactly `expected` — pinning
/// the refusal token, the finding order, and the complete refused set.
fn assert_refuses(repo: &Path, expected: &[UnsupportedRepositoryFeature]) {
    let message = census(repo).expect_err("the census must refuse this repository");
    let expected_message = oci_unsupported_features_refusal(expected).to_string();
    assert_eq!(
        message, expected_message,
        "the refusal must name exactly this finding set"
    );
    assert!(
        message.contains(OCI_UNSUPPORTED_REPOSITORY_FEATURES),
        "the stable refusal code is in the message: {message}"
    );
}

/// Assert the census ADMITS `repo` — the empty refused set.
fn assert_admits(repo: &Path) {
    assert_eq!(
        census(repo),
        Ok(()),
        "the census must admit this repository"
    );
}

#[test]
fn a_clean_git_repo_admits() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    assert_admits(tmp.path());
}

#[test]
fn a_committed_root_gitmodules_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    // `.gitmodules` without a gitlink: the declaration file alone is the
    // submodule feature — a stale one still declares intent the census cannot
    // second-guess.
    fs::write(
        tmp.path().join(".gitmodules"),
        "[submodule \"dep\"]\n\tpath = vendor/dep\n\turl = ../dep\n",
    )
    .unwrap();
    run_git(tmp.path(), &["add", ".gitmodules"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "declare submodule"]);

    assert_refuses(tmp.path(), &[UnsupportedRepositoryFeature::GitmodulesFile]);
}

#[test]
fn a_real_submodule_refuses_gitlink_and_gitmodules() {
    let dep = tempfile::tempdir().unwrap();
    init_git_repo_at(dep.path());
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    run_git(
        tmp.path(),
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            dep.path().to_str().unwrap(),
            "vendor/dep",
        ],
    );
    run_git(tmp.path(), &["commit", "-q", "-m", "add dep submodule"]);

    // Ground truth first: the gitlink is really mode 160000 in git's tree.
    let listing = hermetic_git_in(tmp.path())
        .args(["ls-tree", "HEAD", "vendor/dep"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&listing.stdout).starts_with("160000 commit"),
        "the fixture must hold a real gitlink: {}",
        String::from_utf8_lossy(&listing.stdout)
    );

    assert_refuses(
        tmp.path(),
        &[
            UnsupportedRepositoryFeature::GitmodulesFile,
            UnsupportedRepositoryFeature::GitSubmodule {
                path: "vendor/dep".to_string(),
            },
        ],
    );
}

/// THE NEAR-MISS BATTERY: ordinary `.gitattributes` declarations that change
/// no byte git writes at checkout on this platform are ADMITTED — the census
/// refuses checkout-converting declarations, not the file that carries them.
#[test]
fn a_gitattributes_of_only_safe_declarations_admits() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(
        tmp.path().join(".gitattributes"),
        "* text=auto eol=lf\n\
         *.rs diff=rust\n\
         *.png binary\n\
         *.log -filter\n\
         *.tmp !filter\n\
         *.docx linguist-documentation\n\
         *.tar export-ignore\n\
         *.txt -text\n\
         *.md merge=union\n",
    )
    .unwrap();
    run_git(tmp.path(), &["add", ".gitattributes"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "benign attributes"]);

    assert_admits(tmp.path());
}

#[test]
fn nested_gitattributes_and_filter_declarations_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    // The root file's bare `filter` (git's "set" form) is a declaration too.
    fs::write(tmp.path().join(".gitattributes"), "*.raw filter\n").unwrap();
    fs::create_dir_all(tmp.path().join("sub")).unwrap();
    fs::write(
        tmp.path().join("sub/.gitattributes"),
        "*.big filter=lfs\n*.pack filter=crypt\n*.y -filter\n*.z !filter\n",
    )
    .unwrap();
    run_git(tmp.path(), &["add", ".gitattributes", "sub/.gitattributes"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "filters"]);

    // Ground truth: git itself resolves these declarations — nested
    // `.gitattributes` rules cover `sub/**`, so the probes must name
    // `sub/` paths.
    let check = |pattern: &str| -> String {
        let out = hermetic_git_in(tmp.path())
            .args(["check-attr", "filter", "--", pattern])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert!(
        check("sub/x.big").ends_with("lfs"),
        "{}",
        check("sub/x.big")
    );
    assert!(check("sub/x.pack").ends_with("crypt"));
    assert!(check("sub/x.y").ends_with("unset"));
    assert!(check("x.raw").ends_with("set"));

    assert_refuses(
        tmp.path(),
        &[
            UnsupportedRepositoryFeature::GitFilter {
                source: ".gitattributes".to_string(),
                pattern: "*.raw".to_string(),
                value: None,
            },
            UnsupportedRepositoryFeature::GitFilter {
                source: "sub/.gitattributes".to_string(),
                pattern: "*.big".to_string(),
                value: Some("lfs".to_string()),
            },
            UnsupportedRepositoryFeature::GitFilter {
                source: "sub/.gitattributes".to_string(),
                pattern: "*.pack".to_string(),
                value: Some("crypt".to_string()),
            },
        ],
    );
}

#[test]
fn info_attributes_refuses_with_its_declarations() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(tmp.path().join(".git/info/attributes"), "* filter=lfs\n").unwrap();

    // Ground truth: the info file really applies — git resolves `filter=lfs`
    // for every path.
    let out = hermetic_git_in(tmp.path())
        .args(["check-attr", "filter", "--", "anything"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .trim_end()
            .ends_with("lfs"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    assert_refuses(
        tmp.path(),
        &[UnsupportedRepositoryFeature::GitFilter {
            source: "$GIT_DIR/info/attributes".to_string(),
            pattern: "*".to_string(),
            value: Some("lfs".to_string()),
        }],
    );
}

/// `info/attributes` EXISTS but declares nothing that converts — admitted.
/// Its presence was never the feature; the declarations are.
#[test]
fn info_attributes_with_only_safe_declarations_admits() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(
        tmp.path().join(".git/info/attributes"),
        "* -text\n*.log -filter\n",
    )
    .unwrap();

    assert_admits(tmp.path());
}

/// `ident` expands `$Id$` at checkout — a byte change the verbatim
/// materialization cannot reproduce.
#[test]
fn a_committed_ident_declaration_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(
        tmp.path().join(".gitattributes"),
        "*.i ident\n*.v ident=vcs\n*.n -ident\n",
    )
    .unwrap();
    run_git(tmp.path(), &["add", ".gitattributes"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "ident"]);

    let out = hermetic_git_in(tmp.path())
        .args(["check-attr", "ident", "--", "x.i"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).ends_with("set\n"),
        "the fixture's ident declaration must apply: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    assert_refuses(
        tmp.path(),
        &[
            UnsupportedRepositoryFeature::GitCheckoutConversion {
                source: ".gitattributes".to_string(),
                pattern: "*.i".to_string(),
                attribute: "ident".to_string(),
            },
            UnsupportedRepositoryFeature::GitCheckoutConversion {
                source: ".gitattributes".to_string(),
                pattern: "*.v".to_string(),
                attribute: "ident=vcs".to_string(),
            },
        ],
    );
}

/// `working-tree-encoding` re-encodes the blob on the way to the worktree.
#[test]
fn a_working_tree_encoding_declaration_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(
        tmp.path().join(".gitattributes"),
        "*.e working-tree-encoding=UTF-16\n*.s -working-tree-encoding\n",
    )
    .unwrap();
    run_git(tmp.path(), &["add", ".gitattributes"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "encoding"]);

    assert_refuses(
        tmp.path(),
        &[UnsupportedRepositoryFeature::GitCheckoutConversion {
            source: ".gitattributes".to_string(),
            pattern: "*.e".to_string(),
            attribute: "working-tree-encoding=UTF-16".to_string(),
        }],
    );
}

/// `eol=crlf` writes CRLF at checkout even on Linux (measured); `eol=lf`,
/// `eol=native` and the unset forms are byte-identical to the blob.
#[test]
fn an_eol_crlf_declaration_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(
        tmp.path().join(".gitattributes"),
        "*.t eol=crlf\n*.u eol=CRLF\n*.l eol=lf\n*.n eol=native\n",
    )
    .unwrap();
    run_git(tmp.path(), &["add", ".gitattributes"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "eol"]);

    assert_refuses(
        tmp.path(),
        &[
            UnsupportedRepositoryFeature::GitCheckoutConversion {
                source: ".gitattributes".to_string(),
                pattern: "*.t".to_string(),
                attribute: "eol=crlf".to_string(),
            },
            UnsupportedRepositoryFeature::GitCheckoutConversion {
                source: ".gitattributes".to_string(),
                pattern: "*.u".to_string(),
                attribute: "eol=CRLF".to_string(),
            },
        ],
    );
}

/// An `[attr]` macro carrying a refused attribute refuses each rule that
/// SETS the macro — git keeps `all_macros` on the attribute stack and expands
/// at use time, so the definition applies even to lines before it, and
/// `-macro`/`!macro` do not expand (all three measured against `check-attr`).
#[test]
fn an_attr_macro_declaring_a_refused_attribute_refuses_its_uses() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(
        tmp.path().join(".gitattributes"),
        "*.z mac\n[attr]mac filter=lfs\n*.safe -mac\n*.also !mac\n",
    )
    .unwrap();
    run_git(tmp.path(), &["add", ".gitattributes"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "attr macro"]);

    let check = |path: &str| -> String {
        let out = hermetic_git_in(tmp.path())
            .args(["check-attr", "filter", "--", path])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    assert_eq!(check("x.z"), "x.z: filter: lfs");
    assert_eq!(check("x.safe"), "x.safe: filter: unspecified");

    assert_refuses(
        tmp.path(),
        &[UnsupportedRepositoryFeature::GitFilter {
            source: ".gitattributes".to_string(),
            pattern: "*.z".to_string(),
            value: Some("lfs".to_string()),
        }],
    );
}

/// Macros are defined on the STACK, not per file (measured): a definition in
/// `$GIT_DIR/info/attributes` expands in a committed `.gitattributes`.
#[test]
fn an_attr_macro_defined_in_info_attributes_expands_in_the_tree() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(
        tmp.path().join(".git/info/attributes"),
        "[attr]conv eol=crlf\n",
    )
    .unwrap();
    fs::write(tmp.path().join(".gitattributes"), "*.t conv\n").unwrap();
    run_git(tmp.path(), &["add", ".gitattributes"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "stack macro"]);

    let out = hermetic_git_in(tmp.path())
        .args(["check-attr", "eol", "--", "x.t"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "x.t: eol: crlf",
        "the fixture's macro must expand the way git expands it"
    );

    assert_refuses(
        tmp.path(),
        &[UnsupportedRepositoryFeature::GitCheckoutConversion {
            source: ".gitattributes".to_string(),
            pattern: "*.t".to_string(),
            attribute: "eol=crlf".to_string(),
        }],
    );
}

/// `core.autocrlf=true` and `core.eol=crlf` in the repository's own config
/// convert the tree's text bytes at checkout on this platform (both
/// measured).
#[test]
fn core_autocrlf_true_and_core_eol_crlf_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    run_git(tmp.path(), &["config", "core.autocrlf", "true"]);
    run_git(tmp.path(), &["config", "core.eol", "crlf"]);

    assert_refuses(
        tmp.path(),
        &[
            UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                key: "core.autocrlf".to_string(),
            },
            UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                key: "core.eol".to_string(),
            },
        ],
    );
}

/// `autocrlf=input` converts on COMMIT only and `eol=lf`/`native` write the
/// blob's bytes back — measured byte-identical, admitted. A `[filter]`
/// section with no attribute declaring the filter is inert — also admitted.
#[test]
fn non_converting_config_and_unused_filter_sections_admit() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    run_git(tmp.path(), &["config", "core.autocrlf", "input"]);
    run_git(tmp.path(), &["config", "core.eol", "native"]);
    run_git(
        tmp.path(),
        &["config", "filter.lfs.clean", "git-lfs clean -- %f"],
    );
    run_git(
        tmp.path(),
        &["config", "filter.lfs.smudge", "git-lfs smudge -- %f"],
    );
    run_git(tmp.path(), &["config", "filter.lfs.required", "true"]);
    run_git(
        tmp.path(),
        &["config", "filter.crypt.clean", "crypt-clean %f"],
    );

    assert_admits(tmp.path());
}

#[test]
fn a_shallow_clone_refuses() {
    let src = tempfile::tempdir().unwrap();
    init_git_repo_at(src.path());
    let clone = tempfile::tempdir().unwrap();
    let dst = clone.path().join("repo");
    let out = hermetic_git()
        .args([
            "clone",
            "--quiet",
            "--depth",
            "1",
            &format!("file://{}", src.path().display()),
            dst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shallow clone: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        dst.join(".git/shallow").is_file(),
        "the fixture must be a real shallow clone"
    );

    assert_refuses(&dst, &[UnsupportedRepositoryFeature::ShallowClone]);
}

#[test]
fn partial_clone_config_keys_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    // The three markers `git clone --filter=...` writes into the repository's
    // own config. Written as config here because they are the evidence — a
    // filter the remote ignored still leaves the promisor markers.
    run_git(tmp.path(), &["config", "remote.origin.promisor", "true"]);
    run_git(
        tmp.path(),
        &["config", "remote.origin.partialclonefilter", "blob:none"],
    );
    run_git(tmp.path(), &["config", "extensions.partialclone", "origin"]);

    assert_refuses(
        tmp.path(),
        &[
            UnsupportedRepositoryFeature::PartialClone {
                key: "remote.origin.promisor".to_string(),
            },
            UnsupportedRepositoryFeature::PartialClone {
                key: "remote.origin.partialclonefilter".to_string(),
            },
            UnsupportedRepositoryFeature::PartialClone {
                key: "extensions.partialclone".to_string(),
            },
        ],
    );
}

#[test]
fn promisor_false_and_unrelated_config_do_not_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    // `promisor=false` declares the remote is NOT a promisor — the opposite of
    // a partial clone. Ordinary config (remotes, gc, whitespace rules) is
    // equally not the census's business.
    run_git(tmp.path(), &["config", "remote.origin.promisor", "false"]);
    run_git(tmp.path(), &["config", "remote.origin.url", "../somewhere"]);
    run_git(tmp.path(), &["config", "core.whitespace", "trailing-space"]);
    run_git(tmp.path(), &["config", "diff.submodule", "log"]);
    assert_admits(tmp.path());
}

#[test]
fn core_attributesfile_config_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    // `core.attributesFile` points attribute declarations at a path the
    // census cannot read — refused while non-empty. The `[filter]` sections
    // beside it (what `git lfs install --local` writes) are INERT without an
    // attribute declaring the filter and refuse nothing on their own.
    run_git(
        tmp.path(),
        &["config", "filter.lfs.clean", "git-lfs clean -- %f"],
    );
    run_git(
        tmp.path(),
        &["config", "core.attributesFile", "custom/attrs"],
    );

    assert_refuses(
        tmp.path(),
        &[UnsupportedRepositoryFeature::GitAttributesConfig {
            key: "core.attributesFile".to_string(),
        }],
    );
}

#[test]
fn every_finding_aggregates_into_one_refusal() {
    let dep = tempfile::tempdir().unwrap();
    init_git_repo_at(dep.path());
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    run_git(
        tmp.path(),
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            dep.path().to_str().unwrap(),
            "vendor/dep",
        ],
    );
    fs::create_dir_all(tmp.path().join("sub")).unwrap();
    fs::write(tmp.path().join("sub/.gitattributes"), "*.big filter=lfs\n").unwrap();
    run_git(
        tmp.path(),
        &["add", ".gitmodules", "sub/.gitattributes", "vendor/dep"],
    );
    run_git(tmp.path(), &["commit", "-q", "-m", "submodule + filters"]);
    // A REAL `shallow` boundary entry (the clone marker is a list of commit
    // ids — `rev-parse HEAD`'s is the honest shape), and the promisor config.
    let head = hermetic_git_in(tmp.path())
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    fs::write(tmp.path().join(".git/shallow"), &head.stdout).unwrap();
    run_git(tmp.path(), &["config", "remote.origin.promisor", "true"]);

    assert_refuses(
        tmp.path(),
        &[
            UnsupportedRepositoryFeature::GitmodulesFile,
            UnsupportedRepositoryFeature::GitSubmodule {
                path: "vendor/dep".to_string(),
            },
            UnsupportedRepositoryFeature::ShallowClone,
            UnsupportedRepositoryFeature::PartialClone {
                key: "remote.origin.promisor".to_string(),
            },
            UnsupportedRepositoryFeature::GitFilter {
                source: "sub/.gitattributes".to_string(),
                pattern: "*.big".to_string(),
                value: Some("lfs".to_string()),
            },
        ],
    );
}

#[test]
fn a_separate_git_dir_indirection_is_resolved() {
    // `git clone --separate-git-dir` produces a `.git` FILE containing
    // `gitdir: <path>` — the same indirection a submodule or linked-worktree
    // checkout carries. The census must read the RESOLVED git dir, not join
    // onto the file.
    let src = tempfile::tempdir().unwrap();
    init_git_repo_at(src.path());
    fs::write(src.path().join(".gitattributes"), "*.x text\n").unwrap();
    run_git(src.path(), &["add", ".gitattributes"]);
    run_git(src.path(), &["commit", "-q", "-m", "attrs"]);

    let holder = tempfile::tempdir().unwrap();
    let dst = holder.path().join("worktree");
    let gitdir = holder.path().join("separated.git");
    let out = hermetic_git()
        .args([
            "clone",
            "--quiet",
            "--separate-git-dir",
            gitdir.to_str().unwrap(),
            &format!("file://{}", src.path().display()),
            dst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "separate-git-dir clone: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        dst.join(".git").is_file(),
        "the fixture must hold a gitdir: file, not a directory"
    );
    // The resolved git dir carries the repo-scoped surfaces. The committed
    // `.gitattributes` declares only safe attributes — it admits; the
    // `shallow` marker and the info/attributes filter declaration are the
    // refused features the indirection must not hide.
    fs::write(gitdir.join("shallow"), "").unwrap();
    fs::create_dir_all(gitdir.join("info")).ok();
    fs::write(gitdir.join("info/attributes"), "* filter=sec\n").unwrap();

    assert_refuses(
        &dst,
        &[
            UnsupportedRepositoryFeature::ShallowClone,
            UnsupportedRepositoryFeature::GitFilter {
                source: "$GIT_DIR/info/attributes".to_string(),
                pattern: "*".to_string(),
                value: Some("sec".to_string()),
            },
        ],
    );
}

#[test]
fn conditional_and_global_includes_are_not_imported() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    // A file carrying a REFUSED marker, reachable from the repo's config only
    // through the channels the census refuses BY NAME: an `includeIf` (whose
    // `gitdir:` condition is git's own expansion machinery — never followed,
    // no finding) and `~`-relative and absolute `include.path`s (a GLOBAL
    // file the census cannot answer for — each is a `GitConfigInclude`
    // finding rather than a read, because git would honor a conversion key
    // there while the census saw nothing).
    let refused_inc = tmp.path().join("outside.inc");
    fs::write(
        &refused_inc,
        "[extensions]\n\tpartialclone = origin\n[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n",
    )
    .unwrap();
    let mut config = fs::read_to_string(tmp.path().join(".git/config")).unwrap();
    write!(
        config,
        "[includeIf \"gitdir:{}/\"]\n\tpath = {}\n[include]\n\tpath = ~{}\n\tpath = {}\n",
        tmp.path().display(),
        refused_inc.display(),
        refused_inc.display(),
        refused_inc.display(),
    )
    .unwrap();
    fs::write(tmp.path().join(".git/config"), config).unwrap();

    // A RELATIVE include inside `$GIT_DIR` IS followed (git honors it) — the
    // include machinery still reads, so the findings above are not vacuous.
    fs::write(
        tmp.path().join(".git/local.inc"),
        "[remote \"x\"]\n\tpromisor = true\n",
    )
    .unwrap();
    let mut config = fs::read_to_string(tmp.path().join(".git/config")).unwrap();
    write!(config, "[include]\n\tpath = local.inc\n").unwrap();
    fs::write(tmp.path().join(".git/config"), config).unwrap();

    assert_refuses(
        tmp.path(),
        &[
            UnsupportedRepositoryFeature::GitConfigInclude {
                path: format!("~{} (outside the repository)", refused_inc.display()),
            },
            UnsupportedRepositoryFeature::GitConfigInclude {
                path: format!("{} (outside the repository)", refused_inc.display()),
            },
            UnsupportedRepositoryFeature::PartialClone {
                key: "remote.x.promisor".to_string(),
            },
        ],
    );
}

#[test]
fn a_symlinked_gitattributes_does_not_refuse() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(tmp.path().join("target.txt"), "anything\n").unwrap();
    std::os::unix::fs::symlink("target.txt", tmp.path().join(".gitattributes")).unwrap();
    run_git(tmp.path(), &["add", ".gitattributes", "target.txt"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "symlinked attributes"]);

    // Ground truth: the commit holds a SYMLINK (mode 120000), not a file —
    // git's own in-tree attribute lookup refuses symlinked `.gitattributes`
    // (ELOOP), so its declarations never apply and the capsule's byte-identical
    // materialization diverges from nothing.
    let listing = hermetic_git_in(tmp.path())
        .args(["ls-tree", "HEAD", ".gitattributes"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&listing.stdout).starts_with("120000 blob"),
        "the fixture must hold a committed symlink: {}",
        String::from_utf8_lossy(&listing.stdout)
    );

    assert_admits(tmp.path());
}

#[test]
fn the_refusal_is_a_validation_not_an_internal() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    fs::write(tmp.path().join(".gitmodules"), "[submodule \"d\"]\n").unwrap();
    run_git(tmp.path(), &["add", ".gitmodules"]);
    run_git(tmp.path(), &["commit", "-q", "-m", "modules"]);

    let backend = JjBackend::open(tmp.path()).unwrap();
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).unwrap();
    let err = ExecutionWorkspaceProvider::refuse_unsupported_repository_features(&backend, &handle)
        .expect_err("must refuse");
    ExecutionWorkspaceProvider::remove_workspace(&backend, &key).unwrap();

    // The census refusal is callable-by-humans (Validation), and the stable
    // refusal code leads the message so tooling can find the class.
    assert!(matches!(err, KataError::Validation(_)), "{err}");
    assert!(
        err.to_string()
            .contains(OCI_UNSUPPORTED_REPOSITORY_FEATURES)
    );
}

/// A repository `config` that does not exist is not a refusal — the census's
/// store read skips `NotFound`, and only that one kind of miss.
#[test]
fn a_repository_without_a_config_file_censuses_clean() {
    let tmp = tempfile::tempdir().unwrap();
    init_git_repo_at(tmp.path());
    let backend = JjBackend::open(tmp.path()).unwrap();
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("the census presumes a created execution workspace");
    fs::remove_file(tmp.path().join(".git/config")).unwrap();
    let verdict =
        ExecutionWorkspaceProvider::refuse_unsupported_repository_features(&backend, &handle);
    ExecutionWorkspaceProvider::remove_workspace(&backend, &key).unwrap();
    assert_eq!(
        verdict.map_err(|e| e.to_string()),
        Ok(()),
        "an absent config is the empty config, not an error"
    );
}
