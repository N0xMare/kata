#!/usr/bin/env bash
#
# Materialize the `tally` playground repository kata's gold agentic loop
# improves — a small synthetic fixture rather than kata itself, so a run of
# that loop is deterministic, cheap and repeatable.
#
#     scripts/materialize-gold-fixture.sh <dest>
#     scripts/materialize-gold-fixture.sh --self-test
#     scripts/materialize-gold-fixture.sh --verify-landed <repo> <base> <ref> <sha>
#
# WHY A GIT REPO AND NOT A JJ ONE
# -------------------------------
# kata's DEFAULT execution-workspace backend is jj, and boot's jj arm calls
# `JjBackend::open(&cfg.vcs.jj_repo)` (`build_workspace_provider_from_config`,
# bin/kata/src/boot.rs). That call does not need a jj repo handed to it:
# it ADOPTS a pre-existing top-level `.git` as jj's store and layers `.jj` over
# it without re-initializing, which is exactly what
# `open_adopts_a_pre_existing_git_repo_as_colocated_without_reinitializing`
# (`crates/vcs/src/jj_tests.rs`) pins, and it initializes a colocated git repo
# when there is none at all.
#
# So the shape this script must produce is a plain git repository with a
# reachable HEAD and a deterministic trunk. Two reasons that is the RIGHT
# shape rather than merely a sufficient one:
#
#  1. It is the shipped path. Handing kata a `.jj` we made ourselves would
#     exercise a setup no operator performs; adoption is what an operator's
#     project actually presents to `kata serve`.
#  2. Producing `.jj` here would mean shelling the `jj` CLI. Kata links
#     jj-lib and shells the jj CLI only from test readers, so this fixture
#     adds no jj dependency of its own: a fixture that needs a tool the
#     product does not need is a host dependency bought for nothing.
#
# HERMETICITY IS DERIVED, NOT RE-SPELLED
# --------------------------------------
# The git overrides applied here are PARSED from the runtime behavioral set in
# `crates/types/src/git_policy.rs` plus the fixture identity/trunk additions in
# `crates/test-utils/src/git.rs`, the two inputs to `HERMETIC_OVERRIDES`.
# Re-typing their key/value pairs into a shell script
# would be a second copy that drifts silently — and the cost of drift is not
# hypothetical here: the `commit.gpgsign` entry exists because 23 tests were
# found signing throwaway commits with the operator's GPG key, and `core.hooksPath`
# exists because a global pre-commit hook failed the seed commit of an unrelated
# fixture. A pair added there is applied here on the next run, for free.
#
# IDEMPOTENT, AND WHAT THAT COSTS
# -------------------------------
# Re-running against a destination THIS SCRIPT marked (`.kata-gold-fixture`)
# DESTROYS it and rebuilds it byte-for-byte. That is what makes the second run
# produce the same tree as the first rather than a merge of both. Point it at a
# scratch directory; never at one holding work you want. Any other non-empty
# destination is REFUSED rather than merged into, and there is no `--force`.
#
# REFUSES RATHER THAN HALF-PRODUCES
# ---------------------------------
# Every failure past the copy deletes the destination on the way out. A
# half-materialized repository is worse than none: it is a repo kata will
# happily open, whose validation stage then reports a verdict about a tree
# nobody described. The verification block below re-reads what was written —
# bytes, modes, git identity, working-tree cleanliness — and, crucially, checks
# that `known-fix.patch` still APPLIES, which is how it knows the tree it just
# built is the UNFIXED one. That last check is derived from the oracle's own
# answer instead of re-spelling the defect in a grep.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
fixture_dir="$root/test/fixtures/gold-loop"
src_dir="$fixture_dir/repo"
manifest="$fixture_dir/MANIFEST"
patch_file="$fixture_dir/known-fix.patch"
marker_name=".kata-gold-fixture"
fixture_name="gold-loop/tally"

die() { echo "materialize-gold-fixture.sh: FAIL — $*" >&2; exit 1; }
note() { echo "materialize-gold-fixture.sh: $*" >&2; }

# --------------------------------------------------------------------------
# 0. Inputs the script cannot work without.
# --------------------------------------------------------------------------
for tool in git python3 cmp; do
    command -v "$tool" >/dev/null 2>&1 || die "'$tool' is not on PATH"
done
[ -d "$src_dir" ]     || die "fixture source tree not found: $src_dir"
[ -f "$manifest" ]    || die "manifest not found: $manifest"
[ -f "$patch_file" ]  || die "known-fix patch not found: $patch_file"

# --------------------------------------------------------------------------
# 1. Parse the manifest and REFUSE in both directions.
# --------------------------------------------------------------------------
mapfile -t manifest_lines < <(
    sed -e 's/#.*//' "$manifest" | awk 'NF == 2 { print $1 "\t" $2 }'
)
[ "${#manifest_lines[@]}" -gt 0 ] || die "manifest names no files"

declare -a listed_sources=()
for line in "${manifest_lines[@]}"; do
    listed_sources+=("${line%%$'\t'*}")
done

for s in "${listed_sources[@]}"; do
    [ -f "$src_dir/$s" ] || die "manifest names a source that does not exist: repo/$s"
done

while IFS= read -r found; do
    hit=0
    for s in "${listed_sources[@]}"; do
        [ "$s" = "$found" ] && { hit=1; break; }
    done
    [ "$hit" -eq 1 ] || die "repo/$found exists but NO manifest line names it — \
the materialized repository would be silently incomplete. Add it to $manifest."
done < <(cd "$src_dir" && find . -type f -printf '%P\n' | sort)

# --------------------------------------------------------------------------
# 2. Derive the hermetic git overrides from production's single definition.
# --------------------------------------------------------------------------
# `KATA_HERMETIC_GIT_SRC` exists for ONE reason, the same one
# `footprint-config.sh` takes an optional `source_config` for: so the failure
# modes of this derivation can be PROVOKED and observed instead of reasoned
# about. Nothing in normal use sets it.
hermetic_src="${KATA_HERMETIC_GIT_SRC:-$root/crates/test-utils/src/git.rs}"
overrides="$(
    python3 - "$hermetic_src" "$root/crates/types/src/git_policy.rs" <<'PY'
import re, sys

path = sys.argv[1]
try:
    text = open(path, encoding="utf-8").read()
except OSError as exc:
    sys.exit(f"cannot read {path}: {exc}")

try:
    policy_text = open(sys.argv[2], encoding="utf-8").read()
except OSError as exc:
    sys.exit(f"cannot read {sys.argv[2]}: {exc}")

if not re.search(r'HERMETIC_OVERRIDES\s*:\s*&\[\(&str,\s*&str\)\]\s*=\s*&fixture_overrides\(\)', text):
    sys.exit("HERMETIC_OVERRIDES no longer derives from fixture_overrides; update the derivation")

consts = dict(re.findall(r'const\s+([A-Z_][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]*)"\s*;', text + policy_text))

def override_body(source, name):
    match = re.search(
        rf"{name}\s*:\s*&\[\(&str,\s*&str\)\]\s*=\s*&\[(.*?)\]\s*;",
        source,
        re.S,
    )
    if not match:
        sys.exit(f"{name} was not found; fix the derivation, do not re-spell the pairs")
    return match.group(1)

body = override_body(text, "FIXTURE_IDENTITY_OVERRIDES") + override_body(policy_text, "GIT_EXECUTION_OVERRIDES")

pairs = re.findall(
    r'\(\s*"([^"]+)"\s*,\s*(?:"([^"]*)"|([A-Za-z_][A-Za-z0-9_]*))\s*\)',
    body,
)
if not pairs:
    sys.exit("HERMETIC_OVERRIDES parsed as EMPTY — refusing to build a non-hermetic repo")

# Resolve EVERY entry before printing ANY of them. A parser that streams would
# leave a partial, still-plausible override list on stdout next to a non-zero
# exit — and a caller that ever loses the `|| die` would then build a repo that
# is hermetic in four of seven settings and looks fine.
lines = []
for key, literal, ident in pairs:
    if ident:
        if ident not in consts:
            sys.exit(f"HERMETIC_OVERRIDES entry {key} names {ident}, which no `const … : &str` defines")
        value = consts[ident]
    else:
        value = literal
    if "\t" in key or "\t" in value:
        sys.exit(f"HERMETIC_OVERRIDES entry {key} contains a tab; the shell reader cannot carry it")
    lines.append(f"{key}\t{value}")
print("\n".join(lines))
PY
)" || die "could not derive HERMETIC_OVERRIDES from $hermetic_src: $overrides"

declare -a git_c=()
declare -a ov_keys=() ov_vals=()
while IFS=$'\t' read -r key value; do
    [ -n "$key" ] || continue
    git_c+=(-c "$key=$value")
    ov_keys+=("$key")
    ov_vals+=("$value")
done <<<"$overrides"
[ "${#ov_keys[@]}" -gt 0 ] || die "derived ZERO hermetic overrides"

hgit() { git "${git_c[@]}" -C "$1" "${@:2}"; }

# --------------------------------------------------------------------------
# 3. Destination policy.
# --------------------------------------------------------------------------
materialize() {
    local dest="$1"

    # Resolve the destination BEFORE anything can `rm -rf` it. The marker gate
    # below already means only a directory this script wrote is ever deleted,
    # but a script that deletes trees should not rely on one predicate: these
    # two refusals make \"materialize into the checkout\" impossible outright.
    local abs_parent
    abs_parent="$(cd "$(dirname "$dest")" 2>/dev/null && pwd)" \
        || die "the destination's parent directory does not exist: $(dirname "$dest")"
    dest="$abs_parent/$(basename "$dest")"
    [ "$dest" != "$root" ] || die "refusing to materialize INTO the kata checkout: $dest"
    case "$root/" in
        "$dest"/*) die "refusing: $dest CONTAINS the kata checkout, and a rebuild here would delete it" ;;
    esac

    if [ -e "$dest" ]; then
        [ -d "$dest" ] || die "destination exists and is not a directory: $dest"
        if [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
            if [ -f "$dest/$marker_name" ] && grep -qxF "fixture=$fixture_name" "$dest/$marker_name"; then
                note "destination carries this script's marker; rebuilding it from scratch"
                rm -rf -- "${dest:?}"
            else
                die "destination is non-empty and was NOT materialized by this script: $dest
  There is no --force. Pick an empty path, or delete that directory yourself."
            fi
        fi
    fi

    mkdir -p "$dest" || die "cannot create $dest"

    # 3a. Copy per manifest, preserving modes (tests/check.sh must stay executable).
    for line in "${manifest_lines[@]}"; do
        local s="${line%%$'\t'*}" d="${line##*$'\t'}"
        mkdir -p "$dest/$(dirname "$d")" || { rm -rf -- "$dest"; die "cannot create $dest/$(dirname "$d")"; }
        cp -p "$src_dir/$s" "$dest/$d" || { rm -rf -- "$dest"; die "copy failed: repo/$s -> $d"; }
    done

    # 3b. The marker. Committed, so a clean working tree stays clean, and it is
    # the ONLY thing that makes a rebuild of this destination permissible.
    {
        echo "fixture=$fixture_name"
        echo "source=test/fixtures/gold-loop/repo"
        echo "materialized_by=scripts/materialize-gold-fixture.sh"
        echo "manifest_files=${#manifest_lines[@]}"
    } > "$dest/$marker_name"

    # 3c. The git repo. The trunk NAME is a parameter, defaulting to `main`, because
    # a fixture that can only ever be `main` cannot see a trunk-binding defect — and
    # that is precisely how kata shipped for months forking every non-`main`
    # repository from the empty root. `KATA_GOLD_FIXTURE_TRUNK` is read here rather
    # than inherited from `init.defaultBranch` so the answer stays DELIBERATE: the
    # hermetic overrides below still pin everything else.
    local trunk="${KATA_GOLD_FIXTURE_TRUNK:-main}"
    case "$trunk" in
        ''|-*|*' '*) die "KATA_GOLD_FIXTURE_TRUNK is not a usable branch name: '$trunk'" ;;
    esac
    hgit "$dest" init -q -b "$trunk"        || { rm -rf -- "$dest"; die "git init failed"; }
    local i
    for i in "${!ov_keys[@]}"; do
        hgit "$dest" config "${ov_keys[$i]}" "${ov_vals[$i]}" \
            || { rm -rf -- "$dest"; die "git config ${ov_keys[$i]} failed"; }
    done
    hgit "$dest" add -A                     || { rm -rf -- "$dest"; die "git add failed"; }
    hgit "$dest" commit -q -m "tally: the unfixed playground tree" \
        || { rm -rf -- "$dest"; die "seed commit failed"; }

    # ----------------------------------------------------------------------
    # 4. VERIFY WHAT WAS WRITTEN. Anything wrong here deletes the destination.
    # ----------------------------------------------------------------------
    local problems=()

    for line in "${manifest_lines[@]}"; do
        local s="${line%%$'\t'*}" d="${line##*$'\t'}"
        if [ ! -f "$dest/$d" ]; then
            problems+=("$d is missing from the materialized repo")
        elif ! cmp -s "$src_dir/$s" "$dest/$d"; then
            problems+=("$d differs byte-for-byte from repo/$s")
        fi
        if [ -x "$src_dir/$s" ] && [ ! -x "$dest/$d" ]; then
            problems+=("$d lost its executable bit; check.sh would not be runnable as \`./check.sh\`")
        fi
    done

    # No file the manifest did not put there (git metadata aside).
    while IFS= read -r found; do
        [ "$found" = "$marker_name" ] && continue
        local hit=0 line2
        for line2 in "${manifest_lines[@]}"; do
            [ "${line2##*$'\t'}" = "$found" ] && { hit=1; break; }
        done
        [ "$hit" -eq 1 ] || problems+=("$found is in the materialized repo but no manifest line produced it")
    done < <(cd "$dest" && find . -type f -not -path './.git/*' -printf '%P\n' | sort)

    hgit "$dest" rev-parse --verify HEAD >/dev/null 2>&1 \
        || problems+=("HEAD is unreachable — JjBackend::open adoption needs a committed HEAD")
    local branch
    branch="$(hgit "$dest" rev-parse --abbrev-ref HEAD 2>/dev/null)"
    local want_trunk="${KATA_GOLD_FIXTURE_TRUNK:-main}"
    [ "$branch" = "$want_trunk" ] || problems+=("trunk is '$branch', expected '$want_trunk' — the trunk must be the one this fixture was asked for, or a caller sweeping trunk names is measuring the wrong repository")
    local dirty
    dirty="$(hgit "$dest" status --porcelain 2>/dev/null)"
    [ -z "$dirty" ] || problems+=("working tree is dirty right after the seed commit: $(printf '%s' "$dirty" | tr '\n' ' ')")

    for i in "${!ov_keys[@]}"; do
        local got
        got="$(git -C "$dest" config --local --get "${ov_keys[$i]}" 2>/dev/null)"
        [ "$got" = "${ov_vals[$i]}" ] \
            || problems+=("repo-local ${ov_keys[$i]} = '${got}', expected '${ov_vals[$i]}' — a process kata spawns against this repo would not be hermetic")
    done

    # The tree must be the UNFIXED one. Derived from the oracle's own answer:
    # if the known fix no longer applies, either the fixture was materialized
    # already-fixed or the patch has rotted, and both make the fixture useless
    # as a before/after oracle.
    git -C "$dest" apply --check "$patch_file" 2>/dev/null \
        || problems+=("known-fix.patch does not apply to the materialized tree — this is not the unfixed fixture (or the patch has rotted against src/tally.sh)")

    if [ "${#problems[@]}" -gt 0 ]; then
        echo "materialize-gold-fixture.sh: FAIL — the materialized repo is wrong:" >&2
        printf '  %s\n' "${problems[@]}" >&2
        rm -rf -- "$dest"
        echo "  (destination removed; this script refuses rather than half-produces)" >&2
        exit 1
    fi

    printf '%s\n' "$dest"
}

# --------------------------------------------------------------------------
# 5. --self-test: the before/after pair that makes this fixture an ORACLE.
# --------------------------------------------------------------------------
self_test() {
    # NO TOOL GUARD HERE, on purpose. The fixture is shell (`src/tally.sh`,
    # `tests/test_tail.sh`, driven by `sh tests/check.sh`) and NOTHING in it
    # needs an interpreter — which is
    # forced, since the OCI capsule the validation stage runs inside carries
    # only the node's declared environment. What this mode actually needs is
    # `git`, `python3` (for the hermetic-git derivation above) and `cmp` — all
    # three already checked at entry for every mode — and the honest form of
    # "can this host run the suite at all" is not a `command -v` at all: it is
    # `check.sh`'s own rc 2, which cell 2/4 now names.
    local dest rc out
    # GLOBAL on purpose. A `local tmp` is out of scope by the time the EXIT trap
    # runs, so under `set -u` the trap dies with `tmp: unbound variable` and the
    # temp tree LEAKS on every green self-test — enough, over time, to fill a
    # root filesystem with abandoned fixture repos.
    SELF_TEST_TMP="$(mktemp -d)" || die "mktemp failed"
    trap 'rm -rf -- "${SELF_TEST_TMP:-}"' EXIT
    dest="$SELF_TEST_TMP/tally"

    # Both expectations below are DERIVED from the fixture, not re-typed here.
    # How many tests are RED before the fix: the count of tests whose doc
    # comment says so in `repo/tests/test_tail.sh`. How many files the candidate diff
    # may touch: whatever `known-fix.patch` itself says it touches. Re-spelling
    # either would mean this self-test keeps asserting yesterday's fixture.
    local expect_red expect_paths
    expect_red="$(grep -cE '^[[:space:]]*# RED on the unfixed tree' "$src_dir/tests/test_tail.sh")"
    [ "$expect_red" -gt 0 ] || die "--self-test: repo/tests/test_tail.sh marks NO test as RED before the fix; \
the fixture would be an oracle that proves nothing"
    expect_paths="$(git -C "$root" apply --numstat "$patch_file" 2>/dev/null | cut -f3 | sort)"
    [ -n "$expect_paths" ] || die "--self-test: known-fix.patch names no files"

    echo "== 1/4 materialize"
    materialize "$dest" >/dev/null || exit 1

    echo "== 2/4 UNFIXED tree must FAIL"
    out="$(cd "$dest" && sh tests/check.sh 2>/dev/null)"; rc=$?
    echo "  verdict: $out"
    # rc 2 is "the suite could not be RUN", which check.sh keeps distinct from
    # rc 1 "a test failed" on purpose (see its header). Naming it here is what
    # REPLACES the deleted `command -v cargo` precondition: a host that cannot
    # run the suite is diagnosed by the suite itself, for the tool the fixture
    # actually uses, instead of being guessed at by the caller.
    [ "$rc" -ne 2 ] || die "--self-test: check.sh could not RUN the suite (rc 2, verdict \"error\"): \
$out -- that is a host problem (no sh on PATH?), not a fixture defect"
    [ "$rc" -eq 1 ] || die "--self-test: unfixed suite exited $rc, expected 1"
    case "$out" in
        *'"verdict":"fail"'*) : ;;
        *) die "--self-test: unfixed verdict was not \"fail\": $out" ;;
    esac
    case "$out" in
        *"\"tests_failed\":$expect_red"*) : ;;
        *) die "--self-test: expected exactly $expect_red failing tests on the unfixed tree \
(that is how many repo/tests/test_tail.sh marks RED): $out" ;;
    esac

    echo "== 3/4 apply the known fix; tree must PASS"
    git -C "$dest" apply "$patch_file" || die "--self-test: known-fix.patch failed to apply"
    out="$(cd "$dest" && sh tests/check.sh 2>/dev/null)"; rc=$?
    echo "  verdict: $out"
    [ "$rc" -eq 0 ] || die "--self-test: fixed suite exited $rc, expected 0"
    case "$out" in
        *'"verdict":"pass"'*) : ;;
        *) die "--self-test: fixed verdict was not \"pass\": $out" ;;
    esac

    echo "== 4/4 the candidate diff is exactly the files known-fix.patch names"
    local dirty changed
    dirty="$(git -C "$dest" status --porcelain)"
    changed="$(printf '%s\n' "$dirty" | awk 'NF { print $2 }' | sort)"
    echo "  git status --porcelain: $(printf '%s' "$dirty" | tr '\n' '|')"
    echo "  known-fix.patch touches: $(printf '%s' "$expect_paths" | tr '\n' '|')"
    [ "$changed" = "$expect_paths" ] || die "--self-test: the working tree after the known fix is \
'$(printf '%s' "$changed" | tr '\n' ' ')' but the patch touches '$(printf '%s' "$expect_paths" | tr '\n' ' ')' — \
a build artifact is escaping .gitignore and would land in the candidate diff"

    echo "SELF-TEST OK — the fixture is RED before the known fix and GREEN after it."
}

# --------------------------------------------------------------------------
# 6. --verify-landed: the oracle for a RUN, where --self-test is the oracle for
#    the FIXTURE.
# --------------------------------------------------------------------------
#
# WHY THIS EXISTS. A run of the agentic loop can PRINT A CLEAN TIMELINE while
# landing nothing: every stage `completed`, terminal status `completed`, and the
# `land` stage's envelope reporting `{"commit_sha":"<sha>","operation":"promote",
# "ref_name":"main"}` — while the fixture repo's `refs/heads/main` never moved off
# the trunk base, the diff of the promoted commit against that base is EMPTY, and
# the candidate worktree is then torn down, destroying the agent's real work. A
# recipe that only PRINTS at the end (`--- candidate diff ---` with nothing between
# the markers) and never ASSERTS sees none of it. A printed empty diff after a
# promote is not a pass.
#
# The fixture is a KNOWN-ANSWER test — RED before `known-fix.patch`, GREEN after,
# and that patch names exactly which file a fix must touch — so a successful run
# has a knowable shape, and this mode is that shape written down. Every check
# below is one that failure TRIPS; each names which symptom it catches, and a
# check nobody can point a failure at does not belong here.
#
# OUTCOME, NOT EDIT. Nothing here asserts the agent's exact diff: a model may
# legitimately fix `tail` with a clamp, a guard, a rewrite, or by adding tests
# beside it. What is asserted is what any real fix MUST produce — the trunk ref
# moved, the landed tree differs from base, the file the defect lives in is among
# what changed, and the fixture's own suite goes GREEN on the landed tree. That
# suite is the same $0 oracle `--self-test` uses; no model budget is spent here.
#
# ALL CHECKS ARE EVALUATED, then reported together. Stopping at the first tells
# an operator one true thing about a run that may be wrong in four ways.
verify_landed() {
    local repo="$1" base_sha="$2" claim_ref="$3" claim_sha="$4"
    local problems=() landed_sha expect_paths changed overlap work out rc

    [ -n "$claim_ref" ] || die "--verify-landed: the land stage reported no ref_name"
    [ -n "$claim_sha" ] || die "--verify-landed: the land stage reported no commit_sha"
    git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 \
        || die "--verify-landed: $repo is not a git repository"
    git -C "$repo" rev-parse --verify "${base_sha}^{commit}" >/dev/null 2>&1 \
        || die "--verify-landed: base $base_sha does not resolve in $repo — the trunk this run \
started from is not in the repository it is being checked against"
    # `git archive | tar -x` is how the landed tree is read WITHOUT touching the
    # fixture's working tree or its index. Checked here rather than at entry
    # because materializing needs no tar.
    command -v tar >/dev/null 2>&1 \
        || die "--verify-landed: 'tar' is not on PATH; the landed tree is read with 'git archive | tar -x'"

    expect_paths="$(git -C "$root" apply --numstat "$patch_file" 2>/dev/null | cut -f3 | sort -u)"
    [ -n "$expect_paths" ] || die "--verify-landed: known-fix.patch names no files"

    echo "== verify-landed"
    echo "   repo   $repo"
    echo "   base   $base_sha"
    echo "   claim  ref=$claim_ref commit_sha=$claim_sha"

    # (0) THE NAMED REF RESOLVES AT ALL. Not one of the four assertions: if the
    #     ref the envelope NAMED does not exist in the repository, everything
    #     that reads it can only report noise, so this is a hard stop that quotes
    #     the raw value back.
    landed_sha="$(git -C "$repo" rev-parse --verify "${claim_ref}^{commit}" 2>/dev/null || true)"
    if [ -z "$landed_sha" ]; then
        echo "materialize-gold-fixture.sh: FAIL - the landed state is wrong:" >&2
        echo "  the land stage reported ref_name '$claim_ref', which resolves to NOTHING in $repo" >&2
        echo "  — the envelope named a ref the repository does not have" >&2
        return 1
    fi
    echo "   actual ref '$claim_ref' -> $landed_sha"

    # (1) THE BASE REF ACTUALLY ADVANCED.
    #     CATCHES that failure head on: `refs/heads/main` still holds the
    #     trunk base after a `promote` that reported success.
    if [ "$landed_sha" = "$base_sha" ]; then
        problems+=("the base ref '$claim_ref' still points at the trunk base $base_sha — NOTHING \
was promoted, however the land stage described itself")
    fi

    # (2) THE ENVELOPE'S CLAIM IS THE REPOSITORY'S STATE.
    #     CATCHES the exact lie: `commit_sha` names one commit while the ref
    #     resolves to the base. This is the property the whole failure IS — a
    #     stage envelope believed over the disk.
    if [ "$landed_sha" != "$claim_sha" ]; then
        problems+=("the land stage claimed commit_sha $claim_sha but '$claim_ref' resolves to \
$landed_sha — the envelope's CLAIM does not match the repository's STATE")
    fi

    # (3) THE LANDED TREE DIFFERS FROM BASE, AND TOUCHES WHAT A FIX MUST TOUCH.
    #     CATCHES the empty promoted diff. The intersection with the paths
    #     `known-fix.patch` names is what keeps this from being satisfiable by a
    #     run that changed only, say, a README: the defect lives in those files,
    #     so a real fix touches at least one of them. EXTRA paths are fine on
    #     purpose — an agent that also adds a test beside its fix is not wrong,
    #     and this is where "assert the outcome, not the edit" is spent.
    changed="$(git -C "$repo" diff --name-only "$base_sha" "$landed_sha" 2>/dev/null | sort -u)"
    echo "   changed paths: $(printf '%s' "$changed" | tr '\n' '|')"
    echo "   known-fix.patch touches: $(printf '%s' "$expect_paths" | tr '\n' '|')"
    if [ -z "$changed" ]; then
        problems+=("the landed commit $landed_sha has an EMPTY diff against the base $base_sha — \
a promote that changed nothing is not a landed fix")
    else
        overlap="$(comm -12 <(printf '%s\n' "$changed") <(printf '%s\n' "$expect_paths"))"
        [ -n "$overlap" ] || problems+=("the landed diff touches NONE of the files \
known-fix.patch names ($(printf '%s' "$expect_paths" | tr '\n' ' ')); it touched \
$(printf '%s' "$changed" | tr '\n' ' ') — the defect lives in the former")
    fi

    # (4) THE FIXTURE'S OWN SUITE PASSES ON THE LANDED TREE.
    #     The outcome oracle, and the one that does not care HOW it was fixed.
    #     CATCHES that failure twice over: the base tree is RED by construction, so
    #     a ref that never moved AND a promoted commit with an empty diff both
    #     arrive here as verdict "fail".
    #
    #     READ FROM THE COMMIT, NOT THE CHECKOUT. The fixture's working tree is
    #     still whatever was checked out when the run started; moving a ref does
    #     not update it, so running the suite in `$repo` would test the wrong
    #     bytes and report green or red for reasons unrelated to what landed.
    work="$(mktemp -d)" || die "--verify-landed: mktemp failed"
    if ! git -C "$repo" archive --format=tar "$landed_sha" | tar -x -C "$work"; then
        problems+=("could not extract the landed tree $landed_sha for the suite run")
    else
        out="$(cd "$work" && sh tests/check.sh 2>/dev/null)"; rc=$?
        echo "   suite on the landed tree: rc=$rc $out"
        case "$rc" in
            0) : ;;
            1) problems+=("the fixture suite FAILS on the landed tree ($out) — whatever landed \
does not fix the defect the fixture plants") ;;
            *) problems+=("the fixture suite could not RUN on the landed tree (rc $rc, $out) — \
either the landed tree has no tests/check.sh or sh is broken on this host") ;;
        esac
    fi
    rm -rf -- "$work"

    if [ "${#problems[@]}" -gt 0 ]; then
        echo "materialize-gold-fixture.sh: FAIL - the landed state is wrong:" >&2
        printf '  %s\n' "${problems[@]}" >&2
        return 1
    fi
    echo "VERIFY-LANDED OK - '$claim_ref' advanced $base_sha -> $landed_sha, the diff touches \
$(printf '%s' "$overlap" | tr '\n' ' '), and the fixture suite is GREEN on that tree."
    return 0
}

# --------------------------------------------------------------------------
main() {
    case "${1:-}" in
        --self-test) [ "$#" -eq 1 ] || die "--self-test takes no other arguments"; self_test ;;
        --verify-landed)
            [ "$#" -eq 5 ] || die "--verify-landed takes <repo> <base-sha> <claimed-ref> <claimed-sha>"
            verify_landed "$2" "$3" "$4" "$5" ;;
        ""|-h|--help)
            echo "usage: $0 <dest>"
            echo "       $0 --self-test"
            echo "       $0 --verify-landed <repo> <base-sha> <claimed-ref> <claimed-sha>"
            exit 2 ;;
        -*) die "unknown option: $1" ;;
        *)
            [ "$#" -eq 1 ] || die "expected exactly one destination path"
            local dest
            dest="$(materialize "$1")" || exit 1
            echo "$dest"
            note "materialized. Run its suite with:  (cd $dest \&\& sh tests/check.sh)"
            ;;
    esac
}

main "$@"
