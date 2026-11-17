//! `capability` — ONE spelling of "this host cannot do the thing this test
//! measures", for every crate whose tests can decline to assert.
//!
//! ## TWO CATEGORIES, and only ONE of them is refused
//!
//! A live test declines to assert for one of two reasons, and they are not the
//! same reason:
//!
//! | | the absent thing | door | under [`REQUIRE_LIVE_ENV`] |
//! |---|---|---|---|
//! | **HOST CAPABILITY** | something about the machine: a kernel feature, a namespace, a mount layout, a tool the probe must exec, a non-vacuity control that could not be established, an artifact the lane's own recipe builds, or a GIT-TRACKED source fixture (whose absence is a broken checkout and not a missing gift) | [`capability_skip`] | **FAILURE** |
//! | **OPERATOR FIXTURE** | something the RUN was not GIVEN, that no required lane supplies and none may — an unpacked distro root, a third-party binary | [`operator_fixture_dir`] | skip |
//!
//! **The refused set, stated so it can be checked against the mechanism.**
//! [`REQUIRE_LIVE_ENV`] refuses a skip whose cause the containment lane already
//! asserts about the host it is running on, and it refuses NOTHING ELSE. A host
//! with a functioning userns, an enforcing Landlock, a delegable cgroup and no
//! `ubuntu:24.04` tarball on disk has not failed to prove containment — it was
//! not handed a fixture. AGENTS.md's *"inside containment a capability SKIP is a
//! FAILURE"* is a sentence about CAPABILITIES; routing a FIXTURE through the
//! knob written for one is a category error with a measurable cost: a host that
//! passes every containment proof in the selection would still fail
//! `just gate-containment`, making a REQUIRED pre-push gate un-greenable on
//! every host in the world, because a test asked the capability knob about a
//! tarball.
//!
//! **The distinction is structural, not a comment.** A `fixture_skip(test, why)`
//! sitting beside [`capability_skip`] would be two doors of identical shape, and
//! a call site walking through the wrong one is the entire defect. So the fixture
//! door is not shaped like the capability door at all: [`operator_fixture_dir`]
//! takes the NAME OF AN ENVIRONMENT VARIABLE plus the operator command that
//! supplies it, and hands back a DIRECTORY. *"This kernel does not enforce
//! Landlock"* has no such variable, no such command and no such directory, so a
//! caller holding it has nothing to WRITE in the two arguments the permissive
//! door demands.
//!
//! That friction is SHAPE, not the type system, and the difference matters
//! because a claim wider than its mechanism is this codebase's costliest
//! recurring defect. Nothing here refuses a slip at compile time:
//! [`operator_fixture_dir`] takes three plain `&str`, so any three string
//! literals typecheck into it, and its `#[must_use]` is defeated by `let _ =`
//! — which this module's own `cell_fixture_claimed_but_absent` does on purpose.
//! What the shape buys is that walking through the wrong door requires
//! INVENTING a variable name and a supply command that do not exist, which is a
//! deliberate act and reviewable as one, rather than the one-word substitution
//! `fixture_skip(test, why)` beside `capability_skip(test, why)` would have
//! been.
//!
//! ## Why this is not four private helpers
//!
//! A capability skip is reported by the harness as a **pass**: a probe that
//! fails for an unrelated reason (say, a `/usr`-only bind on a merged-`/usr`
//! host) silently skips every live test it gates, and the suite certifies by
//! not running.
//!
//! [`REQUIRE_LIVE_ENV`] is the knob that turns such a skip into a FAILURE, and
//! `just gate-containment` is the only lane that sets it. A test that early-
//! returns on a host probe *without* consulting the knob therefore cannot be
//! made to fail anywhere: `just gate` reads its skip as a pass, and the
//! containment lane — which would refuse the skip — is not selecting it.
//!
//! Private probes with private `eprintln!(...); return;` skips, spread across
//! crates, make a fix to one no fix to the others.
//! `bin/kata-eval/tests/gate_exclusion.rs` fails
//! the gate for any test binary that can decline to assert and is not selected
//! by a containment-lane recipe, which is what keeps that from recurring — but
//! the guard can only recognise a skip that is spelled a way it knows, and this
//! module is that spelling.

/// Env knob that turns a capability SKIP into a hard FAILURE.
///
/// Set by every recipe on the `just gate-containment` lane, and by nothing on
/// the `just gate` lane — the gate is host-independent by construction, so a
/// host-capability shortfall there must remain a skip.
pub const REQUIRE_LIVE_ENV: &str = "KATA_SANDBOX_REQUIRE_LIVE";

/// Whether the operator demanded that capability-gated tests must not skip.
#[must_use]
pub fn require_live() -> bool {
    std::env::var(REQUIRE_LIVE_ENV).is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

/// Record that `test` is declining to assert because THIS HOST cannot supply
/// `why`, and PANIC instead when [`REQUIRE_LIVE_ENV`] is set.
///
/// # What belongs here, and what belongs at [`operator_fixture_dir`]
///
/// `why` must be a fact about the MACHINE — the kernel, its namespaces, its
/// mount layout, a tool the probe execs, a non-vacuity control that would not
/// establish, an artifact `just oci-live-smoke` builds for itself, or a
/// GIT-TRACKED source fixture, which no recipe builds and no operator supplies:
/// it is in the checkout, so its absence is a broken checkout and the lane must
/// refuse it. Those
/// are the things the containment lane asserts this host has, so their absence
/// under [`REQUIRE_LIVE_ENV`] means the host is not as capable as claimed and
/// the lane must not certify it. That is the whole refused set; see the module
/// header's table for what falls OUTSIDE it and why.
///
/// Call it immediately before the `return`, never instead of one — this
/// function has no way to stop the caller, deliberately, because a skip helper
/// that could `return` for you would also hide the control flow that makes a
/// skip readable at the call site:
///
/// ```no_run
/// # fn kernel_enforces_landlock() -> bool { true }
/// if !kernel_enforces_landlock() {
///     kata_test_utils::capability_skip("my_live_test", "this kernel does not enforce Landlock");
///     return;
/// }
/// ```
///
/// The printed line uses the `SKIP[<test>]:` shape the rest of the workspace
/// prints, which is also the marker `bin/kata-eval/tests/gate_exclusion.rs` scans
/// for when it decides whether a test binary must ride the containment lane.
///
/// # Panics
/// When [`REQUIRE_LIVE_ENV`] is set — that is the entire point of the knob.
pub fn capability_skip(test: &str, why: &str) {
    let msg = format!("SKIP[{test}]: {why}");
    assert!(
        !require_live(),
        "{msg}\n{REQUIRE_LIVE_ENV} is set, so a capability SKIP is a FAILURE here: either \
         this host is not as capable as believed, or the probe is less capable than the \
         thing it gates."
    );
    eprintln!("{msg}");
}

/// Resolve an OPERATOR FIXTURE named by the environment variable `env`, or
/// record that this run was not given one — a skip [`REQUIRE_LIVE_ENV`]
/// deliberately does NOT refuse.
///
/// `supply` is the command an operator runs to produce the fixture, and it is
/// MANDATORY rather than optional prose: an absence with no such command is a
/// property of the machine, which makes it a [`capability_skip`]. A caller who
/// cannot write the command is holding the other category.
///
/// # Unset is a skip; SET is a CLAIM, and a false claim is a FAILURE
///
/// * `env` unset ⇒ `None`, a printed `SKIP[<test>]:` line, and no panic — with
///   or without [`REQUIRE_LIVE_ENV`]. The caller must `return` without
///   asserting, exactly as with [`capability_skip`], and for the same reason:
///   this function deliberately cannot `return` for you.
/// * `env` set to something that is not a directory ⇒ PANIC, knob or no knob.
///   Setting the variable is the operator declaring the fixture supplied, and a
///   run that quietly skipped a proof the operator believed they had armed is
///   the silent-skip defect this module exists to prevent, wearing the other
///   hat. Being TOLD is the only useful outcome.
/// * `env` set to a directory ⇒ `Some(dir)`, and the proof runs.
///
/// The `SKIP[<test>]:` shape is the marker `bin/kata-eval/tests/gate_exclusion.rs`
/// scans for, so a binary whose only early return is a fixture absence is still
/// visible to the containment-coverage guard and must still be claimed by a
/// lane. Being permitted to skip is not being permitted to hide.
///
/// # Panics
/// When `env` is set to a path that is not a directory, as above.
#[must_use]
pub fn operator_fixture_dir(test: &str, env: &str, supply: &str) -> Option<std::path::PathBuf> {
    let Some(raw) = std::env::var_os(env) else {
        eprintln!(
            "SKIP[{test}]: {env} is not set, so this run was not given the fixture this proof \
             needs. That is an OPERATOR FIXTURE and not a host CAPABILITY, so {REQUIRE_LIVE_ENV} \
             does not refuse it: a host with full containment capability and no fixture on disk \
             has not failed to prove containment. Supply it with:\n  {supply}"
        );
        return None;
    };
    let dir = std::path::PathBuf::from(&raw);
    // QUOTED, deliberately: `Display` on a path drops the quotes, and the two
    // values most likely to be behind this refusal — the empty string and a
    // value with a stray leading space — are invisible without them. `raw` is
    // rendered to a `String` first so that stays true under
    // `clippy::unnecessary_debug_formatting`, which would otherwise push this
    // to `raw.display()` and take the quotes with it.
    let named = raw.to_string_lossy().into_owned();
    assert!(
        dir.is_dir(),
        "[{test}] {env}={named:?} does not name a directory. Setting {env} is a CLAIM that the \
         fixture was supplied, and a false claim is a FAILURE whether or not {REQUIRE_LIVE_ENV} \
         is set — a run that skipped a proof its operator believed armed is the silent skip this \
         module exists to prevent. Unset {env} to decline this proof, or supply it with:\n  \
         {supply}"
    );
    // THE POSITIVE ANNOUNCEMENT, the half the skip line implies.
    //
    // `SKIP[..]` makes a DECLINED proof visible; this makes a RUN one visible, so
    // a reader of a required-gate log can tell a fixture proof that executed from
    // one that returned in 10 ms. `just smoke-no-budget` COUNTS these lines and refuses a run where
    // the fixture was supplied and no door opened. Derived from the output rather than from a
    // roster, so a fixture door added tomorrow is counted with no edit anywhere.
    eprintln!("FIXTURE[{test}]: {env}={} — this proof RUNS", dir.display());
    Some(dir)
}

#[cfg(test)]
mod tests {
    use super::{REQUIRE_LIVE_ENV, capability_skip, operator_fixture_dir};

    /// The variable the child cells below read. Deliberately NOT a name any
    /// recipe or product path knows: this is the fixture door's subject under
    /// test, not a real fixture.
    const CELL_FIXTURE_ENV: &str = "KATA_TEST_UTILS_CELL_FIXTURE";

    /// The supply command the fixture door demands. Never executed here — its
    /// job in this file is to be the mandatory argument that a caller holding a
    /// CAPABILITY absence could not have written.
    const CELL_SUPPLY: &str = "mkdir -p /var/tmp/kata-cell-fixture && export \
                               KATA_TEST_UTILS_CELL_FIXTURE=/var/tmp/kata-cell-fixture";

    // ── CHILD CELLS ───────────────────────────────────────────────────────────
    //
    // Each is one call into one door, re-exec'd by a parent below in a process
    // whose environment the parent controls. `#[ignore]` because a cell is a
    // FIXTURE FOR ITS PARENT and asserts nothing on its own: two of the four
    // are supposed to panic, and under `just test` that would be a red.
    //
    // Out-of-process is not ceremony. The property under test is "what does
    // this door do when KATA_SANDBOX_REQUIRE_LIVE is set", the knob is process
    // environment, and `std::env::set_var` is `unsafe` (this workspace denies
    // `unsafe_code`) and unsound beside every other test in a shared process.
    // The parents therefore read the outcome the way the LANE reads it — a
    // process exit status and a stream — rather than by asking this module.

    /// A genuine HOST CAPABILITY absence.
    #[test]
    #[ignore = "child cell: its parent re-execs it with a controlled environment"]
    fn cell_capability_absence() {
        capability_skip(
            "cell_capability_absence",
            "this kernel does not enforce Landlock",
        );
    }

    /// An OPERATOR FIXTURE this run was not given.
    #[test]
    #[ignore = "child cell: its parent re-execs it with a controlled environment"]
    fn cell_fixture_absence() {
        let got = operator_fixture_dir("cell_fixture_absence", CELL_FIXTURE_ENV, CELL_SUPPLY);
        assert!(
            got.is_none(),
            "an unset fixture variable must resolve to nothing; got {got:?}"
        );
    }

    /// The fixture-PRESENT path: the door hands the directory back.
    #[test]
    #[ignore = "child cell: its parent re-execs it with a controlled environment"]
    fn cell_fixture_present() {
        let dir = operator_fixture_dir("cell_fixture_present", CELL_FIXTURE_ENV, CELL_SUPPLY)
            .expect("the fixture was supplied, so the door must hand it back");
        assert!(
            dir.is_dir(),
            "{dir:?} must be the directory that was supplied"
        );
        println!("CELL-RESOLVED {}", dir.display());
    }

    /// The variable is SET and names nothing — a claim that is false.
    #[test]
    #[ignore = "child cell: its parent re-execs it with a controlled environment"]
    fn cell_fixture_claimed_but_absent() {
        let _ = operator_fixture_dir(
            "cell_fixture_claimed_but_absent",
            CELL_FIXTURE_ENV,
            CELL_SUPPLY,
        );
    }

    // ── THE HARNESS ───────────────────────────────────────────────────────────

    /// Run one child cell with an environment this process dictates.
    ///
    /// Both knobs are REMOVED before `envs` is applied, so a parent invoked
    /// under a lane that already exports `KATA_SANDBOX_REQUIRE_LIVE` cannot
    /// leak it into an arm whose whole content is that the knob is absent.
    fn run_cell(cell: &str, envs: &[(&str, &str)]) -> std::process::Output {
        let exe = std::env::current_exe().expect("the unit-test binary has a path");
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "--exact",
            &format!("capability::tests::{cell}"),
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ]);
        cmd.env_remove(REQUIRE_LIVE_ENV);
        cmd.env_remove(CELL_FIXTURE_ENV);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.output().expect("spawn the child cell")
    }

    /// NON-VACUITY, applied to every arm below: the child really ran the ONE
    /// cell it was asked for.
    ///
    /// Without this a mistyped filter selects zero tests, libtest prints
    /// `0 passed` and exits 0, and every "this arm skipped cleanly" assertion
    /// is satisfied by a process that measured nothing. That is exit-4 class,
    /// the same failure `just verify`'s house rule names for a bare nextest
    /// filter, reached through a different door.
    fn assert_ran_exactly_one(cell: &str, out: &std::process::Output) -> String {
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            stdout.contains("running 1 test"),
            "the child must have RUN {cell}, not filtered it away — a child that ran zero \
             tests satisfies every absence claim below.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        format!("{stdout}\n{stderr}")
    }

    /// **ARM 1 — a HOST CAPABILITY absence is still a FAILURE under the knob,
    /// and this is the property AGENTS.md protects.**
    ///
    /// If this stops holding, a required lane has been weakened and the fixture
    /// work above bought that weakening. Its NON-VACUITY control is the second
    /// half: the SAME cell, same argv, WITHOUT the knob, passes and prints the
    /// marker. Without that control an always-panicking cell would read green.
    #[test]
    fn a_capability_absence_is_refused_under_the_knob_and_permitted_without_it() {
        let refused = run_cell("cell_capability_absence", &[(REQUIRE_LIVE_ENV, "1")]);
        let text = assert_ran_exactly_one("cell_capability_absence", &refused);
        assert!(
            !refused.status.success(),
            "a capability absence under {REQUIRE_LIVE_ENV}=1 must FAIL the process; it exited \
             {status:?}.\n{text}",
            status = refused.status,
        );
        assert!(
            text.contains("a capability SKIP is a FAILURE here"),
            "the refusal must say WHY it refused.\n{text}"
        );

        // CONTROL: the knob is what refused it, not the cell.
        let permitted = run_cell("cell_capability_absence", &[]);
        let text = assert_ran_exactly_one("cell_capability_absence", &permitted);
        assert!(
            permitted.status.success(),
            "without the knob the same capability absence must SKIP, not fail; it exited \
             {status:?}.\n{text}",
            status = permitted.status,
        );
        assert!(
            text.contains("SKIP[cell_capability_absence]"),
            "the permitted arm must still PRINT the marker the coverage guard scans for.\n{text}"
        );
    }

    /// **ARM 2 — a missing OPERATOR FIXTURE skips cleanly under the SAME knob.**
    ///
    /// This is the behaviour change, and arm 1 is its non-vacuity control: the
    /// two arms differ only in which door the cell called, so a knob that had
    /// simply stopped working would red arm 1.
    #[test]
    fn a_missing_fixture_skips_cleanly_under_the_same_knob() {
        let out = run_cell("cell_fixture_absence", &[(REQUIRE_LIVE_ENV, "1")]);
        let text = assert_ran_exactly_one("cell_fixture_absence", &out);
        assert!(
            out.status.success(),
            "a missing FIXTURE under {REQUIRE_LIVE_ENV}=1 must skip cleanly — a host with full \
             containment capability and no fixture on disk did not fail to prove containment. \
             It exited {status:?}.\n{text}",
            status = out.status,
        );
        assert!(
            text.contains("SKIP[cell_fixture_absence]"),
            "a permitted skip must still be VISIBLE: the marker is what \
             bin/kata-eval/tests/gate_exclusion.rs scans for.\n{text}"
        );
        assert!(
            text.contains(CELL_SUPPLY),
            "the skip must name the command that supplies the fixture.\n{text}"
        );
    }

    /// **ARM 3 — the fixture-PRESENT path still runs.**
    ///
    /// Arm 2 is satisfiable by a door that returns `None` for everything, which
    /// would silently disable every proof it gates — the silent-skip shape this
    /// module was written for.
    #[test]
    fn a_supplied_fixture_is_handed_back_and_the_proof_runs() {
        let dir = std::env::temp_dir().join(format!(
            "kata-capability-cell-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).expect("plant the fixture directory");

        let out = run_cell(
            "cell_fixture_present",
            &[
                (REQUIRE_LIVE_ENV, "1"),
                (CELL_FIXTURE_ENV, &dir.to_string_lossy()),
            ],
        );
        let text = assert_ran_exactly_one("cell_fixture_present", &out);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            out.status.success(),
            "a SUPPLIED fixture must resolve and the proof must run; it exited {status:?}.\n{text}",
            status = out.status,
        );
        assert!(
            text.contains(&format!("CELL-RESOLVED {}", dir.display())),
            "the door must hand back the directory it was given, not some other one.\n{text}"
        );
        assert!(
            !text.contains("SKIP[cell_fixture_present]"),
            "a supplied fixture must not also print a skip.\n{text}"
        );
    }

    /// **ARM 4 — a variable that is SET and names nothing FAILS, knob or no
    /// knob**, because setting it is the operator claiming they supplied the
    /// fixture.
    ///
    /// Arm 3 is the non-vacuity control for the `is_dir` branch and this is the
    /// control for arm 2: a door that skipped on every value of the variable
    /// would let a typo disable the proof exactly as silently as the bug this
    /// module exists to prevent.
    #[test]
    fn a_fixture_claimed_but_not_supplied_fails_with_or_without_the_knob() {
        let missing = std::env::temp_dir().join("kata-capability-cell-does-not-exist");
        let _ = std::fs::remove_dir_all(&missing);
        let named = missing.to_string_lossy().into_owned();

        for knob in [vec![(REQUIRE_LIVE_ENV, "1")], Vec::new()] {
            let mut envs = knob.clone();
            envs.push((CELL_FIXTURE_ENV, named.as_str()));
            let out = run_cell("cell_fixture_claimed_but_absent", &envs);
            let text = assert_ran_exactly_one("cell_fixture_claimed_but_absent", &out);
            assert!(
                !out.status.success(),
                "{CELL_FIXTURE_ENV} set to a path that is not a directory must FAIL (knob \
                 present={present}); it exited {status:?}.\n{text}",
                present = !knob.is_empty(),
                status = out.status,
            );
            assert!(
                text.contains("is a CLAIM that the"),
                "the refusal must say that setting the variable was a claim.\n{text}"
            );
        }
    }

    /// The knob's accepted spellings are the ones the justfile writes (`=1`)
    /// plus the usual human synonyms; anything else leaves skipping enabled.
    ///
    /// Asserted THROUGH [`super::require_live`] itself — via a cell whose
    /// outcome is nothing but that predicate's answer — and never against a
    /// second `matches!` written here. A local copy is the MIRROR defect: with
    /// one, mutating the production predicate to `matches!(v.trim(), "1")` would
    /// leave this file green while, in the real containment lane, a genuine
    /// capability absence under `KATA_SANDBOX_REQUIRE_LIVE=true` passed at exit
    /// 0 — the required lane silently weakened, and no test in the tree saying
    /// so.
    #[test]
    fn only_affirmative_spellings_arm_the_knob() {
        for v in ["1", "true", "yes", "on", " 1 "] {
            let out = run_cell("cell_capability_absence", &[(REQUIRE_LIVE_ENV, v)]);
            let text = assert_ran_exactly_one("cell_capability_absence", &out);
            assert!(
                !out.status.success(),
                "{REQUIRE_LIVE_ENV}={v:?} must ARM the knob, so a capability absence under it \
                 must FAIL the process; it exited {status:?}.\n{text}",
                status = out.status,
            );
        }
        for v in ["0", "", "false", "no", "off", "maybe"] {
            let out = run_cell("cell_capability_absence", &[(REQUIRE_LIVE_ENV, v)]);
            let text = assert_ran_exactly_one("cell_capability_absence", &out);
            assert!(
                out.status.success(),
                "{REQUIRE_LIVE_ENV}={v:?} must NOT arm the knob, so the SAME absence must skip \
                 cleanly; it exited {status:?}.\n{text}",
                status = out.status,
            );
        }
    }

    /// A skip that does not print the `SKIP[<test>]:` marker is invisible to
    /// the containment-coverage guard, so the marker is part of the contract.
    ///
    /// Read off what the two doors actually WRITE to a child's stderr, never
    /// off a `format!` rebuilt here: a marker assembled in the test is a
    /// tautology that survives any change to the marker the product prints.
    #[test]
    fn the_printed_marker_is_the_shape_the_guard_scans_for() {
        let capability = run_cell("cell_capability_absence", &[]);
        let text = assert_ran_exactly_one("cell_capability_absence", &capability);
        let stderr = String::from_utf8_lossy(&capability.stderr).into_owned();
        assert!(
            stderr.contains("SKIP[cell_capability_absence]: this kernel does not enforce Landlock"),
            "capability_skip must print `SKIP[<test>]: <why>` — the exact shape \
             bin/kata-eval/tests/gate_exclusion.rs scans for.\n{text}"
        );

        let fixture = run_cell("cell_fixture_absence", &[]);
        let text = assert_ran_exactly_one("cell_fixture_absence", &fixture);
        let stderr = String::from_utf8_lossy(&fixture.stderr).into_owned();
        assert!(
            stderr.contains("SKIP[cell_fixture_absence]: "),
            "the fixture door prints the SAME marker: being permitted to skip is not being \
             permitted to hide.\n{text}"
        );
    }
}
