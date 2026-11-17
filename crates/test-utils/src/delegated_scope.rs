//! `delegated_scope` — ONE argv for re-executing a live test inside a delegated
//! systemd user scope, with a kernel-enforced lifetime.
//!
//! # Why the argv is shared, and why it carries `RuntimeMaxSec`
//!
//! Eight live binaries re-exec themselves under `systemd-run --user --scope -p
//! Delegate=yes`, because only a delegated scope lets an unprivileged process write a
//! cgroup limit. The residue that shape leaves, as measured:
//! when nextest kills a test — its `live-smoke` profile SIGKILLs at 300 s — or a
//! whole process group is `SIGKILL`ed, the test process dies and whatever it started
//! does NOT. A `youki run` reparented to init, its container, and busy threads a rig
//! pinned to one CPU were all observed surviving their test; the test never runs its
//! own cleanup and never reaches the boot sweep kata's worker performs.
//!
//! Two candidate guards, and the one chosen is the one that cannot miss:
//!
//! * a sweep of `kata.provider.*.<dead pid>` subtrees BEFORE each delegated run
//!   knows kata's naming and nothing else — it misses a plain `youki run` with no
//!   kata cgroup at all (the observed orphan had none), and it does nothing for the
//!   LAST run on the host, whose residue waits for a next run that may never come;
//! * `RuntimeMaxSec` on the scope is the kernel's own membership: when it expires
//!   systemd stops the unit and kills EVERY process in its cgroup — a `setsid`
//!   descendant reparented to init included (measured with systemd 255: a
//!   detached `sleep 30` in a scope with `RuntimeMaxSec=3` was gone at 5 s) —
//!   whether or not any test process is still alive to ask.
//!
//! The limit is [`SCOPE_RUNTIME_MAX_SECS`], ABOVE the `live-smoke` profile's 300 s
//! kill, so it never ends a test nextest would still have allowed: it bounds how long
//! residue can outlive a test nextest already killed.

/// The scope's lifetime ceiling, in seconds: `live-smoke`'s 300 s kill plus margin.
pub const SCOPE_RUNTIME_MAX_SECS: u32 = 330;

/// The `systemd-run` arguments that precede the re-exec'd command.
#[must_use]
pub fn systemd_run_args() -> Vec<String> {
    vec![
        "--user".to_owned(),
        "--scope".to_owned(),
        "--quiet".to_owned(),
        "-p".to_owned(),
        "Delegate=yes".to_owned(),
        "-p".to_owned(),
        format!("RuntimeMaxSec={SCOPE_RUNTIME_MAX_SECS}"),
        "--".to_owned(),
    ]
}

/// Refuse a delegated inner run that did not run, and pass, exactly the ONE test it
/// named.
///
/// Every caller re-execs its own binary with `--exact <test>`, the name spelled as a
/// string literal beside the function it names. libtest answers a name that matches
/// nothing with `running 0 tests` and exit 0, so a status check alone passes a renamed
/// or moved test without running its body — and nextest's zero-test refusal cannot
/// fire, because the OUTER selection ran one test. Refused: a non-zero exit, and an
/// inner stdout without libtest's `running 1 test` line and a `test result: ok. 1
/// passed; 0 failed;` summary.
///
/// # Panics
///
/// On either refusal, naming `test`; the caller has already printed the captured output.
pub fn assert_inner_ran_the_one_test(test: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "the delegated inner run of `{test}` FAILED (exit {:?}); its captured output is above",
        output.status.code(),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ran_one = stdout.lines().any(|line| line == "running 1 test");
    let passed_one = stdout
        .lines()
        .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed;"));
    assert!(
        ran_one && passed_one,
        "the delegated inner run of `{test}` did not run exactly that one test: `--exact \
         {test}` matched no test of this binary, so its body never ran. The literal passed to \
         the delegated helper must be the enclosing test function's name; its captured output \
         is above",
    );
}

#[cfg(test)]
mod tests {
    use super::assert_inner_ran_the_one_test;

    /// The test this module's cells re-exec by name: one real libtest test that passes.
    #[test]
    fn a_trivial_test_the_cells_rerun_by_name() {}

    /// libtest itself, run on this very binary, is the oracle: `--exact` with a name
    /// that matches nothing exits 0 having run nothing, and the assertion refuses it; the
    /// same binary asked for a test that exists passes it.
    #[test]
    fn a_zero_test_inner_run_is_refused_and_a_one_test_run_is_admitted() {
        let exe = std::env::current_exe().expect("this test binary's path");
        let rerun = |name: &str| {
            std::process::Command::new(&exe)
                .args(["--exact", name, "--test-threads", "1"])
                .output()
                .expect("the test binary re-runs")
        };
        let renamed = rerun("delegated_scope::tests::no_test_has_this_name");
        assert!(
            renamed.status.success(),
            "libtest exits 0 on a name that matches nothing"
        );
        let refused = std::panic::catch_unwind(|| {
            assert_inner_ran_the_one_test("no_test_has_this_name", &renamed);
        });
        assert!(refused.is_err(), "a run of zero tests is refused");

        let real = rerun("delegated_scope::tests::a_trivial_test_the_cells_rerun_by_name");
        assert_inner_ran_the_one_test("a_trivial_test_the_cells_rerun_by_name", &real);
    }
}
