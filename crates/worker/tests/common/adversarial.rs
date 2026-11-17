//! The ADVERSARIAL ROW VOCABULARY: `ATTACKS`, `Ledger`, the driver and its
//! coverage table, read by `oci_adversarial_live.rs`.
//!
//! There is one column — the OCI route — and the table says, per attack,
//! whether the route RUNS the row (with its observation floors) or why it does
//! not.
//!
//! # The coverage table is the suite's own honesty mechanism
//!
//! Not every row is expressible on the route, and the difference between *"not
//! expressible here"* and *"nobody ran it"* is what a reader of the log must be
//! able to see. [`COVERAGE`] states one cell per (driver, attack) pair;
//! [`declare_not_run_rows`] prints a `NOT-RUN` line for every
//! non-[`DriverCoverage::Runs`] cell, so a log always says which rows it declined
//! and why.
//!
//! Put nothing with a `#[test]` attribute here — this is a plain module under
//! `tests/common/`, compiled into every binary in this directory.

// ---------------------------------------------------------------------------
// The EXECUTION DRIVER dimension
// ---------------------------------------------------------------------------

/// WHO runs the stage.
///
/// One variant: the rootless-OCI route. What a container may read is
/// decided by a capsule's guest mappings and by the `config.json` kata renders
/// from it, so the probes are argv INSIDE a container and the non-vacuity
/// controls are runs on the host (or a second container with the declaration
/// widened).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionDriver {
    /// `kata_worker::oci_driver::OciStageDriver` materializes a capsule, plans a
    /// rootless OCI bundle and hands it to `kata-provider-youki`, which `youki
    /// run`s it in a cgroup kata owns.
    OciRuntime,
}

impl ExecutionDriver {
    /// Every driver, so a table over them cannot omit one by being written by
    /// hand. A new variant is `E0004` in [`Self::label`].
    pub const ALL: &'static [ExecutionDriver] = &[ExecutionDriver::OciRuntime];

    pub const fn label(self) -> &'static str {
        match self {
            ExecutionDriver::OciRuntime => "oci_runtime",
        }
    }

    /// The `via=` tag a verdict this driver's spawn produced carries.
    pub const fn spawn_tag(self) -> &'static str {
        match self {
            ExecutionDriver::OciRuntime => "oci",
        }
    }
}

/// Whether one driver runs one attack row, and when it does not, WHY.
///
/// Three-valued rather than two, because *"this route cannot be asked that
/// question"* and *"this route can be asked and nobody has written the row"* are
/// different facts with different futures: the first is permanent and the second
/// is debt. Both print a `NOT-RUN` line, so neither can hide as silence, and the
/// reason token is what a reader diffs across runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverCoverage {
    /// This driver's binary asserts this row, with these FLOORS.
    ///
    /// The floors are per (driver, attack) and not per attack, because a floor is
    /// a property of the PROBES a rig can express.
    Runs {
        /// Minimum CONTAINED observations (attack demonstrated, then refused).
        min_containment: usize,
        /// Minimum PINNED observations (attack demonstrated and NOT refused — a
        /// containment hole recorded as current truth, awaiting a decision).
        min_pinned: usize,
    },
    /// The row is not expressible on this driver, permanently, for the named
    /// reason. Not debt: no work is owed it.
    NotExpressible(&'static str),
    /// The row IS expressible here and is not written yet. DEBT, named.
    Owed(&'static str),
    /// The row is expressible on this driver, and THIS HOST cannot supply its
    /// non-vacuity CONTROL — so counting it would be counting an attack that
    /// never ran.
    ///
    /// # Why a host fact is pinned in a compile-time table
    ///
    /// It does not belong here on principle and it is here for one reason: the
    /// log's declarations come from this table, and a row silently absent is the
    /// exact hole `NOT-RUN` exists to close. A
    /// runtime probe would be better and would need every rig to agree on what
    /// "demonstrable" means — a second producer of a definition, which is the
    /// defect class this table was built to avoid.
    ///
    /// So the discipline is: the reason token names the HOST fact, not the row,
    /// and a host without that fact must promote the cell back to
    /// [`DriverCoverage::Runs`]. Its one use is A1 on the OCI route:
    /// `kernel.apparmor_restrict_unprivileged_userns=1` on the reference host, so
    /// an unconfined unprivileged process may create a user namespace but may not
    /// write its `uid_map` — MEASURED, `unshare -Ur` gives
    /// `write failed /proc/self/uid_map: Operation not permitted` and a bare
    /// `unshare -U` gives `CapEff: 0000000000000000` with `CapBnd` full. The
    /// capability-REGAIN chain therefore cannot be made to succeed anywhere
    /// outside a namespace something else already mapped, so no control for it
    /// exists to build.
    NotDemonstrable(&'static str),
}

impl DriverCoverage {
    /// The `reason=` token a `NOT-RUN` line carries, or `None` when the row runs.
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            DriverCoverage::Runs { .. } => None,
            DriverCoverage::NotExpressible(reason)
            | DriverCoverage::Owed(reason)
            | DriverCoverage::NotDemonstrable(reason) => Some(reason),
        }
    }
}

/// ONE CELL PER (driver, attack). The manifest test asserts this table is total
/// over `ExecutionDriver::ALL` x [`ATTACKS`] and free of duplicates, so a new
/// driver or a new attack cannot land unclassified.
///
/// # Reading the OCI column
///
/// The nine rows the OCI route owes are `Runs`. The three that are
/// `NotExpressible` are so for reasons that are facts about the route and not
/// about this rig:
///
/// * **A5** dials a host `AF_UNIX` socket reached through a bind of a host
///   directory. A capsule has no host path: `MATERIALIZED_ROOTS` places bytes
///   into `/work`, `/out` and a tmpfs `/tmp`, and `spec_for` refuses a mapping
///   outside them, so there is no authorable capsule under which the attack's
///   own precondition (a host socket visible to the stage) exists. Demanding the
///   row would be demanding a control that cannot be constructed, which
///   [`Ledger::control`] correctly refuses to fake.
/// * **A7b** compares the argv a declared bound is rendered into. The OCI route
///   renders no argv for a bound: a bound becomes `linux.resources` in a
///   `config.json` and a `cgroupsPath` kata created, and A7's own container arm
///   observes the enforcement directly. A "plumbing" row here would compare two
///   renderings of one struct and never leave the process.
/// * **A11** substitutes a toolchain under a kata-chosen host mount.
///   `oci_bundle::spec_for` rbinds the authorized Nix closure at its OWN store
///   paths from a `NixEnvironmentManifest`, so the thing A11 attacks — a
///   kata-chosen mount of a kata-chosen host directory, content-addressed by
///   kata — does not exist on this route.
///
pub const COVERAGE: &[(ExecutionDriver, &str, DriverCoverage)] = &[
    // ── The rootless-OCI route: nine rows run, three not expressible, one not
    // demonstrable on the reference host. ──
    (
        ExecutionDriver::OciRuntime,
        A1_CAP_REGAIN,
        // MEASURED on the reference host:
        // `kernel.apparmor_restrict_unprivileged_userns=1`, so `unshare -Ur` fails
        // with `write failed /proc/self/uid_map: Operation not permitted` and a
        // bare `unshare -U` yields `CapEff: 0` (CapBnd full, uid 65534). The
        // regain chain cannot be made to succeed unconstrained ANYWHERE on this
        // host, so its control cannot be built and `Ledger::control` correctly
        // refuses to fake one. A1' carries the one residue syscall that IS
        // demonstrable here. Promote this back to `Runs` on a host without the
        // restriction.
        DriverCoverage::NotDemonstrable("uid_map_write_is_apparmor_restricted_on_this_host"),
    ),
    (
        ExecutionDriver::OciRuntime,
        A2_FS_ESCAPE,
        // TWO, for A9's reason: a capsule declares guest MAPPINGS, not an fs
        // policy, so the two observations are the two shapes that exist here.
        DriverCoverage::Runs {
            min_containment: 2,
            min_pinned: 0,
        },
    ),
    (
        ExecutionDriver::OciRuntime,
        A3_PROCESS_MEMORY,
        DriverCoverage::Runs {
            min_containment: 1,
            min_pinned: 0,
        },
    ),
    (
        ExecutionDriver::OciRuntime,
        A4_NET_EGRESS,
        DriverCoverage::Runs {
            min_containment: 1,
            min_pinned: 0,
        },
    ),
    (
        ExecutionDriver::OciRuntime,
        A5_AF_UNIX_EGRESS,
        DriverCoverage::NotExpressible("no_host_path_is_bindable_into_a_capsule"),
    ),
    (
        ExecutionDriver::OciRuntime,
        A6_DESCENDANT_TEARDOWN,
        DriverCoverage::Runs {
            min_containment: 1,
            min_pinned: 0,
        },
    ),
    (
        ExecutionDriver::OciRuntime,
        A7_DECLARED_BOUNDS,
        // `min_pinned` is ZERO: this route's bound is a cgroup kata created and
        // wrote, so there is no accepted-then-dropped bound to pin.
        DriverCoverage::Runs {
            min_containment: 1,
            min_pinned: 0,
        },
    ),
    (
        ExecutionDriver::OciRuntime,
        A7B_BOUNDS_PLUMBING,
        DriverCoverage::NotExpressible("bounds_render_into_config_json_not_argv"),
    ),
    (
        ExecutionDriver::OciRuntime,
        A8_NAMESPACE_IDENTITY,
        DriverCoverage::Runs {
            min_containment: 2,
            min_pinned: 0,
        },
    ),
    (
        ExecutionDriver::OciRuntime,
        A9_UNDECLARED_WRITE,
        // TWO: this route has no fs policy — a capsule declares guest
        // MAPPINGS — so the two observations are the two shapes that exist
        // here: a path under no mapping at all, and a host absolute path whose
        // bytes are read back from outside.
        DriverCoverage::Runs {
            min_containment: 2,
            min_pinned: 0,
        },
    ),
    (
        ExecutionDriver::OciRuntime,
        A10_CLEARED_ENV,
        DriverCoverage::Runs {
            min_containment: 1,
            min_pinned: 0,
        },
    ),
    (
        ExecutionDriver::OciRuntime,
        A11_TOOLCHAIN_IDENTITY,
        DriverCoverage::NotExpressible("the_closure_is_rbound_at_its_own_store_paths"),
    ),
    (
        ExecutionDriver::OciRuntime,
        A1P_CONSTRUCTION_RESIDUE,
        // FOUR: the three doors to a user namespace — `unshare`, `clone` and
        // `clone3` with CLONE_NEWUSER — and an i386-ABI `unshare`, each of which
        // succeeds unconfined on this host (measured). Not `mount` and `setns`, and
        // the reason is a MEASUREMENT rather than an omission. A residue syscall can
        // only be COUNTED where its attack can be made to succeed with the relevant
        // containment relaxed: `mount` and `setns`
        // both need capabilities in a namespace whose `uid_map` something already
        // wrote — which `apparmor_restrict_unprivileged_userns=1` refuses an
        // unconfined process. And the fence is not relaxable on this route: there
        // is no `KATA_DISABLE_SECCOMP` for a rendered `config.json` and adding one
        // would weaken production to score a test. So `mount` and `setns` are
        // measured and recorded as NOTES (`Ledger::note`), which is this suite's
        // own convention for an attack it cannot demonstrate. Raise this to 6 on a
        // host that permits a mapped-root userns.
        DriverCoverage::Runs {
            min_containment: 4,
            min_pinned: 0,
        },
    ),
];

/// This driver's cell for `attack`, or a PANIC naming the missing classification.
///
/// A panic rather than a default: a row that silently read as `Runs` would demand
/// verdicts no rig produces, and a row that silently read as not-run would let a
/// driver decline a question nobody decided it could decline.
pub fn coverage_of(driver: ExecutionDriver, attack: &str) -> DriverCoverage {
    let mut found = None;
    for (candidate, id, coverage) in COVERAGE {
        if *candidate == driver && *id == attack {
            assert!(
                found.is_none(),
                "COVERAGE declares ({}, {attack}) twice. A duplicated cell means the table \
                 has two answers and `coverage_of` would return whichever came first.",
                driver.label(),
            );
            found = Some(*coverage);
        }
    }
    found.unwrap_or_else(|| {
        panic!(
            "COVERAGE has no cell for ({}, {attack}). Every (driver, attack) pair must be \
             classified: a missing cell is a row the log is silent on.",
            driver.label(),
        )
    })
}

/// The floors THIS driver's rig must meet on `attack`, or a PANIC.
///
/// A panic on a declined row rather than `(0, 0)`: a rig that reached
/// [`Ledger::finish`] for a row its own table says it does not run has either
/// mis-declared the row or run a probe nobody classified, and a zero floor would
/// turn both into a silent pass.
pub fn floor_for(driver: ExecutionDriver, attack: &str) -> (usize, usize) {
    match coverage_of(driver, attack) {
        DriverCoverage::Runs {
            min_containment,
            min_pinned,
        } => (min_containment, min_pinned),
        declined => panic!(
            "driver `{}` reached the observation FLOOR for `{attack}`, which COVERAGE declares \
             it does not run ({declined:?}). Either the table is wrong or this rig ran a probe \
             nobody classified — and a zero floor here would make both a pass.",
            driver.label(),
        ),
    }
}

/// Print a `NOT-RUN` line for every row THIS driver declines, and return how many.
///
/// ONE producer, called from each binary's manifest test — the roll-up test that
/// already runs in every lane and needs no host capability. A per-attack guard
/// inside twelve `#[ignore]`d bodies would emit a declaration only when the lane
/// selected that body, which is exactly when the declaration is not needed.
///
/// The count is returned so the caller can assert non-vacuity: a table that
/// classified everything as `Runs` would print nothing, and a log with no
/// declarations at all cannot tell a total driver from a silent one.
pub fn declare_not_run_rows() -> usize {
    let mut declared = 0;
    for spec in ATTACKS {
        if let Some(reason) = coverage_of(driver(), spec.id).reason() {
            println!(
                "ADVERSARIAL-KERNEL-SUITE NOT-RUN driver={driver} for-attack={id} \
                 reason={reason}",
                driver = driver().label(),
                id = spec.id,
            );
            declared += 1;
        }
    }
    declared
}

/// The rig selector. **Not a `ContainmentLever` and not reachable from
/// production** — it is read in this test binary and nowhere else. `just
/// oci-live-smoke` sets it; a mismatched value is refused by name.
pub const DRIVER_ENV: &str = "KATA_ADVERSARIAL_EXECUTION_DRIVER";

/// How many container SPAWNS have gone through the driver in this process.
///
/// nextest runs one process per test, so this counts one attack's spawns. The
/// ledger samples it at every verdict, which is what lets an observation say
/// whether it really consumed the driver — see [`Ledger::via`].
pub static DRIVER_SPAWNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Which driver this process is running under. Refuses an unknown value rather
/// than defaulting.
pub fn driver() -> ExecutionDriver {
    *BOUND.get_or_init(|| driver_from_env().unwrap_or(ExecutionDriver::OciRuntime))
}

static BOUND: std::sync::OnceLock<ExecutionDriver> = std::sync::OnceLock::new();

/// The driver [`DRIVER_ENV`] names, or `None` when the knob is unset.
///
/// An unknown value PANICS rather than defaulting: a typo must not silently
/// label verdicts with a driver nobody chose.
fn driver_from_env() -> Option<ExecutionDriver> {
    match std::env::var(DRIVER_ENV).ok().as_deref() {
        None | Some("") => None,
        Some("oci") => Some(ExecutionDriver::OciRuntime),
        Some(other) => panic!(
            "{DRIVER_ENV}={other:?} is not an execution driver. Expected `oci` (the \
             rootless-OCI route), the only one this workspace has."
        ),
    }
}

/// Bind this BINARY's driver, refusing a knob that names a different one.
///
/// A binary's driver is a property of the file, so it binds rather than reads:
/// a lane that sets the knob and a developer who sets nothing get the same
/// answer, and a knob that contradicts the file is a named failure.
pub fn bind_driver(expected: ExecutionDriver) {
    if let Some(from_env) = driver_from_env() {
        assert_eq!(
            from_env,
            expected,
            "{DRIVER_ENV} names `{}` and this binary IS the `{}` column. Honouring the knob \
             would print that driver's label on verdicts produced by this file's probes.",
            from_env.label(),
            expected.label(),
        );
    }
    if let Err(already) = BOUND.set(expected) {
        assert_eq!(
            already,
            expected,
            "the driver was already bound to `{}` in this process",
            already.label(),
        );
    }
}

/// One attack this suite is obliged to run, with the FLOOR of containment /
/// pinning observations it must actually execute.
///
/// The floor is a floor, not an equality: adding coverage to an attack does not
/// require editing this table, but silently gutting one does fail. A test whose
/// `attack` is absent from this table panics in [`Ledger::finish`], so a new
/// attack cannot be added without declaring it here.
pub struct AttackSpec {
    /// Stable id, printed in every observation line.
    pub id: &'static str,
    /// The attacker's question, in one sentence.
    pub question: &'static str,
}

pub const A1_CAP_REGAIN: &str = "A1-capability-regain";
pub const A2_FS_ESCAPE: &str = "A2-undeclared-host-path";
pub const A3_PROCESS_MEMORY: &str = "A3-process-memory-and-pids";
pub const A4_NET_EGRESS: &str = "A4-network-egress";
pub const A5_AF_UNIX_EGRESS: &str = "A5-af-unix-egress";
pub const A6_DESCENDANT_TEARDOWN: &str = "A6-descendant-teardown";
pub const A7_DECLARED_BOUNDS: &str = "A7-declared-resource-bounds";
pub const A7B_BOUNDS_PLUMBING: &str = "A7b-declared-bounds-plumbing";
pub const A8_NAMESPACE_IDENTITY: &str = "A8-namespace-identity";
pub const A9_UNDECLARED_WRITE: &str = "A9-undeclared-host-write";
pub const A10_CLEARED_ENV: &str = "A10-cleared-env";
pub const A11_TOOLCHAIN_IDENTITY: &str = "A11-toolchain-identity";
/// A1's RESIDUE, on the one route that has one.
///
/// `A1` asks whether a stage can regain capabilities and so reach
/// `chroot`/`pivot_root`/`mount`. `kata_types::sandbox_seccomp`'s
/// `ConstructionResidue` class is the set of syscalls a stage would use to
/// CONSTRUCT a new namespace or enter one — `unshare`, `mount`, `setns` and
/// their neighbours — and `OciMeasuredBasis::residue_denied` says only that
/// kata's own OCI deny list NAMES all thirteen of them. That the kernel answers
/// `EPERM` for each INSIDE a running container is a different claim, and this
/// row is where it is made — with the two floor entries that are the same door
/// (`clone`/`clone3` with `CLONE_NEWUSER`) and the i386 ABI as a way round all
/// three.
pub const A1P_CONSTRUCTION_RESIDUE: &str = "A1p-construction-residue";

pub const ATTACKS: &[AttackSpec] = &[
    AttackSpec {
        id: A1_CAP_REGAIN,
        question: "can a stage regain capabilities it was stripped of, and so reach \
                   chroot/pivot_root/mount?",
    },
    AttackSpec {
        id: A2_FS_ESCAPE,
        question: "can a stage read an undeclared host path, or be TOLD one?",
    },
    AttackSpec {
        id: A3_PROCESS_MEMORY,
        question: "can a stage read another process's memory, or address a host pid?",
    },
    AttackSpec {
        id: A4_NET_EGRESS,
        question: "under net = offline, can a stage reach a host-only address or open a \
                   raw socket?",
    },
    AttackSpec {
        id: A5_AF_UNIX_EGRESS,
        question: "under net = offline, can a stage connect to a host AF_UNIX socket it was \
                   never granted?",
    },
    AttackSpec {
        id: A6_DESCENDANT_TEARDOWN,
        question: "can a stage leave a descendant running after its container is torn down?",
    },
    AttackSpec {
        id: A7_DECLARED_BOUNDS,
        question: "can a stage exceed a resource bound its own directive declared?",
    },
    AttackSpec {
        id: A7B_BOUNDS_PLUMBING,
        question: "does a declared bound reach the runtime at all, or is it lost in transit?",
    },
    AttackSpec {
        id: A8_NAMESPACE_IDENTITY,
        question: "can a stage name — and so re-enter — a namespace outside its own?",
    },
    AttackSpec {
        id: A9_UNDECLARED_WRITE,
        question: "can a stage WRITE outside its declared surface — and do the bytes land on \
                   the host?",
    },
    AttackSpec {
        id: A10_CLEARED_ENV,
        question: "does a stage read environment nobody declared — the operator's own \
                   variables, and whatever secret the worker process happens to carry?",
    },
    AttackSpec {
        id: A11_TOOLCHAIN_IDENTITY,
        question: "can the toolchain under a PINNED stage be substituted without the \
                   content-address, or the pin, noticing?",
    },
    AttackSpec {
        id: A1P_CONSTRUCTION_RESIDUE,
        question: "inside a rootless container kata planned, does the kernel refuse the \
                   CONSTRUCTION RESIDUE — unshare, mount, setns, and clone/clone3 with \
                   CLONE_NEWUSER, through the x86_64 or the i386 ABI — or only kata's deny \
                   list?",
    },
];

pub fn spec_for(attack: &str) -> &'static AttackSpec {
    let Some(spec) = ATTACKS.iter().find(|a| a.id == attack) else {
        panic!(
            "attack `{attack}` is not declared in ATTACKS. Every attack must be declared \
             with an observation FLOOR, or the suite's printed count is unauditable."
        )
    };
    spec
}

// ---------------------------------------------------------------------------
// The ledger — what makes the count trustworthy
// ---------------------------------------------------------------------------

/// Records, and ENFORCES, one attack's control/containment discipline.
///
/// The enforcement is structural rather than advisory: `contained()` refuses to
/// count an observation whose probe never demonstrated an unconstrained
/// success. That is the anti-tautology property this whole suite exists to
/// have — a containment assertion with no control is a test that passes when the
/// attack silently never ran.
pub struct Ledger {
    attack: &'static str,
    /// Probe names whose UNCONSTRAINED attack was demonstrated to succeed.
    demonstrated: Vec<&'static str>,
    containment: usize,
    pinned: usize,
    notes: usize,
    finished: bool,
    /// [`DRIVER_SPAWNS`] as of the previous verdict, so each verdict can say
    /// whether it consumed the execution driver.
    spawns_at_last_verdict: usize,
    /// Verdicts a driver spawn demonstrably produced. A LOWER BOUND — see
    /// [`Ledger::via`].
    via_driver: usize,
    /// Verdicts with no new driver spawn since the previous one.
    via_host: usize,
}

impl Ledger {
    pub fn new(attack: &'static str) -> Self {
        let spec = spec_for(attack);
        eprintln!(
            "ADVERSARIAL-KERNEL-SUITE begin attack={} question={}",
            spec.id, spec.question
        );
        Self {
            attack,
            demonstrated: Vec::new(),
            containment: 0,
            pinned: 0,
            notes: 0,
            finished: false,
            spawns_at_last_verdict: DRIVER_SPAWNS.load(std::sync::atomic::Ordering::Relaxed),
            via_driver: 0,
            via_host: 0,
        }
    }

    /// Did a driver spawn happen between the previous verdict and this one?
    ///
    /// Derived rather than declared: a verdict is tagged with the driver's
    /// [`ExecutionDriver::spawn_tag`] when a driver spawn occurred since the
    /// previous verdict, and `host` otherwise — so a log says which verdicts a
    /// container actually produced. [`Self::settle`] keeps a host observation
    /// from inheriting an earlier container's spawn.
    pub fn via(&mut self) -> &'static str {
        let now = DRIVER_SPAWNS.load(std::sync::atomic::Ordering::Relaxed);
        let observed = now > self.spawns_at_last_verdict;
        self.spawns_at_last_verdict = now;
        if observed {
            self.via_driver += 1;
            driver().spawn_tag()
        } else {
            self.via_host += 1;
            "host"
        }
    }

    /// Resample the spawn watermark WITHOUT emitting a verdict, so the next
    /// verdict is not credited with a spawn it did not cause.
    ///
    /// # The over-counting this closes, and it is MEASURED
    ///
    /// [`Self::via`] tags a verdict `oci` when a driver spawn happened since the
    /// PREVIOUS verdict. The OCI rig starts a container for `Rig::require_viable`
    /// and then makes a HOST
    /// observation, and without this the host observation would inherit the
    /// viability container's spawn — `attack=A3 … probe=host_pid_is_addressable
    /// via=oci CONTROL=succeeded`, for a control that ran no container at all
    /// (measured).
    ///
    /// That is an OVER-count, and over-counting is the one direction a
    /// non-vacuity control may not err in: a mislabelled host control reads as a
    /// container observation nobody made.
    ///
    /// The rig calls this from its own host-observation helper, so the only way to
    /// run a host probe is a way that settles first.
    pub fn settle(&mut self) {
        self.spawns_at_last_verdict = DRIVER_SPAWNS.load(std::sync::atomic::Ordering::Relaxed);
    }

    /// NON-VACUITY CONTROL: the attack `probe` SUCCEEDS with the relevant
    /// containment relaxed. Asserts it, and unlocks `contained(probe, …)`.
    pub fn control(&mut self, probe: &'static str, succeeded: bool, evidence: &str) {
        assert!(
            succeeded,
            "[{attack}] NON-VACUITY CONTROL FAILED for probe `{probe}`: the attack did NOT \
             succeed even with the containment relaxed, so proving it fails INSIDE proves \
             nothing. Either the probe is broken or the attack is not expressible on this \
             host — say so rather than counting it. Observed: {evidence}",
            attack = self.attack,
        );
        let via = self.via();
        eprintln!(
            "ADVERSARIAL-KERNEL-SUITE   attack={attack} driver={driver} probe={probe} via={via} \
             CONTROL=succeeded :: {evidence}",
            attack = self.attack,
            driver = driver().label(),
        );
        self.demonstrated.push(probe);
    }

    /// THE CONTAINMENT PROPERTY: the same attack FAILS inside the production
    /// posture. Refuses to count unless `control(probe, …)` ran first.
    pub fn contained(&mut self, probe: &'static str, contained: bool, evidence: &str) {
        assert!(
            self.demonstrated.contains(&probe),
            "[{attack}] probe `{probe}` asserted containment with NO non-vacuity control. \
             Call `control(\"{probe}\", …)` first, proving the attack succeeds unconstrained; \
             otherwise this assertion is satisfied by an attack that never ran.",
            attack = self.attack,
        );
        assert!(
            contained,
            "[{attack}] CONTAINMENT BREACH on probe `{probe}`: the attack SUCCEEDED inside \
             the production posture. Observed: {evidence}",
            attack = self.attack,
        );
        self.containment += 1;
        let via = self.via();
        eprintln!(
            "ADVERSARIAL-KERNEL-SUITE   attack={attack} driver={driver} probe={probe} via={via} \
             CONTAINED :: {evidence}",
            attack = self.attack,
            driver = driver().label(),
        );
    }

    /// A KNOWN-OPEN finding, pinned as CURRENT TRUTH rather than fixed.
    ///
    /// `still_open` is asserted, so the day the hole closes this test FAILS and
    /// names itself as the thing to retire — the opposite polarity from
    /// `contained`, and deliberately so. Pinned observations are counted and
    /// printed SEPARATELY so they can never inflate a containment count.
    pub fn pin(
        &mut self,
        probe: &'static str,
        still_open: bool,
        evidence: &str,
        retire_when: &str,
    ) {
        assert!(
            still_open,
            "[{attack}] the PINNED finding `{probe}` no longer reproduces. That is GOOD NEWS \
             and this failure is how you learn it: {retire_when}. Observed: {evidence}",
            attack = self.attack,
        );
        self.pinned += 1;
        let via = self.via();
        eprintln!(
            "ADVERSARIAL-KERNEL-SUITE   attack={attack} driver={driver} probe={probe} via={via} \
             PINNED-OPEN :: {evidence}",
            attack = self.attack,
            driver = driver().label(),
        );
    }

    /// An observation that is NOT an assertion: something measured and worth
    /// recording, which this suite deliberately does not count as coverage.
    pub fn note(&mut self, text: &str) {
        eprintln!(
            "ADVERSARIAL-KERNEL-SUITE   attack={} NOTE :: {text}",
            self.attack
        );
        self.notes += 1;
    }

    /// Print the count and enforce the declared floor.
    pub fn finish(mut self) {
        self.finished = true;
        let spec = spec_for(self.attack);
        // The driver dimension rides the OBSERVATION lines and the separate
        // rollup below, not this count line.
        println!(
            "ADVERSARIAL-KERNEL-SUITE attack={id} controls={c} containment-assertions={n} \
             pinned-open={p} notes={notes}",
            id = spec.id,
            c = self.demonstrated.len(),
            n = self.containment,
            p = self.pinned,
            notes = self.notes,
        );
        println!(
            "ADVERSARIAL-KERNEL-SUITE DRIVER driver={driver} for-attack={id} \
             driver-observed-verdicts={w} host-observed-verdicts={h} driver-spawns={s}",
            driver = driver().label(),
            id = spec.id,
            w = self.via_driver,
            h = self.via_host,
            s = DRIVER_SPAWNS.load(std::sync::atomic::Ordering::Relaxed),
        );
        // THIS DRIVER's floors, out of COVERAGE. A floor is a property of the
        // probes a rig can express — see `DriverCoverage::Runs`.
        let (min_containment, min_pinned) = floor_for(driver(), self.attack);
        assert!(
            self.containment >= min_containment,
            "[{id}] executed {n} containment assertions under driver `{driver}`, below its \
             declared floor of {floor}. A suite that certifies with fewer assertions than it \
             claims is the tautological verification this column exists to eliminate.",
            id = spec.id,
            driver = driver().label(),
            n = self.containment,
            floor = min_containment,
        );
        assert!(
            self.pinned >= min_pinned,
            "[{id}] executed {p} pinned-open observations under driver `{driver}`, below its \
             declared floor of {floor}.",
            id = spec.id,
            driver = driver().label(),
            p = self.pinned,
            floor = min_pinned,
        );
    }
}

impl Drop for Ledger {
    /// A test that returns early without calling [`Ledger::finish`] would skip
    /// the floor check while still reporting PASS — the same silent-skip shape
    /// this suite exists to eliminate. Panic on it, except while already
    /// unwinding (where a second panic aborts the process and hides the first).
    fn drop(&mut self) {
        assert!(
            self.finished || std::thread::panicking(),
            "[{attack}] the ledger was dropped without `finish()`, so the declared assertion \
             floor was never enforced and the count was never printed.",
            attack = self.attack,
        );
    }
}

// ---------------------------------------------------------------------------
// The manifest, and the coverage table's own totality
// ---------------------------------------------------------------------------

/// WHICH PROBE VOCABULARY a rig speaks, printed into its log: argv inside a
/// capsule, in a container kata owns, with exact `via=` attribution — every host
/// probe goes through `on_host`, which calls [`Ledger::settle`], and every
/// containment verdict is made immediately after the container run it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeVocabulary {
    /// `oci_adversarial_live.rs`: argv inside a capsule, in a container kata owns.
    CapsuleArgv,
}

impl ProbeVocabulary {
    /// The `rig=` token.
    pub const fn token(self) -> &'static str {
        match self {
            ProbeVocabulary::CapsuleArgv => "oci_capsule_argv",
        }
    }

    /// How exact this rig's `via=` attribution is — the `attribution=` token.
    pub const fn attribution(self) -> &'static str {
        match self {
            ProbeVocabulary::CapsuleArgv => "exact",
        }
    }
}

/// Print the suite's declared floor, refuse a manifest that certifies nothing,
/// assert [`COVERAGE`] is TOTAL over `ExecutionDriver::ALL` x [`ATTACKS`], and
/// emit this driver's `NOT-RUN` declarations.
///
/// Called by the manifest test. It is host-independent on purpose: it runs under `just
/// test` and `just test-crate kata-worker` (the containment lane runs only the
/// `#[ignore]`d rows), so a new attack or driver reds a cheap test rather than a
/// 25-minute one.
///
/// # Why the declarations are printed HERE
///
/// A per-attack guard inside an `#[ignore]`d body emits its declaration only
/// when the lane selected that body — which is exactly when the declaration is
/// not needed. A row the log is SILENT on is the hole, so the declaration has to
/// come from something that always runs.
pub fn print_manifest_and_check_coverage(vocabulary: ProbeVocabulary) {
    println!(
        "ADVERSARIAL-KERNEL-SUITE PROBE-VOCABULARY driver={driver} rig={rig} \
         attribution={attribution}",
        driver = driver().label(),
        rig = vocabulary.token(),
        attribution = vocabulary.attribution(),
    );
    // THIS DRIVER's floors summed, so the printed manifest is the manifest of the
    // run that printed it rather than of the widest column in the table.
    let floors: Vec<(usize, usize)> = ATTACKS
        .iter()
        .filter_map(|a| match coverage_of(driver(), a.id) {
            DriverCoverage::Runs {
                min_containment,
                min_pinned,
            } => Some((min_containment, min_pinned)),
            _ => None,
        })
        .collect();
    let containment: usize = floors.iter().map(|f| f.0).sum();
    let pinned: usize = floors.iter().map(|f| f.1).sum();
    println!(
        "ADVERSARIAL-KERNEL-SUITE MANIFEST attacks={n} containment-assertion-floor={containment} \
         pinned-open-floor={pinned} driver={driver}",
        n = ATTACKS.len(),
        driver = driver().label(),
    );
    for a in ATTACKS {
        match coverage_of(driver(), a.id) {
            DriverCoverage::Runs {
                min_containment,
                min_pinned,
            } => {
                println!(
                    "ADVERSARIAL-KERNEL-SUITE MANIFEST   {id}: containment>={min_containment} \
                     pinned>={min_pinned} :: {q}",
                    id = a.id,
                    q = a.question,
                );
                assert!(
                    min_containment + min_pinned > 0,
                    "driver `{driver}` declares a floor of ZERO observations for `{id}` while \
                     claiming to RUN it, so that row certifies nothing. Declare it not-run \
                     instead — a run with no floor is the silent skip in a different costume.",
                    driver = driver().label(),
                    id = a.id,
                );
            }
            declined => println!(
                "ADVERSARIAL-KERNEL-SUITE MANIFEST   {id}: NOT RUN by this driver \
                 ({declined:?}) :: {q}",
                id = a.id,
                q = a.question,
            ),
        }
    }
    assert!(
        containment > 0,
        "driver `{driver}` declares a ZERO containment floor across every row it runs",
        driver = driver().label(),
    );
    let mut ids: Vec<&str> = ATTACKS.iter().map(|a| a.id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(before, ids.len(), "duplicate attack id in ATTACKS");

    assert_coverage_is_total();
    // Evaluated on EVERY driver's manifest run, not only the column that holds the
    // cell: the fact is about the host, not the driver.
    let host_facts = assert_not_demonstrable_cells_still_hold();
    assert!(
        host_facts > 0,
        "no NotDemonstrable cell was checked. If none exist any more, delete this assertion together with the arm; while one exists, a check over nothing proves nothing."
    );

    let declared = declare_not_run_rows();
    let runs = ATTACKS
        .iter()
        .filter(|a| matches!(coverage_of(driver(), a.id), DriverCoverage::Runs { .. }))
        .count();
    // NON-VACUITY, on both sides. A driver that declared EVERY row would print a
    // full set of declarations and run no containment at all — and a driver that
    // declared none would be indistinguishable, in a log, from one whose table
    // was never consulted.
    assert!(
        runs > 0,
        "driver `{}` runs NO attack row at all, so its log cannot carry a single verdict",
        driver().label(),
    );
    println!(
        "ADVERSARIAL-KERNEL-SUITE COVERAGE driver={driver} runs={runs} declared-not-run={declared} \
         attacks={total}",
        driver = driver().label(),
        total = ATTACKS.len(),
    );
    assert_eq!(
        runs + declared,
        ATTACKS.len(),
        "driver `{}` classified {runs} + {declared} rows against {} attacks. Every row is \
         either run or declared; the arithmetic is the proof that no third state crept in.",
        driver().label(),
        ATTACKS.len(),
    );
}

/// Every `NotDemonstrable` cell's HOST FACT still holds on this host — or a PANIC
/// telling the reader to promote the cell.
///
/// # Why this is checked and not trusted
///
/// `NotDemonstrable` is the one coverage arm that is a fact about a HOST rather than
/// about a route or the rig, and a hand-declared one goes stale silently: on a
/// host with `kernel.apparmor_restrict_unprivileged_userns = 0`, A1's OCI cell
/// would stay `NotDemonstrable` and the column green while a demonstrable row
/// went unrun. So each reason token names a host predicate
/// this function EVALUATES, a token with no predicate is refused, and a predicate
/// that no longer holds fails the manifest test with the cell to promote.
///
/// Returns how many cells were checked, so the caller can assert non-vacuity.
pub fn assert_not_demonstrable_cells_still_hold() -> usize {
    let mut checked = 0usize;
    for (driver, attack, coverage) in COVERAGE {
        let DriverCoverage::NotDemonstrable(reason) = coverage else {
            continue;
        };
        let (holds, observed) = match *reason {
            "uid_map_write_is_apparmor_restricted_on_this_host" => {
                const KNOB: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
                let value = std::fs::read_to_string(KNOB).map_or_else(
                    |error| format!("unreadable ({error})"),
                    |v| v.trim().to_owned(),
                );
                (value == "1", format!("{KNOB} = {value}"))
            }
            other => panic!(
                "COVERAGE declares ({}, {attack}) NotDemonstrable({other:?}), and no host \
                 predicate is defined for that reason. A NotDemonstrable cell is a claim about \
                 THIS HOST, so it must name a fact this function can read — add the predicate \
                 here, or the cell is an unrun row wearing a reason.",
                driver.label(),
            ),
        };
        assert!(
            holds,
            "PROMOTE THIS CELL: COVERAGE declares ({}, {attack}) \
             NotDemonstrable({reason:?}), and on this host that fact does NOT hold ({observed}). \
             The attack's non-vacuity control is constructible here, so the row must be \
             written and the cell changed to `Runs` with its floors — leaving it declared would \
             keep the column green while a demonstrable row goes unrun.",
            driver.label(),
        );
        checked += 1;
    }
    checked
}

/// [`COVERAGE`] holds exactly one cell per (driver, attack), and no more.
///
/// The compile-time half of the guard is `ExecutionDriver::ALL` plus the
/// exhaustive `match` in [`ExecutionDriver::label`]: a new variant is `E0004`
/// there and then absent from this iteration. The run-time half is this — a new
/// ATTACK is a value, not a type, so nothing about it can fail to compile, and
/// this is what makes it fail cheaply instead of in a 25-minute lane.
pub fn assert_coverage_is_total() {
    let mut cells = 0usize;
    for driver in ExecutionDriver::ALL {
        for spec in ATTACKS {
            // Panics on a missing OR duplicated cell, naming which.
            let coverage = coverage_of(*driver, spec.id);
            if let Some(reason) = coverage.reason() {
                assert!(
                    !reason.is_empty()
                        && reason
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "the NOT-RUN reason for ({}, {}) is {reason:?}, which is not a \
                     `[a-z0-9_]+` token. Prose there is an excuse nobody can diff across \
                     runs.",
                    driver.label(),
                    spec.id,
                );
            }
            cells += 1;
        }
    }
    assert_eq!(
        cells,
        ExecutionDriver::ALL.len() * ATTACKS.len(),
        "the coverage iteration visited {cells} cells for {} drivers x {} attacks",
        ExecutionDriver::ALL.len(),
        ATTACKS.len(),
    );
    assert_eq!(
        COVERAGE.len(),
        cells,
        "COVERAGE has {} rows for {cells} (driver, attack) pairs. A row nothing reads is a \
         classification for a driver or an attack that does not exist.",
        COVERAGE.len(),
    );
}
