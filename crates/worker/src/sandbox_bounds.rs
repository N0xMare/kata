//! What this host's cgroup v2 delegation ACTUALLY carries, and the
//! knobs a capsule's budgets become.
//!
//! # Truthful reporting is the point
//!
//! This module measures rather than infers. An `ls -d` that observes a cgroup
//! directory EXISTS and records "cgroup delegation: present" can be wrong in
//! OPPOSITE directions — `io` not delegated at all, and a subtree a probe
//! called unreachable in fact reachable. Existence is not delegation.
//!
//! So nothing here concludes anything from a path being present. The delegation
//! probe performs the whole round trip in a scratch cgroup — create it, look for
//! the controller's knob FILE in it, write a value, read that value back, remove
//! it — and reports what it saw. A controller counts as usable only when its own
//! knob accepted and returned a value at the position kata would actually use.
//! [`crate::oci_runtime::fold_delegation`] refuses a host whose delegation does
//! not carry memory and pids; [`capsule_cgroup_knobs`] writes a capsule's
//! budgets into what it does carry.
//!
//! # `memory.max` ALONE is not a memory bound, and only running it says so
//!
//! A stage under `memory.max = 64 MiB` measured completing a 256 MiB touched
//! allocation and exiting 0: this host has an 8 GiB swap file, and `memory.max`
//! bounds a cgroup's ANONYMOUS memory while letting the excess spill to swap. The
//! knob was written, was read back, and bounded nothing an operator would
//! recognise. `memory.swap.max = 0` is what makes the ceiling bite, and its round
//! trip is probed separately ([`CgroupDelegation::swap_cap_usable`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Serialize;

/// The unified-hierarchy mount point. A constant rather than a discovered path:
/// cgroup v2's mount point is fixed by every systemd distro, and a kata that
/// searched for it would be inferring a capability from a mount table instead of
/// from a write it performed.
/// The cgroup v2 unified-hierarchy mount point.
///
/// `pub(crate)` because `crate::oci_cgroup` has to express a kata-owned parent
/// RELATIVE to it: the OCI spec reads `linux.cgroupsPath` as a path from the
/// hierarchy mount point, and a second literal for the same directory is how two
/// answers get minted.
pub(crate) const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Basename of the per-worker cgroup kata relocates its OWN process into before
/// enabling controllers.
///
/// This is not optional politeness — it is the cgroup v2 delegation protocol.
/// A non-root cgroup may only distribute a controller to its children when it
/// has no member processes of its own, so a delegated daemon that stays in its
/// own cgroup can never enable a controller for the children it creates. The
/// move is confined to kata's OWN delegated subtree and cannot affect any
/// process outside it.
const SUPERVISOR_CGROUP: &str = "kata.supervisor";

/// The knob that denies a bounded stage swap, so its `memory.max` ceiling is a
/// ceiling rather than a throttle. See this module's docs on why it is probed
/// separately from the memory controller itself.
/// `memory.swap.max`. `pub(crate)` because `crate::oci_cgroup` names it in the
/// refusal it raises when this host did not prove it writable.
pub(crate) const SWAP_MAX_KNOB: &str = "memory.swap.max";

/// Which controller a bound axis needs. A closed enum, because a controller kata
/// cannot name is a controller kata cannot have measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupController {
    /// `memory.max` — a resident-set ceiling.
    Memory,
    /// `cpu.max` — a quota per period.
    Cpu,
    /// `pids.max` — a subtree process-count ceiling.
    Pids,
}

impl CgroupController {
    /// Every controller kata asks about, in report order.
    pub const ALL: [CgroupController; 3] = [
        CgroupController::Memory,
        CgroupController::Cpu,
        CgroupController::Pids,
    ];

    /// The name that appears in `cgroup.controllers` / `cgroup.subtree_control`.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            CgroupController::Memory => "memory",
            CgroupController::Cpu => "cpu",
            CgroupController::Pids => "pids",
        }
    }

    /// The knob file whose EXISTENCE in a child cgroup is the fact "this
    /// controller is enabled at this level" — not a proxy for it.
    #[must_use]
    pub fn knob(self) -> &'static str {
        match self {
            CgroupController::Memory => "memory.max",
            CgroupController::Cpu => "cpu.max",
            CgroupController::Pids => "pids.max",
        }
    }

    /// A value the round-trip probe writes and reads back. Chosen to be
    /// unmistakably a probe value and to be legal for the knob: `max` is the
    /// documented "no limit" spelling every one of these knobs accepts, so a
    /// scratch cgroup is never left holding a restrictive limit if a `rmdir`
    /// races.
    #[must_use]
    fn probe_value(self) -> &'static str {
        match self {
            CgroupController::Memory | CgroupController::Pids => "max",
            CgroupController::Cpu => "max 100000",
        }
    }
}

// ---------------------------------------------------------------------------
// The observation — impure, host-specific, taken once.
// ---------------------------------------------------------------------------

/// What the live delegation probe SAW, before any verdict is folded from it.
///
/// Separated from the verdict so a reader can disagree with the fold without
/// re-running the probe — the same producer/consumer split
/// [`crate::sandbox_posture`] uses for every other containment fact.
#[derive(Clone, Debug, Serialize)]
pub struct CgroupObservation {
    /// Whether `/sys/fs/cgroup/cgroup.controllers` exists — the unified
    /// hierarchy's own marker. `false` means cgroup v1, a hybrid mount, or no
    /// cgroupfs, and no v2 claim can be made.
    pub unified_hierarchy: bool,
    /// The calling process's own cgroup, absolute. `Err` carries the reason
    /// `/proc/self/cgroup` could not be read or had no `0::` line.
    pub own_cgroup: Result<PathBuf, String>,
    /// The controllers `<own>/cgroup.controllers` offers — what COULD be
    /// enabled, which is not what IS enabled.
    pub offered: BTreeSet<CgroupController>,
    /// The controllers `<own>/cgroup.subtree_control` has enabled for children.
    pub enabled_for_children: BTreeSet<CgroupController>,
    /// `mkdir <own>/<scratch>` — `Err` carries the OS error text verbatim.
    /// This is the single fact that decides whether kata can create a per-stage
    /// cgroup at all, and it is a WRITE, not a `stat`.
    pub scratch_mkdir: Result<(), String>,
    /// Per controller, the write-and-read-back round trip performed in the
    /// scratch child. `Ok` carries what was read back; `Err` carries why the
    /// round trip failed (knob absent, write refused, value not retained).
    pub round_trips: BTreeMap<CgroupController, Result<String, String>>,
    /// Whether kata relocated its own process into [`SUPERVISOR_CGROUP`] to
    /// satisfy the delegation protocol's no-internal-processes rule.
    pub relocated_self: bool,
    /// Per offered controller, the delegation protocol's `+<controller>` write to
    /// `<own>/cgroup.subtree_control`: `Err` carries the OS error verbatim
    /// (`EBUSY` while `<own>` still has a member process). Empty when the
    /// protocol did not run: the scratch child already had a knob, or `<own>`
    /// offered nothing.
    pub subtree_enables: BTreeMap<CgroupController, Result<(), String>>,
    /// The `memory.swap.max` round trip, when the memory controller was present
    /// to have one. `None` when the memory knob itself was absent.
    ///
    /// Separate from [`Self::round_trips`] because it is not a CONTROLLER — it is
    /// the second half of the memory controller's bound, and a host can have the
    /// first without the second. Folding it in with `memory` would erase the
    /// difference between a ceiling that holds and a ceiling a stage can spill
    /// past into swap.
    pub swap_cap: Option<Result<String, String>>,
}

/// The folded verdict: where per-stage cgroups can be created, and with which
/// controllers PROVEN usable there.
#[derive(Clone, Debug, Serialize)]
pub struct CgroupDelegation {
    /// The directory per-stage cgroups are created under. `None` ⇒ no cgroup
    /// enforcement is possible here.
    pub usable_parent: Option<PathBuf>,
    /// Controllers whose knob accepted and returned a value in a real child of
    /// [`Self::usable_parent`]. Never populated from a controller LIST.
    pub controllers: BTreeSet<CgroupController>,
    /// Whether `memory.swap.max` round-tripped, i.e. whether a memory ceiling can
    /// be made to BITE rather than spill into swap.
    pub swap_cap_usable: bool,
    /// What was observed, in the observer's words.
    pub evidence: String,
    /// The action an operator can take, when there is one that exists and works.
    pub remediation: Option<String>,
    /// The raw observation, retained so the posture report can carry it.
    pub observation: CgroupObservation,
}

impl CgroupDelegation {
    /// Whether `controller` was PROVEN usable at the stage-cgroup position.
    #[must_use]
    pub fn has(&self, controller: CgroupController) -> bool {
        self.usable_parent.is_some() && self.controllers.contains(&controller)
    }
}

/// Read the calling process's own cgroup v2 path out of `/proc/self/cgroup`.
///
/// The unified hierarchy is always the `0::` line. A host with only v1
/// controllers has no such line, which is itself the answer.
fn read_own_cgroup(root: &Path) -> Result<PathBuf, String> {
    let raw = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| format!("/proc/self/cgroup unreadable: {e}"))?;
    let rel = raw
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            format!(
                "/proc/self/cgroup has no `0::` unified-hierarchy line (read {} bytes); this \
                 process is not on cgroup v2",
                raw.len()
            )
        })?
        .trim();
    Ok(root.join(rel.trim_start_matches('/')))
}

/// Parse a `cgroup.controllers` / `cgroup.subtree_control` file into the closed
/// controller set. Unknown tokens (`cpuset`, `io`, `hugetlb`, …) are dropped:
/// this module only claims what it can also PROVE, and it proves only three.
fn parse_controllers(path: &Path) -> BTreeSet<CgroupController> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    raw.split_whitespace()
        .filter_map(|tok| CgroupController::ALL.into_iter().find(|c| c.token() == tok))
        .collect()
}

/// Move this process into `<parent>/kata.supervisor` so `<parent>` has no member
/// processes and can therefore distribute controllers to its children.
///
/// Returns `Ok(true)` when the move happened, `Ok(false)` when it was
/// unnecessary (the process is already elsewhere), `Err` with the OS text
/// otherwise. Writing a pid to `cgroup.procs` moves the whole thread group, so
/// one write covers the worker's entire runtime.
fn relocate_self(parent: &Path, own: &Path) -> Result<bool, String> {
    if own != parent {
        // Already in a leaf below (or beside) the delegation root; the
        // no-internal-processes rule is satisfied without moving anything.
        return Ok(false);
    }
    let supervisor = parent.join(SUPERVISOR_CGROUP);
    if let Err(e) = std::fs::create_dir(&supervisor)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(format!("mkdir {}: {e}", supervisor.display()));
    }
    let pid = std::process::id();
    std::fs::write(supervisor.join("cgroup.procs"), format!("{pid}\n"))
        .map_err(|e| format!("write {pid} to {}/cgroup.procs: {e}", supervisor.display()))?;
    Ok(true)
}

/// Ask `<parent>/cgroup.subtree_control` to enable every offered controller,
/// and say how each write went. Best effort per controller — a partial enable
/// is a real, reportable state, and refusing all three because one was
/// rejected would understate what the host can do — but never silent: the
/// round trip after it can only say a knob is absent, and why it is absent is
/// this write's answer. A write refused `EBUSY` (`<parent>` still has a
/// member) carries the members `<parent>` listed right after it.
fn enable_subtree_controllers(
    parent: &Path,
    offered: &BTreeSet<CgroupController>,
) -> BTreeMap<CgroupController, Result<(), String>> {
    let control = parent.join("cgroup.subtree_control");
    offered
        .iter()
        .map(|c| {
            let written = std::fs::write(&control, format!("+{}", c.token())).map_err(|e| {
                let mut why = format!("write +{} to {}: {e}", c.token(), control.display());
                if e.kind() == std::io::ErrorKind::ResourceBusy {
                    let _ = write!(why, " ({})", cgroup_members(parent));
                }
                why
            });
            (*c, written)
        })
        .collect()
}

/// The processes and threads `cgroup` lists as its own members, each list as
/// read, or why it could not be read.
fn cgroup_members(cgroup: &Path) -> String {
    let list = |file: &str| {
        std::fs::read_to_string(cgroup.join(file)).map_or_else(
            |e| format!("unreadable: {e}"),
            |ids| ids.split_whitespace().collect::<Vec<_>>().join(" "),
        )
    };
    format!(
        "its cgroup.procs then listed [{}] and its cgroup.threads [{}]",
        list("cgroup.procs"),
        list("cgroup.threads")
    )
}

/// What `<own>` offered and enabled for its children, and what the delegation
/// protocol did about it: the facts that say why a scratch child has no knob.
fn delegation_account(own: &Path, observation: &CgroupObservation) -> String {
    let enabled = render_controllers(&observation.enabled_for_children);
    let offered = render_controllers(&observation.offered);
    if observation.subtree_enables.is_empty() {
        return format!(
            "`{own}` offered [{offered}] and enabled [{enabled}] for its children; the \
             delegation protocol did not run",
            own = own.display()
        );
    }
    let writes = observation
        .subtree_enables
        .iter()
        .map(|(c, r)| match r {
            Ok(()) => format!("+{} accepted", c.token()),
            Err(why) => why.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "`{own}` offered [{offered}]; the delegation protocol {moved}wrote each to its \
         `cgroup.subtree_control` ({writes}), after which it enabled [{enabled}] for its children",
        own = own.display(),
        moved = if observation.relocated_self {
            format!("moved kata into `{SUPERVISOR_CGROUP}` and ")
        } else {
            String::new()
        },
    )
}

/// MEASURE cgroup v2 delegation by using it.
///
/// Every step is an operation whose FAILURE is the answer, never a `stat` whose
/// success is taken for one:
///
/// 1. `<root>/cgroup.controllers` must exist — the unified hierarchy's marker.
/// 2. `/proc/self/cgroup` must have a `0::` line — this process is on v2.
/// 3. `mkdir <own>/<scratch>` must SUCCEED — the delegation question. On the
///    reference host this is `Permission denied` and everything below is moot.
/// 4. If no controller knob appears in the scratch child, run the delegation
///    protocol (relocate self, enable `subtree_control`, keeping each write's
///    answer for the evidence) and re-create it. A delegated daemon that skips
///    this can never enable a controller for its children, so skipping it would
///    report an enforceable host as unenforceable.
/// 5. For each controller, its knob file must EXIST in the child, must ACCEPT a
///    write, and must RETURN that value on read-back.
/// 6. `rmdir` the scratch child, leaving the hierarchy as found.
#[must_use]
pub fn measure_cgroup_delegation() -> CgroupDelegation {
    measure_cgroup_delegation_at(Path::new(CGROUP_ROOT))
}

/// [`measure_cgroup_delegation`] against an explicit hierarchy root.
///
/// The root is a parameter so a test can point the probe at a directory that is
/// NOT a cgroupfs and assert the refusal path — the one arm a real cgroupfs
/// cannot produce on demand.
#[must_use]
pub fn measure_cgroup_delegation_at(root: &Path) -> CgroupDelegation {
    let unified_hierarchy = root.join("cgroup.controllers").exists();
    let own_cgroup = if unified_hierarchy {
        read_own_cgroup(root)
    } else {
        Err(format!(
            "{}/cgroup.controllers does not exist, so this host has no cgroup v2 unified \
             hierarchy mounted there",
            root.display()
        ))
    };

    let mut obs = CgroupObservation {
        unified_hierarchy,
        own_cgroup: own_cgroup.clone(),
        offered: BTreeSet::new(),
        enabled_for_children: BTreeSet::new(),
        scratch_mkdir: Err("not attempted".to_string()),
        round_trips: BTreeMap::new(),
        relocated_self: false,
        subtree_enables: BTreeMap::new(),
        swap_cap: None,
    };

    let Ok(own) = own_cgroup else {
        return fold_cgroup_delegation(obs);
    };

    obs.offered = parse_controllers(&own.join("cgroup.controllers"));
    obs.enabled_for_children = parse_controllers(&own.join("cgroup.subtree_control"));

    let scratch = own.join(format!(".kata-bounds-probe-{}", std::process::id()));
    obs.scratch_mkdir =
        std::fs::create_dir(&scratch).map_err(|e| format!("mkdir {}: {e}", scratch.display()));
    if obs.scratch_mkdir.is_err() {
        return fold_cgroup_delegation(obs);
    }

    // Step 4 — the delegation protocol. If the scratch child has no controller
    // knobs, `<own>` has not distributed anything to its children yet. That is
    // the DEFAULT state of a freshly delegated unit, not a refusal.
    let no_knobs = CgroupController::ALL
        .into_iter()
        .all(|c| !scratch.join(c.knob()).exists());
    if no_knobs && !obs.offered.is_empty() {
        let _ = std::fs::remove_dir(&scratch);
        match relocate_self(&own, &own) {
            Ok(moved) => obs.relocated_self = moved,
            Err(why) => {
                obs.scratch_mkdir = Err(format!(
                    "the delegation protocol could not be run: {why}. `{}` offers {} but has \
                     enabled none for its children, and a cgroup with member processes cannot \
                     distribute a controller.",
                    own.display(),
                    render_controllers(&obs.offered),
                ));
                return fold_cgroup_delegation(obs);
            }
        }
        obs.subtree_enables = enable_subtree_controllers(&own, &obs.offered);
        obs.enabled_for_children = parse_controllers(&own.join("cgroup.subtree_control"));
        obs.scratch_mkdir = std::fs::create_dir(&scratch).map_err(|e| {
            format!(
                "mkdir {} after enabling controllers: {e}",
                scratch.display()
            )
        });
        if obs.scratch_mkdir.is_err() {
            return fold_cgroup_delegation(obs);
        }
    }

    // Step 5 — the round trip. A knob that exists but does not RETAIN a written
    // value is not a usable knob, and only a read-back can tell.
    for c in CgroupController::ALL {
        let knob = scratch.join(c.knob());
        obs.round_trips
            .insert(c, round_trip(&knob, c.probe_value()));
    }
    // The memory ceiling's second half. `memory.max` bounds a cgroup's anonymous
    // memory and lets the excess spill to SWAP — measured on a host with an 8 GiB
    // swap file, a stage under `memory.max = 64 MiB` completed a 256 MiB touched
    // allocation and exited 0. Only `memory.swap.max = 0` makes the ceiling bite,
    // so whether that knob is usable is a separate question with a separate
    // answer.
    if obs
        .round_trips
        .get(&CgroupController::Memory)
        .is_some_and(Result::is_ok)
    {
        obs.swap_cap = Some(round_trip(&scratch.join(SWAP_MAX_KNOB), "max"));
    }

    // Step 6 — leave the hierarchy as found.
    let _ = std::fs::remove_dir(&scratch);

    fold_cgroup_delegation(obs)
}

/// Write `value` to `knob` and read it back. `Ok` carries the read-back.
fn round_trip(knob: &Path, value: &str) -> Result<String, String> {
    if !knob.exists() {
        return Err(format!(
            "{} does not exist — the controller is not enabled at this level",
            knob.display()
        ));
    }
    std::fs::write(knob, value)
        .map_err(|e| format!("write {value:?} to {}: {e}", knob.display()))?;
    let read_back = std::fs::read_to_string(knob)
        .map_err(|e| format!("read back {}: {e}", knob.display()))?
        .trim()
        .to_string();
    if read_back == value {
        Ok(read_back)
    } else {
        Err(format!(
            "{} accepted {value:?} but read back {read_back:?} — the knob does not retain what \
             it is given, so a limit written here would not be the limit in force",
            knob.display()
        ))
    }
}

fn render_controllers(set: &BTreeSet<CgroupController>) -> String {
    if set.is_empty() {
        return "none".to_string();
    }
    set.iter().map(|c| c.token()).collect::<Vec<_>>().join(" ")
}

/// Fold an observation into a verdict. PURE and total, so every arm — including
/// the ones this host cannot produce — is reachable in a unit test.
#[must_use]
pub fn fold_cgroup_delegation(observation: CgroupObservation) -> CgroupDelegation {
    if !observation.unified_hierarchy {
        return CgroupDelegation {
            usable_parent: None,
            controllers: BTreeSet::new(),
            swap_cap_usable: false,
            evidence: "no cgroup v2 unified hierarchy is mounted at /sys/fs/cgroup, so there is \
                       no cgroup bound to apply and none is claimed"
                .to_string(),
            remediation: Some(
                "cgroup v2 requires a unified-hierarchy mount. On a systemd host this is the \
                 default; on a v1/hybrid host boot with `systemd.unified_cgroup_hierarchy=1`."
                    .to_string(),
            ),
            observation,
        };
    }

    let own = match &observation.own_cgroup {
        Ok(own) => own.clone(),
        Err(why) => {
            let evidence = format!("this process's own cgroup could not be determined: {why}");
            return CgroupDelegation {
                usable_parent: None,
                controllers: BTreeSet::new(),
                swap_cap_usable: false,
                evidence,
                remediation: None,
                observation,
            };
        }
    };

    if let Err(why) = &observation.scratch_mkdir {
        let evidence = format!(
            "cgroup v2 is mounted and this process sits in `{own}`, which OFFERS [{offered}] — \
             but creating a child cgroup there was REFUSED, so kata cannot place a stage under \
             any bound: {why}. Offering a controller and delegating the subtree are different \
             facts; only the second lets an unprivileged process write a limit.",
            own = own.display(),
            offered = render_controllers(&observation.offered),
        );
        return CgroupDelegation {
            usable_parent: None,
            controllers: BTreeSet::new(),
            swap_cap_usable: false,
            evidence,
            remediation: Some(format!(
                "run the worker under a cgroup that is DELEGATED to this uid — a systemd unit \
                 with `Delegate=yes` (`systemctl --user edit kata-worker.service`, add \
                 `[Service]\\nDelegate=yes`), or a transient `systemd-run --user --scope -p \
                 Delegate=yes -- kata worker …`. Verify with `mkdir {own}/probe` succeeding.",
                own = own.display()
            )),
            observation,
        };
    }

    let proven: BTreeSet<CgroupController> = observation
        .round_trips
        .iter()
        .filter(|(_, r)| r.is_ok())
        .map(|(c, _)| *c)
        .collect();

    if proven.is_empty() {
        let failures = observation
            .round_trips
            .iter()
            .filter_map(|(c, r)| r.as_ref().err().map(|e| format!("{}: {e}", c.token())))
            .collect::<Vec<_>>()
            .join("; ");
        return CgroupDelegation {
            usable_parent: None,
            controllers: BTreeSet::new(),
            swap_cap_usable: false,
            evidence: format!(
                "a child cgroup under `{own}` CAN be created, but no controller knob was usable \
                 in it — {failures}. {account}. A writable directory is not a bound.",
                own = own.display(),
                account = delegation_account(&own, &observation),
            ),
            remediation: Some(format!(
                "enable the controllers for children of `{own}`: \
                 `echo '+memory +cpu +pids' > {own}/cgroup.subtree_control`. This requires \
                 `{own}` to have no member processes of its own.",
                own = own.display()
            )),
            observation,
        };
    }

    let missing: Vec<String> = observation
        .round_trips
        .iter()
        .filter_map(|(c, r)| r.as_ref().err().map(|e| format!("{}: {e}", c.token())))
        .collect();
    let mut evidence = format!(
        "MEASURED by round trip in a scratch cgroup under `{own}`: [{proven}] each accepted a \
         written value and returned it on read-back{relocated}",
        own = own.display(),
        proven = render_controllers(&proven),
        relocated = if observation.relocated_self {
            format!(
                " (kata relocated its own process into `{SUPERVISOR_CGROUP}` first, as the \
                 cgroup v2 delegation protocol requires — a cgroup with member processes \
                 cannot distribute a controller to its children)"
            )
        } else {
            String::new()
        }
    );
    if !missing.is_empty() {
        let _ = write!(
            evidence,
            ". NOT usable: {}. {}",
            missing.join("; "),
            delegation_account(&own, &observation)
        );
    }

    let swap_cap_usable = observation.swap_cap.as_ref().is_some_and(Result::is_ok);
    if proven.contains(&CgroupController::Memory) {
        if swap_cap_usable {
            evidence.push_str(
                ". `memory.swap.max` also round-tripped, so a declared memory ceiling can be \
                 made to HOLD rather than spill into swap",
            );
        } else {
            let why = observation
                .swap_cap
                .as_ref()
                .and_then(|r| r.as_ref().err().cloned())
                .unwrap_or_else(|| format!("{SWAP_MAX_KNOB} was not probed"));
            let _ = write!(
                evidence,
                ". `{SWAP_MAX_KNOB}` is NOT usable ({why}), so `memory.max` bounds this \
                 cgroup's anonymous memory while letting the excess spill to SWAP — a real \
                 ceiling on RAM, but not the ceiling `memory_mb` declares"
            );
        }
    }

    CgroupDelegation {
        usable_parent: Some(own),
        controllers: proven,
        swap_cap_usable,
        evidence,
        remediation: None,
        observation,
    }
}

/// The process-wide delegation measurement, taken ONCE.
///
/// A `OnceLock` because the probe mutates the hierarchy (it creates and removes a scratch
/// cgroup, and may relocate this process per the delegation protocol), and a
/// second run could observe a different answer than the one the bounds were planned
/// from.
pub fn cgroup_delegation() -> &'static CgroupDelegation {
    static MEASURED: OnceLock<CgroupDelegation> = OnceLock::new();
    MEASURED.get_or_init(measure_cgroup_delegation)
}

// ---------------------------------------------------------------------------
// The OCI route's parent-cgroup knobs.
// ---------------------------------------------------------------------------

/// **PURE** — the knob writes one capsule's budgets ask for, gated on what this
/// host's delegation PROVED.
///
/// The gate is [`CgroupDelegation::has`] and [`CgroupDelegation::swap_cap_usable`],
/// so a knob nobody wrote and read back in a real child of the usable parent is
/// never emitted.
///
/// # Why `pids.max` is here and `cpu.max` is not
///
/// [`CapsuleBudgets`] has a `process_count` and no CPU field. Deriving a quota
/// from anything else would be kata inventing a bound — the capsule's exhaustive
/// destructure in `crate::oci_bundle::spec_for` is what keeps that visible the day
/// a CPU field is added.
///
/// # This is the ENFORCED mechanism on the OCI route, and the leaf is not
///
/// The same three bounds also ride `linux.resources` in the bundle, where the
/// runtime applies them to its own leaf. **MEASURED on the reference
/// host: youki 0.7.0 applies `memory.limit` and `pids.limit` to the leaf and does
/// NOT apply the swap half** — a leaf under an absolute `linux.cgroupsPath` reads
/// `memory.swap.max: max` from a spec carrying `swap == limit`. cgroup v2 limits
/// bind at every ancestor, so the knobs written HERE are what make all three hold;
/// the leaf's copy is defence in depth against a parent kata failed to populate,
/// and for swap it is defence that this runtime does not provide at all.
///
/// # The gate here can therefore never be PARTIAL in production
///
/// This function emits a knob only when the delegation probe PROVED it, which on a
/// host missing an axis would return a set short of the three — and, since these
/// writes are the enforced mechanism, a container bounded on paper only.
/// [`crate::oci_cgroup::OciParentCgroup::establish`] refuses that host BY NAME
/// before any directory exists
/// ([`ParentCgroupRefusal::UnprovenBound`](crate::oci_cgroup::ParentCgroupRefusal::UnprovenBound)),
/// so on this route the emitted set is the full three or there is no container. The
/// per-axis gate stays because the alternative is emitting a write the probe never
/// verified, which would fail the establishment with the kernel's words instead of
/// kata's.
#[must_use]
pub fn capsule_cgroup_knobs(
    delegation: &CgroupDelegation,
    budgets: &kata_types::execution_contract::CapsuleBudgets,
) -> Vec<(String, String)> {
    let mut knobs: Vec<(String, String)> = Vec::new();
    if delegation.has(CgroupController::Memory) {
        knobs.push((
            CgroupController::Memory.knob().to_owned(),
            budgets.memory_bytes.to_string(),
        ));
        // Deny the stage swap, or the ceiling above is a throttle rather than a
        // ceiling — see this module's docs — and only when the probe proved the knob.
        if delegation.swap_cap_usable {
            knobs.push((SWAP_MAX_KNOB.to_owned(), "0".to_owned()));
        }
    }
    if delegation.has(CgroupController::Pids) {
        knobs.push((
            CgroupController::Pids.knob().to_owned(),
            budgets.process_count.to_string(),
        ));
    }
    knobs
}

/// The controllers a cgroup must offer its children for
/// [`capsule_cgroup_knobs`]' writes to be available one level down.
///
/// Returned as the PROVEN subset rather than as a wish list: a
/// `cgroup.subtree_control` write for a controller this host never round-tripped
/// would fail, and failing the establishment over it would refuse a host where the
/// other axis is enforceable.
#[must_use]
pub fn capsule_subtree_controllers(delegation: &CgroupDelegation) -> Vec<CgroupController> {
    [CgroupController::Memory, CgroupController::Pids]
        .into_iter()
        .filter(|c| delegation.has(*c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory laid out as a cgroup v2 mount, holding this process's own
    /// cgroup path (read off `/proc/self/cgroup`) with `offered` in its
    /// `cgroup.controllers`. Returns that cgroup.
    fn mount_like(root: &Path, offered: &str) -> PathBuf {
        std::fs::write(root.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        let own = read_own_cgroup(root).expect("this process is on cgroup v2");
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(own.join("cgroup.controllers"), offered).unwrap();
        own
    }

    /// **A refused enable lists the cgroup's members as read.** Every write
    /// fails `EBUSY` while `<own>` has a member, and which member is the fact
    /// that names the cause; a list that cannot be read says why.
    #[test]
    fn the_members_a_busy_cgroup_lists_are_named_as_read() {
        let cgroup = tempfile::tempdir().unwrap();
        std::fs::write(cgroup.path().join("cgroup.procs"), "4242\n").unwrap();
        std::fs::write(cgroup.path().join("cgroup.threads"), "4242\n4243\n").unwrap();
        assert_eq!(
            cgroup_members(cgroup.path()),
            "its cgroup.procs then listed [4242] and its cgroup.threads [4242 4243]"
        );
        std::fs::write(cgroup.path().join("cgroup.procs"), "").unwrap();
        std::fs::remove_file(cgroup.path().join("cgroup.threads")).unwrap();
        let unread = cgroup_members(cgroup.path());
        assert!(
            unread.starts_with(
                "its cgroup.procs then listed [] and its cgroup.threads [unreadable: "
            ),
            "{unread}"
        );
    }

    /// **A delegation whose knobs never appeared names why.** The round trip can
    /// only say a knob is absent; what `<own>` offered and enabled, and each
    /// `+<controller>` write the protocol made, say why. Every write fails here
    /// (the control file is a directory, as every write fails with `EBUSY` on a
    /// cgroup that still has a member process), and the evidence quotes each;
    /// a cgroup offering nothing gets no protocol, and the evidence says that.
    ///
    /// Needs only a process on cgroup v2 (a `0::` line in `/proc/self/cgroup`):
    /// the mount is a directory the cell lays out, and nothing is delegated or
    /// written in a cgroupfs.
    ///
    /// **Would red if:** the protocol's writes were discarded again, or the
    /// evidence of a delegation with no usable knob left out what `<own>`
    /// offered.
    #[test]
    fn a_delegation_with_no_knob_names_what_it_was_offered_and_each_enable_write() {
        let root = tempfile::tempdir().unwrap();
        let own = mount_like(root.path(), "cpu memory pids\n");
        let control = own.join("cgroup.subtree_control");
        std::fs::create_dir(&control).unwrap();
        let refused = measure_cgroup_delegation_at(root.path());
        assert!(refused.usable_parent.is_none(), "{}", refused.evidence);
        assert!(
            refused
                .evidence
                .contains(&format!("`{}` offered [memory cpu pids]", own.display())),
            "{}",
            refused.evidence
        );
        for c in CgroupController::ALL {
            let token = c.token();
            assert!(
                refused.evidence.contains(&format!(
                    "write +{token} to {}: Is a directory",
                    control.display()
                )),
                "the {token} write: {}",
                refused.evidence
            );
        }

        let root = tempfile::tempdir().unwrap();
        let own = mount_like(root.path(), "");
        let unoffered = measure_cgroup_delegation_at(root.path());
        assert!(unoffered.usable_parent.is_none(), "{}", unoffered.evidence);
        assert!(
            unoffered.evidence.contains(&format!(
                "`{}` offered [none] and enabled [none] for its children; the delegation \
                 protocol did not run",
                own.display()
            )),
            "{}",
            unoffered.evidence
        );
    }
}
