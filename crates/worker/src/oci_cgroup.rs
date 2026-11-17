//! The KATA-OWNED cgroup one rootless OCI container's leaf
//! is created beneath, and the attempt-local state root that travels with it.
//!
//! # The defect this module exists to close
//!
//! With `linux.cgroupsPath` unset, **MEASURED on the reference host**, youki
//! 0.7.0 asks the user manager for a
//! transient `youki-<id>.scope` and the container's init lands in
//! `/user.slice/user-1000.slice/user@1000.service/user.slice/youki-<id>.scope` —
//! outside every subtree kata owns. `ProviderSupervisor::contain` sweeps the
//! PROVIDER's cgroup and scores [`TeardownProbe::CgroupPopulation`] over it, so on
//! a stage timeout, a refused handshake or a `SIGKILL`ed provider the container
//! would survive while kata reported `TeardownOutcome::Confirmed` — a verdict over a
//! subtree the stage was never in. The same measurement confirmed the
//! survival directly: `SIGKILL` on the `youki run` client left `youki list`
//! reporting `Running` and the init alive.
//!
//! # What was measured, and the shape it forces
//!
//! All five rows below were taken on the reference host with a throwaway bundle, under
//! `systemd-run --user --scope -p Delegate=yes`, with `linux.resources` asking for
//! `memory.limit == memory.swap == 256 MiB` and `pids.limit == 37`:
//!
//! 1. **`cgroupsPath` unset** — init in `youki-<id>.scope`; `memory.max` and
//!    `pids.max` applied there; a transient scope unit exists.
//! 2. **An ABSOLUTE `cgroupsPath`** (`<delegated scope>/<parent>/leaf`) — the init
//!    lands at EXACTLY that path, no scope unit is created, and `memory.max` and
//!    `pids.max` are applied to the leaf. This is the row this module builds on.
//! 3. **A RELATIVE `cgroupsPath`** (`<parent>/leaf`) — no container at all: youki
//!    routes a non-absolute path to its systemd manager and refuses with
//!    *"failed to destructure cgroups path: cgroups path is malformed"*.
//! 4. **A systemd triple** (`kata-x.slice:kata:leaf`, with `--systemd-cgroup`) —
//!    the init lands under `user@1000.service/kata.slice/…`, outside kata's parent.
//!    `--systemd-cgroup` is a NO-OP for row 2: the manager is chosen by the path's
//!    shape, and an absolute path lands at that path with or without the flag.
//! 5. **A leaf whose ANCESTOR holds a process** — no container: `EOPNOTSUPP`
//!    writing the init's pid to the leaf's `cgroup.procs`. This is cgroup v2's
//!    no-internal-processes rule, and it is why
//!    [`crate::provider_supervisor::outer_cgroup_bounds`] now plans a PROCESS-FREE
//!    sweep root with the provider itself in a child: with the provider a member of
//!    the swept cgroup, no usable leaf can exist beneath it at all.
//!
//! So the shape is three levels, and each one is there because a measurement said
//! so:
//!
//! ```text
//! <delegation usable_parent>/
//!   kata.provider.<name>.<pid>/          sweep root — kata creates it, no processes
//!     provider/                          the provider process (CgroupPlan)
//!     kata.oci.<container_id>/           THIS module: knobs, controllers enabled
//!       container/                       youki's own leaf (linux.cgroupsPath)
//! ```
//!
//! `cgroup.kill` on the sweep root reaches the container's init, and
//! `live_cgroup_members` recurses, so the sweep and the probe need nothing
//! container-specific — the placement is what makes them reach it. Measured on the same host:
//! after `SIGKILL` on the runtime client the init was alive, and one write of `1` to
//! the sweep root's `cgroup.kill` left the whole subtree empty.
//!
//! [`TeardownProbe::CgroupPopulation`]: kata_agent::resource_bounds::TeardownProbe::CgroupPopulation
//! [`TeardownOutcome::Confirmed`]: kata_agent::resource_bounds::TeardownOutcome::Confirmed

use std::path::{Component, Path, PathBuf};

use kata_types::{KataError, KataResult, execution_contract::CapsuleBudgets};

use crate::sandbox_bounds::{
    CGROUP_ROOT, CgroupController, CgroupDelegation, SWAP_MAX_KNOB, capsule_cgroup_knobs,
    capsule_subtree_controllers,
};

/// The basename of the cgroup youki creates for the container itself.
///
/// Kata names it rather than letting the runtime choose, because the name is half
/// of `linux.cgroupsPath` and a plan whose leaf path kata cannot predict is a plan
/// whose placement kata cannot assert from the host.
pub const CONTAINER_LEAF: &str = "container";

/// The prefix of the per-container parent kata owns. `kata.oci.` distinguishes it
/// from the `provider` sibling and from the per-stage `kata.stage-*` cgroups at a glance
/// in `systemd-cgls`, which is the only place an operator meets all three.
const PARENT_PREFIX: &str = "kata.oci.";

/// Where kata put one container: the parent cgroup kata owns, and the worker-local
/// directory the provider writes the bundle and the runtime state tree beneath.
///
/// **PURE.** It validates and derives; it creates nothing and reads no directory.
/// Establishing the cgroup is [`OciParentCgroup`]'s job, and the split is the one
/// `sandbox_bounds` already draws between measuring a host and describing a plan: a
/// constructor that also created directories could not be called by the golden
/// test, and a golden that could not name a containment would pin a `config.json`
/// with no placement in it.
///
/// # Both fields are PRIVATE and the constructor is the only way in
///
/// Public fields would let a caller name any two absolute paths, and the two this
/// type carries are not free: the cgroup parent must be expressible RELATIVE to the
/// cgroup v2 mount point (that is what `linux.cgroupsPath` is), and the state root
/// must be somewhere the worker owns. A caller that could assign them
/// independently could hand a provider a state root under another attempt's tree,
/// and this type would have no way to tell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptContainment {
    cgroup_parent: PathBuf,
    state_root: PathBuf,
}

impl AttemptContainment {
    /// The parent cgroup kata owns plus the attempt-local state root.
    ///
    /// # Refused set
    ///
    /// * `cgroup_parent` that is not ABSOLUTE, or that is not strictly beneath
    ///   [`CGROUP_ROOT`]. `linux.cgroupsPath` is read by a runtime as a path from
    ///   the cgroup v2 mount point, so a parent kata cannot express relative to
    ///   that mount point is a parent kata cannot put in a bundle. The cgroup root
    ///   ITSELF is refused too: the root is not a cgroup kata created, owns or may
    ///   sweep, and a leaf placed directly under it would be outside every subtree
    ///   [`crate::provider_supervisor::ProviderSupervisor`] looks at.
    /// * `state_root` that is not ABSOLUTE. A relative path resolves against
    ///   whatever directory the PROVIDER happens to have been started in, so the
    ///   bundle and the runtime state would land somewhere kata does not know to
    ///   look — and a container whose state kata cannot find can be neither torn
    ///   down nor read back.
    /// * a `..` component in either. `..` can name a directory outside the attempt
    ///   the worker owns and outside the subtree kata sweeps, and it does so
    ///   without any of the text looking wrong.
    ///
    /// A `.` component is NOT refused — it is dropped, because `Path`'s own
    /// normalization already treats `/a/./b` and `/a/b` as the same directory and a
    /// refusal there would be a lint on spelling rather than a bound on reach.
    ///
    /// # Errors
    /// [`KataError::Validation`] naming which clause refused and why.
    pub fn new(cgroup_parent: PathBuf, state_root: PathBuf) -> KataResult<Self> {
        let refuse = |reason: String| {
            Err(KataError::Validation(format!(
                "oci containment refused: {reason}"
            )))
        };
        for (what, path) in [
            ("the kata-owned parent cgroup", &cgroup_parent),
            ("the attempt-local state root", &state_root),
        ] {
            if !path.is_absolute() {
                return refuse(format!(
                    "{what} `{p}` is not absolute. A relative path resolves against whatever \
                     directory the process that reads it happens to be in, so it names a \
                     different place depending on who started what",
                    p = path.display(),
                ));
            }
            if path.components().any(|c| matches!(c, Component::ParentDir)) {
                return refuse(format!(
                    "{what} `{p}` contains a `..` component, which can name a directory outside \
                     the subtree kata owns without any of the text looking wrong",
                    p = path.display(),
                ));
            }
        }
        let root = Path::new(CGROUP_ROOT);
        if !cgroup_parent.starts_with(root) || cgroup_parent == root {
            return refuse(format!(
                "the kata-owned parent cgroup `{p}` is not strictly beneath the cgroup v2 mount \
                 point {CGROUP_ROOT}. `linux.cgroupsPath` is read as a path FROM that mount \
                 point, so a parent kata cannot express relative to it cannot be put in a \
                 bundle — and the mount point itself is not a cgroup kata created, owns, or may \
                 sweep",
                p = cgroup_parent.display(),
            ));
        }
        Ok(Self {
            cgroup_parent,
            state_root,
        })
    }

    /// The kata-owned parent cgroup, as an absolute host path.
    #[must_use]
    pub fn cgroup_parent(&self) -> &Path {
        &self.cgroup_parent
    }

    /// The attempt-local directory the provider writes the bundle and the runtime
    /// state tree beneath.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// `linux.cgroupsPath`: the parent relative to the cgroup v2 mount point, with
    /// [`CONTAINER_LEAF`] appended — ABSOLUTE, because that is the one spelling
    /// youki 0.7.0 honours as a path (row 3 of this module's measurements: a
    /// relative one is refused as malformed by its systemd manager).
    #[must_use]
    pub fn cgroups_path(&self) -> PathBuf {
        let relative = self
            .cgroup_parent
            .strip_prefix(CGROUP_ROOT)
            // UNREACHABLE by construction: `new` refuses a parent that is not
            // strictly beneath the mount point. Written as a fallback rather than
            // an `expect` so a future constructor cannot turn a bad path into a
            // panic inside a plan producer.
            .unwrap_or(&self.cgroup_parent);
        Path::new("/").join(relative).join(CONTAINER_LEAF)
    }
}

/// Why a kata-owned parent cgroup could not be established.
///
/// Three arms, because an operator acts differently on each: the first is a HOST that
/// cannot enforce a bound this route requires (the recourse is the delegation
/// remediation `sandbox_bounds` already prints), and the second is an operation on a
/// hierarchy that should have worked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParentCgroupRefusal {
    /// A knob this route's bounds rest on was not PROVEN writable at the stage
    /// position by `measure_cgroup_delegation`'s round trip.
    UnprovenBound {
        /// The cgroup file that was not proven — `memory.max`, `memory.swap.max` or
        /// `pids.max`.
        knob: &'static str,
        /// What the delegation probe observed, in the observer's own words.
        evidence: String,
    },
    /// An operation on the cgroup hierarchy failed, in the OS's words.
    Os(String),
    /// The supervisor that would own this parent established NO sweep root, so there
    /// is no subtree kata sweeps and nowhere a container can be placed that a
    /// teardown could reach.
    ///
    /// Its own arm rather than an [`Self::Os`] carrying a sentence, because it is not
    /// an operation that failed: nothing was attempted. An operator's recourse is a
    /// DELEGATED cgroup (`systemd-run --user --scope -p Delegate=yes`, what
    /// `just _containment-preconditions` checks), which is a different action from
    /// either of the other two arms.
    NoSweepRoot,
}

impl ParentCgroupRefusal {
    /// Stable snake_case token — the log field and the metric dimension.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            ParentCgroupRefusal::UnprovenBound { .. } => "unproven_bound",
            ParentCgroupRefusal::Os(_) => "cgroup_operation_failed",
            ParentCgroupRefusal::NoSweepRoot => "no_sweep_root",
        }
    }
}

impl std::fmt::Display for ParentCgroupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParentCgroupRefusal::UnprovenBound { knob, evidence } => write!(
                f,
                "this host did not prove `{knob}` writable at the stage position, so the capsule's \
                 bound on that axis cannot be made to hold. ADR-0001's initial profile has no \
                 weaker-sandbox fallback and containment law reads a capability SKIP as a \
                 FAILURE, so the container is refused rather than started under a bound nobody \
                 applied. What the delegation probe observed: {evidence}"
            ),
            ParentCgroupRefusal::Os(why) => f.write_str(why),
            ParentCgroupRefusal::NoSweepRoot => f.write_str(
                "the provider supervisor established NO outer cgroup, so there is no subtree kata \
                 sweeps and nowhere to place a container that a teardown could reach. On this \
                 route an unplaced container is one nothing can tear down, so it is not started. \
                 A delegated cgroup is the recourse — `systemd-run --user --scope -p \
                 Delegate=yes` is what supplies one at zero privilege, and `just \
                 _containment-preconditions` is what checks it",
            ),
        }
    }
}

impl std::error::Error for ParentCgroupRefusal {}

/// The kata-owned parent cgroup for ONE container: created, populated with this
/// capsule's bounds, and removed when this value is dropped.
///
/// # Why kata creates it and the runtime does not
///
/// The runtime creates its own leaf and applies `linux.resources` there, and that
/// is not enough for two measured reasons. **Placement:** a leaf the runtime chose
/// is a leaf kata cannot sweep (rows 1 and 4). **Enforcement:** youki 0.7.0 does
/// not apply the swap half of `linux.resources.memory` to a cgroupfs leaf (row 2 —
/// the leaf reads `memory.swap.max: max` from a spec carrying `swap == limit`), so
/// a memory ceiling resting on the leaf alone is a throttle that spills into the
/// host's swap rather than a bound. cgroup v2 limits bind at every ancestor, so the
/// knobs written HERE are the enforced mechanism and the leaf's copy is defence in
/// depth.
#[derive(Debug)]
pub struct OciParentCgroup {
    path: PathBuf,
    knobs: Vec<(String, String)>,
}

impl OciParentCgroup {
    /// **PURE** — where [`Self::establish`] would create this container's parent.
    ///
    /// Split out so a caller can render the `config.json` (whose `linux.cgroupsPath`
    /// names a leaf beneath this path) BEFORE any directory exists. That ordering is
    /// what makes a refused PLAN leave no cgroup behind: creating the parent first and
    /// then discovering the capsule has no bundle means an `rmdir` in a `Drop` is the
    /// only thing standing between a refusal and residue, and a destructor's
    /// best-effort removal is a weaker guarantee than never having created it.
    ///
    /// It derives and nothing else — no `mkdir`, no read — so `establish`'s own
    /// refusals are unchanged and a caller cannot use this to skip them. The two are
    /// held to agreement by `establish` returning a value whose [`Self::path`] is this
    /// path.
    #[must_use]
    pub fn path_for(sweep_root: &Path, container_id: &str) -> PathBuf {
        sweep_root.join(format!("{PARENT_PREFIX}{container_id}"))
    }

    /// Create `<sweep_root>/kata.oci.<container_id>`, write every knob this host's
    /// delegation PROVED, and enable the controllers its leaf will need.
    ///
    /// # EVERY axis must be PROVEN, and a missing one is a refusal
    ///
    /// The knobs written here are the ENFORCED mechanism on this route — the runtime
    /// applies `memory.limit` and `pids.limit` to its own leaf and does not apply the
    /// swap half at all — so a parent short of one is a container running under a
    /// bound nobody applied while every layer answers `completed`. ADR-0001's initial
    /// profile has no weaker-sandbox fallback and the containment lane reads a
    /// capability SKIP as a FAILURE, so this refuses unless the memory controller,
    /// the swap denial ([`CgroupDelegation::swap_cap_usable`], because a ceiling a
    /// stage can spill past into swap is a throttle) and [`CgroupController::Pids`]
    /// were all proven by round trip.
    ///
    /// That is what makes `capsule_cgroup_knobs`' per-axis gate unreachable in
    /// production rather than silent: it still emits only proven knobs, and this
    /// refusal is why the emitted set is never short of the three.
    ///
    /// # Errors
    /// [`ParentCgroupRefusal::UnprovenBound`] for an axis this host did not prove,
    /// naming the knob; [`ParentCgroupRefusal::Os`] for the first operation on the
    /// hierarchy that failed, naming the path. A PARTIALLY populated parent is an
    /// error and not a warning: the leaf beneath it is where a stage runs, and a
    /// stage that started with half a bound is exactly the outcome `stage_cgroup`'s
    /// knob loop already refuses one plane over.
    pub fn establish(
        sweep_root: &Path,
        container_id: &str,
        delegation: &CgroupDelegation,
        budgets: &CapsuleBudgets,
    ) -> Result<Self, ParentCgroupRefusal> {
        // The AXES FIRST, before any directory exists: a refusal that had already
        // created a cgroup would leave residue for a container that was never
        // started.
        let unproven = if delegation.has(CgroupController::Memory) {
            if delegation.swap_cap_usable {
                None
            } else {
                Some(SWAP_MAX_KNOB)
            }
        } else {
            Some(CgroupController::Memory.knob())
        }
        .or_else(|| {
            (!delegation.has(CgroupController::Pids)).then(|| CgroupController::Pids.knob())
        });
        if let Some(knob) = unproven {
            return Err(ParentCgroupRefusal::UnprovenBound {
                knob,
                evidence: delegation.evidence.clone(),
            });
        }

        let path = Self::path_for(sweep_root, container_id);
        std::fs::create_dir(&path)
            .map_err(|e| ParentCgroupRefusal::Os(format!("mkdir {}: {e}", path.display())))?;
        let established = Self {
            path,
            knobs: capsule_cgroup_knobs(delegation, budgets),
        };
        for (knob, value) in &established.knobs {
            let file = established.path.join(knob);
            std::fs::write(&file, value).map_err(|e| {
                ParentCgroupRefusal::Os(format!("write {value} to {}: {e}", file.display()))
            })?;
        }
        // The controllers the LEAF needs, after the knobs: `subtree_control` is
        // about children and the knobs are about this cgroup, and a host that
        // refused one would otherwise be indistinguishable from a host that
        // refused the other.
        let subtree = established.path.join("cgroup.subtree_control");
        for controller in capsule_subtree_controllers(delegation) {
            std::fs::write(&subtree, format!("+{}", controller.token())).map_err(|e| {
                ParentCgroupRefusal::Os(format!(
                    "write +{token} to {file}: {e}. Without it the container's own leaf has no \
                     {token} knob, and the runtime's `linux.resources` write fails the container \
                     rather than the bound",
                    token = controller.token(),
                    file = subtree.display(),
                ))
            })?;
        }
        Ok(established)
    }

    /// The kata-owned parent directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The leaf the runtime will create inside it — derived, never read back, so a
    /// caller asserting about it is asserting about what kata PLANNED.
    #[must_use]
    pub fn leaf(&self) -> PathBuf {
        self.path.join(CONTAINER_LEAF)
    }

    /// The knob writes that were applied here, in order. For the posture surface
    /// and for a test that has to say which bound this host actually took.
    #[must_use]
    pub fn knobs(&self) -> &[(String, String)] {
        &self.knobs
    }
}

impl Drop for OciParentCgroup {
    /// # This usually runs AFTER `contain` has already removed the tree
    ///
    /// The supervisor's `contain` sweeps its whole sweep root and removes it
    /// depth-first once the emptiness is observed, and this value is typically held by
    /// the caller that owned the supervisor — so by the time it drops, both
    /// directories are usually already gone and both `rmdir`s are `NotFound`, which
    /// is tolerated silently. The ordering is deliberately NOT relied on in either
    /// direction: when this drops FIRST (a plan that was never assigned, a refused
    /// assignment) the removal here is the only one there will be, and when it drops
    /// last it is a no-op. What must not happen is dropping it while the container is
    /// alive: the `rmdir` would fail `EBUSY` and the caller would have discarded the
    /// only handle to the cgroup the stage is in.
    fn drop(&mut self) {
        // Leaf first: `rmdir` on a cgroup with a child is `EBUSY`. Both are
        // best-effort and logged rather than propagated, for `StageCgroup`'s
        // reason — a populated cgroup here means the container outlived the value
        // that named it, which is a TEARDOWN fact for `contain` to record and not
        // a cleanup failure to raise from a destructor.
        for path in [self.leaf(), self.path.clone()] {
            if let Err(e) = std::fs::remove_dir(&path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                // WARN and not DEBUG: every reason this can fail is one an operator
                // needs to see. `EBUSY` means the container outlived the value that
                // named it — residue in a subtree kata owns, with the only handle to
                // it now gone — and `EACCES` or `ENOTDIR` mean the hierarchy is not
                // what kata created. A destructor cannot raise them, so the log line
                // is the whole report, and one at `debug` is a report nobody reads.
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "oci parent cgroup NOT removed; a cgroup left under kata's sweep root is \
                     residue an operator reads as a live stage, and on EBUSY the container \
                     outlived the handle that named it"
                );
            }
        }
    }
}
