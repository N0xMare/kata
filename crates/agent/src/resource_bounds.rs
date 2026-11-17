//! The RESOLVED resource-bound instruction a spawn site executes.
//!
//! # Why this is dumb data and not a decision
//!
//! Deciding *whether* a bound can be enforced on this host is a MEASUREMENT
//! (`kata_worker::sandbox_bounds`); replacing that measurement with an
//! inference — observing that a DIRECTORY EXISTS and concluding "cgroup
//! delegation: present" — yields claims wrong in opposite directions.
//!
//! So the split is deliberate. The worker MEASURES, folds the measurement into a
//! three-state verdict per axis, and emits this struct carrying only what is
//! left to *do*. The spawn site (`kata_worker::process`) executes it and
//! decides nothing: it cannot silently downgrade a bound, because it was never
//! given the inputs a downgrade would be derived from.
//!
//! That is the same shape [`CommandPrefix::kata_floor_bpf`] uses — the worker
//! decides whether a floor is requested, the spawn site installs it — and it is
//! chosen for the same reason: one producer, one consumer, no second spelling
//! of the predicate.
//!
//! [`CommandPrefix::kata_floor_bpf`]: crate::CommandPrefix::kata_floor_bpf

use std::path::PathBuf;

/// A per-stage cgroup v2 the spawn site must CREATE and place the child into.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CgroupPlan {
    /// Absolute path of the cgroup v2 directory the per-stage cgroup is created
    /// UNDER. Proven writable — the producer created and removed a scratch child
    /// here — not merely observed to exist.
    pub parent: PathBuf,
    /// Basename of the per-stage cgroup to create under [`Self::parent`].
    /// Unique per spawn; the spawn site removes it on teardown.
    pub name: String,
}

impl CgroupPlan {
    /// Absolute path of the per-stage cgroup this plan creates.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.parent.join(&self.name)
    }
}

/// Everything a spawn site must do to put a stage under its declared bounds.
///
/// Empty (`ResourceBounds::default()`) is the honest representation of "no bound
/// was declared, or none is enforceable here". It is NOT a claim that the stage
/// is unbounded by accident — the producer records that verdict, with evidence,
/// in the containment posture the operator reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceBounds {
    /// The per-stage cgroup, when cgroup v2 enforcement was MEASURED usable.
    pub cgroup: Option<CgroupPlan>,
}

impl ResourceBounds {
    /// Whether this plan asks the spawn site to do anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cgroup.is_none()
    }
}

/// How a teardown ended — and, crucially, whether anyone OBSERVED it end.
///
/// # Why a clean `Ok(())` was a defect
///
/// A teardown ladder that returned `Ok(())` from its grace-window-expired arm —
/// SIGKILL the process group, reap the direct child, report success without
/// ever asking whether the group was gone — would leave a caller unable to
/// distinguish "the subtree is provably empty" from "we sent
/// a signal and stopped looking", and the second was recorded as the first.
///
/// This mirrors the rule for timeouts — a timeout is
/// AMBIGUOUS, not a clean failure — and applies it to cancellation: a cancel
/// that could not observe the group's absence is [`Self::Ambiguous`], never a
/// success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TeardownOutcome {
    /// The group's absence was OBSERVED, by the probe named.
    Confirmed {
        /// What observation established the absence.
        probe: TeardownProbe,
        /// Wall-clock milliseconds from the first signal to the observation.
        elapsed_ms: u64,
    },
    /// The teardown could NOT be confirmed. Never a clean success.
    Ambiguous {
        /// Why the absence could not be established.
        reason: AmbiguousTeardown,
        /// Wall-clock milliseconds spent trying.
        elapsed_ms: u64,
    },
}

impl TeardownOutcome {
    /// Stable lowercase label — the metric dimension and the log field, so an
    /// operator greps one token across both.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            TeardownOutcome::Confirmed { .. } => "confirmed",
            TeardownOutcome::Ambiguous { .. } => "ambiguous",
        }
    }

    /// Whether the subtree's absence was established.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        matches!(self, TeardownOutcome::Confirmed { .. })
    }
}

/// The observation that established a subtree's absence.
///
/// Two probes, and they are NOT equally strong. Naming which one answered is the
/// point: an operator auditing a cancellation must be able to tell a cgroup
/// population read (authoritative — the kernel's own membership count) from a
/// signal probe (strong, but a statement about one process group id).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TeardownProbe {
    /// The stage's cgroup reported ZERO member processes. Authoritative: cgroup
    /// membership is the kernel's own accounting of the subtree, and it covers a
    /// descendant that left the process group (`setsid`) as well as one that
    /// stayed.
    CgroupPopulation,
    /// `killpg(pgid, 0)` returned `ESRCH` — no process remains in the group.
    /// Strong, and it cannot false-negative through pid reuse (reuse can only
    /// make a dead group look ALIVE, never the reverse), but it says nothing
    /// about a descendant that called `setsid(2)` and left the group.
    SignalProbe,
    /// The egress proxy's live-tunnel registry reported ZERO tunnels.
    ///
    /// Authoritative for exactly ONE thing and it must not be read as more: the
    /// accepted connections THIS proxy is still relaying. It says nothing about the
    /// processes at either end of a tunnel it already closed, and nothing about a
    /// socket some other component opened — the cgroup and signal probes above are
    /// the ones that answer about processes. Separate from both because a proxy has
    /// no process group and no cgroup of its own: it is tasks inside the worker, and
    /// the only observation that establishes their absence is its own count.
    EgressTunnelRegistry,
}

impl TeardownProbe {
    /// Stable lowercase label for logs and metrics.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            TeardownProbe::CgroupPopulation => "cgroup_population",
            TeardownProbe::SignalProbe => "signal_probe",
            TeardownProbe::EgressTunnelRegistry => "egress_tunnel_registry",
        }
    }
}

/// Why a teardown could not be confirmed.
///
/// Each variant is a DIFFERENT operational situation and they must not collapse
/// into one "failed" bucket: the first is a stage that outlived its kill, the
/// second is kata unable to look, the third is kata having nothing to look at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmbiguousTeardown {
    /// Members were still present when the observation budget expired. The
    /// subtree may have died a millisecond later; nobody saw it.
    StillPresentAtDeadline {
        /// What the last observation reported, in the observer's own words.
        observed: String,
    },
    /// The observation ITSELF failed — `EPERM` on the signal probe, an
    /// unreadable `cgroup.procs`. Kata cannot say whether the subtree is gone.
    Unobservable(String),
    /// No process group id was ever captured, so there is nothing to observe and
    /// nothing to claim. Recorded rather than treated as success: "we never had
    /// a handle" and "the handle's target is provably gone" are different facts.
    NoGroupCaptured,
}

impl AmbiguousTeardown {
    /// Stable lowercase discriminant for the metric dimension.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            AmbiguousTeardown::StillPresentAtDeadline { .. } => "still_present_at_deadline",
            AmbiguousTeardown::Unobservable(_) => "unobservable",
            AmbiguousTeardown::NoGroupCaptured => "no_group_captured",
        }
    }
}

impl std::fmt::Display for AmbiguousTeardown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmbiguousTeardown::StillPresentAtDeadline { observed } => {
                write!(
                    f,
                    "the observation budget expired with the subtree still present: {observed}"
                )
            }
            AmbiguousTeardown::Unobservable(why) => {
                write!(f, "the absence could not be observed: {why}")
            }
            AmbiguousTeardown::NoGroupCaptured => f.write_str(
                "no process group was captured, so there was nothing to observe — this is not \
                 evidence that the subtree is gone",
            ),
        }
    }
}
