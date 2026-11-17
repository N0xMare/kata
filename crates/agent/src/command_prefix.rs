//! [`CommandPrefix`] — the wrapper argv, seccomp floor and resource bounds a
//! worker spawn site applies to a child it starts.

use std::ffi::OsString;

/// Ordered argv pieces that wrap a spawned child, plus the floor and bounds
/// installed on it.
///
/// The spawn site (`kata_worker::process::command_with_prefix`) builds:
///
/// ```text
/// <program> <args…> <the caller's own argv tail…>
/// ```
///
/// …with the resource bounds and the kata floor installed on the child. The production
/// prefix is the external execution provider's
/// (`kata_worker::provider_supervisor::provider_command_prefix`), carrying the
/// kata seccomp floor in `kata_floor_bpf`.
///
/// This struct is only constructed when real wrapping is happening — it's
/// never the "identity prefix."
#[derive(Clone, Debug, Default)]
pub struct CommandPrefix {
    /// argv\[0\] of the selected execution-provider wrapper.
    pub program: OsString,
    /// Flags passed to the wrapper, in order. Does NOT include the
    /// separator or the wrapped agent's argv.
    pub args: Vec<OsString>,
    /// The KATA FLOOR, loaded by **kata itself** in `pre_exec` onto
    /// the spawning child, **before `execve`**, carrying the `KataFloor` subset
    /// of `DENIED_SYSCALLS` only. (A capsule's own syscall fence is the OCI
    /// runtime's, inside its `config.json`.)
    ///
    /// The floor exists so kata does not have to trust the process it is about
    /// to `execve` to enforce anything: `PR_SET_NO_NEW_PRIVS` plus
    /// `seccomp(SECCOMP_SET_MODE_FILTER, …)` are issued between `fork` and
    /// `execve`, so the filter is inherited, survives the `execve`, and cannot
    /// be dropped. That is why the subset omits the `ConstructionResidue`
    /// entries: an external provider inherits this filter and must still be
    /// able to BUILD a sandbox.
    ///
    /// The bytes are `struct sock_filter[]` (native-endian); the spawn site
    /// (`kata_worker::process::command_with_prefix`) decodes them and issues
    /// the syscall. `None` is the SOLE "spawn without the floor" state, and
    /// there is no operator knob that produces it: an operator cannot ask for
    /// an unfloored external provider.
    ///
    /// **Who populates this.** Only the external provider spawn path,
    /// `kata_worker::provider_supervisor::provider_command_prefix`.
    pub kata_floor_bpf: Option<Vec<u8>>,
    /// The RESOLVED resource-bound instruction for the spawned child — a
    /// cgroup v2 to create and place the child into.
    ///
    /// Carried here rather than in the argv for the same reason
    /// [`Self::kata_floor_bpf`] is: neither can be expressed as an argv flag. A
    /// cgroup placement is a write to `cgroup.procs` from inside the post-`fork`
    /// child.
    ///
    /// EMPTY is the default and means the spawn site applies nothing. It is not
    /// a claim that anything is bounded. The only production value comes from
    /// `kata_worker::provider_supervisor::outer_cgroup_bounds`, passed to
    /// `provider_command_prefix`: an outer provider cgroup with no knobs, used
    /// to account membership at teardown. A stage's own bounds go on its
    /// per-container cgroup, not on this prefix.
    pub resource_bounds: crate::resource_bounds::ResourceBounds,
}
