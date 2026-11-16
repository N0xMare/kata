//! The kernel's account of this process's memory: a witness that shares no
//! code with the adapter, the engine or the interpreter host. A cell that
//! fills its heap in THIS process lifts this process's resident high-water
//! mark by about what it filled; one that fills it in an interpreter process
//! lifts that process's instead.

/// This process's peak resident set (`VmHWM` in `/proc/self/status`), in
/// bytes.
pub fn peak_resident_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|kib| kib.trim().parse().ok())
        .expect("a VmHWM line in kB");
    kib * 1024
}
