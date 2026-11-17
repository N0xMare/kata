//! The kernel's account of this process's Code Mode host threads: a witness
//! that shares no code with the adapter or the engine; and the one long native
//! step the cells use to keep such a thread running past a turn's end.

use std::collections::BTreeSet;

/// The ids of this process's live threads named for nanocode's QuickJS host
/// (`nanocode-code-mode-quickjs`, which the kernel's 15-byte `comm` cuts to
/// `nanocode-code-m`), read off `/proc`.
pub fn quickjs_threads() -> BTreeSet<u32> {
    std::fs::read_dir("/proc/self/task")
        .expect("/proc/self/task")
        .flatten()
        .filter(|task| {
            std::fs::read_to_string(task.path().join("comm"))
                .is_ok_and(|comm| comm.trim_end() == "nanocode-code-m")
        })
        .filter_map(|task| task.file_name().to_str()?.parse().ok())
        .collect()
}

/// The CPU time, in clock ticks (`utime` + `stime`), the kernel has charged this
/// process's thread `tid`; `None` once the thread is gone.
#[allow(dead_code)]
pub fn cpu_ticks(tid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
    // Fields after the parenthesised `comm`, which may itself hold spaces:
    // state is the first, utime the 12th and stime the 13th.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    Some(fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?)
}

/// One native step the interpreter's interrupt cannot reach: a
/// default-comparator sort of 200,000 references to two distinct 1 MiB strings
/// of equal bytes, so every compare is a whole 1 MiB `memcmp` (the strings are
/// two, not one: the same sort over one string's references returns in
/// microseconds). It holds about 10 MiB of heap, far below kata's Code Mode
/// heap limit, so its length is set by its compares and not by the heap.
/// MEASURED on rquickjs 0.14.0's QuickJS (the vendored engine's) on the lane's
/// host at load average 35 to 60: about 65 s, and 31 s at 100,000 references.
/// A cell that must outlive a turn's end needs it running about 7 s past its
/// start (its yield and timer, the failed model request, the shutdown's 5 s
/// grace, a 1 s witness), so a host nine times faster still holds it; a host
/// that ended it sooner turns an outlived-the-outcome witness red, never green.
#[allow(dead_code)]
pub const A_LONG_NATIVE_STEP: &str = "const one = \"x\".repeat(1 << 20);\n\
     const other = \"x\".repeat(1 << 20);\n\
     const strings = Array.from({ length: 200000 }, (_, i) => (i % 2 ? one : other));\n\
     strings.sort();\n\
     text(\"sorted\");";

/// The pids of this process's Code Mode interpreter processes, unreaped ones
/// included: its children (`/proc/self/task/<tid>/children`, one list per
/// thread that started any) started with `kata_code_mode_host::INTERPRETER_ARGS`,
/// and its zombies (whose `/proc/<pid>/cmdline` reads empty).
#[allow(dead_code)]
pub fn interpreters() -> BTreeSet<u32> {
    std::fs::read_dir("/proc/self/task")
        .expect("/proc/self/task")
        .flatten()
        .filter_map(|task| std::fs::read_to_string(task.path().join("children")).ok())
        .flat_map(|children| {
            children
                .split_whitespace()
                .filter_map(|pid| pid.parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
                cmdline.is_empty() || cmdline.ends_with(b"kata-code-mode-interpreter\0")
            })
        })
        .collect()
}

/// The CPU time, in clock ticks (`utime` + `stime`), the kernel has charged
/// process `pid`; `None` once it is gone.
#[allow(dead_code)]
pub fn process_cpu_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    Some(fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?)
}

/// What `list` reads once it lists at least `hosts` hosts: a sample taken on
/// the kernel's account of a host, not on a sleep, since an interpreter
/// process (or a QuickJS thread) starts on its own schedule, which host load
/// stretches. Unbounded: a caller bounds it.
#[allow(dead_code)]
pub async fn once_listed(hosts: usize, list: impl Fn() -> BTreeSet<u32>) -> BTreeSet<u32> {
    loop {
        let listed = list();
        if listed.len() >= hosts {
            return listed;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
