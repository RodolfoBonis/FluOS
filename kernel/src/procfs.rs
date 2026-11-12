//! A minimal, dynamic `/proc` filesystem.
//!
//! Unlike the root tmpfs (a static inode tree in the `vfs` crate), procfs nodes
//! are *generated on access* from live kernel state: a read snapshots the
//! content at open time, and `/proc/<pid>/fd/N` resolves to the actual OPEN FILE
//! the target holds (not a path re-open), so a pipe handed in by shell process
//! substitution (`source <(cmd)` → `/proc/self/fd/13`) keeps working.
//!
//! The provider is consulted by the fs layer for any path under `/proc` (and the
//! `/dev/fd/N` alias). It is deliberately a standalone module so a future
//! per-container `/proc` can mount its own instance over the same machinery.

use crate::fs::{FileKind, OpenFile};
use crate::sync::SpinLock;
use abi::types;
use abi::Errno;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Whether `path` is owned by this provider.
#[must_use]
pub fn is_proc(path: &str) -> bool {
    path == "/proc" || path.starts_with("/proc/")
}

/// Attempts to open `path` as a procfs node (or the `/dev/fd/N` alias). Returns
/// `Some(result)` if this provider owns the path, else `None` (fall through to
/// the tmpfs).
pub fn open(path: &str, _flags: u64) -> Option<Result<Arc<SpinLock<OpenFile>>, Errno>> {
    if let Some(n) = path.strip_prefix("/dev/fd/") {
        return Some(open_fd(current_pid(), n));
    }
    if !is_proc(path) {
        return None;
    }
    Some(open_proc(path))
}

/// `stat`/`lstat` for a procfs path, if owned here.
pub fn stat(path: &str) -> Option<Result<types::Stat, Errno>> {
    if !is_proc(path) && !path.starts_with("/dev/fd/") {
        return None;
    }
    Some(stat_inner(path))
}

/// `readlink` for a procfs magic symlink (`/proc/self`, `/proc/<pid>/cwd`).
pub fn readlink(path: &str) -> Option<Result<String, Errno>> {
    if !is_proc(path) {
        return None;
    }
    Some(readlink_inner(path))
}

fn readlink_inner(path: &str) -> Result<String, Errno> {
    let comps = components(path);
    match comps.as_slice() {
        ["self"] => Ok(current_pid().to_string()),
        ["self", "cwd"] => cwd_of(current_pid()),
        [pid, "cwd"] => {
            let pid: i32 = pid.parse().map_err(|_| Errno::ENOENT)?;
            cwd_of(pid)
        }
        _ => Err(Errno::EINVAL),
    }
}

fn cwd_of(pid: i32) -> Result<String, Errno> {
    let p = proc_handle(pid)?;
    let cwd = p.lock().cwd;
    crate::fs::with_vfs(|v| v.path_of(cwd))
}

// --- resolution ------------------------------------------------------------

fn components(path: &str) -> Vec<&str> {
    let rest = path.strip_prefix("/proc").unwrap_or(path);
    rest.split('/').filter(|c| !c.is_empty()).collect()
}

fn current_pid() -> i32 {
    crate::process::current().map_or(0, |p| p.lock().pid)
}

/// Resolves a pid component (`self` or a number) to a live process handle.
fn proc_handle(pid: i32) -> Result<Arc<SpinLock<crate::process::Process>>, Errno> {
    crate::process::find(pid).ok_or(Errno::ENOENT)
}

/// `/proc/<pid>/fd/N` (and `/dev/fd/N`): a dup of the target's open file N.
fn open_fd(pid: i32, n: &str) -> Result<Arc<SpinLock<OpenFile>>, Errno> {
    let n: i32 = n.parse().map_err(|_| Errno::ENOENT)?;
    let p = proc_handle(pid)?;
    let f = p.lock().fds.get(n)?;
    Ok(f)
}

fn data_file(content: String) -> Arc<SpinLock<OpenFile>> {
    Arc::new(SpinLock::new(OpenFile {
        kind: FileKind::ProcData { data: Arc::new(content.into_bytes()), offset: 0 },
        flags: 0,
        readable: true,
        writable: false,
    }))
}

fn dir_file(entries: Vec<(String, u8)>) -> Arc<SpinLock<OpenFile>> {
    Arc::new(SpinLock::new(OpenFile {
        kind: FileKind::ProcDir { entries: Arc::new(entries), pos: 0 },
        flags: 0,
        readable: true,
        writable: false,
    }))
}

fn open_proc(path: &str) -> Result<Arc<SpinLock<OpenFile>>, Errno> {
    let comps = components(path);
    match comps.as_slice() {
        [] => Ok(dir_file(root_entries())),
        ["meminfo"] => Ok(data_file(meminfo())),
        ["cpuinfo"] => Ok(data_file(cpuinfo())),
        ["stat"] => Ok(data_file(sys_stat_file())),
        ["uptime"] => Ok(data_file(uptime())),
        ["loadavg"] => Ok(data_file(loadavg())),
        ["version"] => Ok(data_file(version())),
        ["mounts"] => Ok(data_file(mounts())),
        ["filesystems"] => Ok(data_file(filesystems())),
        ["fluos"] => Ok(dir_file(alloc::vec![("stats".to_string(), types::DT_REG)])),
        ["fluos", "stats"] => Ok(data_file(fluos_stats())),
        // Per-process nodes. `self` maps to the caller.
        ["self", rest @ ..] => open_pid(current_pid(), rest),
        [pid, rest @ ..] => {
            let pid: i32 = pid.parse().map_err(|_| Errno::ENOENT)?;
            open_pid(pid, rest)
        }
    }
}

fn open_pid(pid: i32, rest: &[&str]) -> Result<Arc<SpinLock<OpenFile>>, Errno> {
    let p = proc_handle(pid)?;
    match rest {
        [] => Ok(dir_file(pid_entries())),
        ["fd"] => {
            let fds = p.lock().fds.open_fd_numbers();
            Ok(dir_file(fds.into_iter().map(|n| (n.to_string(), types::DT_LNK)).collect()))
        }
        ["fd", n] => open_fd(pid, n),
        ["cmdline"] => Ok(data_file(pid_cmdline(&p))),
        ["comm"] => Ok(data_file(format!("{}\n", p.lock().comm))),
        ["stat"] => Ok(data_file(pid_stat(&p))),
        ["status"] => Ok(data_file(pid_status(&p))),
        _ => Err(Errno::ENOENT),
    }
}

// --- content generators ----------------------------------------------------

fn root_entries() -> Vec<(String, u8)> {
    let mut e: Vec<(String, u8)> = [
        "meminfo", "cpuinfo", "stat", "uptime", "loadavg", "version", "mounts",
        "filesystems",
    ]
    .iter()
    .map(|n| ((*n).to_string(), types::DT_REG))
    .collect();
    e.push(("self".to_string(), types::DT_LNK));
    e.push(("fluos".to_string(), types::DT_DIR));
    for pid in crate::process::pids() {
        e.push((pid.to_string(), types::DT_DIR));
    }
    e
}

fn pid_entries() -> Vec<(String, u8)> {
    [
        ("fd", types::DT_DIR),
        ("cmdline", types::DT_REG),
        ("comm", types::DT_REG),
        ("stat", types::DT_REG),
        ("status", types::DT_REG),
        ("cwd", types::DT_LNK),
    ]
    .iter()
    .map(|(n, t)| ((*n).to_string(), *t))
    .collect()
}

fn meminfo() -> String {
    let (free, total) = crate::mm::phys::stats();
    let free_kb = free * 4;
    let total_kb = total * 4;
    format!(
        "MemTotal:       {total_kb} kB\nMemFree:        {free_kb} kB\nMemAvailable:   {free_kb} kB\n"
    )
}

fn cpuinfo() -> String {
    let mut s = String::new();
    for i in 0..crate::percpu::count() {
        s += &format!(
            "processor\t: {i}\nvendor_id\t: FluOS\nmodel name\t: FluOS virtual CPU\n\n"
        );
    }
    s
}

fn sys_stat_file() -> String {
    let n = crate::percpu::count();
    let mut s = String::from("cpu  0 0 0 0 0 0 0 0 0 0\n");
    for i in 0..n {
        s += &format!("cpu{i} 0 0 0 0 0 0 0 0 0 0\n");
    }
    s += &format!("ctxt 0\nbtime 0\nprocesses {}\n", crate::process::pids().len());
    s
}

fn uptime() -> String {
    let ms = uptime_ms();
    let secs = ms / 1000;
    let cs = (ms % 1000) / 10;
    format!("{secs}.{cs:02} {secs}.{cs:02}\n")
}

fn uptime_ms() -> u64 {
    // SAFETY: `_rdtsc` reads the timestamp counter.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    tsc / crate::arch::x86_64::apic::tsc_per_ms()
}

fn loadavg() -> String {
    let n = crate::process::pids().len();
    format!("0.00 0.00 0.00 1/{n} {}\n", current_pid())
}

fn version() -> String {
    // Tools parse the leading "Linux version <x>"; keep that shape.
    "Linux version 6.6.0-fluos (FluOS) #1 SMP\n".to_string()
}

fn mounts() -> String {
    "rootfs / rootfs rw 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\n\
     devtmpfs /dev devtmpfs rw,nosuid 0 0\n"
        .to_string()
}

fn filesystems() -> String {
    "nodev\tproc\nnodev\tdevtmpfs\n\text4\n".to_string()
}

fn fluos_stats() -> String {
    let (free, total) = crate::mm::phys::stats();
    let mut s = format!("frames_free {free}\nframes_total {total}\n");
    for i in 0..crate::percpu::count() {
        if let Some(c) = crate::percpu::by_id(i) {
            use core::sync::atomic::Ordering::Relaxed;
            s += &format!(
                "cpu{i} switches {} steals {} now {}\n",
                c.switches.load(Relaxed),
                c.steals.load(Relaxed),
                c.now.load(Relaxed),
            );
        }
    }
    s
}

fn pid_cmdline(p: &SpinLock<crate::process::Process>) -> String {
    // We do not retain argv; approximate with the command name + NUL terminator
    // (the shape `/proc/<pid>/cmdline` callers expect).
    let g = p.lock();
    format!("{}\0", g.comm)
}

fn pid_stat(p: &SpinLock<crate::process::Process>) -> String {
    let g = p.lock();
    // A subset of the 52-field stat line; enough for `ps`/parsers that index the
    // early positions (pid, comm, state, ppid, pgrp, session). Remaining fields
    // are zeroed.
    let mut fields = format!("{} ({}) R {} {} {}", g.pid, g.comm, g.ppid, g.pgid, g.sid);
    for _ in 0..44 {
        fields += " 0";
    }
    fields.push('\n');
    fields
}

fn pid_status(p: &SpinLock<crate::process::Process>) -> String {
    let g = p.lock();
    format!(
        "Name:\t{}\nState:\tR (running)\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\n\
         Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\n",
        g.comm,
        g.pid,
        g.pid,
        g.ppid,
        uid = g.uid,
        gid = g.gid,
    )
}

// --- stat ------------------------------------------------------------------

fn stat_inner(path: &str) -> Result<types::Stat, Errno> {
    // Resolve by opening (cheap — content is generated anyway) and reading the
    // resulting node's kind/size.
    let file = if let Some(n) = path.strip_prefix("/dev/fd/") {
        return {
            let f = open_fd(current_pid(), n)?;
            // Mirror the underlying file's stat as best we can: report a pipe-ish
            // character node; callers of /dev/fd mostly just need isatty/size.
            let _ = f;
            Ok(char_stat())
        };
    } else {
        open_proc(path)?
    };
    let g = file.lock();
    let mut st = types::Stat::default();
    match &g.kind {
        FileKind::ProcDir { .. } => {
            st.st_mode = types::S_IFDIR | 0o555;
            st.st_nlink = 2;
        }
        FileKind::ProcData { data, .. } => {
            st.st_mode = types::S_IFREG | 0o444;
            st.st_nlink = 1;
            st.st_size = data.len() as i64;
        }
        _ => {
            // An fd dup (e.g. /proc/self/fd/N): report a character node.
            return Ok(char_stat());
        }
    }
    st.st_blksize = 4096;
    Ok(st)
}

fn char_stat() -> types::Stat {
    let mut st = types::Stat::default();
    st.st_mode = types::S_IFCHR | 0o600;
    st.st_blksize = 4096;
    st
}
