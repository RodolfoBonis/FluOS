//! The Linux x86_64 syscall dispatcher.
//!
//! [`dispatch`] is called from the `syscall` entry assembly with the saved user
//! [`Regs`]. It decodes the number and arguments, runs the handler, and writes
//! the result (or negated errno) back into `rax`. Any syscall we do not yet
//! implement is logged once by name/number and returns `-ENOSYS`, which is our
//! observability for the next gaps while running real binaries.

use crate::arch::x86_64::user::Regs;
use crate::fs;
use crate::process::{self, Process};
use crate::sync::SpinLock;
use crate::usercopy::{self, copy_from_user, copy_to_user, put_user};
use abi::types;
use abi::{Errno, SysResult, errno, nr};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// Linux's cap on a single read/write length.
const MAX_RW: usize = 0x7fff_f000;
/// Bounded bounce-buffer size for streaming user copies (never user-controlled).
const BOUNCE: usize = 64 * 1024;

/// Entry from the syscall assembly: runs the handler and stores the result.
/// Temporary syscall trace (first N calls once armed) for shell bring-up.
pub static TRACE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub extern "C" fn dispatch(regs: &mut Regs) {
    let n = regs.rax;
    let a = regs.args();
    if TRACE.load(Ordering::Relaxed) > 0 {
        TRACE.fetch_sub(1, Ordering::Relaxed);
        let name = nr::name(n).unwrap_or("?");
        crate::log::info!("SYS {n} {name}({:#x},{:#x},{:#x})", a[0], a[1], a[2]);
    }
    let result = handle(n, a, regs);
    let restartable = matches!(result, Err(Errno::ERESTARTSYS));
    // ERESTARTSYS is internal: if no signal resolves it, fall back to EINTR.
    let encoded = match result {
        Err(Errno::ERESTARTSYS) => errno::encode(Err(Errno::ERESTARTSYS)),
        other => errno::encode(other),
    };
    regs.rax = encoded;
    // Deliver any pending signal on the way back to ring 3 (and resolve a
    // pending restart against the chosen disposition).
    crate::signal::on_syscall_return(regs, n, restartable);
    // If this process is doing a group exit, this thread tears itself down here
    // (it has just finished whatever syscall it was in / was woken from). The
    // last thread to die closes the shared fd table and reports the status.
    if process::current_group_exiting() {
        group_thread_exit();
    }
}

/// The current process, or `EFAULT` if there somehow is none.
fn proc() -> Result<&'static SpinLock<Process>, Errno> {
    process::current().ok_or(Errno::EFAULT)
}

/// `strace=` cmdline tracer. `strace=all` traces every process; `strace=<comm>`
/// traces only processes whose command name (execve basename) matches;
/// `strace=exec` logs only `execve` calls (path + argv). Off unless armed from
/// the kernel cmdline by [`strace_init`].
static STRACE_ON: AtomicBool = AtomicBool::new(false);
static STRACE_TARGET: SpinLock<alloc::string::String> = SpinLock::new(alloc::string::String::new());

/// Parses the kernel cmdline for `strace=<target>` and arms the tracer. Called
/// once at boot.
pub fn strace_init() {
    let cmdline = crate::boot::cmdline();
    for tok in cmdline.split_ascii_whitespace() {
        if let Some(val) = tok.strip_prefix("strace=") {
            if !val.is_empty() {
                *STRACE_TARGET.lock() = val.into();
                STRACE_ON.store(true, Ordering::Relaxed);
                crate::log::info!("strace: armed for target '{val}'");
            }
        }
    }
}

/// Whether the current process should be traced.
fn strace_matches() -> bool {
    if !STRACE_ON.load(Ordering::Relaxed) {
        return false;
    }
    let target = STRACE_TARGET.lock();
    if target.as_str() == "all" {
        return true;
    }
    if target.as_str() == "exec" {
        return false;
    }
    process::current().is_some_and(|p| p.lock().comm == *target)
}

/// Whether `strace=exec` is armed (log every execve, nothing else).
fn strace_exec_only() -> bool {
    STRACE_ON.load(Ordering::Relaxed) && STRACE_TARGET.lock().as_str() == "exec"
}

/// Human-readable name for the common syscall numbers (falls back to the raw nr).
fn sysname(nr: u64) -> &'static str {
    match nr {
        0 => "read", 1 => "write", 2 => "open", 3 => "close", 4 => "stat",
        5 => "fstat", 6 => "lstat", 7 => "poll", 8 => "lseek", 9 => "mmap",
        10 => "mprotect", 11 => "munmap", 12 => "brk", 13 => "rt_sigaction",
        14 => "rt_sigprocmask", 15 => "rt_sigreturn", 16 => "ioctl",
        19 => "readv", 20 => "writev", 21 => "access", 22 => "pipe",
        23 => "select", 25 => "mremap", 32 => "dup", 33 => "dup2",
        39 => "getpid", 56 => "clone", 57 => "fork", 59 => "execve",
        60 => "exit", 61 => "wait4", 62 => "kill", 63 => "uname",
        72 => "fcntl", 79 => "getcwd", 80 => "chdir", 82 => "rename",
        83 => "mkdir", 86 => "link", 87 => "unlink", 88 => "symlink",
        89 => "readlink", 90 => "chmod", 95 => "umask", 96 => "gettimeofday",
        97 => "getrlimit", 98 => "getrusage", 102 => "getuid", 104 => "getgid",
        107 => "geteuid", 108 => "getegid", 130 => "rt_sigsuspend",
        131 => "sigaltstack", 157 => "prctl", 158 => "arch_prctl",
        186 => "gettid", 202 => "futex", 217 => "getdents64",
        218 => "set_tid_address", 228 => "clock_gettime", 231 => "exit_group",
        257 => "openat", 258 => "mkdirat", 262 => "newfstatat", 263 => "unlinkat",
        264 => "renameat", 267 => "readlinkat", 269 => "faccessat",
        270 => "pselect6", 271 => "ppoll", 273 => "set_robust_list",
        275 => "splice", 281 => "epoll_pwait", 292 => "dup3", 293 => "pipe2",
        302 => "prlimit64", 318 => "getrandom", 334 => "rseq",
        _ => "?",
    }
}

fn handle(number: u64, a: [u64; 6], regs: &mut Regs) -> SysResult {
    if strace_matches() {
        crate::log::info!(
            "strace {}({}) a0={:#x} a1={:#x} a2={:#x}",
            sysname(number),
            number,
            a[0],
            a[1],
            a[2]
        );
    }
    match number {
        nr::WRITE => sys_write(a[0] as i32, a[1], a[2] as usize),
        nr::READ => sys_read(a[0] as i32, a[1], a[2] as usize),
        nr::WRITEV => sys_writev(a[0] as i32, a[1], a[2] as usize),
        nr::READV => sys_readv(a[0] as i32, a[1], a[2] as usize),
        nr::OPENAT => sys_openat(a[0] as i32, a[1], a[2], a[3] as u32),
        nr::OPEN => sys_openat(types::AT_FDCWD, a[0], a[1], a[2] as u32),
        nr::CLOSE => sys_close(a[0] as i32),
        nr::LSEEK => sys_lseek(a[0] as i32, a[1] as i64, a[2] as u32),
        nr::EXIT => sys_exit_thread(a[0] as i32),
        nr::EXIT_GROUP => sys_exit_group(a[0] as i32),
        nr::GETPID => sys_getpid(),
        nr::GETTID => sys_gettid(),
        nr::GETPPID => Ok(1),
        nr::GETUID | nr::GETEUID => Ok(u64::from(proc()?.lock().uid)),
        nr::GETGID | nr::GETEGID => Ok(u64::from(proc()?.lock().gid)),
        nr::SETUID => set_ids(id_arg(a[0]), None),
        nr::SETGID => set_ids(None, id_arg(a[0])),
        nr::SETREUID => set_ids(id_arg(a[1]).or(id_arg(a[0])), None),
        nr::SETREGID => set_ids(None, id_arg(a[1]).or(id_arg(a[0]))),
        nr::SETRESUID => set_ids(id_arg(a[1]).or(id_arg(a[0])).or(id_arg(a[2])), None),
        nr::SETRESGID => set_ids(None, id_arg(a[1]).or(id_arg(a[0])).or(id_arg(a[2]))),
        nr::GETRESUID => get_res_ids(proc()?.lock().uid, [a[0], a[1], a[2]]),
        nr::GETRESGID => get_res_ids(proc()?.lock().gid, [a[0], a[1], a[2]]),
        // One group per process: no supplementary groups.
        nr::GETGROUPS => Ok(0),
        nr::SETGROUPS => if proc()?.lock().uid == 0 { Ok(0) } else { Err(Errno::EPERM) },
        nr::MREMAP => sys_mremap(a[0], a[1], a[2], a[3]),
        nr::SETITIMER => sys_setitimer(a[0], a[1], a[2]),
        nr::GETITIMER => sys_getitimer(a[0], a[1]),
        nr::ALARM => sys_alarm(a[0]),
        nr::EVENTFD => sys_eventfd2(a[0], 0),
        nr::EVENTFD2 => sys_eventfd2(a[0], a[1]),
        // No network stack until M7: report the address family unsupported (Go
        // and curl fall back cleanly) rather than ENOSYS.
        nr::SOCKET => Err(Errno::EAFNOSUPPORT),
        // tee(2) only works between pipes; callers (uutils tee) fall back to
        // read/write on EINVAL.
        nr::TEE => Err(Errno::EINVAL),
        nr::ARCH_PRCTL => sys_arch_prctl(a[0], a[1]),
        nr::SET_TID_ADDRESS => sys_set_tid_address(a[0]),
        nr::BRK => sys_brk(a[0]),
        nr::MMAP => sys_mmap(a[0], a[1], a[2], a[3], a[4] as i32, a[5]),
        nr::MUNMAP => sys_munmap(a[0], a[1]),
        nr::MPROTECT => Ok(0),
        nr::IOCTL => sys_ioctl(a[0] as i32, a[1], a[2]),
        nr::UNAME => sys_uname(a[0]),
        nr::GETRANDOM => sys_getrandom(a[0], a[1] as usize),
        nr::CLOCK_GETTIME => sys_clock_gettime(a[0], a[1]),
        nr::GETTIMEOFDAY => sys_gettimeofday(a[0]),
        nr::TIME => sys_time(a[0]),
        nr::FSTAT => sys_fstat(a[0] as i32, a[1]),
        nr::NEWFSTATAT => sys_newfstatat(a[0] as i32, a[1], a[2], a[3] as i32),
        nr::STAT => sys_stat(a[0], a[1], true),
        nr::LSTAT => sys_stat(a[0], a[1], false),
        nr::GETDENTS64 => sys_getdents64(a[0] as i32, a[1], a[2] as usize),
        nr::GETCWD => sys_getcwd(a[0], a[1] as usize),
        nr::CHDIR => sys_chdir(a[0]),
        nr::MKDIR => sys_mkdirat(types::AT_FDCWD, a[0], a[1] as u32),
        nr::MKDIRAT => sys_mkdirat(a[0] as i32, a[1], a[2] as u32),
        nr::RENAME => sys_renameat(types::AT_FDCWD, a[0], types::AT_FDCWD, a[1]),
        nr::RENAMEAT => sys_renameat(a[0] as i32, a[1], a[2] as i32, a[3]),
        nr::RENAMEAT2 => sys_renameat(a[0] as i32, a[1], a[2] as i32, a[3]),
        nr::LINK => sys_linkat(types::AT_FDCWD, a[0], types::AT_FDCWD, a[1]),
        nr::LINKAT => sys_linkat(a[0] as i32, a[1], a[2] as i32, a[3]),
        nr::SYMLINK => sys_symlinkat(a[0], types::AT_FDCWD, a[1]),
        nr::SYMLINKAT => sys_symlinkat(a[0], a[1] as i32, a[2]),
        nr::UNLINK => sys_unlinkat(types::AT_FDCWD, a[0]),
        nr::UNLINKAT => sys_unlinkat(a[0] as i32, a[1]),
        nr::CHMOD => sys_fchmodat(types::AT_FDCWD, a[0], a[1] as u32),
        nr::SPLICE => sys_splice(a[0] as i32, a[1], a[2] as i32, a[3], a[4] as usize),
        nr::SETRLIMIT | nr::FADVISE64 => Ok(0),
        nr::FCHMODAT => sys_fchmodat(a[0] as i32, a[1], a[2] as u32),
        nr::READLINK => sys_readlinkat(types::AT_FDCWD, a[0], a[1], a[2] as usize),
        nr::READLINKAT => sys_readlinkat(a[0] as i32, a[1], a[2], a[3] as usize),
        nr::UMASK => sys_umask(a[0] as u32),
        nr::GETRUSAGE => sys_getrusage(a[0] as i32, a[1]),
        nr::SIGALTSTACK => sys_sigaltstack(a[0], a[1]),
        nr::RT_SIGSUSPEND => sys_rt_sigsuspend(a[0], a[1] as usize),
        nr::PRCTL => Ok(0),
        nr::DUP => dup(a[0] as i32),
        nr::DUP2 => dup2(a[0] as i32, a[1] as i32),
        nr::DUP3 => dup3(a[0] as i32, a[1] as i32, a[2]),
        nr::FCNTL => sys_fcntl(a[0] as i32, a[1], a[2]),
        nr::SCHED_YIELD => {
            crate::scheduler::yield_now();
            Ok(0)
        }
        nr::SCHED_GETAFFINITY => sys_sched_getaffinity(a[2], a[1] as usize),
        nr::SCHED_SETAFFINITY => sys_sched_setaffinity(a[0] as i32, a[1] as usize, a[2]),
        nr::SET_ROBUST_LIST | nr::RSEQ => Ok(0),
        nr::RT_SIGACTION => sys_rt_sigaction(a[0] as i32, a[1], a[2], a[3] as usize),
        nr::RT_SIGPROCMASK => sys_rt_sigprocmask(a[0] as i32, a[1], a[2], a[3] as usize),
        nr::RT_SIGRETURN => crate::signal::sys_rt_sigreturn(regs),
        nr::PRLIMIT64 => sys_prlimit64(a[2], a[3]),
        nr::GETRLIMIT => sys_getrlimit(a[1]),
        nr::POLL => sys_poll(a[0], a[1] as usize, PollTimeout::Millis(a[2] as i64)),
        nr::PPOLL => sys_ppoll(a[0], a[1] as usize, a[2]),
        nr::SELECT => sys_select(a[0] as i32, a[1], a[2], a[3], a[4]),
        nr::PSELECT6 => sys_pselect6(a[0] as i32, a[1], a[2], a[3], a[4]),
        nr::NANOSLEEP => sys_nanosleep(a[0], a[1]),
        nr::CLOCK_NANOSLEEP => sys_nanosleep(a[2], a[3]),
        nr::FUTEX => sys_futex(a[0], a[1] as u32, a[2] as u32),
        nr::SENDFILE => sys_sendfile(a[0] as i32, a[1] as i32, a[2], a[3] as usize),
        nr::PIPE => sys_pipe2(a[0], 0),
        nr::PIPE2 => sys_pipe2(a[0], a[1]),
        nr::KILL => sys_kill(a[0] as i32, a[1] as i32),
        nr::TKILL => sys_tkill(a[0] as i32, a[1] as i32),
        nr::TGKILL => sys_tkill(a[1] as i32, a[2] as i32),
        nr::WAIT4 => sys_wait4(a[0] as i32, a[1], a[2] as u32),
        nr::FORK | nr::VFORK => sys_fork(regs),
        nr::CLONE => sys_clone(a[0], a[1], a[2], a[3], a[4], regs),
        nr::EXECVE => sys_execve(a[0], a[1], a[2]),
        nr::ACCESS => sys_access(types::AT_FDCWD, a[0]),
        nr::FACCESSAT => sys_access(a[0] as i32, a[1]),
        nr::GETPGRP => Ok(proc()?.lock().pgid as u64),
        nr::GETPGID => sys_getpgid(a[0] as i32),
        nr::SETPGID => sys_setpgid(a[0] as i32, a[1] as i32),
        nr::SETSID => sys_setsid(),
        nr::GETSID => Ok(proc()?.lock().sid as u64),
        _ => {
            log_enosys(number);
            Err(Errno::ENOSYS)
        }
    }
}

// --- process state helpers -------------------------------------------------

/// getpid round-trip benchmark state.
static BENCH_N: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BENCH_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BENCH_T0: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static BENCH_CYCLES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Arms the getpid round-trip benchmark for `n` calls.
pub fn bench_arm(n: u64) {
    BENCH_CYCLES.store(0, Ordering::Relaxed);
    BENCH_COUNT.store(0, Ordering::Relaxed);
    BENCH_N.store(n, Ordering::Release);
}

/// Returns the measured cycles-per-getpid (0 until the benchmark completes).
pub fn bench_result() -> u64 {
    BENCH_CYCLES.load(Ordering::Acquire)
}

fn sys_getpid() -> SysResult {
    let n = BENCH_N.load(Ordering::Relaxed);
    if n != 0 {
        let c = BENCH_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        // SAFETY: `_rdtsc` reads the timestamp counter.
        let now = unsafe { core::arch::x86_64::_rdtsc() };
        if c == 1 {
            BENCH_T0.store(now, Ordering::Relaxed);
        } else if c == n {
            let t0 = BENCH_T0.load(Ordering::Relaxed);
            BENCH_CYCLES.store((now - t0) / n, Ordering::Release);
            BENCH_N.store(0, Ordering::Release);
        }
    }
    Ok(cur_pid()? as u64)
}

fn sys_getpgid(pid: i32) -> SysResult {
    let p = proc()?.lock();
    if pid == 0 || pid == p.pid { Ok(p.pgid as u64) } else { Err(Errno::ESRCH) }
}

fn sys_setpgid(pid: i32, pgid: i32) -> SysResult {
    if pgid < 0 {
        return Err(Errno::EINVAL);
    }
    let self_pid = proc()?.lock().pid;
    let target = if pid == 0 { self_pid } else { pid };
    let newpg = if pgid == 0 { target } else { pgid };
    if target == self_pid {
        proc()?.lock().pgid = newpg;
        return Ok(0);
    }
    // POSIX allows a parent to set a child's group (before it execs); a shell
    // does this from both sides of `fork` to start a job's group race-free.
    process::with_pid(target, |c| {
        if c.ppid == self_pid {
            c.pgid = newpg;
            Ok(())
        } else {
            Err(Errno::ESRCH)
        }
    })
    .unwrap_or(Err(Errno::ESRCH))
    .map(|()| 0)
}

fn sys_setsid() -> SysResult {
    let mut p = proc()?.lock();
    p.sid = p.pid;
    p.pgid = p.pid;
    Ok(p.pid as u64)
}

fn cur_pid() -> Result<i32, Errno> {
    Ok(proc()?.lock().pid)
}

fn fd(fd: i32) -> Result<Arc<SpinLock<fs::OpenFile>>, Errno> {
    proc()?.lock().fds.get(fd)
}

// --- file I/O --------------------------------------------------------------

fn sys_write(fd_num: i32, buf: u64, len: usize) -> SysResult {
    let file = fd(fd_num)?;
    let len = len.min(MAX_RW);
    let mut total = 0usize;
    while total < len {
        let n = (len - total).min(BOUNCE);
        let mut chunk = vec![0u8; n];
        copy_from_user(buf + total as u64, &mut chunk)?;
        let w = fs::write(&file, &chunk)? as usize;
        total += w;
        if w < n {
            break; // short write
        }
    }
    Ok(total as u64)
}

fn sys_read(fd_num: i32, buf: u64, len: usize) -> SysResult {
    let file = fd(fd_num)?;
    let n = len.min(BOUNCE);
    let mut data = vec![0u8; n];
    let got = fs::read(&file, &mut data)? as usize;
    copy_to_user(buf, &data[..got])?;
    Ok(got as u64)
}

fn sys_writev(fd_num: i32, iov: u64, count: usize) -> SysResult {
    let file = fd(fd_num)?;
    let mut total = 0u64;
    for i in 0..count {
        let mut raw = [0u8; 16];
        copy_from_user(iov + (i * 16) as u64, &mut raw)?;
        let base = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let ilen = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;
        if ilen == 0 {
            continue;
        }
        let ilen = ilen.min(MAX_RW);
        let mut written = 0usize;
        while written < ilen {
            let n = (ilen - written).min(BOUNCE);
            let mut chunk = vec![0u8; n];
            copy_from_user(base + written as u64, &mut chunk)?;
            let w = fs::write(&file, &chunk)? as usize;
            written += w;
            total += w as u64;
            if w < n {
                break;
            }
        }
    }
    Ok(total)
}

fn sys_readv(fd_num: i32, iov: u64, count: usize) -> SysResult {
    let file = fd(fd_num)?;
    let mut total = 0u64;
    for i in 0..count {
        let mut raw = [0u8; 16];
        copy_from_user(iov + (i * 16) as u64, &mut raw)?;
        let base = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let ilen = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;
        if ilen == 0 {
            continue;
        }
        let n = ilen.min(BOUNCE);
        let mut data = vec![0u8; n];
        let got = fs::read(&file, &mut data)? as usize;
        copy_to_user(base, &data[..got])?;
        total += got as u64;
        if got < n {
            break;
        }
    }
    Ok(total)
}

fn sys_openat(dirfd: i32, path: u64, flags: u64, mode: u32) -> SysResult {
    let path = read_path(path)?;
    let (base, umask) = {
        let g = proc()?.lock();
        (dirfd_base(&g, dirfd, &path)?, g.umask)
    };
    let mode = if flags & types::O_CREAT != 0 { (mode & !umask) & 0o777 } else { mode };
    let file = fs::open(base, &path, flags, mode)?;
    Ok(proc()?.lock().fds.alloc_with(file, flags & types::O_CLOEXEC != 0) as u64)
}

/// Resolves the directory a `*at` syscall path is relative to: the cwd for an
/// absolute path or `AT_FDCWD`, otherwise the directory the given fd is open on.
fn dirfd_base(g: &Process, dirfd: i32, path: &str) -> Result<vfs::Ino, Errno> {
    if path.starts_with('/') || dirfd == types::AT_FDCWD {
        return Ok(g.cwd);
    }
    let file = g.fds.get(dirfd)?;
    let f = file.lock();
    match &f.kind {
        fs::FileKind::Dir { ino, .. } => Ok(*ino),
        _ => Err(Errno::ENOTDIR),
    }
}

fn sys_close(fd_num: i32) -> SysResult {
    proc()?.lock().fds.close(fd_num)?;
    Ok(0)
}

fn sys_lseek(fd_num: i32, off: i64, whence: u32) -> SysResult {
    const SEEK_SET: u32 = 0;
    const SEEK_CUR: u32 = 1;
    const SEEK_END: u32 = 2;
    let file = fd(fd_num)?;
    let mut f = file.lock();
    match &mut f.kind {
        fs::FileKind::File { ino, offset } => {
            let size = fs::with_vfs(|v| v.size(*ino))? as i64;
            let base = match whence {
                SEEK_SET => 0,
                SEEK_CUR => *offset as i64,
                SEEK_END => size,
                _ => return Err(Errno::EINVAL),
            };
            let new = base + off;
            if new < 0 {
                return Err(Errno::EINVAL);
            }
            *offset = new as u64;
            Ok(new as u64)
        }
        // Devices and directories are not seekable.
        _ => Err(Errno::ESPIPE),
    }
}

fn dup(old: i32) -> SysResult {
    Ok(proc()?.lock().fds.dup(old)? as u64)
}

/// `dup2(old, new)`: like dup3 without flags, and `old == new` is a no-op
/// that only validates `old`.
fn dup2(old: i32, new: i32) -> SysResult {
    let p = proc()?;
    let mut g = p.lock();
    if old == new {
        g.fds.get(old)?;
        return Ok(new as u64);
    }
    Ok(g.fds.dup3(old, new, false)? as u64)
}

/// `dup3(old, new, flags)`: `O_CLOEXEC` is the only flag; `old == new` is EINVAL.
fn dup3(old: i32, new: i32, flags: u64) -> SysResult {
    if old == new || flags & !types::O_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(proc()?.lock().fds.dup3(old, new, flags & types::O_CLOEXEC != 0)? as u64)
}

fn sys_fcntl(fd_num: i32, cmd: u64, arg: u64) -> SysResult {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const FD_CLOEXEC: u64 = 1;
    // Status flags F_SETFL may change; the access mode and creation flags stay.
    const SETFL_MASK: u64 = types::O_NONBLOCK | types::O_APPEND;
    match cmd {
        F_DUPFD => proc()?.lock().fds.dup_from(fd_num, arg as i32, false),
        F_DUPFD_CLOEXEC => proc()?.lock().fds.dup_from(fd_num, arg as i32, true),
        F_GETFD => Ok(u64::from(proc()?.lock().fds.cloexec(fd_num)?)),
        F_SETFD => {
            proc()?.lock().fds.set_cloexec(fd_num, arg & FD_CLOEXEC != 0)?;
            Ok(0)
        }
        F_GETFL => {
            let file = fd(fd_num)?;
            let f = file.lock();
            let access = match (f.readable, f.writable) {
                (true, true) => types::O_RDWR,
                (false, true) => types::O_WRONLY,
                _ => types::O_RDONLY,
            };
            Ok(access | (f.flags & SETFL_MASK))
        }
        F_SETFL => {
            let file = fd(fd_num)?;
            let mut f = file.lock();
            f.flags = (f.flags & !SETFL_MASK) | (arg & SETFL_MASK);
            Ok(0)
        }
        // Locks (F_GETLK/F_SETLK/F_SETLKW) and the rest: accepted as no-ops;
        // FluOS has a single user session and no advisory locking yet.
        _ => Ok(0),
    }
}

// --- memory ----------------------------------------------------------------

fn sys_brk(addr: u64) -> SysResult {
    let p = proc()?;
    let mut g = p.lock();
    if g.brk_start == 0 {
        // Lazily anchor the heap just above the mmap region base if unset.
        g.brk_start = g.brk.max(0x5000_0000);
        g.brk = g.brk_start;
    }
    // Query, or a request below the heap base: report the current break.
    if addr == 0 || addr < g.brk_start {
        return Ok(g.brk);
    }
    // The new break must stay within the user half; otherwise leave the break
    // unchanged (Linux returns the old value rather than failing).
    if addr >= crate::usercopy::USER_MAX {
        return Ok(g.brk);
    }
    let old = g.brk;
    if addr > old {
        let grow = addr - old; // addr > old: no underflow
        // Reserve lazily: pages are faulted in (zeroed) on first touch.
        g.space.reserve_region(old, grow, true, false);
    }
    g.brk = addr;
    Ok(addr)
}

/// `munmap(addr, len)`: unmaps the range and reclaims its frames. In a shared
/// (CLONE_VM) address space, a TLB shootdown precedes reuse so a peer CPU cannot
/// write a freed-then-recycled frame through a stale entry (use-after-free).
fn sys_munmap(addr: u64, len: u64) -> SysResult {
    if addr & 0xfff != 0 {
        return Err(Errno::EINVAL);
    }
    let p = proc()?;
    let (shared, frames) = {
        let mut g = p.lock();
        let shared = g.thread_count > 1;
        let frames = g.space.unmap_region(addr, len);
        (shared, frames)
    };
    // Flush peers BEFORE freeing, so a stale entry can't reach a recycled frame.
    if shared {
        crate::mm::paging::shootdown_all();
    }
    for f in frames {
        crate::mm::phys::free_user_frame(f);
    }
    Ok(0)
}

/// `mremap(old, old_size, new_size, flags, new_addr)` for anonymous mappings.
/// Shrinks in place, grows in place when the following pages are free, or moves
/// (with `MREMAP_MAYMOVE`) by relocating page-table entries, not data. An
/// address range that is not fully mapped yields `EFAULT`; a blocked in-place
/// grow yields `ENOMEM` (musl probes the main-thread stack size this way).
fn sys_mremap(old: u64, old_size: u64, new_size: u64, flags: u64) -> SysResult {
    const MREMAP_MAYMOVE: u64 = 1;
    const PAGE: u64 = 4096;
    if old & (PAGE - 1) != 0 || new_size == 0 || old_size == 0 || flags & !MREMAP_MAYMOVE != 0 {
        return Err(Errno::EINVAL);
    }
    let round = |v: u64| v.checked_add(PAGE - 1).map(|x| x & !(PAGE - 1)).ok_or(Errno::EINVAL);
    let (old_size, new_size) = (round(old_size)?, round(new_size)?);
    let user_max = crate::usercopy::USER_MAX;
    let old_end = old.checked_add(old_size).ok_or(Errno::EINVAL)?;
    if old_end > user_max {
        return Err(Errno::EFAULT);
    }
    let p = proc()?;
    let mut g = p.lock();
    if !(old..old_end).step_by(PAGE as usize).all(|a| g.space.page_in_use(a)) {
        return Err(Errno::EFAULT);
    }
    if new_size <= old_size {
        let frames = g.space.unmap_region(old + new_size, old_size - new_size);
        let shared = g.thread_count > 1;
        drop(g);
        x86_64::instructions::tlb::flush_all();
        if shared {
            crate::mm::paging::shootdown_all();
        }
        for f in frames {
            crate::mm::phys::free_user_frame(f);
        }
        return Ok(old);
    }
    let writable = g.space.page_writable(old);
    let grow_end = old.checked_add(new_size).ok_or(Errno::ENOMEM)?;
    let tail_free = grow_end <= user_max
        && (old_end..grow_end).step_by(PAGE as usize).all(|a| !g.space.page_in_use(a));
    if tail_free {
        g.space.reserve_region(old_end, new_size - old_size, writable, false);
        return Ok(old);
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return Err(Errno::ENOMEM);
    }
    let base = g.mmap_next;
    let next = base.checked_add(new_size).ok_or(Errno::ENOMEM)?;
    if next > user_max {
        return Err(Errno::ENOMEM);
    }
    g.mmap_next = next;
    g.space.move_range(old, base, old_size);
    g.space.reserve_region(base + old_size, new_size - old_size, writable, false);
    let shared = g.thread_count > 1;
    drop(g);
    x86_64::instructions::tlb::flush_all();
    if shared {
        crate::mm::paging::shootdown_all();
    }
    Ok(base)
}

/// `struct itimerval` is two `struct timeval {i64 sec; i64 usec}`: interval, value.
fn read_itimerval(uaddr: u64) -> Result<(u64, u64), Errno> {
    let mut b = [0u8; 32];
    copy_from_user(uaddr, &mut b)?;
    let field = |i: usize| i64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
    let to_ms = |sec: i64, usec: i64| -> Result<u64, Errno> {
        if sec < 0 || !(0..1_000_000).contains(&usec) {
            return Err(Errno::EINVAL);
        }
        Ok((sec as u64).saturating_mul(1000) + (usec as u64).div_ceil(1000))
    };
    Ok((to_ms(field(2), field(3))?, to_ms(field(0), field(1))?))
}

fn write_itimerval(uaddr: u64, value_ms: u64, interval_ms: u64) -> Result<(), Errno> {
    let mut b = [0u8; 32];
    for (i, v) in [interval_ms / 1000, (interval_ms % 1000) * 1000, value_ms / 1000, (value_ms % 1000) * 1000]
        .into_iter()
        .enumerate()
    {
        b[i * 8..i * 8 + 8].copy_from_slice(&(v as i64).to_le_bytes());
    }
    copy_to_user(uaddr, &b)
}

/// Only `ITIMER_REAL` (0) is supported; the CPU-time timers are EINVAL.
fn sys_setitimer(which: u64, new: u64, old: u64) -> SysResult {
    if which != 0 {
        return Err(Errno::EINVAL);
    }
    let (value_ms, interval_ms) = if new == 0 { (0, 0) } else { read_itimerval(new)? };
    let pid = proc()?.lock().pid;
    let (old_value, old_interval) = crate::itimer::set(pid, value_ms, interval_ms);
    if old != 0 {
        write_itimerval(old, old_value, old_interval)?;
    }
    Ok(0)
}

fn sys_getitimer(which: u64, cur: u64) -> SysResult {
    if which != 0 {
        return Err(Errno::EINVAL);
    }
    let pid = proc()?.lock().pid;
    let (value_ms, interval_ms) = crate::itimer::get(pid);
    write_itimerval(cur, value_ms, interval_ms)?;
    Ok(0)
}

/// `alarm(secs)`: one-shot real timer; returns the seconds left on the old one.
fn sys_alarm(secs: u64) -> SysResult {
    let pid = proc()?.lock().pid;
    let (old_ms, _) = crate::itimer::set(pid, secs.saturating_mul(1000), 0);
    Ok(old_ms.div_ceil(1000))
}

/// `eventfd2(initval, flags)`: EFD_SEMAPHORE (1), EFD_NONBLOCK, EFD_CLOEXEC.
fn sys_eventfd2(init: u64, flags: u64) -> SysResult {
    const EFD_SEMAPHORE: u64 = 1;
    let allowed = EFD_SEMAPHORE | types::O_NONBLOCK | types::O_CLOEXEC;
    if flags & !allowed != 0 || init > u64::from(u32::MAX) {
        return Err(Errno::EINVAL);
    }
    let file = fs::make_eventfd(init as u32, flags & EFD_SEMAPHORE != 0, flags & types::O_NONBLOCK);
    Ok(proc()?.lock().fds.alloc_with(file, flags & types::O_CLOEXEC != 0) as u64)
}

/// Credential syscalls. FluOS keeps one uid and one gid per process (real ==
/// effective == saved), so the `res`/`re` variants collapse onto them. Only
/// root may change identity; anyone may "set" their current ids (what zsh's
/// `unsetopt privileged` and login shells do).
fn set_ids(uid: Option<u32>, gid: Option<u32>) -> SysResult {
    let p = proc()?;
    let mut g = p.lock();
    let allowed = |cur: u32, want: Option<u32>| want.is_none_or(|w| w == cur);
    if g.uid != 0 && !(allowed(g.uid, uid) && allowed(g.gid, gid)) {
        return Err(Errno::EPERM);
    }
    if let Some(u) = uid {
        g.uid = u;
    }
    if let Some(gi) = gid {
        g.gid = gi;
    }
    Ok(0)
}

/// Maps a `-1` ("unchanged") id argument to `None`.
fn id_arg(v: u64) -> Option<u32> {
    let v = v as u32;
    (v != u32::MAX).then_some(v)
}

/// `getresuid`/`getresgid`: writes the single id to all three pointers.
fn get_res_ids(id: u32, ptrs: [u64; 3]) -> SysResult {
    for ptr in ptrs {
        if ptr != 0 {
            put_user(ptr, id)?;
        }
    }
    Ok(0)
}

fn sys_mmap(addr: u64, len: u64, _prot: u64, flags: u64, _fd: i32, _off: u64) -> SysResult {
    if len == 0 || len > MAX_RW as u64 {
        return Err(Errno::EINVAL);
    }
    let p = proc()?;
    let mut g = p.lock();
    let page = 4096u64;
    // Page-round the length, rejecting overflow.
    let size = len
        .checked_add(page - 1)
        .map(|v| v & !(page - 1))
        .ok_or(Errno::EINVAL)?;
    let user_max = crate::usercopy::USER_MAX;
    let base = if flags & types::MAP_FIXED != 0 && addr != 0 {
        // Honor a fixed hint only if page-aligned and fully inside the user
        // half (checked end, no wrap into the kernel range).
        if addr & (page - 1) != 0 {
            return Err(Errno::EINVAL);
        }
        let end = addr.checked_add(size).ok_or(Errno::EINVAL)?;
        if end > user_max {
            return Err(Errno::EINVAL);
        }
        addr
    } else {
        let b = g.mmap_next;
        let next = b.checked_add(size).ok_or(Errno::ENOMEM)?;
        if next > user_max {
            return Err(Errno::ENOMEM);
        }
        g.mmap_next = next;
        b
    };
    // Anonymous mapping: reserve lazily (demand-paged, zero-filled).
    g.space.reserve_region(base, size, true, false);
    Ok(base)
}

// --- process / misc --------------------------------------------------------

/// `exit`: terminates only the calling thread. If it is the last thread in the
/// group, the group's exit status is recorded and the parent notified. A
/// clone(CLONE_CHILD_CLEARTID) thread clears its child-tid word and futex-wakes
/// it (how `pthread_join` observes completion).
fn sys_exit_thread(code: i32) -> SysResult {
    // SAFETY: `current()` is this CPU's running thread.
    let clear = unsafe { (*crate::percpu::current()).clear_child_tid };
    if clear != 0 {
        let _ = put_user(clear, 0u32);
        futex_wake(clear);
    }
    let (last, ppid, fds) = if let Some(p) = process::current() {
        let mut g = p.lock();
        g.thread_count = g.thread_count.saturating_sub(1);
        let last = g.thread_count == 0;
        if last {
            g.exit_code = Some(code);
        }
        // On the last thread, take the fd table so its files close now (peers
        // blocked on a pipe/pty get EOF/EPIPE immediately, not only on reap).
        let fds = if last { Some(g.fds.take_all()) } else { None };
        (last, g.ppid, fds)
    } else {
        (false, 0, None)
    };
    drop(fds); // close files outside the process lock
    if last {
        crate::signal::notify_parent(ppid);
        process::notify_child_exit();
        crate::log::info!("process exited with status {code}");
    }
    crate::scheduler::thread_exit();
}

/// `exit_group`: terminates the WHOLE thread group. Marks the group exiting,
/// wakes/preempts every sibling (so a thread blocked in futex/poll/read/sleep
/// returns and dies at the dispatcher's group-exit check), then tears down this
/// calling thread. The LAST thread to die closes the shared fd table — which is
/// what closes a pipe's write end so a reader (e.g. a shell waiting on
/// `eval "$(cmd)"`) finally gets EOF, even when `cmd` is multithreaded.
fn sys_exit_group(code: i32) -> SysResult {
    if let Some(p) = process::current() {
        {
            let mut g = p.lock();
            if g.group_exit.is_none() {
                g.group_exit = Some(code);
                g.exit_code = Some(code);
            }
        }
        let proc_ptr = core::ptr::from_ref(p) as u64;
        crate::scheduler::kick_group(proc_ptr);
    }
    group_thread_exit();
}

/// Tears down the calling thread as part of a group exit (or a normal last-thread
/// exit): clears its child-tid futex, decrements the live-thread count, and — on
/// the LAST thread — closes the shared fd table (outside the lock, so pipe/pty
/// peers get EOF/EPIPE immediately), notifies the parent, and logs the status.
fn group_thread_exit() -> ! {
    // SAFETY: `current()` is this CPU's running thread.
    let clear = unsafe { (*crate::percpu::current()).clear_child_tid };
    if clear != 0 {
        let _ = put_user(clear, 0u32);
        futex_wake(clear);
    }
    let (last, ppid, code, fds) = if let Some(p) = process::current() {
        let mut g = p.lock();
        g.thread_count = g.thread_count.saturating_sub(1);
        let last = g.thread_count == 0;
        let code = g.exit_code.unwrap_or(0);
        let fds = if last { Some(g.fds.take_all()) } else { None };
        (last, g.ppid, code, fds)
    } else {
        (false, 0, 0, None)
    };
    drop(fds); // close files outside the process lock
    if last {
        crate::signal::notify_parent(ppid);
        process::notify_child_exit();
        crate::log::info!("process exited with status {code}");
    }
    crate::scheduler::thread_exit();
}

fn sys_gettid() -> SysResult {
    // SAFETY: this CPU's running thread.
    Ok(unsafe { (*crate::percpu::current()).linux_tid } as u64)
}

// --- clone / futex ---------------------------------------------------------

/// `clone`: with `CLONE_VM` creates a thread sharing this process's address
/// space and fds (the pthread path); without it, falls back to `fork`.
fn sys_clone(flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64, regs: &Regs) -> SysResult {
    use x86_64::registers::model_specific::{FsBase, KernelGsBase};
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_SETTLS: u64 = 0x0008_0000;
    const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
    const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
    const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

    if flags & CLONE_VM == 0 {
        // No shared address space: a fork is the correct, conservative behaviour.
        return sys_fork(regs);
    }

    let proc = proc()?;
    let cr3 = proc.lock().space.cr3();
    let proc_ptr = core::ptr::from_ref(proc) as u64;
    let tid = process::alloc_tid();

    let mut child = *regs;
    child.rax = 0;
    if stack != 0 {
        child.user_rsp = stack;
    }
    child.rflags = crate::signal::sanitize_user_rflags(child.rflags);

    let fs = if flags & CLONE_SETTLS != 0 { tls } else { FsBase::read().as_u64() };
    let user_gs = KernelGsBase::read().as_u64();

    if flags & CLONE_PARENT_SETTID != 0 && ptid != 0 {
        put_user(ptid, tid)?;
    }
    if flags & CLONE_CHILD_SETTID != 0 && ctid != 0 {
        put_user(ctid, tid)?;
    }
    let clear = if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 };

    proc.lock().thread_count += 1;
    // The address space is now shared across threads/CPUs.
    usercopy::ADDRESS_SPACE_SHARED.store(true, Ordering::Relaxed);

    crate::userspace::spawn_thread(child, cr3, proc_ptr, fs, user_gs, tid, clear)?;
    Ok(tid as u64)
}

/// Fixed-size futex wait-queue hash (Linux-style): `(pid, uaddr)` hashes to a
/// bucket; collisions only cause harmless spurious wakeups (callers re-check).
static FUTEX_BUCKETS: [crate::scheduler::WaitQueue; 256] =
    [const { crate::scheduler::WaitQueue::new() }; 256];

fn futex_bucket(uaddr: u64) -> &'static crate::scheduler::WaitQueue {
    let pid = process::current().map_or(0, |p| p.lock().pid) as u64;
    let key = (uaddr >> 2).wrapping_add(pid.wrapping_mul(0x9e37_79b9));
    &FUTEX_BUCKETS[(key % 256) as usize]
}

/// Wakes all futex waiters on `uaddr` (used by FUTEX_WAKE and thread-exit join).
fn futex_wake(uaddr: u64) {
    crate::scheduler::wake_all(futex_bucket(uaddr));
}

/// `futex`: the FUTEX_WAIT / FUTEX_WAKE subset (private or shared) that musl's
/// locks and `pthread_join` need.
fn sys_futex(uaddr: u64, op: u32, val: u32) -> SysResult {
    const FUTEX_WAIT: u32 = 0;
    const FUTEX_WAKE: u32 = 1;
    const FUTEX_WAIT_BITSET: u32 = 9;
    const FUTEX_WAKE_BITSET: u32 = 10;
    let cmd = op & 0x7f;
    let bucket = futex_bucket(uaddr);
    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            // Capture the wake generation BEFORE re-reading the word, so a wake
            // in the gap refuses the block (no lost wakeup).
            let generation = bucket.prepare();
            let mut cur = [0u8; 4];
            copy_from_user(uaddr, &mut cur)?;
            if u32::from_le_bytes(cur) != val {
                return Err(Errno::EAGAIN);
            }
            if proc()?.lock().interrupted() {
                return Err(Errno::EINTR);
            }
            crate::scheduler::block_with_gen(bucket, generation);
            Ok(0)
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            crate::scheduler::wake_all(bucket);
            Ok(u64::from(val))
        }
        _ => Ok(0),
    }
}

fn sys_arch_prctl(code: u64, addr: u64) -> SysResult {
    use x86_64::VirtAddr;
    use x86_64::registers::model_specific::FsBase;
    use x86_64::registers::model_specific::KernelGsBase;
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;
    match code {
        ARCH_SET_FS => {
            if addr >= crate::usercopy::USER_MAX {
                return Err(Errno::EINVAL);
            }
            let va = VirtAddr::try_new(addr).map_err(|_| Errno::EINVAL)?;
            // SAFETY: a validated user-range FS base for TLS; recorded in the
            // thread so the context switch preserves it.
            FsBase::write(va);
            let t = crate::percpu::current();
            unsafe { (*t).fs_base = addr };
            Ok(0)
        }
        ARCH_GET_FS => {
            put_user(addr, FsBase::read().as_u64())?;
            Ok(0)
        }
        ARCH_SET_GS => {
            if addr >= crate::usercopy::USER_MAX {
                return Err(Errno::EINVAL);
            }
            let va = VirtAddr::try_new(addr).map_err(|_| Errno::EINVAL)?;
            // The user GS lives in KERNEL_GS_BASE while in the kernel; recorded
            // in the thread for context-switch preservation.
            KernelGsBase::write(va);
            let t = crate::percpu::current();
            // SAFETY: `t` is this CPU's running thread.
            unsafe { (*t).user_gs = addr };
            Ok(0)
        }
        ARCH_GET_GS => {
            put_user(addr, KernelGsBase::read().as_u64())?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

fn sys_set_tid_address(ptr: u64) -> SysResult {
    // SAFETY: this CPU's running thread; clear-child-tid is per-thread.
    unsafe { (*crate::percpu::current()).clear_child_tid = ptr };
    sys_gettid()
}

/// How long a `poll`/`ppoll` should wait.
enum PollTimeout {
    /// Milliseconds; negative means block indefinitely.
    Millis(i64),
    /// Scheduler ticks (converted from a ppoll timespec); `None` = indefinite.
    Ticks(Option<u64>),
}

/// `poll(fds, nfds, timeout_ms)`: reports POLLIN readiness per fd (POLLOUT is
/// assumed ready). Blocks by sleeping (not busy-spinning) until a fd is ready,
/// the timeout elapses, or a signal arrives.
fn sys_poll(fds: u64, nfds: usize, timeout: PollTimeout) -> SysResult {
    const POLLIN: i16 = 0x001;
    const POLLOUT: i16 = 0x004;
    const POLLNVAL: i16 = 0x020;
    const TICKS_PER_SEC: u64 = 250;
    let nfds = nfds.min(1024);
    let deadline = match timeout {
        PollTimeout::Millis(ms) if ms < 0 => None,
        PollTimeout::Millis(ms) => {
            let ticks = (ms as u64).saturating_mul(TICKS_PER_SEC) / 1000;
            Some(crate::percpu::this().now.load(Ordering::Relaxed) + ticks)
        }
        PollTimeout::Ticks(None) => None,
        PollTimeout::Ticks(Some(t)) => {
            Some(crate::percpu::this().now.load(Ordering::Relaxed) + t)
        }
    };
    loop {
        let mut ready = 0u64;
        for i in 0..nfds {
            let base = fds + (i * 8) as u64;
            let mut pfd = [0u8; 8];
            copy_from_user(base, &mut pfd)?;
            let fdn = i32::from_le_bytes(pfd[0..4].try_into().unwrap());
            let events = i16::from_le_bytes(pfd[4..6].try_into().unwrap());
            let mut revents: i16 = 0;
            if fdn >= 0 {
                match fd(fdn) {
                    Ok(file) => {
                        if events & POLLIN != 0 && fs::poll_readable(&file) {
                            revents |= POLLIN;
                        }
                        if events & POLLOUT != 0 {
                            revents |= POLLOUT;
                        }
                    }
                    Err(_) => revents |= POLLNVAL,
                }
            }
            copy_to_user(base + 6, &revents.to_le_bytes())?;
            if revents != 0 {
                ready += 1;
            }
        }
        if ready > 0 {
            return Ok(ready);
        }
        let now = crate::percpu::this().now.load(Ordering::Relaxed);
        if let Some(d) = deadline {
            if now >= d {
                return Ok(0);
            }
        }
        if proc()?.lock().interrupted() {
            return Err(Errno::EINTR);
        }
        crate::scheduler::sleep_ticks(1);
    }
}

/// `ppoll(fds, nfds, timespec, sigmask, sz)`: like poll with a timespec timeout
/// (NULL = block indefinitely); the signal mask is ignored for now.
fn sys_ppoll(fds: u64, nfds: usize, tsptr: u64) -> SysResult {
    const TICKS_PER_SEC: u64 = 250;
    let timeout = if tsptr == 0 {
        PollTimeout::Ticks(None)
    } else {
        let mut ts = [0u8; 16];
        copy_from_user(tsptr, &mut ts)?;
        let secs = i64::from_le_bytes(ts[0..8].try_into().unwrap()).max(0) as u64;
        let nsecs = i64::from_le_bytes(ts[8..16].try_into().unwrap()).max(0) as u64;
        let ticks = secs.saturating_mul(TICKS_PER_SEC)
            + nsecs.saturating_mul(TICKS_PER_SEC) / 1_000_000_000;
        PollTimeout::Ticks(Some(ticks))
    };
    sys_poll(fds, nfds, timeout)
}

const SELECT_TICKS_PER_SEC: u64 = 250;

/// `select(nfds, readfds, writefds, exceptfds, timeout)`: a real readiness check
/// over the fd_set bitmaps (previously a fake "always 1 ready", which made zsh's
/// ZLE typeahead probe take the wrong path and spin). A zero timeout returns
/// immediately; NULL blocks until an fd is ready. Exceptfds is always cleared.
fn sys_select(nfds: i32, rfds: u64, wfds: u64, efds: u64, tv: u64) -> SysResult {
    let deadline = if tv == 0 {
        None
    } else {
        let mut b = [0u8; 16];
        copy_from_user(tv, &mut b)?;
        let sec = i64::from_le_bytes(b[0..8].try_into().unwrap()).max(0) as u64;
        let usec = i64::from_le_bytes(b[8..16].try_into().unwrap()).max(0) as u64;
        let ticks = sec * SELECT_TICKS_PER_SEC + usec * SELECT_TICKS_PER_SEC / 1_000_000;
        Some(crate::percpu::this().now.load(Ordering::Relaxed) + ticks)
    };
    select_core(nfds, rfds, wfds, efds, deadline)
}

/// `pselect6`: like select with a `timespec` timeout; the signal mask argument
/// is ignored for now (matching `ppoll`).
fn sys_pselect6(nfds: i32, rfds: u64, wfds: u64, efds: u64, ts: u64) -> SysResult {
    let deadline = if ts == 0 {
        None
    } else {
        let mut b = [0u8; 16];
        copy_from_user(ts, &mut b)?;
        let sec = i64::from_le_bytes(b[0..8].try_into().unwrap()).max(0) as u64;
        let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap()).max(0) as u64;
        let ticks = sec * SELECT_TICKS_PER_SEC + nsec * SELECT_TICKS_PER_SEC / 1_000_000_000;
        Some(crate::percpu::this().now.load(Ordering::Relaxed) + ticks)
    };
    select_core(nfds, rfds, wfds, efds, deadline)
}

fn select_core(nfds: i32, rfds: u64, wfds: u64, efds: u64, deadline: Option<u64>) -> SysResult {
    let nfds = nfds.clamp(0, 1024) as usize;
    let nbytes = (nfds + 7) / 8;
    let mut rin = vec![0u8; nbytes];
    let mut win = vec![0u8; nbytes];
    if rfds != 0 {
        copy_from_user(rfds, &mut rin)?;
    }
    if wfds != 0 {
        copy_from_user(wfds, &mut win)?;
    }
    loop {
        let mut rout = vec![0u8; nbytes];
        let mut wout = vec![0u8; nbytes];
        let mut count = 0u64;
        for fdn in 0..nfds {
            let byte = fdn / 8;
            let bit = 1u8 << (fdn % 8);
            if rfds != 0 && rin[byte] & bit != 0 {
                if let Ok(file) = fd(fdn as i32) {
                    if fs::poll_readable(&file) {
                        rout[byte] |= bit;
                        count += 1;
                    }
                }
            }
            if wfds != 0 && win[byte] & bit != 0 && fd(fdn as i32).is_ok() {
                // No write-side backpressure is modelled yet: a valid fd is writable.
                wout[byte] |= bit;
                count += 1;
            }
        }
        let now = crate::percpu::this().now.load(Ordering::Relaxed);
        let expired = deadline.is_some_and(|d| now >= d);
        if count > 0 || expired {
            if rfds != 0 {
                copy_to_user(rfds, &rout)?;
            }
            if wfds != 0 {
                copy_to_user(wfds, &wout)?;
            }
            if efds != 0 {
                copy_to_user(efds, &alloc::vec![0u8; nbytes])?;
            }
            return Ok(count);
        }
        if proc()?.lock().interrupted() {
            return Err(Errno::EINTR);
        }
        crate::scheduler::sleep_ticks(1);
    }
}

fn sys_ioctl(fd_num: i32, request: u64, arg: u64) -> SysResult {
    use fs::TtyKind;
    let file = fd(fd_num)?;
    let kind = fs::tty_kind(&file);
    if matches!(kind, TtyKind::NotTty) {
        // A handful of ioctls are harmless no-ops on non-ttys; the rest ENOTTY.
        return Err(Errno::ENOTTY);
    }

    // Helpers that read/write the terminal state of whichever tty `fd` is.
    let get_termios = |k: &TtyKind| -> types::Termios {
        match k {
            TtyKind::PtyMaster(p) | TtyKind::PtySlave(p) => p.termios(),
            _ => fs::termios(),
        }
    };
    let put_termios = |k: &TtyKind, t: types::Termios| match k {
        TtyKind::PtyMaster(p) | TtyKind::PtySlave(p) => p.set_termios(t),
        _ => fs::set_termios(t),
    };

    match request {
        types::TCGETS => {
            let t = get_termios(&kind);
            let bytes = unsafe {
                core::slice::from_raw_parts(core::ptr::from_ref(&t).cast::<u8>(), size_of::<types::Termios>())
            };
            copy_to_user(arg, bytes)?;
            Ok(0)
        }
        types::TCSETS | types::TCSETSW | types::TCSETSF => {
            let mut t = types::Termios::default();
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(core::ptr::from_mut(&mut t).cast::<u8>(), size_of::<types::Termios>())
            };
            copy_from_user(arg, bytes)?;
            put_termios(&kind, t);
            Ok(0)
        }
        types::TIOCGWINSZ => {
            let ws = match &kind {
                TtyKind::PtyMaster(p) | TtyKind::PtySlave(p) => p.winsize(),
                _ => fs::console_winsize(),
            };
            let bytes = unsafe {
                core::slice::from_raw_parts(core::ptr::from_ref(&ws).cast::<u8>(), size_of::<types::Winsize>())
            };
            copy_to_user(arg, bytes)?;
            Ok(0)
        }
        types::TIOCSWINSZ => {
            let mut ws = types::Winsize::default();
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(core::ptr::from_mut(&mut ws).cast::<u8>(), size_of::<types::Winsize>())
            };
            copy_from_user(arg, bytes)?;
            // Set the size and deliver SIGWINCH to the terminal's foreground group.
            let fg = match &kind {
                TtyKind::PtyMaster(p) | TtyKind::PtySlave(p) => p.set_winsize(ws),
                _ => fs::set_console_winsize(ws),
            };
            if fg > 0 {
                crate::signal::send_to_pgrp(fg, types::SIGWINCH);
            }
            Ok(0)
        }
        types::TIOCGPGRP => {
            let fg = match &kind {
                TtyKind::PtyMaster(p) | TtyKind::PtySlave(p) => p.fg_pgrp(),
                _ => fs::foreground_pgrp(),
            };
            let pgid = if fg != 0 { fg } else { proc()?.lock().pgid };
            put_user(arg, pgid as u32)?;
            Ok(0)
        }
        types::TIOCSPGRP => {
            let mut raw = [0u8; 4];
            copy_from_user(arg, &mut raw)?;
            let pgid = i32::from_le_bytes(raw);
            if pgid > 0 {
                match &kind {
                    TtyKind::PtyMaster(p) | TtyKind::PtySlave(p) => p.set_fg_pgrp(pgid),
                    _ => {
                        fs::set_foreground_pgrp(pgid);
                        crate::log::info!("tty: foreground pgrp -> {pgid}");
                    }
                }
            }
            Ok(0)
        }
        types::TIOCGPTN => {
            // Master only: the slave number for ptsname (/dev/pts/N).
            if let TtyKind::PtyMaster(p) = &kind {
                put_user(arg, p.ptn)?;
                Ok(0)
            } else {
                Err(Errno::ENOTTY)
            }
        }
        types::TIOCSPTLCK | types::TIOCGPTLCK => Ok(0), // unlockpt/lock: accepted
        types::TIOCSCTTY => Ok(0), // controlling-terminal bookkeeping: accepted
        types::FIONREAD => {
            // Queued input bytes. zsh/ZLE uses this to probe typeahead and drive
            // bracketed paste; a wrong answer makes it mis-handle keystrokes.
            let n: u32 = match &kind {
                TtyKind::PtyMaster(p) => p.queued(true) as u32,
                TtyKind::PtySlave(p) => p.queued(false) as u32,
                _ => crate::arch::x86_64::input::available() as u32,
            };
            put_user(arg, n)?;
            Ok(0)
        }
        types::TIOCOUTQ => {
            // Output is written synchronously, so nothing is ever queued.
            put_user(arg, 0u32)?;
            Ok(0)
        }
        // tcflush: accept but do NOT discard queued input (dropping bytes the
        // shell still wants is worse than keeping a few stale ones).
        types::TCFLSH => Ok(0),
        _ => Err(Errno::ENOTTY),
    }
}

fn sys_uname(buf: u64) -> SysResult {
    let mut u = types::Utsname::default();
    fill(&mut u.sysname, b"Linux");
    fill(&mut u.nodename, b"fluos");
    fill(&mut u.release, b"6.1.0-fluos");
    fill(&mut u.version, b"#1 SMP FluOS");
    fill(&mut u.machine, b"x86_64");
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(&u).cast::<u8>(), size_of::<types::Utsname>())
    };
    copy_to_user(buf, bytes)?;
    Ok(0)
}

fn fill(dst: &mut [u8; 65], src: &[u8]) {
    let n = src.len().min(64);
    dst[..n].copy_from_slice(&src[..n]);
}

fn sys_getrandom(buf: u64, len: usize) -> SysResult {
    let len = len.min(MAX_RW);
    let mut done = 0usize;
    while done < len {
        let n = (len - done).min(BOUNCE);
        let mut data = vec![0u8; n];
        crate::rng::fill(&mut data);
        copy_to_user(buf + done as u64, &data)?;
        done += n;
    }
    Ok(len as u64)
}

/// Fallback wall-clock base when the bootloader reports no boot date, so
/// CLOCK_REALTIME still looks like a real post-2000 date (zinit's timing and
/// `$EPOCHREALTIME` assume one) rather than seconds since boot.
const FALLBACK_REALTIME_BASE_SECS: u64 = 1_762_000_000; // 2025-11-01

/// UNIX time at boot: the firmware RTC value Limine reports, else the fallback.
fn realtime_base_secs() -> u64 {
    crate::boot::unix_time_at_boot().unwrap_or(FALLBACK_REALTIME_BASE_SECS)
}

/// Seconds + nanoseconds of monotonic uptime, from the TSC and calibrated
/// cycles-per-ms. Always advancing and non-zero.
fn uptime_sec_nsec() -> (u64, u64) {
    let tpms = crate::arch::x86_64::apic::tsc_per_ms();
    // SAFETY: `_rdtsc` reads the timestamp counter.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let ms = tsc / tpms;
    let sub = tsc % tpms; // leftover cycles within the current ms
    (ms / 1000, (ms % 1000) * 1_000_000 + sub * 1_000_000 / tpms)
}

/// `(sec, nsec)` for a clock id: CLOCK_REALTIME (0) and its coarse variant add
/// the epoch base; everything else is treated as monotonic uptime.
fn clock_sec_nsec(clk: u64) -> (u64, u64) {
    const CLOCK_REALTIME: u64 = 0;
    const CLOCK_REALTIME_COARSE: u64 = 5;
    let (sec, nsec) = uptime_sec_nsec();
    if clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE {
        (sec + realtime_base_secs(), nsec)
    } else {
        (sec, nsec)
    }
}

fn sys_clock_gettime(clk: u64, ts: u64) -> SysResult {
    let (sec, nsec) = clock_sec_nsec(clk);
    let t = types::Timespec { tv_sec: sec as i64, tv_nsec: nsec as i64 };
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(&t).cast::<u8>(), size_of::<types::Timespec>())
    };
    copy_to_user(ts, bytes)?;
    Ok(0)
}

/// `gettimeofday(tv, tz)`: wall-clock `struct timeval { i64 tv_sec; i64 tv_usec }`
/// (16 bytes). zsh's datetime module backs `$EPOCHREALTIME` with this; a missing
/// or non-advancing value stalls zinit's async timing loops.
fn sys_gettimeofday(tv: u64) -> SysResult {
    if tv != 0 {
        let (sec, nsec) = clock_sec_nsec(0);
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&(sec as i64).to_le_bytes());
        buf[8..16].copy_from_slice(&((nsec / 1000) as i64).to_le_bytes());
        copy_to_user(tv, &buf)?;
    }
    Ok(0)
}

/// `time(tloc)`: wall-clock seconds, also written to `*tloc` if non-NULL.
fn sys_time(tloc: u64) -> SysResult {
    let (sec, _) = clock_sec_nsec(0);
    if tloc != 0 {
        put_user(tloc, sec)?;
    }
    Ok(sec)
}

fn sys_fstat(fd_num: i32, statbuf: u64) -> SysResult {
    let file = fd(fd_num)?;
    let st = {
        let f = file.lock();
        match &f.kind {
            fs::FileKind::File { ino, .. } | fs::FileKind::Dir { ino, .. } => {
                fs::with_vfs(|v| v.stat(*ino))?
            }
            fs::FileKind::Device(_) => {
                let mut s = types::Stat::default();
                s.st_mode = types::S_IFCHR | 0o666;
                s.st_rdev = 0;
                s
            }
            fs::FileKind::Pipe { .. } => {
                let mut s = types::Stat::default();
                s.st_mode = types::S_IFIFO | 0o600;
                s
            }
            // PTY ends report as character devices (isatty() => true).
            fs::FileKind::PtyMaster(_) | fs::FileKind::PtySlave(_) => {
                let mut s = types::Stat::default();
                s.st_mode = types::S_IFCHR | 0o620;
                s
            }
            fs::FileKind::ProcData { data, .. } => {
                let mut s = types::Stat::default();
                s.st_mode = types::S_IFREG | 0o444;
                s.st_size = data.len() as i64;
                s
            }
            fs::FileKind::ProcDir { .. } => {
                let mut s = types::Stat::default();
                s.st_mode = types::S_IFDIR | 0o555;
                s.st_nlink = 2;
                s
            }
            // Like Linux's anon inodes: no file-type bits.
            fs::FileKind::EventFd(_) => {
                let mut s = types::Stat::default();
                s.st_mode = 0o600;
                s
            }
        }
    };
    write_stat(statbuf, &st)
}

fn sys_newfstatat(_dirfd: i32, path: u64, statbuf: u64, _flags: i32) -> SysResult {
    let follow = true;
    sys_stat(path, statbuf, follow)
}

fn sys_stat(path: u64, statbuf: u64, follow: bool) -> SysResult {
    let path = read_path(path)?;
    if let Some(r) = crate::procfs::stat(&path) {
        return write_stat(statbuf, &r?);
    }
    let cwd = proc()?.lock().cwd;
    let st = fs::with_vfs(|v| {
        let ino = v.resolve(cwd, &path, follow)?;
        v.stat(ino)
    })?;
    write_stat(statbuf, &st)
}

fn write_stat(statbuf: u64, st: &types::Stat) -> SysResult {
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(st).cast::<u8>(), size_of::<types::Stat>())
    };
    copy_to_user(statbuf, bytes)?;
    Ok(0)
}

fn sys_getdents64(fd_num: i32, buf: u64, len: usize) -> SysResult {
    let file = fd(fd_num)?;
    // Snapshot the directory entries as (name, d_ino, d_type), from either the
    // tmpfs or a synthetic procfs directory.
    let (entries, start): (Vec<(alloc::string::String, u64, u8)>, usize) = {
        let f = file.lock();
        match &f.kind {
            fs::FileKind::Dir { ino, pos } => {
                let e = fs::with_vfs(|v| v.readdir(*ino))?
                    .into_iter()
                    .map(|(n, c, t)| (n, u64::from(c) + 1, t))
                    .collect();
                (e, *pos)
            }
            fs::FileKind::ProcDir { entries, pos } => {
                let e = entries
                    .iter()
                    .enumerate()
                    .map(|(i, (n, t))| (n.clone(), i as u64 + 1, *t))
                    .collect();
                (e, *pos)
            }
            _ => return Err(Errno::ENOTDIR),
        }
    };
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    while pos < entries.len() {
        let (name, ino, dtype) = &entries[pos];
        let reclen = (19 + name.len() + 1 + 7) & !7; // header 19 + name + NUL, 8-aligned
        if out.len() + reclen > len {
            break;
        }
        out.extend_from_slice(&ino.to_le_bytes()); // d_ino
        out.extend_from_slice(&(pos as i64 + 1).to_le_bytes()); // d_off
        out.extend_from_slice(&(reclen as u16).to_le_bytes()); // d_reclen
        out.push(*dtype); // d_type
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        pos += 1;
    }
    copy_to_user(buf, &out)?;
    match &mut file.lock().kind {
        fs::FileKind::Dir { pos: p, .. } | fs::FileKind::ProcDir { pos: p, .. } => *p = pos,
        _ => {}
    }
    Ok(out.len() as u64)
}

fn sys_getcwd(buf: u64, size: usize) -> SysResult {
    let cwd = proc()?.lock().cwd;
    let path = fs::with_vfs(|v| v.path_of(cwd))?;
    let mut bytes = path.into_bytes();
    bytes.push(0);
    if size < bytes.len() {
        return Err(Errno::ERANGE);
    }
    copy_to_user(buf, &bytes)?;
    Ok(bytes.len() as u64)
}

fn sys_access(_dirfd: i32, path: u64) -> SysResult {
    let path = read_path(path)?;
    if let Some(r) = crate::procfs::stat(&path) {
        return r.map(|_| 0);
    }
    let cwd = proc()?.lock().cwd;
    fs::with_vfs(|v| v.resolve(cwd, &path, true))?;
    Ok(0)
}

/// `chdir`: point the process cwd at the resolved directory inode.
fn sys_chdir(path: u64) -> SysResult {
    let path = read_path(path)?;
    let cwd = proc()?.lock().cwd;
    let ino = fs::with_vfs(|v| {
        let ino = v.resolve(cwd, &path, true)?;
        if v.kind(ino)? != vfs::Kind::Dir {
            return Err(Errno::ENOTDIR);
        }
        Ok(ino)
    })?;
    proc()?.lock().cwd = ino;
    Ok(0)
}

/// `mkdir`/`mkdirat`: create a directory, honouring the process umask.
fn sys_mkdirat(dirfd: i32, path: u64, mode: u32) -> SysResult {
    let path = read_path(path)?;
    let (base, umask) = {
        let g = proc()?.lock();
        (dirfd_base(&g, dirfd, &path)?, g.umask)
    };
    fs::with_vfs(|v| {
        let (dir, name) = v.split_parent(base, &path)?;
        v.mkdir(dir, name, (mode & !umask) & 0o777)?;
        Ok(())
    })?;
    Ok(0)
}

/// `rename`/`renameat`/`renameat2`: move an entry, reparenting the inode. Flags
/// (renameat2) are ignored — the common `RENAME_NOREPLACE`/exchange cases that
/// zsh/coreutils rely on at startup are not used.
fn sys_renameat(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64) -> SysResult {
    let oldp = read_path(oldpath)?;
    let newp = read_path(newpath)?;
    let (ob, nb) = {
        let g = proc()?.lock();
        (dirfd_base(&g, olddirfd, &oldp)?, dirfd_base(&g, newdirfd, &newp)?)
    };
    fs::with_vfs(|v| {
        let (od, on) = v.split_parent(ob, &oldp)?;
        let (nd, nn) = v.split_parent(nb, &newp)?;
        v.rename(od, on, nd, nn)
    })?;
    Ok(0)
}

/// `link`/`linkat`: create a hard link. The final component of the source is
/// not dereferenced (AT_SYMLINK_FOLLOW is not requested by our callers).
fn sys_linkat(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64) -> SysResult {
    let oldp = read_path(oldpath)?;
    let newp = read_path(newpath)?;
    let (ob, nb) = {
        let g = proc()?.lock();
        (dirfd_base(&g, olddirfd, &oldp)?, dirfd_base(&g, newdirfd, &newp)?)
    };
    fs::with_vfs(|v| {
        let ino = v.resolve(ob, &oldp, false)?;
        let (nd, nn) = v.split_parent(nb, &newp)?;
        v.link(ino, nd, nn).map(|_| ())
    })?;
    Ok(0)
}

/// `symlink`/`symlinkat`: create a symlink `linkpath` -> `target`.
fn sys_symlinkat(target: u64, newdirfd: i32, linkpath: u64) -> SysResult {
    let target = read_path(target)?;
    let linkp = read_path(linkpath)?;
    let nb = {
        let g = proc()?.lock();
        dirfd_base(&g, newdirfd, &linkp)?
    };
    fs::with_vfs(|v| {
        let (nd, nn) = v.split_parent(nb, &linkp)?;
        v.symlink(nd, nn, &target).map(|_| ())
    })?;
    Ok(0)
}

/// `unlink`/`unlinkat`: remove a non-directory (or empty directory). The
/// `AT_REMOVEDIR` flag is implicit — `vfs::unlink` already accepts empty dirs.
fn sys_unlinkat(dirfd: i32, path: u64) -> SysResult {
    let path = read_path(path)?;
    let base = {
        let g = proc()?.lock();
        dirfd_base(&g, dirfd, &path)?
    };
    fs::with_vfs(|v| {
        let (d, n) = v.split_parent(base, &path)?;
        v.unlink(d, n)
    })?;
    Ok(0)
}

/// `chmod`/`fchmodat`: set the permission bits of the resolved inode.
fn sys_fchmodat(dirfd: i32, path: u64, mode: u32) -> SysResult {
    let path = read_path(path)?;
    let base = {
        let g = proc()?.lock();
        dirfd_base(&g, dirfd, &path)?
    };
    fs::with_vfs(|v| {
        let ino = v.resolve(base, &path, true)?;
        v.chmod(ino, mode)
    })?;
    Ok(0)
}

/// `readlink`/`readlinkat`: copy a symlink's target (not NUL-terminated) into
/// the caller's buffer, truncated to its length; `EINVAL` if not a symlink.
fn sys_readlinkat(dirfd: i32, path: u64, buf: u64, bufsize: usize) -> SysResult {
    let path = read_path(path)?;
    if let Some(r) = crate::procfs::readlink(&path) {
        let target = r?.into_bytes();
        let n = target.len().min(bufsize);
        copy_to_user(buf, &target[..n])?;
        return Ok(n as u64);
    }
    let base = {
        let g = proc()?.lock();
        dirfd_base(&g, dirfd, &path)?
    };
    let target = fs::with_vfs(|v| {
        let ino = v.resolve(base, &path, false)?; // do not follow the final link
        Ok(v.readlink(ino)?.as_bytes().to_vec())
    })?;
    let n = target.len().min(bufsize);
    copy_to_user(buf, &target[..n])?;
    Ok(n as u64)
}

/// `umask`: set the file-creation mask, returning the previous value.
fn sys_umask(mask: u32) -> SysResult {
    let p = proc()?;
    let mut g = p.lock();
    let old = g.umask;
    g.umask = mask & 0o777;
    Ok(u64::from(old))
}

/// `getrusage`: report zeroed counters (we do not yet track per-process CPU
/// time). `struct rusage` is 144 bytes on x86_64.
fn sys_getrusage(_who: i32, usage: u64) -> SysResult {
    if usage != 0 {
        copy_to_user(usage, &[0u8; 144])?;
    }
    Ok(0)
}

/// `sigaltstack`: store/report the alternate signal stack. `stack_t` is
/// `{ void *ss_sp; int ss_flags; size_t ss_size; }` = 24 bytes (ss_size at
/// offset 16 after 4 bytes of padding).
fn sys_sigaltstack(new: u64, old: u64) -> SysResult {
    let p = proc()?;
    if old != 0 {
        let (sp, size, flags) = p.lock().altstack;
        let mut out = [0u8; 24];
        out[0..8].copy_from_slice(&sp.to_le_bytes());
        out[8..12].copy_from_slice(&flags.to_le_bytes());
        out[16..24].copy_from_slice(&size.to_le_bytes());
        copy_to_user(old, &out)?;
    }
    if new != 0 {
        let mut inb = [0u8; 24];
        copy_from_user(new, &mut inb)?;
        let sp = u64::from_le_bytes(inb[0..8].try_into().unwrap());
        let flags = i32::from_le_bytes(inb[8..12].try_into().unwrap());
        let size = u64::from_le_bytes(inb[16..24].try_into().unwrap());
        p.lock().altstack = (sp, size, flags);
    }
    Ok(0)
}

/// `rt_sigsuspend`: atomically install `set` as the blocked mask, give pending
/// work (e.g. a child exiting and posting `SIGCHLD`) a chance to run, then
/// restore the previous mask and return `EINTR` — sigsuspend's only outcome.
///
/// We deliberately do *not* block forever on `has_deliverable`: under the
/// "deliver on syscall-return" model a signal can be delivered (its handler run,
/// the pending bit cleared) during a `yield_now` before we observe it, which
/// would wedge us permanently. POSIX allows sigsuspend to return `EINTR`
/// spuriously — callers re-test their own condition in a loop — so a bounded
/// wait that always returns is both race-free and correct for job-control loops
/// (zsh re-checks `waitpid` after each return).
fn sys_rt_sigsuspend(set_ptr: u64, sigsetsize: usize) -> SysResult {
    if sigsetsize != 8 {
        return Err(Errno::EINVAL);
    }
    let mut tmp = [0u8; 8];
    copy_from_user(set_ptr, &mut tmp)?;
    let newmask = u64::from_le_bytes(tmp);
    let p = proc()?;
    // Install the temporary mask and arm a post-handler restore of the caller's
    // mask. The temp mask stays in effect as we return, so `on_syscall_return`
    // delivers a now-unblocked signal (e.g. SIGCHLD): its handler runs, and
    // `sigreturn` restores the pre-suspend mask from the armed value.
    let old = {
        let mut g = p.lock();
        let old = g.sig.set_mask(newmask);
        g.sig.arm_restore_mask(old);
        old
    };
    // Wait (bounded, yielding) until a signal is deliverable under the temp mask.
    // We must NOT restore the mask here on the common path — delivery happens
    // after we return. Only a spurious timeout path undoes the arming.
    let mut delivered = false;
    for _ in 0..1024 {
        if p.lock().interrupted() {
            delivered = true;
            break;
        }
        crate::scheduler::yield_now();
    }
    if !delivered {
        // Nothing arrived: undo the temporary mask and disarm, then report EINTR.
        let mut g = p.lock();
        let _ = g.sig.take_restore_mask();
        g.sig.set_mask(old);
    }
    Err(Errno::EINTR)
}

/// `sched_setaffinity(pid, cpusetsize, mask)`. Only the calling thread (pid 0
/// or the caller's own tid) is honored; the mask is intersected with the online
/// CPUs and must be non-empty. zsh/Go/starship call this; FluOS also uses it to
/// pin threads for the CoW-coherence regression test.
fn sys_sched_setaffinity(pid: i32, len: usize, maskptr: u64) -> SysResult {
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    let mut raw = [0u8; 8];
    let n = len.min(8);
    copy_from_user(maskptr, &mut raw[..n])?;
    let requested = u64::from_le_bytes(raw);
    let online = crate::percpu::count();
    let online_mask = if online >= 64 { u64::MAX } else { (1u64 << online) - 1 };
    let mask = requested & online_mask;
    if mask == 0 {
        return Err(Errno::EINVAL);
    }
    let self_tid = unsafe { (*crate::percpu::current()).linux_tid };
    if pid == 0 || pid == self_tid {
        crate::scheduler::set_affinity_current(mask);
    }
    // Setting another thread's affinity is accepted but not enforced here.
    Ok(0)
}

fn sys_sched_getaffinity(mask: u64, len: usize) -> SysResult {
    let cpus = crate::percpu::count().min(64);
    let bits: u64 = if cpus >= 64 { u64::MAX } else { (1u64 << cpus) - 1 };
    let n = len.min(8);
    copy_to_user(mask, &bits.to_le_bytes()[..n])?;
    Ok(n as u64)
}

fn sys_prlimit64(new: u64, old: u64) -> SysResult {
    // Report an 8 MiB stack / unlimited-ish for anything queried.
    if old != 0 {
        let rlim = [8u64 * 1024 * 1024, u64::MAX];
        let bytes = unsafe {
            core::slice::from_raw_parts(rlim.as_ptr().cast::<u8>(), 16)
        };
        copy_to_user(old, bytes)?;
    }
    let _ = new;
    Ok(0)
}

fn sys_getrlimit(old: u64) -> SysResult {
    let rlim = [8u64 * 1024 * 1024, u64::MAX];
    let bytes = unsafe { core::slice::from_raw_parts(rlim.as_ptr().cast::<u8>(), 16) };
    copy_to_user(old, bytes)?;
    Ok(0)
}

/// Reads a path string (up to 4096 bytes) from user memory.
fn read_path(ptr: u64) -> Result<alloc::string::String, Errno> {
    let bytes = usercopy::read_cstr(ptr, 4096)?;
    alloc::string::String::from_utf8(bytes).map_err(|_| Errno::EINVAL)
}

/// `kill`: minimal — signal 0 is an existence check (always OK here); real
/// delivery lands with the signal subsystem. Returns success so job-control
/// shells proceed.
/// `splice(fd_in, off_in, fd_out, off_out, len, flags)`: moves up to `len`
/// bytes between two descriptors through a kernel bounce buffer. Offsets are
/// ignored (callers splicing to/from pipes pass NULL), which covers the shell
/// and coreutils uses; it is a straightforward read-then-write, not zero-copy.
fn sys_splice(fd_in: i32, off_in: u64, fd_out: i32, off_out: u64, len: usize) -> SysResult {
    // `splice(fd_in, off_in*, fd_out, off_out*, len, flags)`, emulated as a
    // bounded read/write copy. Offsets, when given, position the (regular-file)
    // ends like pread/pwrite and are advanced in user memory afterwards.
    let len = len.min(MAX_RW);
    let infile = fd(fd_in)?;
    let outfile = fd(fd_out)?;
    if off_in != 0 {
        let start = read_user_u64(off_in)?;
        set_file_offset(&infile, start)?;
    }
    if off_out != 0 {
        let start = read_user_u64(off_out)?;
        set_file_offset(&outfile, start)?;
    }
    let mut buf = vec![0u8; len.min(4096).max(1)];
    let mut total = 0u64;
    while (total as usize) < len {
        let want = buf.len().min(len - total as usize);
        let n = fs::read(&infile, &mut buf[..want])?;
        if n == 0 {
            break; // EOF
        }
        let mut written = 0usize;
        while written < n as usize {
            let w = fs::write(&outfile, &buf[written..n as usize])?;
            if w == 0 {
                break;
            }
            written += w as usize;
        }
        total += written as u64;
        if (written as u64) < n {
            break;
        }
        // With a pipe on either end, move one chunk per call (a partial result,
        // as Linux returns): callers like cp alternate file->pipe and
        // pipe->file splices on one thread, so filling the pipe past what it
        // holds, or waiting on it for more input, would self-deadlock.
        let is_pipe = |f: &Arc<SpinLock<fs::OpenFile>>| matches!(f.lock().kind, fs::FileKind::Pipe { .. });
        if is_pipe(&infile) || is_pipe(&outfile) {
            break;
        }
    }
    if off_in != 0 {
        put_user(off_in, file_offset(&infile))?;
    }
    if off_out != 0 {
        put_user(off_out, file_offset(&outfile))?;
    }
    Ok(total)
}

/// Reads a little-endian `u64` from user memory.
fn read_user_u64(uaddr: u64) -> Result<u64, Errno> {
    let mut b = [0u8; 8];
    copy_from_user(uaddr, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Sets the position of a regular file (`ESPIPE` for pipes/devices).
fn set_file_offset(file: &Arc<SpinLock<fs::OpenFile>>, pos: u64) -> Result<(), Errno> {
    match &mut file.lock().kind {
        fs::FileKind::File { offset, .. } => {
            *offset = pos;
            Ok(())
        }
        _ => Err(Errno::ESPIPE),
    }
}

/// Current position of a regular file (0 for anything else).
fn file_offset(file: &Arc<SpinLock<fs::OpenFile>>) -> u64 {
    match &file.lock().kind {
        fs::FileKind::File { offset, .. } => *offset,
        _ => 0,
    }
}

/// `sendfile(out, in, offset, count)`: copies up to `count` bytes from `in` to
/// `out` through a kernel buffer.
fn sys_sendfile(out_fd: i32, in_fd: i32, offset_ptr: u64, count: usize) -> SysResult {
    let count = count.min(MAX_RW);
    let infile = fd(in_fd)?;
    let outfile = fd(out_fd)?;
    let mut total = 0u64;
    let mut buf = vec![0u8; 4096.min(count.max(1))];
    // Honour an explicit start offset for the input file.
    if offset_ptr != 0 {
        let mut off = [0u8; 8];
        copy_from_user(offset_ptr, &mut off)?;
        let start = u64::from_le_bytes(off);
        if let fs::FileKind::File { offset, .. } = &mut infile.lock().kind {
            *offset = start;
        }
    }
    while (total as usize) < count {
        let want = buf.len().min(count - total as usize);
        let n = fs::read(&infile, &mut buf[..want])? as usize;
        if n == 0 {
            break;
        }
        fs::write(&outfile, &buf[..n])?;
        total += n as u64;
    }
    if offset_ptr != 0 {
        if let fs::FileKind::File { offset, .. } = &infile.lock().kind {
            put_user(offset_ptr, *offset)?;
        }
    }
    Ok(total)
}

/// `kill`: post `sig` to a pid (`pid > 0`), a process group (`pid < -1` or
/// `pid == 0` for the caller's group), or broadcast (`pid == -1`, best-effort).
/// `sig == 0` is an existence/permission probe.
/// `pipe2(pipefd[2], flags)` (and `pipe` with flags=0): creates a pipe and
/// installs its read/write ends at the two lowest free descriptors.
fn sys_pipe2(uaddr: u64, flags: u64) -> SysResult {
    let (rd, wr) = fs::make_pipe(flags);
    let p = proc()?;
    let (rfd, wfd) = {
        let mut g = p.lock();
        let cloexec = flags & types::O_CLOEXEC != 0;
        let rfd = g.fds.alloc_with(rd, cloexec);
        let wfd = g.fds.alloc_with(wr, cloexec);
        (rfd, wfd)
    };
    let mut raw = [0u8; 8];
    raw[0..4].copy_from_slice(&rfd.to_le_bytes());
    raw[4..8].copy_from_slice(&wfd.to_le_bytes());
    copy_to_user(uaddr, &raw)?;
    Ok(0)
}

fn sys_kill(pid: i32, sig: i32) -> SysResult {
    if !(0..=crate::signal::NSIG as i32).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    if sig == 0 {
        // Existence check only.
        return if pid <= 0 || process::with_pid(pid, |_| ()).is_some() {
            Ok(0)
        } else {
            Err(Errno::ESRCH)
        };
    }
    if pid > 0 {
        if crate::signal::send_to_pid(pid, sig) {
            Ok(0)
        } else {
            Err(Errno::ESRCH)
        }
    } else {
        let pgid = if pid == 0 || pid == -1 { proc()?.lock().pgid } else { -pid };
        crate::signal::send_to_pgrp(pgid, sig);
        Ok(0)
    }
}

/// `tkill(tid, sig)` / `tgkill(tgid, tid, sig)`: with one thread per process,
/// the tid is the pid, so these post `sig` to that process.
fn sys_tkill(tid: i32, sig: i32) -> SysResult {
    if tid <= 0 || !(0..=crate::signal::NSIG as i32).contains(&sig) {
        return Err(Errno::EINVAL);
    }
    if sig == 0 {
        return Ok(0);
    }
    if crate::signal::send_to_pid(tid, sig) {
        Ok(0)
    } else {
        Err(Errno::ESRCH)
    }
}

/// `nanosleep`/`clock_nanosleep`: sleep for the requested `timespec`, waking
/// early (with `ERESTARTSYS`) if a deliverable signal arrives. `rem` is filled
/// with the remaining time on interruption.
fn sys_nanosleep(req: u64, rem: u64) -> SysResult {
    // timespec { i64 tv_sec; i64 tv_nsec }
    let mut ts = [0u8; 16];
    copy_from_user(req, &mut ts)?;
    let secs = i64::from_le_bytes(ts[0..8].try_into().unwrap()).max(0) as u64;
    let nsecs = i64::from_le_bytes(ts[8..16].try_into().unwrap()).max(0) as u64;
    // The scheduler tick is the time base (~4 ms/slice => 250 ticks/s).
    const TICKS_PER_SEC: u64 = 250;
    let total_ns = secs.saturating_mul(1_000_000_000).saturating_add(nsecs);
    let ticks = total_ns.saturating_mul(TICKS_PER_SEC) / 1_000_000_000;
    let start = crate::percpu::this().now.load(Ordering::Relaxed);
    let deadline = start.saturating_add(ticks.max(1));
    loop {
        let now = crate::percpu::this().now.load(Ordering::Relaxed);
        if now >= deadline {
            return Ok(0);
        }
        if let Some(pr) = process::current() {
            if pr.lock().interrupted() {
                if rem != 0 {
                    // Report (approximate) remaining time.
                    let left_ticks = deadline - now;
                    let left_ns = left_ticks.saturating_mul(1_000_000_000) / TICKS_PER_SEC;
                    let mut out = [0u8; 16];
                    out[0..8].copy_from_slice(&((left_ns / 1_000_000_000) as i64).to_le_bytes());
                    out[8..16].copy_from_slice(&((left_ns % 1_000_000_000) as i64).to_le_bytes());
                    let _ = copy_to_user(rem, &out);
                }
                return Err(Errno::ERESTARTSYS);
            }
        }
        // Really sleep (descheduled) rather than busy-yield, in short chunks so
        // a signal is noticed within a tick or so.
        let remaining = deadline - now;
        crate::scheduler::sleep_ticks(remaining.min(4));
    }
}

/// `rt_sigaction`: install/query a signal disposition. `sigsetsize` must be 8.
fn sys_rt_sigaction(sig: i32, act: u64, oldact: u64, sigsetsize: usize) -> SysResult {
    use crate::signal::SigAction;
    if sigsetsize != 8 {
        return Err(Errno::EINVAL);
    }
    let p = proc()?;
    let old = p.lock().sig.action(sig);
    if act != 0 {
        let mut raw = [0u8; 32]; // handler, flags, restorer, mask (4 x u64)
        copy_from_user(act, &mut raw)?;
        let a = SigAction {
            handler: u64::from_le_bytes(raw[0..8].try_into().unwrap()),
            flags: u64::from_le_bytes(raw[8..16].try_into().unwrap()),
            restorer: u64::from_le_bytes(raw[16..24].try_into().unwrap()),
            mask: u64::from_le_bytes(raw[24..32].try_into().unwrap()),
        };
        p.lock().sig.set_action(sig, a);
    }
    if oldact != 0 {
        let mut raw = [0u8; 32];
        raw[0..8].copy_from_slice(&old.handler.to_le_bytes());
        raw[8..16].copy_from_slice(&old.flags.to_le_bytes());
        raw[16..24].copy_from_slice(&old.restorer.to_le_bytes());
        raw[24..32].copy_from_slice(&old.mask.to_le_bytes());
        copy_to_user(oldact, &raw)?;
    }
    Ok(0)
}

/// `rt_sigprocmask`: query/modify the blocked-signal mask. `sigsetsize` is 8.
fn sys_rt_sigprocmask(how: i32, set: u64, oldset: u64, sigsetsize: usize) -> SysResult {
    if sigsetsize != 8 {
        return Err(Errno::EINVAL);
    }
    let p = proc()?;
    let cur = p.lock().sig.mask();
    if oldset != 0 {
        copy_to_user(oldset, &cur.to_le_bytes())?;
    }
    if set != 0 {
        let mut raw = [0u8; 8];
        copy_from_user(set, &mut raw)?;
        let arg = u64::from_le_bytes(raw);
        let new = match how {
            types::SIG_BLOCK => cur | arg,
            types::SIG_UNBLOCK => cur & !arg,
            types::SIG_SETMASK => arg,
            _ => return Err(Errno::EINVAL),
        };
        p.lock().sig.set_mask(new);
    }
    Ok(0)
}

/// `wait4`: reap an exited child; block (yielding) until one is available.
fn sys_wait4(_pid: i32, wstatus: u64, options: u32) -> SysResult {
    const WNOHANG: u32 = 1;
    let parent = cur_pid()?;
    loop {
        // Capture the wait-queue generation BEFORE re-checking for an exited
        // child, so a child that exits in the gap before we block either is
        // reaped now or bumps the generation and refuses our block (no lost
        // wakeup, even though the condition spans multiple locks).
        let wq_gen = process::child_exit_wq().prepare();
        if let Some((child_pid, code)) = process::reap_child(parent) {
            if wstatus != 0 {
                // W_EXITCODE(code, 0): low 8 bits signal, next 8 exit code.
                put_user(wstatus, ((code & 0xff) as u32) << 8)?;
            }
            return Ok(child_pid as u64);
        }
        if !process::has_children(parent) {
            return Err(Errno::ECHILD);
        }
        if options & WNOHANG != 0 {
            return Ok(0);
        }
        if let Some(pr) = process::current() {
            if pr.lock().interrupted() {
                return Err(Errno::ERESTARTSYS);
            }
        }
        crate::scheduler::block_with_gen(process::child_exit_wq(), wq_gen);
    }
}

/// `fork`: eager-copy the address space, duplicate the fd table, and spawn a
/// child thread that resumes at the fork point returning 0. Parent gets the pid.
fn sys_fork(regs: &Regs) -> SysResult {
    let parent = proc()?;
    let child = {
        let mut p = parent.lock();
        Process::fork_from(&mut p).ok_or(Errno::ENOMEM)?
    };
    let child_pid = child.lock().pid;
    process::register(child.clone());
    let mut child_regs = *regs;
    child_regs.rax = 0;
    // Defense in depth: never let a child resume with privileged RFLAGS bits
    // (IOPL/NT/...) inherited from a frame, matching the sigreturn sanitiser.
    child_regs.rflags = crate::signal::sanitize_user_rflags(child_regs.rflags);
    crate::userspace::spawn_fork_child(&child, child_regs)?;
    Ok(child_pid as u64)
}

/// `execve`: replace the current image with a new ELF, rebuild argv/envp/auxv,
/// switch to the new address space, and enter it. Never returns on success.
fn sys_execve(path: u64, argv: u64, envp: u64) -> SysResult {
    use x86_64::registers::control::{Cr3, Cr3Flags};
    use x86_64::structures::paging::PhysFrame;
    use x86_64::PhysAddr;

    let path = read_path(path)?;
    let argv_strs = read_str_array(argv)?;
    let envp_strs = read_str_array(envp)?;
    // Resolve relative to the caller's cwd; the image itself is not read here
    // (the loader pages it in on demand).
    let cwd = proc()?.lock().cwd;
    let (ino, st) = fs::with_vfs(|v| {
        let ino = v.resolve(cwd, &path, true)?;
        Ok((ino, v.stat(ino)?))
    })?;
    if st.st_mode & types::S_IFMT != types::S_IFREG {
        return Err(Errno::EACCES);
    }
    if st.st_mode & 0o111 == 0 {
        return Err(Errno::EACCES);
    }

    let argv_refs: Vec<&str> = argv_strs.iter().map(alloc::string::String::as_str).collect();
    let envp_refs: Vec<&str> = envp_strs.iter().map(alloc::string::String::as_str).collect();

    if strace_exec_only() {
        let pid = process::current().map_or(0, |p| p.lock().pid);
        crate::log::info!("exec: pid {pid} {path} {argv_refs:?} ({} KiB image)", st.st_size / 1024);
    }

    let proc = proc()?;
    let (entry, user_sp, cr3) = {
        let mut p = proc.lock();
        let mut space = crate::process::AddressSpace::new().ok_or(Errno::ENOMEM)?;
        let loaded = crate::elf::load_file(&mut space, ino)?;
        let sp = crate::userspace::build_stack(&mut space, &loaded, &argv_refs, &envp_refs)
            .map_err(|_| Errno::ENOMEM)?;
        // Reclaim the old image's user frames before swapping in the new space
        // (shared CoW frames are only freed if this was the last owner).
        p.space.free_leaves();
        p.space = space;
        p.brk = 0;
        p.brk_start = 0;
        p.mmap_next = 0x6000_0000;
        p.sig.exec_reset();
        p.comm = path.rsplit('/').next().unwrap_or(&path).into();
        (loaded.entry, sp, p.space.cr3())
    };
    // Close FD_CLOEXEC descriptors; dropped outside the process lock because
    // closing a pipe end wakes its peers.
    let closed = proc.lock().fds.take_cloexec();
    drop(closed);

    // Switch this thread to the new address space and enter it.
    // SAFETY: `cr3` is a valid PML4 with the kernel higher half; `entry`/`user_sp`
    // are valid in it.
    unsafe {
        // Reset the FS/GS user bases: the new image sets up its own TLS; the old
        // bases point into the discarded address space.
        use x86_64::registers::model_specific::{FsBase, KernelGsBase};
        FsBase::write(x86_64::VirtAddr::new(0));
        KernelGsBase::write(x86_64::VirtAddr::new(0));
        (*crate::percpu::current()).user_gs = 0;
        (*crate::percpu::current()).fs_base = 0;
        (*crate::percpu::current()).cr3 = cr3;
        let frame = PhysFrame::containing_address(PhysAddr::new(cr3));
        Cr3::write(frame, Cr3Flags::empty());
        crate::arch::x86_64::user::enter_user(entry, user_sp);
    }
}

/// Reads a NUL-terminated array of user string pointers into owned strings.
fn read_str_array(uaddr: u64) -> Result<Vec<alloc::string::String>, Errno> {
    if uaddr == 0 {
        return Ok(Vec::new());
    }
    let ptrs = usercopy::read_ptr_array(uaddr, 1024)?;
    let mut out = Vec::with_capacity(ptrs.len());
    for p in ptrs {
        let bytes = usercopy::read_cstr(p, 4096)?;
        out.push(alloc::string::String::from_utf8_lossy(&bytes).into_owned());
    }
    Ok(out)
}

// --- ENOSYS logging --------------------------------------------------------

/// Tracks which syscall numbers have already been logged as unimplemented.
static LOGGED: [AtomicBool; 512] = [const { AtomicBool::new(false) }; 512];

fn log_enosys(number: u64) {
    let idx = number as usize;
    if idx < LOGGED.len() && !LOGGED[idx].swap(true, Ordering::Relaxed) {
        match nr::name(number) {
            Some(name) => crate::log::warning!("ENOSYS: syscall {number} ({name}) not implemented"),
            None => crate::log::warning!("ENOSYS: syscall {number} (unknown) not implemented"),
        }
    }
}

use core::mem::size_of;
