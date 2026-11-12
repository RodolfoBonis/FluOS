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
}

/// The current process, or `EFAULT` if there somehow is none.
fn proc() -> Result<&'static SpinLock<Process>, Errno> {
    process::current().ok_or(Errno::EFAULT)
}

fn handle(number: u64, a: [u64; 6], regs: &mut Regs) -> SysResult {
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
        nr::SETUID => { proc()?.lock().uid = a[0] as u32; Ok(0) }
        nr::SETGID => { proc()?.lock().gid = a[0] as u32; Ok(0) }
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
        nr::FSTAT => sys_fstat(a[0] as i32, a[1]),
        nr::NEWFSTATAT => sys_newfstatat(a[0] as i32, a[1], a[2], a[3] as i32),
        nr::STAT => sys_stat(a[0], a[1], true),
        nr::LSTAT => sys_stat(a[0], a[1], false),
        nr::GETDENTS64 => sys_getdents64(a[0] as i32, a[1], a[2] as usize),
        nr::GETCWD => sys_getcwd(a[0], a[1] as usize),
        nr::CHDIR => sys_chdir(a[0]),
        nr::MKDIR => sys_mkdirat(types::AT_FDCWD, a[0], a[1] as u32),
        nr::MKDIRAT => sys_mkdirat(a[0] as i32, a[1], a[2] as u32),
        nr::READLINK => sys_readlinkat(types::AT_FDCWD, a[0], a[1], a[2] as usize),
        nr::READLINKAT => sys_readlinkat(a[0] as i32, a[1], a[2], a[3] as usize),
        nr::UMASK => sys_umask(a[0] as u32),
        nr::GETRUSAGE => sys_getrusage(a[0] as i32, a[1]),
        nr::SIGALTSTACK => sys_sigaltstack(a[0], a[1]),
        nr::RT_SIGSUSPEND => sys_rt_sigsuspend(a[0], a[1] as usize),
        nr::PRCTL => Ok(0),
        nr::DUP => dup(a[0] as i32),
        nr::DUP2 => dup3(a[0] as i32, a[1] as i32),
        nr::DUP3 => dup3(a[0] as i32, a[1] as i32),
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
        nr::PSELECT6 | nr::SELECT => Ok(1),
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
    Ok(proc()?.lock().fds.alloc(file) as u64)
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

fn dup3(old: i32, new: i32) -> SysResult {
    Ok(proc()?.lock().fds.dup3(old, new)? as u64)
}

fn sys_fcntl(fd_num: i32, cmd: u64, arg: u64) -> SysResult {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => proc()?.lock().fds.dup_from(fd_num, arg as i32),
        F_GETFD | F_GETFL => Ok(0),
        F_SETFD | F_SETFL => Ok(0),
        _ => {
            let _ = arg;
            Ok(0)
        }
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

/// `exit_group`: terminates the whole thread group. Records the status, notifies
/// the parent, and exits the calling thread. (Sibling threads finish on their
/// own next exit; a joined program has none left by here.)
fn sys_exit_group(code: i32) -> SysResult {
    if let Some(p) = process::current() {
        let (ppid, fds) = {
            let mut g = p.lock();
            g.exit_code = Some(code);
            g.thread_count = 0;
            (g.ppid, g.fds.take_all())
        };
        drop(fds); // close files outside the lock -> peers see EOF/EPIPE now
        crate::signal::notify_parent(ppid);
    }
    process::notify_child_exit();
    crate::log::info!("process exited with status {code}");
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
            if proc()?.lock().sig.has_deliverable() {
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
        if proc()?.lock().sig.has_deliverable() {
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

fn sys_clock_gettime(_clk: u64, ts: u64) -> SysResult {
    // Monotonic-ish from the TSC is future work; report a fixed epoch for now.
    let t = types::Timespec { tv_sec: 0, tv_nsec: 0 };
    let bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(&t).cast::<u8>(), size_of::<types::Timespec>())
    };
    copy_to_user(ts, bytes)?;
    Ok(0)
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
    let (ino, start) = {
        let f = file.lock();
        match &f.kind {
            fs::FileKind::Dir { ino, pos } => (*ino, *pos),
            _ => return Err(Errno::ENOTDIR),
        }
    };
    let entries = fs::with_vfs(|v| v.readdir(ino))?;
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    while pos < entries.len() {
        let (name, child, dtype) = &entries[pos];
        let reclen = (19 + name.len() + 1 + 7) & !7; // header 19 + name + NUL, 8-aligned
        if out.len() + reclen > len {
            break;
        }
        out.extend_from_slice(&(u64::from(*child) + 1).to_le_bytes()); // d_ino
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
    if let fs::FileKind::Dir { pos: p, .. } = &mut file.lock().kind {
        *p = pos;
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

/// `readlink`/`readlinkat`: copy a symlink's target (not NUL-terminated) into
/// the caller's buffer, truncated to its length; `EINVAL` if not a symlink.
fn sys_readlinkat(dirfd: i32, path: u64, buf: u64, bufsize: usize) -> SysResult {
    let path = read_path(path)?;
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
    let old = p.lock().sig.set_mask(newmask);
    // Bounded wait: break early once something is deliverable, but never spin
    // forever. Each yield lets other threads (and exiting children) run.
    for _ in 0..64 {
        if p.lock().sig.has_deliverable() {
            break;
        }
        crate::scheduler::yield_now();
    }
    p.lock().sig.set_mask(old);
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
        let rfd = g.fds.alloc(rd);
        let wfd = g.fds.alloc(wr);
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
            if pr.lock().sig.has_deliverable() {
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
            if pr.lock().sig.has_deliverable() {
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
    let image = fs::read_file(&path)?;

    let argv_refs: Vec<&str> = argv_strs.iter().map(alloc::string::String::as_str).collect();
    let envp_refs: Vec<&str> = envp_strs.iter().map(alloc::string::String::as_str).collect();

    let proc = proc()?;
    let (entry, user_sp, cr3) = {
        let mut p = proc.lock();
        let mut space = crate::process::AddressSpace::new().ok_or(Errno::ENOMEM)?;
        let loaded = crate::elf::load(&mut space, &image)?;
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
        (loaded.entry, sp, p.space.cr3())
    };

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
