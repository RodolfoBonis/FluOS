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

/// Entry from the syscall assembly: runs the handler and stores the result.
pub extern "C" fn dispatch(regs: &mut Regs) {
    let result = handle(regs.rax, regs.args(), regs);
    regs.rax = errno::encode(result);
}

/// The current process, or `EFAULT` if there somehow is none.
fn proc() -> Result<&'static SpinLock<Process>, Errno> {
    process::current().ok_or(Errno::EFAULT)
}

fn handle(number: u64, a: [u64; 6], _regs: &mut Regs) -> SysResult {
    match number {
        nr::WRITE => sys_write(a[0] as i32, a[1], a[2] as usize),
        nr::READ => sys_read(a[0] as i32, a[1], a[2] as usize),
        nr::WRITEV => sys_writev(a[0] as i32, a[1], a[2] as usize),
        nr::READV => sys_readv(a[0] as i32, a[1], a[2] as usize),
        nr::OPENAT => sys_openat(a[0] as i32, a[1], a[2], a[3] as u32),
        nr::OPEN => sys_openat(types::AT_FDCWD, a[0], a[1], a[2] as u32),
        nr::CLOSE => sys_close(a[0] as i32),
        nr::LSEEK => sys_lseek(a[0] as i32, a[1] as i64, a[2] as u32),
        nr::EXIT | nr::EXIT_GROUP => sys_exit(a[0] as i32),
        nr::GETPID | nr::GETTID => sys_getpid(),
        nr::GETPPID => Ok(1),
        nr::GETUID | nr::GETEUID | nr::GETGID | nr::GETEGID => Ok(0),
        nr::ARCH_PRCTL => sys_arch_prctl(a[0], a[1]),
        nr::SET_TID_ADDRESS => sys_set_tid_address(a[0]),
        nr::BRK => sys_brk(a[0]),
        nr::MMAP => sys_mmap(a[0], a[1], a[2], a[3], a[4] as i32, a[5]),
        nr::MUNMAP => Ok(0), // regions are not reclaimed yet
        nr::MPROTECT => Ok(0),
        nr::IOCTL => sys_ioctl(a[0] as i32, a[1], a[2]),
        nr::UNAME => sys_uname(a[0]),
        nr::GETRANDOM => sys_getrandom(a[0], a[1] as usize),
        nr::CLOCK_GETTIME => sys_clock_gettime(a[0], a[1]),
        nr::FSTAT => sys_fstat(a[0] as i32, a[1]),
        nr::NEWFSTATAT => sys_newfstatat(a[0] as i32, a[1], a[2], a[3] as i32),
        nr::GETDENTS64 => sys_getdents64(a[0] as i32, a[1], a[2] as usize),
        nr::GETCWD => sys_getcwd(a[0], a[1] as usize),
        nr::DUP => dup(a[0] as i32),
        nr::DUP2 => dup3(a[0] as i32, a[1] as i32),
        nr::DUP3 => dup3(a[0] as i32, a[1] as i32),
        nr::FCNTL => sys_fcntl(a[0] as i32, a[1], a[2]),
        nr::SCHED_YIELD => {
            crate::scheduler::yield_now();
            Ok(0)
        }
        nr::SCHED_GETAFFINITY => sys_sched_getaffinity(a[2], a[1] as usize),
        nr::SET_ROBUST_LIST | nr::RSEQ => Ok(0),
        nr::RT_SIGPROCMASK | nr::RT_SIGACTION => Ok(0),
        nr::PRLIMIT64 => sys_prlimit64(a[2], a[3]),
        nr::GETRLIMIT => sys_getrlimit(a[1]),
        nr::POLL | nr::PPOLL | nr::PSELECT6 | nr::SELECT => Ok(1),
        nr::NANOSLEEP | nr::CLOCK_NANOSLEEP => {
            crate::scheduler::yield_now();
            Ok(0)
        }
        nr::FUTEX => Ok(0),
        nr::ACCESS => sys_access(types::AT_FDCWD, a[0]),
        nr::FACCESSAT => sys_access(a[0] as i32, a[1]),
        nr::SETPGID | nr::SETSID | nr::GETPGRP | nr::GETPGID | nr::GETSID => Ok(0),
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

fn cur_pid() -> Result<i32, Errno> {
    Ok(proc()?.lock().pid)
}

fn fd(fd: i32) -> Result<Arc<SpinLock<fs::OpenFile>>, Errno> {
    proc()?.lock().fds.get(fd)
}

// --- file I/O --------------------------------------------------------------

fn sys_write(fd_num: i32, buf: u64, len: usize) -> SysResult {
    let file = fd(fd_num)?;
    let mut data = vec![0u8; len];
    copy_from_user(buf, &mut data)?;
    fs::write(&file, &data)
}

fn sys_read(fd_num: i32, buf: u64, len: usize) -> SysResult {
    let file = fd(fd_num)?;
    let mut data = vec![0u8; len];
    let n = fs::read(&file, &mut data)? as usize;
    copy_to_user(buf, &data[..n])?;
    Ok(n as u64)
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
        let mut data = vec![0u8; ilen];
        copy_from_user(base, &mut data)?;
        total += fs::write(&file, &data)?;
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
        let mut data = vec![0u8; ilen];
        let n = fs::read(&file, &mut data)? as usize;
        copy_to_user(base, &data[..n])?;
        total += n as u64;
        if n < ilen {
            break;
        }
    }
    Ok(total)
}

fn sys_openat(_dirfd: i32, path: u64, flags: u64, mode: u32) -> SysResult {
    let path = read_path(path)?;
    let file = fs::open(vfs::ROOT, &path, flags, mode)?;
    Ok(proc()?.lock().fds.alloc(file) as u64)
}

fn sys_close(fd_num: i32) -> SysResult {
    proc()?.lock().fds.close(fd_num)?;
    Ok(0)
}

fn sys_lseek(_fd: i32, _off: i64, _whence: u32) -> SysResult {
    // Offsets for regular files are tracked in the open file; a full lseek lands
    // with the VFS integration. Report unsupported-on-device for now.
    Err(Errno::ESPIPE)
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
    match cmd {
        F_DUPFD => dup(fd_num),
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
    if addr == 0 || addr < g.brk_start {
        return Ok(g.brk);
    }
    let old = g.brk;
    if addr > old {
        g.space.map_region(old, addr - old, true, false);
        flush_tlb();
    }
    g.brk = addr;
    Ok(addr)
}

fn sys_mmap(addr: u64, len: u64, _prot: u64, flags: u64, _fd: i32, _off: u64) -> SysResult {
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    let p = proc()?;
    let mut g = p.lock();
    let page = 4096u64;
    let size = (len + page - 1) & !(page - 1);
    let base = if flags & types::MAP_FIXED != 0 && addr != 0 {
        addr
    } else {
        let b = g.mmap_next;
        g.mmap_next += size;
        b
    };
    g.space.map_region(base, size, true, false);
    flush_tlb();
    Ok(base)
}

fn flush_tlb() {
    x86_64::instructions::tlb::flush_all();
}

// --- process / misc --------------------------------------------------------

fn sys_exit(code: i32) -> SysResult {
    if let Some(p) = process::current() {
        p.lock().exit_code = Some(code);
    }
    crate::log::info!("process exited with status {code}");
    crate::scheduler::thread_exit();
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
            // SAFETY: setting the user FS base for TLS.
            FsBase::write(VirtAddr::new(addr));
            Ok(0)
        }
        ARCH_GET_FS => {
            put_user(addr, FsBase::read().as_u64())?;
            Ok(0)
        }
        ARCH_SET_GS => {
            // The user GS lives in KERNEL_GS_BASE while in the kernel (swapgs
            // restores it to GS on sysret); also record it in the thread so the
            // context switch preserves it.
            KernelGsBase::write(VirtAddr::new(addr));
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
    let p = proc()?;
    let pid = {
        let mut g = p.lock();
        g.clear_child_tid = ptr;
        g.pid
    };
    Ok(pid as u64)
}

fn sys_ioctl(_fd: i32, request: u64, arg: u64) -> SysResult {
    match request {
        types::TCGETS => {
            // Report a cooked tty so isatty() succeeds.
            let mut t = types::Termios::default();
            t.c_iflag = types::ICRNL;
            t.c_oflag = types::OPOST | types::ONLCR;
            t.c_lflag = types::ICANON | types::ECHO | types::ISIG;
            t.c_cc[types::VERASE] = 0x7f;
            t.c_cc[types::VINTR] = 3;
            t.c_cc[types::VEOF] = 4;
            let bytes = unsafe {
                core::slice::from_raw_parts(core::ptr::from_ref(&t).cast::<u8>(), size_of::<types::Termios>())
            };
            copy_to_user(arg, bytes)?;
            Ok(0)
        }
        types::TCSETS | types::TCSETSW | types::TCSETSF => Ok(0),
        types::TIOCGWINSZ => {
            let ws = types::Winsize { ws_row: 40, ws_col: 128, ws_xpixel: 0, ws_ypixel: 0 };
            let bytes = unsafe {
                core::slice::from_raw_parts(core::ptr::from_ref(&ws).cast::<u8>(), size_of::<types::Winsize>())
            };
            copy_to_user(arg, bytes)?;
            Ok(0)
        }
        types::TIOCGPGRP => {
            put_user(arg, cur_pid()? as u32)?;
            Ok(0)
        }
        types::TIOCSPGRP => Ok(0),
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
    let mut data = vec![0u8; len];
    crate::rng::fill(&mut data);
    copy_to_user(buf, &data)?;
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
        }
    };
    write_stat(statbuf, &st)
}

fn sys_newfstatat(_dirfd: i32, path: u64, statbuf: u64, _flags: i32) -> SysResult {
    let path = read_path(path)?;
    let st = fs::with_vfs(|v| {
        let ino = v.resolve(vfs::ROOT, &path, true)?;
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
    let cwd = b"/\0";
    if size < cwd.len() {
        return Err(Errno::ERANGE);
    }
    copy_to_user(buf, cwd)?;
    Ok(cwd.len() as u64)
}

fn sys_access(_dirfd: i32, path: u64) -> SysResult {
    let path = read_path(path)?;
    fs::with_vfs(|v| v.resolve(vfs::ROOT, &path, true))?;
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
