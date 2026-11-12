//! POSIX signals: per-process disposition, a pending set and blocked mask, and
//! delivery on the syscall-return path.
//!
//! Delivery model. FluOS currently runs one thread per process and delivers
//! signals when a syscall is about to return to ring 3 (see [`on_syscall_return`],
//! called from the dispatcher). That is the only point where we hold the full
//! user register frame ([`Regs`]) and are guaranteed to be on the target
//! process. A caught signal gets a Linux-compatible `rt_sigframe` built on the
//! user stack (GP registers + an FXSAVE blob), the handler runs in ring 3, and
//! its `sa_restorer` invokes `rt_sigreturn` ([`sys_rt_sigreturn`]) to restore the
//! interrupted context. Blocking syscalls cooperate by returning `ERESTARTSYS`
//! when a deliverable signal is pending, which this layer turns into either a
//! transparent restart (`SA_RESTART`) or `EINTR`.

use crate::arch::x86_64::context;
use crate::arch::x86_64::user::Regs;
use crate::process::{self, Process};
use abi::types;

/// Highest supported signal number (1..=NSIG).
pub const NSIG: usize = 64;

/// Returns the pending-set bit for signal `n` (1-based).
#[inline]
fn bit(n: i32) -> u64 {
    debug_assert!((1..=NSIG as i32).contains(&n));
    1u64 << (n - 1)
}

/// A signal disposition, matching Linux's `struct sigaction` field order so the
/// `rt_sigaction` payload maps on directly.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigAction {
    /// `SIG_DFL` (0), `SIG_IGN` (1), or a user handler address.
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    /// Extra signals blocked while the handler runs.
    pub mask: u64,
}

impl SigAction {
    pub const DFL: SigAction = SigAction { handler: 0, flags: 0, restorer: 0, mask: 0 };
}

/// Per-process signal state (guarded by the process lock).
#[derive(Clone)]
pub struct SignalState {
    actions: [SigAction; NSIG + 1],
    /// Pending, not-yet-delivered signals (bit `n-1`).
    pending: u64,
    /// Blocked signals (bit `n-1`).
    mask: u64,
}

impl SignalState {
    #[must_use]
    pub fn new() -> Self {
        Self { actions: [SigAction::DFL; NSIG + 1], pending: 0, mask: 0 }
    }

    /// `execve` keeps the mask but resets every *caught* signal to its default
    /// (ignored dispositions survive, as Linux does).
    pub fn exec_reset(&mut self) {
        for a in &mut self.actions {
            if a.handler != types::SIG_IGN {
                *a = SigAction::DFL;
            } else {
                a.flags = 0;
                a.restorer = 0;
                a.mask = 0;
            }
        }
        self.pending = 0;
    }

    /// Whether a signal is pending that is not currently blocked.
    #[must_use]
    pub fn has_deliverable(&self) -> bool {
        self.pending & !self.mask != 0
    }

    /// A `fork` child's signal state: inherited handlers and mask, empty pending.
    #[must_use]
    pub fn forked(&self) -> Self {
        let mut s = self.clone();
        s.pending = 0;
        s
    }

    /// Replaces the blocked mask (used by `rt_sigprocmask`), returning the old.
    pub fn set_mask(&mut self, mask: u64) -> u64 {
        let old = self.mask;
        self.mask = mask & !(bit(abi::types::SIGKILL) | bit(abi::types::SIGSTOP));
        old
    }

    /// The current blocked mask.
    #[must_use]
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// Installs a disposition for `sig`, returning the previous one. Ignores
    /// out-of-range or uncatchable signals (returns default).
    pub fn set_action(&mut self, sig: i32, act: SigAction) -> SigAction {
        if !(1..=NSIG as i32).contains(&sig)
            || sig == abi::types::SIGKILL
            || sig == abi::types::SIGSTOP
        {
            return SigAction::DFL;
        }
        core::mem::replace(&mut self.actions[sig as usize], act)
    }

    /// The disposition for `sig` (default if out of range).
    #[must_use]
    pub fn action(&self, sig: i32) -> SigAction {
        if (1..=NSIG as i32).contains(&sig) {
            self.actions[sig as usize]
        } else {
            SigAction::DFL
        }
    }
}

impl Default for SignalState {
    fn default() -> Self {
        Self::new()
    }
}

/// The default kernel action for a signal with no user handler.
enum Default_ {
    Term,
    Ignore,
    Stop,
    Cont,
}

fn default_action(sig: i32) -> Default_ {
    use abi::types::*;
    match sig {
        SIGCHLD | SIGURG | SIGWINCH => Default_::Ignore,
        SIGCONT => Default_::Cont,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => Default_::Stop,
        _ => Default_::Term, // Term/Core collapse to "terminate" here
    }
}

// --- raising signals -------------------------------------------------------

/// Posts `sig` to `p`'s pending set. Returns `true` if it was newly set.
/// Discarding `SIG_IGN`/default-ignore here keeps the pending set meaningful.
fn post(p: &mut Process, sig: i32) -> bool {
    if !(1..=NSIG as i32).contains(&sig) {
        return false;
    }
    let act = p.sig.actions[sig as usize];
    // A signal dispositioned to ignore (explicitly, or by default with no
    // handler) is dropped rather than left pending — except SIGCONT, which has
    // side effects we honour elsewhere. SIGKILL/SIGSTOP cannot be ignored.
    if sig != abi::types::SIGKILL && sig != abi::types::SIGSTOP {
        let ignored = act.handler == abi::types::SIG_IGN
            || (act.handler == abi::types::SIG_DFL
                && matches!(default_action(sig), Default_::Ignore));
        if ignored {
            return false;
        }
    }
    p.sig.pending |= bit(sig);
    true
}

/// Sends `sig` to the process with pid `pid`. Returns `true` if delivered to a
/// live process. Safe to call from IRQ context (the process lock is IRQ-safe).
pub fn send_to_pid(pid: i32, sig: i32) -> bool {
    process::with_pid(pid, |p| post(p, sig)).unwrap_or(false)
}

/// Sends `sig` to every process in group `pgid`. Returns the count reached.
pub fn send_to_pgrp(pgid: i32, sig: i32) -> usize {
    process::for_each_in_pgrp(pgid, |p| {
        post(p, sig);
    })
}

/// Notifies `ppid` that a child changed state (used on exit).
pub fn notify_parent(ppid: i32) {
    send_to_pid(ppid, abi::types::SIGCHLD);
}

/// Whether the current process has a signal pending that is not blocked. Used
/// by in-kernel blocking loops (tty reads, sleeps) to break out and let the
/// signal be delivered on the syscall-return path.
#[must_use]
pub fn current_has_deliverable() -> bool {
    process::current().is_some_and(|p| p.lock().sig.has_deliverable())
}

// --- rt_sigframe (Linux x86_64 layout) -------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SigContext {
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rax: u64,
    rcx: u64,
    rsp: u64,
    rip: u64,
    eflags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    err: u64,
    trapno: u64,
    oldmask: u64,
    cr2: u64,
    fpstate: u64,
    reserved: [u64; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Stack {
    ss_sp: u64,
    ss_flags: i32,
    _pad: i32,
    ss_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UContext {
    uc_flags: u64,
    uc_link: u64,
    uc_stack: Stack,
    uc_mcontext: SigContext,
    uc_sigmask: [u64; 16],
    fpregs_mem: [u64; 64],
}

impl Default for UContext {
    fn default() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: Stack::default(),
            uc_mcontext: SigContext::default(),
            uc_sigmask: [0; 16],
            fpregs_mem: [0; 64],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtSigFrame {
    pretcode: u64,
    uc: UContext,
    info: [u8; 128],
}

const FXSAVE_SIZE: usize = 512;

/// RFLAGS bits a signal handler may change through `rt_sigreturn`:
/// CF PF AF ZF SF TF DF OF AC (Linux's `FIX_EFLAGS` minus RF).
/// Everything else — notably IOPL, which `sysretq` would load and which grants
/// ring 3 raw port I/O — comes from the kernel, never from the user's frame.
const USER_RFLAGS_MASK: u64 = 0x0004_0dd5;
/// IF set plus the always-one reserved bit 1.
const USER_RFLAGS_FIXED: u64 = 0x0000_0202;

/// Sanitizes RFLAGS loaded from a user-controlled sigframe.
fn sanitize_user_rflags(user: u64) -> u64 {
    (user & USER_RFLAGS_MASK) | USER_RFLAGS_FIXED
}

// --- delivery on the syscall-return path -----------------------------------

/// Called from the dispatcher after a syscall handler runs, with the raw user
/// frame. `orig_nr` is the syscall number on entry and `raw_result` the value
/// already stored in `regs.rax`. If a deliverable signal exists it is applied
/// here (handler set up, process terminated, etc.); `ERESTARTSYS` semantics are
/// resolved against the chosen disposition.
pub fn on_syscall_return(regs: &mut Regs, orig_nr: u64, restartable: bool) {
    loop {
        let Some(proc) = process::current() else { return };

        // Pick the lowest-numbered deliverable signal under the lock, then act
        // without holding it (termination and user-stack writes must not).
        let (sig, act) = {
            let mut g = proc.lock();
            let deliverable = g.sig.pending & !g.sig.mask;
            if deliverable == 0 {
                // No signal: resolve a pending restart request transparently.
                if restartable && regs.rax == (-abi::errno::ERESTARTSYS) as u64 {
                    restart(regs, orig_nr);
                }
                return;
            }
            let sig = (deliverable.trailing_zeros() + 1) as i32;
            g.sig.pending &= !bit(sig);
            (sig, g.sig.actions[sig as usize])
        };

        if act.handler == abi::types::SIG_IGN {
            // Explicitly ignored: drop it and, if we were mid-restart, retry.
            if restartable && regs.rax == (-abi::errno::ERESTARTSYS) as u64 {
                restart(regs, orig_nr);
                return;
            }
            continue;
        }

        if act.handler == abi::types::SIG_DFL {
            match default_action(sig) {
                Default_::Ignore | Default_::Cont => {
                    if restartable && regs.rax == (-abi::errno::ERESTARTSYS) as u64 {
                        restart(regs, orig_nr);
                        return;
                    }
                    continue;
                }
                Default_::Stop => {
                    // No full job-control stop yet: log and ignore so the shell
                    // stays alive. (A real stop lands with step 4's scheduler.)
                    crate::log::info!("signal {sig}: default-stop not yet implemented; ignored");
                    continue;
                }
                Default_::Term => terminate(sig),
            }
        }

        // A user handler: restartable syscalls either rewind to re-run after the
        // handler (SA_RESTART) or report EINTR in the saved context.
        if restartable && regs.rax == (-abi::errno::ERESTARTSYS) as u64 {
            if act.flags & abi::types::SA_RESTART != 0 {
                restart(regs, orig_nr);
            } else {
                regs.rax = (-abi::errno::EINTR) as u64;
            }
        }

        if setup_handler(regs, sig, &act) {
            return;
        }
        // Frame build failed (bad user stack): kill with SIGSEGV.
        terminate(abi::types::SIGSEGV);
    }
}

/// Rewinds a restartable syscall so it re-executes after returning to ring 3:
/// the `syscall` instruction is 2 bytes, and the number goes back into `rax`.
fn restart(regs: &mut Regs, orig_nr: u64) {
    regs.rip = regs.rip.wrapping_sub(2);
    regs.rax = orig_nr;
}

/// Terminates the current process as if killed by `sig`, notifying the parent.
fn terminate(sig: i32) -> ! {
    if let Some(p) = process::current() {
        let ppid = {
            let mut g = p.lock();
            g.exit_code = Some(128 + sig);
            g.ppid
        };
        notify_parent(ppid);
    }
    let pid = process::current().map(|p| p.lock().pid);
    crate::log::info!("process {pid:?} terminated by signal {sig}");
    crate::scheduler::thread_exit();
}

/// Builds the `rt_sigframe` on the user stack and redirects `regs` into the
/// handler. Returns `false` if the user stack could not be written.
fn setup_handler(regs: &mut Regs, sig: i32, act: &SigAction) -> bool {
    use core::mem::{offset_of, size_of};

    // A restorer is mandatory (musl/glibc always pass SA_RESTORER). Without one
    // we cannot return from the handler, so fall back to terminating.
    if act.flags & abi::types::SA_RESTORER == 0 || act.restorer == 0 {
        crate::log::warning!("signal {sig}: handler without SA_RESTORER; terminating");
        return false;
    }

    // Snapshot the FPU state the handler will clobber.
    let mut fx = alloc::vec![0u8; FXSAVE_SIZE];
    // SAFETY: `fx` is 512 bytes; fxsave64 writes exactly that much.
    unsafe { context::fxsave(fx.as_mut_ptr()) };

    // Carve the frame out below the red zone, keeping the FXSAVE blob 64-aligned
    // and the frame base at `rsp % 16 == 8` (so the handler sees a call-aligned
    // stack, i.e. `(rsp + 8) % 16 == 0`).
    let sp = regs.user_rsp.saturating_sub(128);
    let fp_addr = (sp.saturating_sub(FXSAVE_SIZE as u64)) & !63u64;
    let frame_size = size_of::<RtSigFrame>() as u64;
    let frame_addr = ((fp_addr.saturating_sub(frame_size)) & !15u64).wrapping_sub(8);

    let mut frame = RtSigFrame {
        pretcode: act.restorer,
        uc: UContext::default(),
        info: [0u8; 128],
    };
    // Minimal siginfo: si_signo in the first int.
    frame.info[0..4].copy_from_slice(&sig.to_le_bytes());

    let mc = &mut frame.uc.uc_mcontext;
    mc.r8 = regs.r8;
    mc.r9 = regs.r9;
    mc.r10 = regs.r10;
    mc.r12 = regs.r12;
    mc.r13 = regs.r13;
    mc.r14 = regs.r14;
    mc.r15 = regs.r15;
    mc.rdi = regs.rdi;
    mc.rsi = regs.rsi;
    mc.rbp = regs.rbp;
    mc.rbx = regs.rbx;
    mc.rdx = regs.rdx;
    mc.rax = regs.rax;
    mc.rsp = regs.user_rsp;
    mc.rip = regs.rip;
    mc.eflags = regs.rflags;
    mc.cs = 0x33;
    mc.ss = 0x2b;
    mc.fpstate = fp_addr;

    // Save the current blocked mask into the frame and block this signal (plus
    // the action's mask) for the duration of the handler.
    let (old_mask, info_addr, uc_addr) = {
        let proc = match process::current() {
            Some(p) => p,
            None => return false,
        };
        let mut g = proc.lock();
        let old = g.sig.mask;
        frame.uc.uc_sigmask[0] = old;
        g.sig.mask |= act.mask | bit(sig);
        (
            old,
            frame_addr + offset_of!(RtSigFrame, info) as u64,
            frame_addr + offset_of!(RtSigFrame, uc) as u64,
        )
    };
    let _ = old_mask;

    // Publish the FXSAVE blob and the frame to the user stack.
    if crate::usercopy::copy_to_user(fp_addr, &fx).is_err() {
        return false;
    }
    // SAFETY: `frame` is a plain repr(C) value with no padding we rely on; view
    // it as bytes to copy out.
    let frame_bytes = unsafe {
        core::slice::from_raw_parts(core::ptr::from_ref(&frame).cast::<u8>(), size_of::<RtSigFrame>())
    };
    if crate::usercopy::copy_to_user(frame_addr, frame_bytes).is_err() {
        return false;
    }

    // Enter the handler: handler(sig, &info, &uc) with a call-aligned stack.
    regs.rip = act.handler;
    regs.user_rsp = frame_addr;
    regs.rdi = sig as u64;
    regs.rsi = info_addr;
    regs.rdx = uc_addr;
    regs.rax = 0;
    // Clear DF/TF for the handler, keep the rest (IF stays set).
    regs.rflags &= !(0x0000_0400 | 0x0000_0100);
    true
}

/// `rt_sigreturn`: restore the context saved by [`setup_handler`] from the user
/// stack. Returns the restored `rax` so the dispatcher's write-back is a no-op.
pub fn sys_rt_sigreturn(regs: &mut Regs) -> abi::SysResult {
    use core::mem::{offset_of, size_of};
    // The restorer popped `pretcode`, so the frame base is `rsp - 8`.
    let frame_addr = regs.user_rsp.wrapping_sub(8);
    let mc_addr =
        frame_addr + offset_of!(RtSigFrame, uc) as u64 + offset_of!(UContext, uc_mcontext) as u64;

    let mut mc = SigContext::default();
    // SAFETY: `mc` is plain old data; fill it from user memory as bytes.
    let mc_bytes = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::from_mut(&mut mc).cast::<u8>(), size_of::<SigContext>())
    };
    crate::usercopy::copy_from_user(mc_addr, mc_bytes)?;

    // Restore the blocked mask from uc_sigmask.
    let mask_addr =
        frame_addr + offset_of!(RtSigFrame, uc) as u64 + offset_of!(UContext, uc_sigmask) as u64;
    let mut mask_bytes = [0u8; 8];
    crate::usercopy::copy_from_user(mask_addr, &mut mask_bytes)?;
    if let Some(proc) = process::current() {
        proc.lock().sig.mask = u64::from_le_bytes(mask_bytes);
    }

    // Restore the FPU state the handler ran over.
    if mc.fpstate != 0 {
        let mut fx = alloc::vec![0u8; FXSAVE_SIZE];
        if crate::usercopy::copy_from_user(mc.fpstate, &mut fx).is_ok() {
            // SAFETY: 512-byte FXSAVE image restored into the live FPU.
            unsafe { context::fxrstor(fx.as_ptr()) };
        }
    }

    // Restore the general-purpose context into the syscall frame.
    regs.r8 = mc.r8;
    regs.r9 = mc.r9;
    regs.r10 = mc.r10;
    regs.r12 = mc.r12;
    regs.r13 = mc.r13;
    regs.r14 = mc.r14;
    regs.r15 = mc.r15;
    regs.rdi = mc.rdi;
    regs.rsi = mc.rsi;
    regs.rbp = mc.rbp;
    regs.rbx = mc.rbx;
    regs.rdx = mc.rdx;
    regs.rax = mc.rax;
    regs.rip = mc.rip;
    regs.user_rsp = mc.rsp;
    regs.rflags = sanitize_user_rflags(mc.eflags);

    Ok(mc.rax)
}
