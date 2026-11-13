//! Per-CPU state, reachable in O(1) through the GS base.
//!
//! Each CPU owns a heap-allocated [`CpuState`] holding its runqueue, timer
//! queue, current/idle threads, preemption counter, and statistics. The GS base
//! MSR points at this CPU's state, so [`this`] is a single register read; a
//! global pointer table additionally lets other CPUs reach a peer's state for
//! work stealing and wakeups.

use crate::sync::SpinLock;
use crate::thread::Thread;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use sched::{Eevdf, TimerQueue};
use x86_64::VirtAddr;
use x86_64::registers::model_specific::GsBase;

/// Hard cap on supported CPUs.
pub const MAX_CPUS: usize = 64;

/// Everything a single CPU needs to schedule.
///
/// `repr(C)` with the syscall-entry scratch fields first: the assembly syscall
/// entry reaches them at fixed offsets through the GS base (`gs:[0]` =
/// `kernel_rsp`, `gs:[8]` = `user_rsp_scratch`).
#[repr(C)]
pub struct CpuState {
    /// Kernel stack top for the current user thread's syscall/interrupt entry.
    pub kernel_rsp: AtomicU64,
    /// Scratch slot where the syscall entry parks the user RSP.
    pub user_rsp_scratch: AtomicU64,
    pub cpu_id: u32,
    pub lapic_id: u32,
    /// Runnable threads on this CPU (EEVDF). Locked for cross-CPU stealing.
    pub runqueue: SpinLock<Eevdf>,
    /// Pending timers for sleep/wakeup and timeslice expiry.
    pub timers: SpinLock<TimerQueue>,
    /// The thread currently executing on this CPU.
    pub current: AtomicPtr<Thread>,
    /// The idle thread run when the runqueue is empty.
    pub idle: AtomicPtr<Thread>,
    /// Outgoing thread parked during a switch, re-queued once its context is
    /// saved (see `scheduler::finish_switch`).
    pub prev: AtomicPtr<Thread>,
    /// Nesting depth of preemption-disabled regions.
    pub preempt_count: AtomicUsize,
    /// Set by the timer tick when a reschedule is due.
    pub need_resched: AtomicBool,
    /// Context switches performed (stats).
    pub switches: AtomicU64,
    /// Threads stolen from peers (stats).
    pub steals: AtomicU64,
    /// Monotonic local tick counter (advanced by the timer), for timers.
    pub now: AtomicU64,
    /// Pointer to this CPU's TSS (for updating RSP0 on context switch to user).
    pub tss: AtomicU64,
    /// Raw pointer to the current user process (`*const SpinLock<Process>`), 0
    /// for kernel-only threads. The process stays alive in the process table.
    pub current_proc: AtomicU64,
    /// CR3 currently loaded on this CPU (to skip redundant reloads).
    pub active_cr3: AtomicU64,
    /// Last TLB-shootdown sequence this CPU has serviced (see `paging`).
    pub shootdown_seen: AtomicU64,
    /// Non-zero while this CPU is inside the page-fault handler (nest guard).
    pub in_fault: AtomicU32,
    /// Signature (cr2 ^ rip ^ cr3) of the most recent page fault, with a repeat
    /// counter, to detect a fault that resolves but never makes progress (a
    /// page-table bug). See the #PF handler's fault-loop guard.
    pub last_fault_sig: AtomicU64,
    pub fault_repeats: AtomicU32,
}

static CPUS: [AtomicPtr<CpuState>; MAX_CPUS] = [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];
static CPU_COUNT: AtomicU32 = AtomicU32::new(0);
static PERCPU_READY: AtomicBool = AtomicBool::new(false);

/// Initialises this CPU's state, publishes it in the table, and points the GS
/// base at it. Returns a static reference to the new state.
pub fn init(cpu_id: u32, lapic_id: u32, tss: u64) -> &'static CpuState {
    let state = Box::leak(Box::new(CpuState {
        kernel_rsp: AtomicU64::new(0),
        user_rsp_scratch: AtomicU64::new(0),
        cpu_id,
        lapic_id,
        runqueue: SpinLock::new(Eevdf::new()),
        timers: SpinLock::new(TimerQueue::new()),
        current: AtomicPtr::new(core::ptr::null_mut()),
        idle: AtomicPtr::new(core::ptr::null_mut()),
        prev: AtomicPtr::new(core::ptr::null_mut()),
        preempt_count: AtomicUsize::new(0),
        need_resched: AtomicBool::new(false),
        switches: AtomicU64::new(0),
        steals: AtomicU64::new(0),
        now: AtomicU64::new(0),
        tss: AtomicU64::new(tss),
        current_proc: AtomicU64::new(0),
        active_cr3: AtomicU64::new(0),
        shootdown_seen: AtomicU64::new(0),
        in_fault: AtomicU32::new(0),
        last_fault_sig: AtomicU64::new(0),
        fault_repeats: AtomicU32::new(0),
    }));

    // Pre-reserve runqueue capacity so timer-IRQ enqueues don't allocate (C3).
    state.runqueue.lock().reserve(256);
    CPUS[cpu_id as usize].store(state, Ordering::Release);
    GsBase::write(VirtAddr::new(core::ptr::from_ref(state) as u64));
    // KERNEL_GS_BASE holds the running thread's user GS (0 for kernel threads);
    // swapgs exchanges it with GS_BASE on ring transitions.
    x86_64::registers::model_specific::KernelGsBase::write(VirtAddr::new(0));
    PERCPU_READY.store(true, Ordering::Release);
    state
}

/// Records the total number of CPUs brought online.
pub fn set_cpu_count(n: u32) {
    CPU_COUNT.store(n, Ordering::Release);
}

/// Number of CPUs online.
pub fn count() -> u32 {
    CPU_COUNT.load(Ordering::Acquire)
}

/// This CPU's state, via the GS base.
pub fn this() -> &'static CpuState {
    let base = GsBase::read().as_u64();
    // SAFETY: `init` set GS base to a leaked, live `CpuState` for this CPU.
    unsafe { &*(base as *const CpuState) }
}

/// A peer CPU's state by id, if it is online.
pub fn by_id(cpu_id: u32) -> Option<&'static CpuState> {
    let ptr = CPUS.get(cpu_id as usize)?.load(Ordering::Acquire);
    // SAFETY: a non-null entry is a leaked, live `CpuState`.
    (!ptr.is_null()).then(|| unsafe { &*ptr })
}

/// This CPU's id.
pub fn cpu_id() -> u32 {
    this().cpu_id
}

/// Whether per-CPU state (and the GS base) has been initialised on some CPU.
pub fn is_ready() -> bool {
    PERCPU_READY.load(Ordering::Acquire)
}

/// This CPU's id, or `None` before per-CPU state is set up (safe to call early).
pub fn try_cpu_id() -> Option<u32> {
    is_ready().then(cpu_id)
}

/// The thread currently running on this CPU.
pub fn current() -> *mut Thread {
    this().current.load(Ordering::Acquire)
}

/// Sets the thread currently running on this CPU.
pub fn set_current(thread: *mut Thread) {
    this().current.store(thread, Ordering::Release);
}
