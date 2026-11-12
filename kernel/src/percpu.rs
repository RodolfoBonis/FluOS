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
pub struct CpuState {
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
}

static CPUS: [AtomicPtr<CpuState>; MAX_CPUS] = [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];
static CPU_COUNT: AtomicU32 = AtomicU32::new(0);

/// Initialises this CPU's state, publishes it in the table, and points the GS
/// base at it. Returns a static reference to the new state.
pub fn init(cpu_id: u32, lapic_id: u32) -> &'static CpuState {
    let state = Box::leak(Box::new(CpuState {
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
    }));

    CPUS[cpu_id as usize].store(state, Ordering::Release);
    GsBase::write(VirtAddr::new(core::ptr::from_ref(state) as u64));
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

/// The thread currently running on this CPU.
pub fn current() -> *mut Thread {
    this().current.load(Ordering::Acquire)
}

/// Sets the thread currently running on this CPU.
pub fn set_current(thread: *mut Thread) {
    this().current.store(thread, Ordering::Release);
}
