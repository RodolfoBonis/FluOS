//! The per-CPU preemptive scheduler.
//!
//! Each CPU keeps an EEVDF runqueue of *ready* threads (from the host-tested
//! [`sched`] crate). The thread currently executing is **removed** from the
//! runqueue while it runs, so a thread is always in exactly one place — in one
//! CPU's runqueue, or that CPU's `current` — which makes both work stealing and
//! the context switch race-free.
//!
//! The switch itself uses a two-phase handshake to stay correct on SMP: the
//! outgoing thread is *not* returned to the runqueue before switching (another
//! CPU could grab and run it before its registers are saved). Instead it is
//! parked in `prev`, and the thread we switch *to* re-queues it in
//! [`finish_switch`], by which point its context is fully saved.

use crate::percpu::{self, CpuState};
use crate::sync::SpinLock;
use crate::thread::{self, State, Thread, Tid};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use sched::eevdf::Eevdf;
use sched::{steal, weight_from_nice};
use x86_64::instructions::interrupts;

/// Virtual-time charged to the running thread per timer tick.
const TICK_CHARGE: u64 = 1;

/// Every worker thread ever spawned (by scheduler Tid), for self-test stats.
static THREADS: SpinLock<Vec<Tid>> = SpinLock::new(Vec::new());
/// Count of threads that have run to completion.
static FINISHED: AtomicU32 = AtomicU32::new(0);

/// Disables preemption on this CPU (nestable). The counter bump runs with
/// interrupts off so a tick cannot migrate us between reading per-CPU state and
/// the increment (C2); once the count is non-zero the thread is pinned.
pub fn preempt_disable() {
    let was_on = interrupts::are_enabled();
    interrupts::disable();
    percpu::this().preempt_count.fetch_add(1, Ordering::Acquire);
    if was_on {
        interrupts::enable();
    }
}

/// Re-enables preemption on this CPU, honouring a pending reschedule (M10): if
/// the count hits zero and a tick asked to reschedule while preemption was off,
/// reschedule now.
pub fn preempt_enable() {
    let was_on = interrupts::are_enabled();
    interrupts::disable();
    let cpu = percpu::this();
    let prev = cpu.preempt_count.fetch_sub(1, Ordering::Release);
    let resched = prev == 1 && cpu.need_resched.load(Ordering::Relaxed);
    if was_on {
        interrupts::enable();
    }
    if resched {
        schedule();
    }
}

/// Promotes the CPU's current execution into a thread so it can be scheduled.
/// Returns the new current thread.
pub fn adopt_current(nice: i8) -> *mut Thread {
    let t: *mut Thread = Box::leak(Thread::new_current(weight_from_nice(nice)));
    percpu::set_current(t);
    t
}

/// Creates this CPU's idle thread on a fresh stack and registers it.
pub fn create_idle() -> *mut Thread {
    let t: *mut Thread = Box::leak(Thread::new_worker(idle_entry, 0, weight_from_nice(0)));
    percpu::this().idle.store(t, Ordering::Release);
    t
}

/// Makes the CPU's *current* context its idle thread (used on APs, whose entry
/// context becomes the idle loop).
pub fn adopt_current_as_idle() -> *mut Thread {
    let t: *mut Thread = Box::leak(Thread::new_current(weight_from_nice(0)));
    let cpu = percpu::this();
    cpu.idle.store(t, Ordering::Release);
    percpu::set_current(t);
    t
}

/// Spawns a worker on `cpu_id` running `entry(arg)` at the given nice level.
/// Returns the new thread's tid, or `EINVAL` if the target CPU is not online
/// (rather than silently dropping the thread — M6).
pub fn spawn(entry: extern "C" fn(usize), arg: usize, nice: i8, cpu_id: u32) -> Result<Tid, abi::Errno> {
    let weight = weight_from_nice(nice);
    let Some(cpu) = percpu::by_id(cpu_id) else {
        return Err(abi::Errno::EINVAL);
    };
    let t: *mut Thread = Box::leak(Thread::new_worker(entry, arg, weight));
    // SAFETY: `t` was just leaked and is uniquely owned here.
    let tid = unsafe { (*t).tid() };
    THREADS.lock().push(tid);
    cpu.runqueue.lock().insert_at_v(tid, weight);
    // Poke a remote CPU so it preempts and picks up the new thread promptly.
    // Read our own id with interrupts off so a migration can't make it stale.
    let me = interrupts::without_interrupts(percpu::cpu_id);
    if cpu_id != me {
        crate::arch::x86_64::apic::send_reschedule(cpu.lapic_id);
    }
    Ok(tid)
}

/// Entry trampoline for freshly created threads: finishes the pending switch,
/// enables interrupts, runs the thread body, then exits.
pub extern "C" fn thread_trampoline() -> ! {
    finish_switch();
    interrupts::enable();
    let t = percpu::current();
    // SAFETY: a worker always has an entry; `t` is this CPU's current thread.
    let (entry, arg) = unsafe { ((*t).entry.expect("worker has entry"), (*t).arg) };
    entry(arg);
    thread_exit();
}

/// Terminates the current thread and never returns.
pub fn thread_exit() -> ! {
    let t = percpu::current();
    // SAFETY: `t` is this CPU's current thread.
    unsafe { (*t).state = State::Finished };
    FINISHED.fetch_add(1, Ordering::Release);
    loop {
        schedule();
        // Unreachable in practice: a Finished thread is never requeued.
        core::hint::spin_loop();
    }
}

/// Re-queues the thread parked by the previous switch, now that its context is
/// safely saved. Runs on the incoming thread right after a switch.
fn finish_switch() {
    let cpu = percpu::this();
    let prev = cpu.prev.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if prev.is_null() {
        return;
    }
    let idle = cpu.idle.load(Ordering::Acquire);
    // SAFETY: `prev` is a live thread whose registers are now fully saved, so it
    // is safe to make it runnable or to arm its sleep timer here (not before the
    // switch, which would risk another CPU running a half-saved thread).
    unsafe {
        if prev == idle {
            return;
        }
        match (*prev).state {
            State::Ready => {
                let weight = (*prev).weight;
                let vruntime = u128::from((*prev).vruntime.load(Ordering::Relaxed));
                cpu.runqueue.lock().insert_clamped((*prev).tid(), weight, vruntime);
            }
            State::Blocked if (*prev).wake_at != 0 => {
                // Arm the sleep timer now that `prev` is fully parked. Because the
                // timer is inserted only here (never while the thread is current),
                // the tick path can never wake a running thread (C1-B).
                cpu.timers.lock().insert((*prev).wake_at, (*prev).tid());
            }
            _ => {}
        }
    }
}

/// Picks the next thread and switches to it. Safe to call from thread context
/// (voluntary yield) or the timer handler.
pub fn schedule() {
    // Disable interrupts BEFORE reading per-CPU state: otherwise a tick could
    // migrate us and leave `cpu` pointing at the previous CPU's runqueue (C2).
    let interrupts_were_on = interrupts::are_enabled();
    interrupts::disable();
    let cpu = percpu::this();
    cpu.need_resched.store(false, Ordering::Relaxed);

    let cur = percpu::current();
    let idle = cpu.idle.load(Ordering::Acquire);

    // Claim the next ready thread out of the runqueue (or fall back to idle).
    let next: *mut Thread = {
        let mut rq = cpu.runqueue.lock();
        match rq.pick() {
            Some(tid) => {
                rq.remove(tid);
                tid as *mut Thread
            }
            None => idle,
        }
    };

    if next == cur {
        if interrupts_were_on {
            interrupts::enable();
        }
        return;
    }

    // SAFETY: `cur` and `next` are live threads owned by this CPU right now.
    unsafe {
        if cur != idle && (*cur).state == State::Running {
            (*cur).state = State::Ready; // eligible to be re-queued by finish_switch
        }
        (*next).state = State::Running;
        (*next).run_count.fetch_add(1, Ordering::Relaxed);
        (*next).ran_on.fetch_or(1 << cpu.cpu_id, Ordering::Relaxed);
    }

    cpu.prev.store(cur, Ordering::Release);
    cpu.switches.fetch_add(1, Ordering::Relaxed);
    percpu::set_current(next);
    // SAFETY: `next` is the live thread we are switching to.
    unsafe { crate::process::switch_mm(next) };

    thread::check_canary(cur);
    // SAFETY: both are live; `cur` is the running thread being switched out.
    unsafe { thread::switch(cur, next) };

    // Resumed as `cur`; complete the switch that brought us back.
    finish_switch();
    if interrupts_were_on {
        interrupts::enable();
    }
}

/// Voluntarily yields the CPU to the scheduler.
pub fn yield_now() {
    schedule();
}

/// Timer-tick entry: ages the running thread and reschedules if allowed.
/// Called from the LAPIC timer handler (interrupts already disabled).
pub fn tick() {
    let cpu = percpu::this();

    // Advance local time and wake any threads whose sleep expired. Use a fixed
    // per-call buffer so the IRQ path never allocates (C3). Timers only hold
    // parked (non-current) threads, so this can never double-run current (C1).
    let now = cpu.now.fetch_add(1, Ordering::Relaxed) + 1;
    const WAKE_BATCH: usize = 64;
    let mut woken = [0u64; WAKE_BATCH];
    let n = cpu.timers.lock().expire_into(now, &mut woken);
    for &tid in &woken[..n] {
        // SAFETY: a sleeping tid is a live Thread parked only in the timer queue.
        unsafe {
            let t = tid as *mut Thread;
            (*t).state = State::Ready;
            (*t).wake_at = 0;
            let weight = (*t).weight;
            let vruntime = u128::from((*t).vruntime.load(Ordering::Relaxed));
            cpu.runqueue.lock().insert_clamped(tid, weight, vruntime);
        }
    }

    let cur = percpu::current();
    let idle = cpu.idle.load(Ordering::Acquire);
    if cur != idle {
        // SAFETY: `cur` is this CPU's running thread.
        unsafe {
            let vd = Eevdf::vdelta((*cur).weight, TICK_CHARGE) as u64;
            (*cur).vruntime.fetch_add(vd, Ordering::Relaxed);
        }
    }
    cpu.need_resched.store(true, Ordering::Relaxed);
    if cpu.preempt_count.load(Ordering::Acquire) == 0 {
        schedule();
    }
}

/// Sleeps the current thread for `ticks` scheduling ticks, yielding the CPU.
/// A timer requeues it (see [`tick`]) once the deadline passes.
pub fn sleep_ticks(ticks: u64) {
    // Run the block-then-switch as one interrupts-off critical section: a tick
    // must not fire between marking Blocked and switching away, or the wakeup
    // would be lost and the thread leaked (C1-A). The timer is armed by
    // `finish_switch` once the thread is fully parked, not here.
    let was_on = interrupts::are_enabled();
    interrupts::disable();
    let cpu = percpu::this();
    let cur = percpu::current();
    // SAFETY: `cur` is this CPU's running thread; only this CPU touches it.
    unsafe {
        (*cur).wake_at = cpu.now.load(Ordering::Relaxed) + ticks.max(1);
        (*cur).state = State::Blocked;
    }
    schedule();
    if was_on {
        interrupts::enable();
    }
}

/// Idle-thread body: steal work if any, otherwise wait for an interrupt.
extern "C" fn idle_entry(_: usize) {
    run_idle();
}

/// The idle loop, run by each CPU's idle thread.
pub fn run_idle() -> ! {
    loop {
        let stole = try_steal();
        let has_work = !percpu::this().runqueue.lock().is_empty();
        if stole || has_work {
            schedule();
        } else {
            let addr = core::ptr::from_ref(&percpu::this().need_resched) as usize;
            crate::arch::x86_64::idle_wait(addr);
        }
    }
}

/// Attempts to steal a batch-worth of work from the busiest peer. Returns
/// `true` if at least one thread was migrated here.
pub fn try_steal() -> bool {
    let me = percpu::this();
    let n = percpu::count();

    // Snapshot peer loads to choose a victim (busiest with >= 2 ready).
    let mut loads = [0usize; crate::percpu::MAX_CPUS];
    for id in 0..n {
        if let Some(p) = percpu::by_id(id) {
            loads[id as usize] = p.runqueue.lock().len();
        }
    }
    let Some((victim_id, count)) = steal::plan_steal(&loads[..n as usize], me.cpu_id as usize)
    else {
        return false;
    };

    let Some(victim) = percpu::by_id(victim_id as u32) else {
        return false;
    };
    let victim_current = victim.current.load(Ordering::Acquire) as u64;

    let mut moved = 0;
    for _ in 0..count {
        let stolen = {
            let mut rq = victim.runqueue.lock();
            let cand = rq.tids().into_iter().find(|&t| t != victim_current);
            match cand {
                Some(t) => {
                    rq.remove(t);
                    Some(t)
                }
                None => None,
            }
        };
        let Some(tid) = stolen else { break };
        // SAFETY: a ready thread's context is fully saved, so it is safe to
        // migrate. Its address (the tid) is a live Thread.
        unsafe {
            let t = tid as *mut Thread;
            let weight = (*t).weight;
            let vruntime = u128::from((*t).vruntime.load(Ordering::Relaxed));
            me.runqueue.lock().insert_clamped(tid, weight, vruntime);
        }
        moved += 1;
    }

    if moved > 0 {
        me.steals.fetch_add(moved, Ordering::Relaxed);
        true
    } else {
        false
    }
}

// --- self-test accounting --------------------------------------------------

/// All worker tids ever spawned.
pub fn all_threads() -> Vec<Tid> {
    THREADS.lock().clone()
}

/// Number of threads that have finished.
pub fn finished_count() -> u32 {
    FINISHED.load(Ordering::Acquire)
}

/// `(switches, steals)` for a CPU.
pub fn cpu_stats(cpu: &CpuState) -> (u64, u64) {
    (cpu.switches.load(Ordering::Relaxed), cpu.steals.load(Ordering::Relaxed))
}
