//! `ITIMER_REAL` interval timers (`setitimer`/`getitimer`/`alarm`).
//!
//! Each armed timer is serviced by a small kernel thread that sleeps until the
//! deadline and posts `SIGALRM` to the owning process. Re-arming or disarming
//! bumps the timer's generation, so a stale thread notices and exits instead of
//! firing.

use crate::sync::SpinLock;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;

const SIGALRM: i32 = 14;

/// Milliseconds the scheduler sleeps per tick (see `apic::SLICE_MS`).
const TICK_MS: u64 = 4;

#[derive(Clone, Copy)]
struct Timer {
    generation: u64,
    /// Absolute uptime (ms) of the next expiry; 0 = disarmed.
    deadline_ms: u64,
    interval_ms: u64,
}

/// Armed timers, keyed by pid.
static TIMERS: SpinLock<BTreeMap<i32, Timer>> = SpinLock::new(BTreeMap::new());

/// Monotonic uptime in milliseconds, from the calibrated TSC.
fn now_ms() -> u64 {
    let tpms = crate::arch::x86_64::apic::tsc_per_ms().max(1);
    // SAFETY: `_rdtsc` only reads the timestamp counter.
    unsafe { core::arch::x86_64::_rdtsc() / tpms }
}

/// `(value_ms, interval_ms)` currently left on `pid`'s timer.
pub fn get(pid: i32) -> (u64, u64) {
    match TIMERS.lock().get(&pid) {
        Some(t) if t.deadline_ms != 0 => (t.deadline_ms.saturating_sub(now_ms()).max(1), t.interval_ms),
        _ => (0, 0),
    }
}

/// Arms (or with `value_ms == 0`, disarms) `pid`'s real timer, returning the
/// previous `(value_ms, interval_ms)`.
pub fn set(pid: i32, value_ms: u64, interval_ms: u64) -> (u64, u64) {
    let old = get(pid);
    let generation = {
        let mut timers = TIMERS.lock();
        let entry = timers.entry(pid).or_insert(Timer { generation: 0, deadline_ms: 0, interval_ms: 0 });
        entry.generation = entry.generation.wrapping_add(1);
        entry.deadline_ms = if value_ms == 0 { 0 } else { now_ms() + value_ms };
        entry.interval_ms = interval_ms;
        entry.generation
    };
    if value_ms != 0 {
        let arg = Box::into_raw(Box::new((pid, generation))) as usize;
        if crate::scheduler::spawn(timer_thread, arg, 0, crate::percpu::cpu_id()).is_err() {
            // SAFETY: the thread was not created, so we still own the box.
            drop(unsafe { Box::from_raw(arg as *mut (i32, u64)) });
            crate::log::warning!("itimer: could not start timer thread for pid {pid}");
        }
    }
    old
}

extern "C" fn timer_thread(arg: usize) {
    // SAFETY: `arg` is the box leaked by `set` for exactly this thread.
    let (pid, generation) = *unsafe { Box::from_raw(arg as *mut (i32, u64)) };
    loop {
        let remaining = {
            let timers = TIMERS.lock();
            match timers.get(&pid) {
                Some(t) if t.generation == generation && t.deadline_ms != 0 => t.deadline_ms.saturating_sub(now_ms()),
                _ => break, // re-armed, disarmed or process gone
            }
        };
        if remaining > 0 {
            crate::scheduler::sleep_ticks(remaining.div_ceil(TICK_MS));
            continue;
        }
        let rearm = {
            let mut timers = TIMERS.lock();
            match timers.get_mut(&pid) {
                Some(t) if t.generation == generation => {
                    if t.interval_ms == 0 {
                        t.deadline_ms = 0;
                        false
                    } else {
                        t.deadline_ms += t.interval_ms;
                        true
                    }
                }
                _ => break,
            }
        };
        if !crate::signal::send_to_pid(pid, SIGALRM) || !rearm {
            break;
        }
    }
    crate::scheduler::thread_exit();
}
