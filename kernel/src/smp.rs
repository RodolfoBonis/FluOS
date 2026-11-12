//! SMP bring-up and the scheduler self-test.
//!
//! The BSP initialises its own per-CPU state and idle thread, then uses the
//! Limine MP request to start each application processor. Every AP installs its
//! own GDT/IDT, per-CPU state, and LAPIC timer, then enters the idle loop where
//! it participates in scheduling and work stealing. The self-test spawns far
//! more threads than there are CPUs, all on the BSP, and verifies they all run
//! (migrating across CPUs via stealing) before measuring context-switch cost.

use crate::arch::x86_64::{apic, cpu, gdt, idt};
use crate::thread::Thread;
use crate::{boot, percpu, scheduler};
use core::arch::x86_64::_rdtsc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use x86_64::instructions::interrupts;

static APS_ONLINE: AtomicU32 = AtomicU32::new(0);

/// Work counter incremented by self-test worker threads.
static COUNTER: AtomicU64 = AtomicU64::new(0);
/// Increments each worker performs.
const WORK_PER_THREAD: u64 = 4000;

/// Bench completion counter and iteration count.
static BENCH_DONE: AtomicU32 = AtomicU32::new(0);
const BENCH_ITERS: u64 = 3000;

/// Count of sleepers that woke on time (soft sleep/wakeup sub-test).
static SLEEP_WOKE: AtomicU32 = AtomicU32::new(0);

/// Initialises the BSP's per-CPU state, bootstrap thread, and idle thread.
pub fn init_bsp() {
    let (bsp_id, bsp_lapic) = match boot::mp() {
        Some((cpus, bsp_lapic)) => {
            let idx = cpus.iter().position(|c| c.lapic_id == bsp_lapic).unwrap_or(0) as u32;
            (idx, bsp_lapic)
        }
        None => (0, 0),
    };
    percpu::init(bsp_id, bsp_lapic);
    scheduler::adopt_current(0); // promote the boot context to a schedulable thread
    scheduler::create_idle();
}

/// Starts the application processors and waits for them to come online.
pub fn bringup() {
    let Some((cpus, bsp_lapic)) = boot::mp() else {
        crate::log::warning!("no MP info from bootloader; running single-CPU");
        percpu::set_cpu_count(1);
        return;
    };

    percpu::set_cpu_count(cpus.len() as u32);
    crate::log::info!("smp: bringing up {} CPUs", cpus.len());

    for (i, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == bsp_lapic {
            continue;
        }
        cpu.bootstrap(ap_entry, i as u64);
    }

    let expected = cpus.len() as u32 - 1;
    let mut spins = 0u64;
    while APS_ONLINE.load(Ordering::Acquire) < expected {
        core::hint::spin_loop();
        spins += 1;
        if spins > 2_000_000_000 {
            crate::log::error!("smp: AP bring-up timed out ({} of {})", APS_ONLINE.load(Ordering::Acquire), expected);
            break;
        }
    }
    crate::log::info!("smp: {} application processors online", APS_ONLINE.load(Ordering::Acquire));
}

/// Entry point each application processor jumps to from the bootloader.
unsafe extern "C" fn ap_entry(info: &limine::mp::MpInfo) -> ! {
    let cpu_id = info.extra_argument() as u32;

    // Adopt the kernel page tables (APs start on the bootloader's tables, which
    // lack our device-MMIO mappings).
    crate::mm::paging::activate();

    gdt::init_ap();
    idt::init();
    cpu::enable_protections();
    cpu::enable_sse();

    percpu::init(cpu_id, info.lapic_id);
    apic::enable_lapic();
    scheduler::adopt_current_as_idle();
    apic::start_timer();

    APS_ONLINE.fetch_add(1, Ordering::Release);
    interrupts::enable();
    scheduler::run_idle();
}

/// Self-test worker: does bounded work, yielding periodically so the scheduler
/// has chances to migrate and preempt it.
extern "C" fn worker(arg: usize) {
    for i in 0..WORK_PER_THREAD {
        COUNTER.fetch_add(1, Ordering::Relaxed);
        if i % 128 == 0 {
            scheduler::yield_now();
        }
    }
    let _ = arg;
}

/// Ping-pong thread for the latency benchmark: nothing but yields.
extern "C" fn bench(_: usize) {
    for _ in 0..BENCH_ITERS {
        scheduler::yield_now();
    }
    BENCH_DONE.fetch_add(1, Ordering::Release);
}

/// Sleeper: blocks on the timer queue, then records that it woke.
extern "C" fn sleeper(_: usize) {
    scheduler::sleep_ticks(5);
    SLEEP_WOKE.fetch_add(1, Ordering::Release);
}

/// Exercises sleep/wakeup via the per-CPU timer queue (soft: logged, not asserted).
fn sleep_test() {
    const SLEEPERS: u32 = 4;
    SLEEP_WOKE.store(0, Ordering::Relaxed);
    let bsp = percpu::cpu_id();
    for _ in 0..SLEEPERS {
        scheduler::spawn(sleeper, 0, 0, bsp);
    }
    let mut spins = 0u64;
    while SLEEP_WOKE.load(Ordering::Acquire) < SLEEPERS {
        scheduler::yield_now();
        spins += 1;
        if spins > 50_000_000 {
            break;
        }
    }
    crate::log::info!("selftest: {}/{} sleepers woke from timer queue", SLEEP_WOKE.load(Ordering::Acquire), SLEEPERS);
}

/// Runs the scheduler self-test: spawn many threads on the BSP, confirm they
/// all run across CPUs with work stealing, then measure context-switch latency.
pub fn run_selftest() {
    let ncpu = percpu::count();
    let n = (ncpu * 6).max(8);
    COUNTER.store(0, Ordering::Relaxed);

    let bsp = percpu::cpu_id();
    crate::log::info!("selftest: spawning {} threads on cpu {} across {} cpus", n, bsp, ncpu);
    for i in 0..n {
        scheduler::spawn(worker, i as usize, 0, bsp);
    }

    // Wait for completion, yielding so workers (and the BSP's share) run.
    let mut spins = 0u64;
    while scheduler::finished_count() < n {
        scheduler::yield_now();
        spins += 1;
        if spins > 200_000_000 {
            crate::log::error!("selftest: timed out ({} of {} finished)", scheduler::finished_count(), n);
            break;
        }
    }

    // Which CPUs did work run on?
    let mut cpu_mask = 0u32;
    for &tid in &scheduler::all_threads() {
        // SAFETY: a spawned tid is a live, leaked Thread for the kernel's life.
        let mask = unsafe { (*(tid as *const Thread)).ran_on.load(Ordering::Relaxed) };
        cpu_mask |= mask;
    }
    let distinct = cpu_mask.count_ones();

    // Exercise the IPI paths: nudge every peer to reschedule and flush its TLB.
    let mut peers = 0u32;
    for id in 0..ncpu {
        if id != bsp {
            if let Some(c) = percpu::by_id(id) {
                apic::send_reschedule(c.lapic_id);
                apic::send_tlb_shootdown(c.lapic_id);
                peers += 1;
            }
        }
    }
    crate::log::info!("selftest: sent reschedule + TLB-shootdown IPIs to {} peers", peers);

    // Read the aggregate stats with preemption disabled for a consistent snapshot.
    scheduler::preempt_disable();
    let mut switches = 0u64;
    let mut steals = 0u64;
    for id in 0..ncpu {
        if let Some(c) = percpu::by_id(id) {
            let (sw, st) = scheduler::cpu_stats(c);
            switches += sw;
            steals += st;
        }
    }
    scheduler::preempt_enable();

    crate::log::info!(
        "selftest: {} threads finished, counter={} (expected {}), ran on {} cpu(s), {} switches, {} steals",
        scheduler::finished_count(),
        COUNTER.load(Ordering::Relaxed),
        n as u64 * WORK_PER_THREAD,
        distinct,
        switches,
        steals,
    );

    assert_eq!(scheduler::finished_count(), n, "not all threads finished");
    assert_eq!(COUNTER.load(Ordering::Relaxed), n as u64 * WORK_PER_THREAD, "lost work");
    if ncpu > 1 {
        assert!(distinct > 1, "threads never migrated across CPUs");
        assert!(steals > 0, "no work stealing occurred");
    }

    sleep_test();
    bench_latency();
}

/// Measures average context-switch cost via two yield-only threads.
fn bench_latency() {
    BENCH_DONE.store(0, Ordering::Relaxed);
    let cpu = percpu::this();
    let bsp = cpu.cpu_id;

    let sw0 = cpu.switches.load(Ordering::Relaxed);
    // SAFETY: `_rdtsc` reads the timestamp counter.
    let t0 = unsafe { _rdtsc() };

    scheduler::spawn(bench, 0, 0, bsp);
    scheduler::spawn(bench, 1, 0, bsp);
    while BENCH_DONE.load(Ordering::Acquire) < 2 {
        scheduler::yield_now();
    }

    let t1 = unsafe { _rdtsc() };
    let sw1 = cpu.switches.load(Ordering::Relaxed);
    let switches = sw1 - sw0;
    let cycles = t1 - t0;
    let per = if switches > 0 { cycles / switches } else { 0 };

    crate::log::info!(
        "context-switch latency: ~{} cycles/switch ({} switches, {} cycles total)",
        per,
        switches,
        cycles,
    );
}
