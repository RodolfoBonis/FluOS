//! Local and I/O APIC: device interrupts, the per-CPU scheduling timer, and IPIs.
//!
//! We fully mask the legacy 8259 PICs (after remapping their vectors out of the
//! exception range) and drive everything through the APICs. The Local APIC's
//! timer preempts the scheduler — in TSC-deadline mode when the CPU supports it
//! (tickless), otherwise periodic — calibrated once against the PIT. Inter-
//! processor interrupts provide reschedule and TLB-shootdown signalling.

use super::acpi::ApicInfo;
use super::port::{inb, outb};
use crate::mm::paging;
use core::arch::x86_64::{__cpuid_count, _rdtsc};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use x86_64::registers::model_specific::Msr;

/// IDT vector the keyboard IRQ is delivered on.
pub const KEYBOARD_VECTOR: u8 = 0x21;
/// Vector for the COM1 serial RX interrupt (ISA IRQ 4).
pub const SERIAL_VECTOR: u8 = 0x22;
/// LAPIC spurious-interrupt vector.
pub const SPURIOUS_VECTOR: u8 = 0xFF;
/// LAPIC timer vector (scheduler preemption).
pub const TIMER_VECTOR: u8 = 0x30;
/// Reschedule IPI vector.
pub const RESCHED_VECTOR: u8 = 0x40;
/// TLB-shootdown IPI vector.
pub const TLB_VECTOR: u8 = 0x41;

// LAPIC register offsets.
const LAPIC_ID: u64 = 0x20;
const LAPIC_EOI: u64 = 0xB0;
const LAPIC_SVR: u64 = 0xF0;
const LAPIC_ICR_LOW: u64 = 0x300;
const LAPIC_ICR_HIGH: u64 = 0x310;
const LVT_TIMER: u64 = 0x320;
const TIMER_INIT_COUNT: u64 = 0x380;
const TIMER_CUR_COUNT: u64 = 0x390;
const TIMER_DIVIDE: u64 = 0x3E0;

/// IA32_TSC_DEADLINE MSR.
const IA32_TSC_DEADLINE: u32 = 0x6E0;

/// Scheduling quantum in milliseconds.
const SLICE_MS: u64 = 4;

/// Virtual address of the LAPIC register page, set during [`init`].
static LAPIC_VIRT: AtomicU64 = AtomicU64::new(0);
/// Virtual address of the I/O APIC register window, set during [`init`].
static IOAPIC_VIRT: AtomicU64 = AtomicU64::new(0);
/// Whether to use TSC-deadline mode (tickless) versus periodic timer.
static USE_TSC_DEADLINE: AtomicBool = AtomicBool::new(false);
/// TSC ticks per scheduling slice (for TSC-deadline rearm).
static TSC_PER_SLICE: AtomicU64 = AtomicU64::new(0);
/// Calibrated TSC cycles per millisecond, for a monotonic `clock_gettime`.
static TSC_PER_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// LAPIC timer initial count for one slice (for periodic mode).
static LAPIC_COUNT_PER_SLICE: AtomicU64 = AtomicU64::new(0);

/// Masks the PICs, enables the BSP LAPIC, routes the keyboard IRQ, and
/// calibrates the scheduling timer. Call once on the bootstrap CPU.
pub fn init(info: ApicInfo) {
    mask_legacy_pic();

    let lapic_va = paging::map_mmio(info.lapic_base, 0x1000);
    let ioapic_va = paging::map_mmio(info.ioapic_base, 0x1000);
    LAPIC_VIRT.store(lapic_va, Ordering::Release);
    IOAPIC_VIRT.store(ioapic_va, Ordering::Release);
    enable_lapic();

    let apic_id = (lapic_read(LAPIC_ID) >> 24) & 0xFF;
    if info.ioapic_base == 0 {
        crate::log::warning!("apic: no I/O APIC in MADT; device IRQs (keyboard) unavailable");
    } else if info.keyboard_gsi < info.ioapic_gsi_base {
        crate::log::warning!(
            "apic: keyboard GSI {} below I/O APIC GSI base {}; not routing",
            info.keyboard_gsi,
            info.ioapic_gsi_base
        );
    } else {
        route_ioapic(&info, apic_id);
        route_serial(apic_id, info.ioapic_gsi_base);
    }
    calibrate();

    crate::log::info!(
        "apic: lapic@{:#x} ioapic@{:#x} kbd gsi {} -> vector {:#x}; timer {} ({} ms slice)",
        info.lapic_base,
        info.ioapic_base,
        info.keyboard_gsi,
        KEYBOARD_VECTOR,
        if USE_TSC_DEADLINE.load(Ordering::Relaxed) { "TSC-deadline" } else { "periodic" },
        SLICE_MS,
    );
}

/// Enables this CPU's Local APIC via the spurious-vector register.
pub fn enable_lapic() {
    lapic_write(LAPIC_SVR, 0x100 | u32::from(SPURIOUS_VECTOR));
}

/// Signals end-of-interrupt to the LAPIC.
pub fn eoi() {
    lapic_write(LAPIC_EOI, 0);
}

/// Reads the current CPU's LAPIC id.
#[allow(dead_code)] // accessor kept for diagnostics
pub fn lapic_id() -> u32 {
    (lapic_read(LAPIC_ID) >> 24) & 0xFF
}

/// Whether the CPU supports TSC-deadline timer mode.
fn has_tsc_deadline() -> bool {
    // `__cpuid_count` is safe: a pure CPU-identification read.
    let leaf = __cpuid_count(1, 0);
    leaf.ecx & (1 << 24) != 0
}

/// Whether the CPU advertises an invariant (constant-rate) TSC
/// (CPUID 8000_0007h EDX bit 8) — required before trusting TSC-deadline timing.
fn has_invariant_tsc() -> bool {
    let leaf = __cpuid_count(0x8000_0007, 0);
    leaf.edx & (1 << 8) != 0
}

/// Calibrates the scheduling timer against the PIT: measures TSC and LAPIC
/// timer rates over a 50 ms window and derives per-slice counts.
fn calibrate() {
    // LAPIC timer one-shot, divide-by-16, counting down from max.
    lapic_write(TIMER_DIVIDE, 0x3);
    lapic_write(LVT_TIMER, 1 << 16); // masked, one-shot
    lapic_write(TIMER_INIT_COUNT, u32::MAX);

    // SAFETY: `_rdtsc` reads the timestamp counter.
    let tsc_start = unsafe { _rdtsc() };
    pit_wait_ms(50);
    let tsc_elapsed = unsafe { _rdtsc() } - tsc_start;
    let lapic_elapsed = u64::from(u32::MAX - lapic_read(TIMER_CUR_COUNT));
    lapic_write(TIMER_INIT_COUNT, 0); // stop

    let tsc_per_ms = tsc_elapsed / 50;
    let lapic_per_ms = lapic_elapsed / 50;

    let use_deadline = has_tsc_deadline() && has_invariant_tsc() && tsc_per_ms > 0;
    USE_TSC_DEADLINE.store(use_deadline, Ordering::Release);
    TSC_PER_SLICE.store(tsc_per_ms * SLICE_MS, Ordering::Release);
    TSC_PER_MS.store(tsc_per_ms.max(1), Ordering::Release);
    // Fall back to a sane count if calibration produced nothing usable.
    let count = (lapic_per_ms * SLICE_MS).max(1).min(u64::from(u32::MAX));
    LAPIC_COUNT_PER_SLICE.store(count, Ordering::Release);
}

/// Calibrated TSC cycles per millisecond (at least 1), for deriving wall time.
#[must_use]
pub fn tsc_per_ms() -> u64 {
    TSC_PER_MS.load(Ordering::Acquire).max(1)
}

/// Starts this CPU's scheduling timer. Call after the scheduler is ready on
/// each CPU.
pub fn start_timer() {
    if USE_TSC_DEADLINE.load(Ordering::Acquire) {
        // TSC-deadline mode: LVT bits [18:17] = 10b.
        lapic_write(LVT_TIMER, u32::from(TIMER_VECTOR) | (0b10 << 17));
        rearm_timer();
    } else {
        // Periodic mode: LVT bits [18:17] = 01b.
        lapic_write(TIMER_DIVIDE, 0x3);
        lapic_write(LVT_TIMER, u32::from(TIMER_VECTOR) | (0b01 << 17));
        let count = LAPIC_COUNT_PER_SLICE.load(Ordering::Acquire) as u32;
        lapic_write(TIMER_INIT_COUNT, count);
    }
}

/// Reprograms the next TSC-deadline interrupt (no-op in periodic mode). Called
/// from the timer handler.
pub fn rearm_timer() {
    if USE_TSC_DEADLINE.load(Ordering::Relaxed) {
        let interval = TSC_PER_SLICE.load(Ordering::Relaxed);
        // SAFETY: `_rdtsc` reads the TSC; the MSR write arms the next deadline.
        let deadline = unsafe { _rdtsc() } + interval;
        // SAFETY: IA32_TSC_DEADLINE is a valid MSR when TSC-deadline is enabled.
        unsafe { Msr::new(IA32_TSC_DEADLINE).write(deadline) };
    }
}

/// Stops this CPU's scheduling timer (used when leaving the scheduler).
///
/// Refuses to disarm while this CPU still has sleepers parked on its timer
/// queue — tearing the timer down then would leave them to sleep forever (L5).
/// In that case the timer is re-armed instead; only a CPU with no pending
/// sleepers fully disarms. (Migrating sleepers to another CPU is the eventual
/// path once CPUs can go offline; keeping the timer live is correct until then.)
#[allow(dead_code)] // retained for the non-shell boot path
pub fn stop_timer() {
    if crate::percpu::try_cpu_id().is_some() && crate::scheduler::has_pending_sleepers() {
        rearm_timer();
        return;
    }
    lapic_write(LVT_TIMER, 1 << 16); // masked
    if USE_TSC_DEADLINE.load(Ordering::Relaxed) {
        // SAFETY: writing 0 disarms the TSC deadline.
        unsafe { Msr::new(IA32_TSC_DEADLINE).write(0) };
    } else {
        lapic_write(TIMER_INIT_COUNT, 0);
    }
}

/// Sends a fixed-delivery IPI with `vector` to the CPU with `dest_apic_id`.
///
/// Interrupts are masked around the ICR_HIGH/ICR_LOW pair so a preemption can't
/// interleave another IPI between the two writes, and we poll the delivery-
/// status bit (ICR_LOW bit 12) before and after so sends don't race (H3).
fn send_ipi(dest_apic_id: u32, vector: u8) {
    use x86_64::instructions::interrupts;
    interrupts::without_interrupts(|| {
        // Wait for any in-flight IPI to be accepted.
        while lapic_read(LAPIC_ICR_LOW) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }
        lapic_write(LAPIC_ICR_HIGH, dest_apic_id << 24);
        lapic_write(LAPIC_ICR_LOW, u32::from(vector) | (1 << 14));
        // Wait for this IPI to be accepted before returning.
        while lapic_read(LAPIC_ICR_LOW) & (1 << 12) != 0 {
            core::hint::spin_loop();
        }
    });
}

/// Sends a reschedule IPI to a CPU by its LAPIC id.
pub fn send_reschedule(dest_apic_id: u32) {
    send_ipi(dest_apic_id, RESCHED_VECTOR);
}

/// Sends a TLB-shootdown IPI to a CPU by its LAPIC id.
pub fn send_tlb_shootdown(dest_apic_id: u32) {
    send_ipi(dest_apic_id, TLB_VECTOR);
}

/// Broadcasts an NMI to every other CPU (used to halt them during a panic).
pub fn send_nmi_all_others() {
    if LAPIC_VIRT.load(Ordering::Relaxed) == 0 {
        return;
    }
    // Shorthand "all excluding self" (0b11 << 18), delivery mode NMI (0b100 << 8).
    lapic_write(LAPIC_ICR_LOW, (0b11 << 18) | (0b100 << 8));
}

fn lapic_read(offset: u64) -> u32 {
    let addr = LAPIC_VIRT.load(Ordering::Relaxed) + offset;
    // SAFETY: `addr` is within the mapped LAPIC page once `init` has run.
    unsafe { (addr as *const u32).read_volatile() }
}

fn lapic_write(offset: u64, value: u32) {
    let addr = LAPIC_VIRT.load(Ordering::Relaxed) + offset;
    // SAFETY: as above; LAPIC registers are 32-bit MMIO.
    unsafe { (addr as *mut u32).write_volatile(value) };
}

/// Programs the I/O APIC redirection entry for the keyboard's GSI.
fn route_ioapic(info: &ApicInfo, dest_apic_id: u32) {
    let base = IOAPIC_VIRT.load(Ordering::Acquire);
    let index = info.keyboard_gsi - info.ioapic_gsi_base;
    let redtbl_lo = 0x10 + index * 2;

    let polarity = info.keyboard_flags & 0b11;
    let trigger = (info.keyboard_flags >> 2) & 0b11;
    let mut low = u32::from(KEYBOARD_VECTOR);
    if polarity == 0b11 {
        low |= 1 << 13; // active low
    }
    if trigger == 0b11 {
        low |= 1 << 15; // level triggered
    }
    ioapic_write(base, redtbl_lo + 1, dest_apic_id << 24);
    ioapic_write(base, redtbl_lo, low);
}

/// Routes the COM1 serial RX line (ISA IRQ 4) to [`SERIAL_VECTOR`] on
/// `dest_apic_id`, edge-triggered / active-high (the ISA default). Best-effort:
/// if the GSI base is above 4 we skip it (serial input simply stays disabled).
fn route_serial(dest_apic_id: u32, gsi_base: u32) {
    const COM1_GSI: u32 = 4;
    if COM1_GSI < gsi_base {
        return;
    }
    let base = IOAPIC_VIRT.load(Ordering::Acquire);
    let index = COM1_GSI - gsi_base;
    let redtbl_lo = 0x10 + index * 2;
    ioapic_write(base, redtbl_lo + 1, dest_apic_id << 24);
    ioapic_write(base, redtbl_lo, u32::from(SERIAL_VECTOR));
}

fn ioapic_write(base: u64, reg: u32, value: u32) {
    // SAFETY: `base` points at the mapped I/O APIC window.
    unsafe {
        (base as *mut u32).write_volatile(reg);
        ((base + 0x10) as *mut u32).write_volatile(value);
    }
}

/// Remaps the 8259 PICs out of the exception range and masks every line.
fn mask_legacy_pic() {
    const M_CMD: u16 = 0x20;
    const M_DATA: u16 = 0x21;
    const S_CMD: u16 = 0xA0;
    const S_DATA: u16 = 0xA1;
    // SAFETY: standard 8259 init sequence followed by a full mask.
    unsafe {
        outb(M_CMD, 0x11);
        io_wait();
        outb(S_CMD, 0x11);
        io_wait();
        outb(M_DATA, 0x20);
        io_wait();
        outb(S_DATA, 0x28);
        io_wait();
        outb(M_DATA, 0x04);
        io_wait();
        outb(S_DATA, 0x02);
        io_wait();
        outb(M_DATA, 0x01);
        io_wait();
        outb(S_DATA, 0x01);
        io_wait();
        outb(M_DATA, 0xFF);
        outb(S_DATA, 0xFF);
    }
}

/// Busy-waits `ms` milliseconds using PIT channel 2 (mode 0, terminal count).
fn pit_wait_ms(ms: u64) {
    const PIT_HZ: u64 = 1_193_182;
    // Channel 2 counts at most 65535; cap each wait window accordingly.
    let mut remaining = ms;
    while remaining > 0 {
        let chunk = remaining.min(50); // <= 50 ms keeps count < 65536
        let count = (PIT_HZ * chunk / 1000) as u16;
        // SAFETY: programming PIT channel 2 and its gate via ports 0x61/0x42/0x43.
        unsafe {
            // Disable speaker (bit1=0), enable gate (bit0=1).
            let p = inb(0x61) & 0xFC;
            outb(0x61, p | 0x01);
            // Channel 2, lobyte/hibyte, mode 0, binary.
            outb(0x43, 0xB0);
            outb(0x42, (count & 0xFF) as u8);
            outb(0x42, (count >> 8) as u8);
            // Reload the gate to start the count.
            let g = inb(0x61) & 0xFE;
            outb(0x61, g);
            outb(0x61, g | 0x01);
            // Wait until OUT (bit 5) goes high at terminal count.
            while inb(0x61) & 0x20 == 0 {
                core::hint::spin_loop();
            }
        }
        remaining -= chunk;
    }
}

/// Brief I/O delay by touching an unused port.
unsafe fn io_wait() {
    // SAFETY: port 0x80 is the conventional inert POST port.
    unsafe { outb(0x80, 0) };
}

/// Drains any byte in the i8042 output buffer.
pub fn drain_ps2() {
    // SAFETY: reading the i8042 ports only clears the output buffer.
    while unsafe { inb(0x64) } & 1 != 0 {
        let _ = unsafe { inb(0x60) };
    }
}
