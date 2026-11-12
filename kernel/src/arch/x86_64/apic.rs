//! Local and I/O APIC bring-up for device interrupts.
//!
//! We fully mask the legacy 8259 PICs (after remapping their vectors out of the
//! exception range, so a stray spurious IRQ lands on a defined vector), enable
//! the Local APIC, and program one I/O APIC redirection entry to route the PS/2
//! keyboard's GSI to [`KEYBOARD_VECTOR`] on the bootstrap CPU. MMIO for both
//! APICs lives above RAM, so it is mapped on demand through the HHDM.

use super::acpi::ApicInfo;
use super::port::{inb, outb};
use crate::mm::{paging, phys};
use core::sync::atomic::{AtomicU64, Ordering};

/// IDT vector the keyboard IRQ is delivered on.
pub const KEYBOARD_VECTOR: u8 = 0x21;
/// LAPIC spurious-interrupt vector.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

// LAPIC register offsets.
const LAPIC_ID: u64 = 0x20;
const LAPIC_EOI: u64 = 0xB0;
const LAPIC_SVR: u64 = 0xF0;

/// HHDM virtual address of the LAPIC register page, set during [`init`].
static LAPIC_VIRT: AtomicU64 = AtomicU64::new(0);

/// Masks the PICs, enables the LAPIC, and routes the keyboard IRQ.
pub fn init(info: ApicInfo) {
    mask_legacy_pic();

    paging::map_mmio(info.lapic_base, 0x1000);
    paging::map_mmio(info.ioapic_base, 0x1000);

    let lapic = phys::phys_to_virt(info.lapic_base);
    LAPIC_VIRT.store(lapic, Ordering::Relaxed);

    // Enable the LAPIC: set the spurious-vector register's enable bit (8).
    lapic_write(LAPIC_SVR, 0x100 | u32::from(SPURIOUS_VECTOR));

    let apic_id = (lapic_read(LAPIC_ID) >> 24) & 0xFF;
    route_ioapic(&info, apic_id);

    crate::log::info!(
        "apic: lapic@{:#x} ioapic@{:#x} kbd gsi {} -> vector {:#x}",
        info.lapic_base,
        info.ioapic_base,
        info.keyboard_gsi,
        KEYBOARD_VECTOR,
    );
}

/// Signals end-of-interrupt to the LAPIC. Called at the tail of every handled
/// device IRQ.
pub fn eoi() {
    lapic_write(LAPIC_EOI, 0);
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
    let base = phys::phys_to_virt(info.ioapic_base);
    let index = info.keyboard_gsi - info.ioapic_gsi_base;
    let redtbl_lo = 0x10 + index * 2;

    // Decode polarity/trigger from the MADT flags (0 => ISA edge/active-high).
    let polarity = info.keyboard_flags & 0b11;
    let trigger = (info.keyboard_flags >> 2) & 0b11;
    let active_low = polarity == 0b11;
    let level = trigger == 0b11;

    let mut low = u32::from(KEYBOARD_VECTOR); // fixed delivery, physical dest, unmasked
    if active_low {
        low |= 1 << 13;
    }
    if level {
        low |= 1 << 15;
    }
    let high = dest_apic_id << 24;

    ioapic_write(base, redtbl_lo + 1, high);
    ioapic_write(base, redtbl_lo, low);
}

fn ioapic_write(base: u64, reg: u32, value: u32) {
    // SAFETY: `base` points at the mapped I/O APIC window: a 32-bit index
    // register at +0x00 selects which 32-bit data register appears at +0x10.
    unsafe {
        (base as *mut u32).write_volatile(reg);
        ((base + 0x10) as *mut u32).write_volatile(value);
    }
}

/// Remaps the master/slave 8259 PICs out of the CPU exception range and masks
/// every line, so all device IRQs come exclusively through the I/O APIC.
fn mask_legacy_pic() {
    const M_CMD: u16 = 0x20;
    const M_DATA: u16 = 0x21;
    const S_CMD: u16 = 0xA0;
    const S_DATA: u16 = 0xA1;

    // SAFETY: the standard 8259 ICW initialisation sequence, followed by a full
    // mask. These ports exist on every PC and masking them is always safe.
    unsafe {
        // ICW1: begin init (cascade, ICW4 present).
        outb(M_CMD, 0x11);
        io_wait();
        outb(S_CMD, 0x11);
        io_wait();
        // ICW2: vector offsets (0x20 and 0x28) out of the exception range.
        outb(M_DATA, 0x20);
        io_wait();
        outb(S_DATA, 0x28);
        io_wait();
        // ICW3: master/slave cascade on IRQ2.
        outb(M_DATA, 0x04);
        io_wait();
        outb(S_DATA, 0x02);
        io_wait();
        // ICW4: 8086 mode.
        outb(M_DATA, 0x01);
        io_wait();
        outb(S_DATA, 0x01);
        io_wait();
        // Mask all lines on both PICs.
        outb(M_DATA, 0xFF);
        outb(S_DATA, 0xFF);
    }
}

/// Brief I/O delay by touching an unused port, letting the PIC latch each write.
unsafe fn io_wait() {
    // SAFETY: port 0x80 is the conventional POST/debug port; writing it is inert.
    unsafe { outb(0x80, 0) };
}

/// Drains and discards any byte sitting in the i8042 output buffer, so a
/// keypress that occurred before routing does not block further IRQs.
pub fn drain_ps2() {
    // SAFETY: reading the i8042 data port is side-effect-free beyond clearing
    // the output buffer.
    while unsafe { inb(0x64) } & 1 != 0 {
        let _ = unsafe { inb(0x60) };
    }
}
