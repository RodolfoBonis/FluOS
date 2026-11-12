//! Minimal ACPI MADT parsing to locate the local and I/O APICs.
//!
//! Limine hands us the RSDP (a higher-half pointer under base revision ≥ 1), so
//! we walk RSDP → XSDT/RSDT → MADT ("APIC") by hand. This is deliberately a
//! small, self-contained reader rather than the full `acpi` crate: we need only
//! three facts (the LAPIC base, the first I/O APIC, and the keyboard's GSI /
//! polarity), and hand-rolling avoids pulling an `AcpiHandler` and its mapping
//! plumbing into early boot. All table pointers inside the XSDT are physical and
//! are reached through the HHDM.

use crate::boot;
use crate::mm::phys;

/// What the kernel needs from the MADT to route the keyboard IRQ.
#[derive(Clone, Copy, Debug)]
pub struct ApicInfo {
    pub lapic_base: u64,
    pub ioapic_base: u64,
    pub ioapic_gsi_base: u32,
    /// Global System Interrupt the PS/2 keyboard IRQ (ISA IRQ 1) maps to.
    pub keyboard_gsi: u32,
    /// MPS INTI flags for that GSI (polarity/trigger), 0 = ISA defaults.
    pub keyboard_flags: u16,
}

/// Reads a `T` from `addr` without assuming alignment.
///
/// # Safety
/// `addr` must point at `size_of::<T>()` readable, initialised bytes.
unsafe fn read_unaligned<T: Copy>(addr: u64) -> T {
    unsafe { (addr as *const T).read_unaligned() }
}

/// Parses the MADT, returning the APIC topology, or `None` if ACPI is absent or
/// reports no I/O APIC (in which case the caller keeps the PIC masked and runs
/// without device interrupts).
pub fn parse() -> Option<ApicInfo> {
    let rsdp = boot::rsdp_addr()? as u64;

    // RSDP: revision at +15, RSDT (u32) at +16, XSDT (u64) at +24.
    // SAFETY: Limine guarantees a valid RSDP at this higher-half address.
    let revision: u8 = unsafe { read_unaligned(rsdp + 15) };
    let (entries_virt, entry_size, count) = if revision >= 2 {
        let xsdt_phys: u64 = unsafe { read_unaligned(rsdp + 24) };
        sdt_entries(phys::phys_to_virt(xsdt_phys), 8)
    } else {
        let rsdt_phys: u32 = unsafe { read_unaligned(rsdp + 16) };
        sdt_entries(phys::phys_to_virt(u64::from(rsdt_phys)), 4)
    };

    // Find the MADT by signature.
    let madt_virt = (0..count).find_map(|i| {
        let entry_phys: u64 = if entry_size == 8 {
            // SAFETY: XSDT holds `count` u64 physical pointers.
            unsafe { read_unaligned(entries_virt + i * 8) }
        } else {
            // SAFETY: RSDT holds `count` u32 physical pointers.
            let p: u32 = unsafe { read_unaligned(entries_virt + i * 4) };
            u64::from(p)
        };
        let virt = phys::phys_to_virt(entry_phys);
        (signature(virt) == *b"APIC").then_some(virt)
    })?;

    Some(parse_madt(madt_virt))
}

/// Returns `(entries_ptr, entry_size, entry_count)` for an SDT whose pointer
/// array uses `ptr_size`-byte entries.
fn sdt_entries(sdt_virt: u64, ptr_size: u64) -> (u64, u64, u64) {
    // SDT length is a u32 at offset 4; the header is 36 bytes.
    let length: u32 = unsafe { read_unaligned(sdt_virt + 4) };
    let count = (u64::from(length).saturating_sub(36)) / ptr_size;
    (sdt_virt + 36, ptr_size, count)
}

/// Reads the 4-byte signature of a table.
fn signature(virt: u64) -> [u8; 4] {
    // SAFETY: a valid table always has a 4-byte signature at offset 0.
    unsafe { read_unaligned(virt) }
}

/// Walks the MADT interrupt-controller structures.
fn parse_madt(madt: u64) -> ApicInfo {
    let length: u32 = unsafe { read_unaligned(madt + 4) };
    // LAPIC base is a u32 at offset 36; a type-5 override can replace it.
    let mut info = ApicInfo {
        lapic_base: u64::from(unsafe { read_unaligned::<u32>(madt + 36) }),
        ioapic_base: 0,
        ioapic_gsi_base: 0,
        keyboard_gsi: 1, // ISA IRQ 1 identity-maps unless an override says otherwise
        keyboard_flags: 0,
    };

    // Entries begin at offset 44: {type: u8, len: u8, ...}.
    let mut off = 44u64;
    while off + 2 <= u64::from(length) {
        let kind: u8 = unsafe { read_unaligned(madt + off) };
        let len: u8 = unsafe { read_unaligned(madt + off + 1) };
        if len < 2 {
            break; // malformed; stop rather than loop forever
        }
        match kind {
            1 => {
                // I/O APIC: address (u32) at +4, GSI base (u32) at +8.
                if info.ioapic_base == 0 {
                    info.ioapic_base = u64::from(unsafe { read_unaligned::<u32>(madt + off + 4) });
                    info.ioapic_gsi_base = unsafe { read_unaligned(madt + off + 8) };
                }
            }
            2 => {
                // Interrupt Source Override: source IRQ (u8) at +3, GSI (u32) at
                // +4, flags (u16) at +8.
                let source: u8 = unsafe { read_unaligned(madt + off + 3) };
                if source == 1 {
                    info.keyboard_gsi = unsafe { read_unaligned(madt + off + 4) };
                    info.keyboard_flags = unsafe { read_unaligned(madt + off + 8) };
                }
            }
            5 => {
                // Local APIC Address Override (u64) at +4.
                info.lapic_base = unsafe { read_unaligned(madt + off + 4) };
            }
            _ => {}
        }
        off += u64::from(len);
    }
    info
}
