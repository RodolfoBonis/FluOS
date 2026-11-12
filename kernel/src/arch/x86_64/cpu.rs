//! CPU feature detection and protection-bit enablement.
//!
//! We opportunistically turn on the memory-protection features the hardware
//! advertises: NX (no-execute, required before any page table sets the NX bit),
//! write-protect (so supervisor writes honour read-only mappings), and — when
//! present — SMEP, SMAP, and PCID. Everything here is cheap and runs once on
//! the bootstrap processor before paging is rebuilt.

use core::arch::x86_64::__cpuid_count;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
use x86_64::registers::model_specific::{Efer, EferFlags};

/// Protection features supported by this CPU.
#[derive(Clone, Copy, Default)]
pub struct Features {
    pub nx: bool,
    pub smep: bool,
    pub smap: bool,
    pub pcid: bool,
}

/// Probes CPUID for the protection features we care about.
pub fn detect() -> Features {
    // Leaf 1: ECX reports PCID (bit 17); EDX (leaf 0x8000_0001) reports NX.
    // Leaf 7 subleaf 0: EBX reports SMEP (bit 7) and SMAP (bit 20).
    // `__cpuid_count` is safe: it only reads CPU identification data.
    let leaf1 = __cpuid_count(1, 0);
    let leaf7 = __cpuid_count(7, 0);
    let ext1 = __cpuid_count(0x8000_0001, 0);

    Features {
        nx: ext1.edx & (1 << 20) != 0,
        smep: leaf7.ebx & (1 << 7) != 0,
        smap: leaf7.ebx & (1 << 20) != 0,
        pcid: leaf1.ecx & (1 << 17) != 0,
    }
}

/// Enables every supported protection feature and returns what was turned on.
///
/// Must run before switching to page tables that use the NX bit.
pub fn enable_protections() -> Features {
    let features = detect();

    if features.nx {
        // SAFETY: setting EFER.NXE only enables honouring the NX bit; it does
        // not itself change any mapping.
        unsafe { Efer::update(|f| f.insert(EferFlags::NO_EXECUTE_ENABLE)) };
    }

    // SAFETY: WRITE_PROTECT makes the CPU honour read-only pages in ring 0; our
    // mappings are built with that in mind, so enabling it is safe.
    unsafe { Cr0::update(|f| f.insert(Cr0Flags::WRITE_PROTECT)) };

    // SAFETY: SMEP/SMAP/PCID only restrict or optimise accesses to user pages,
    // of which the kernel currently has none, so enabling the supported subset
    // cannot fault existing kernel accesses.
    unsafe {
        Cr4::update(|f| {
            if features.smep {
                f.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION);
            }
            if features.smap {
                f.insert(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
            }
            if features.pcid {
                f.insert(Cr4Flags::PCID);
            }
        });
    }

    features
}
