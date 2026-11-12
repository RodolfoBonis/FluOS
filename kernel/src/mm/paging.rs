//! 4-level paging: build the kernel's own page tables and switch to them.
//!
//! Limine drops us into its bootstrap tables. We replace them with tables we
//! control so we can enforce W^X on the kernel image (text executable but
//! read-only, rodata read-only + NX, data writable + NX) and lay down the HHDM
//! direct map with the largest pages the CPU supports. All page-table frames
//! come from the buddy allocator and are touched through the HHDM.

use crate::boot;
use crate::mm::phys;
use core::arch::x86_64::__cpuid_count;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::mapper::{MapToError, MapperFlush};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags as Flags, PhysFrame,
    Size1GiB, Size2MiB, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use core::sync::atomic::{AtomicU64, Ordering};

/// Translates a virtual address through the *currently active* page tables,
/// returning its physical address if mapped. Used by the user-copy routines to
/// reach user memory via the HHDM.
pub fn translate_active(vaddr: u64) -> Option<u64> {
    use x86_64::structures::paging::mapper::Translate;
    let hhdm = phys::hhdm_offset();
    let mapper = active_mapper(hhdm);
    mapper.translate_addr(VirtAddr::new(vaddr)).map(|p| p.as_u64())
}

/// Physical address of the kernel PML4, published by [`init`] so APs can load
/// the same tables.
static KERNEL_PML4: AtomicU64 = AtomicU64::new(0);

const GIB: u64 = 0x4000_0000;
const MIB2: u64 = 0x20_0000;
const KIB4: u64 = 0x1000;

/// Adapts the physical frame allocator to the `x86_64` mapper's interface.
/// Every page-table frame it returns is zeroed, as `map_to` requires.
struct Frames;

// SAFETY: `alloc_frame_zeroed` returns a unique, zeroed, otherwise-unused frame
// each call, exactly as the trait demands.
unsafe impl FrameAllocator<Size4KiB> for Frames {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        phys::alloc_frame_zeroed().map(|p| PhysFrame::containing_address(PhysAddr::new(p)))
    }
}

unsafe extern "C" {
    static __kernel_start: u8;
    static __requests_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __kernel_end: u8;
}

/// Virtual address of a linker symbol.
fn sym(s: &'static u8) -> u64 {
    core::ptr::from_ref(s) as u64
}

/// Builds the kernel page tables and loads them into CR3.
pub fn init(hhdm: u64) {
    let (phys_base, virt_base) = boot::kernel_address();

    let pml4_phys = phys::alloc_frame_zeroed().expect("PML4 frame");
    // SAFETY: the frame is freshly allocated, zeroed, and HHDM-mapped, so it is
    // a valid, exclusively-owned, empty page table for the lifetime of these
    // tables. `OffsetPageTable` needs the HHDM base to walk frames.
    let mut mapper = unsafe {
        let pml4 = &mut *((hhdm + pml4_phys) as *mut PageTable);
        OffsetPageTable::new(pml4, VirtAddr::new(hhdm))
    };
    let mut frames = Frames;

    // Kernel image, with W^X per section. `virt - virt_base + phys_base` gives
    // each page's physical frame.
    let ro = Flags::PRESENT | Flags::NO_EXECUTE;
    let rx = Flags::PRESENT;
    let rw = Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE;

    // SAFETY (all four): we map kernel virtual pages to their actual load
    // frames with correct permissions into fresh, inactive tables; nothing is
    // aliased writably within the image itself.
    unsafe {
        map_range(&mut mapper, &mut frames, sym(&__kernel_start), sym(&__requests_end), ro, virt_base, phys_base);
        map_range(&mut mapper, &mut frames, sym(&__text_start), sym(&__text_end), rx, virt_base, phys_base);
        map_range(&mut mapper, &mut frames, sym(&__rodata_start), sym(&__rodata_end), ro, virt_base, phys_base);
        map_range(&mut mapper, &mut frames, sym(&__data_start), sym(&__kernel_end), rw, virt_base, phys_base);
    }

    map_hhdm(&mut mapper, &mut frames, hhdm);

    let pml4_frame = PhysFrame::containing_address(PhysAddr::new(pml4_phys));
    KERNEL_PML4.store(pml4_phys, Ordering::Release);
    // SAFETY: `pml4_frame` holds a complete set of tables that map this code,
    // the current stack (via the HHDM), and all RAM/MMIO, so execution
    // continues seamlessly after the switch.
    unsafe { Cr3::write(pml4_frame, Cr3Flags::empty()) };

    crate::log::info!(
        "kernel page tables active (W^X, {} HHDM pages)",
        if supports_1gib_pages() { "1 GiB" } else { "2 MiB" },
    );
}

/// Maps `[start, end)` (both 4 KiB-aligned) as 4 KiB pages.
///
/// # Safety
/// The caller guarantees the physical translation and flags are correct for an
/// inactive table; mapping into the live table could alias existing memory.
unsafe fn map_range(
    mapper: &mut OffsetPageTable,
    frames: &mut Frames,
    start: u64,
    end: u64,
    flags: Flags,
    virt_base: u64,
    phys_base: u64,
) {
    let mut v = start;
    while v < end {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(v));
        let phys = v - virt_base + phys_base;
        let frame = PhysFrame::containing_address(PhysAddr::new(phys));
        // SAFETY: inactive table; see the function contract.
        let res = unsafe { mapper.map_to(page, frame, flags, frames) };
        expect_mapped(res);
        v += KIB4;
    }
}

/// Lays down the HHDM direct map over all physical memory with the largest
/// pages available, so the kernel can reach any frame (RAM, framebuffer, MMIO)
/// at `phys + hhdm`.
fn map_hhdm(mapper: &mut OffsetPageTable, frames: &mut Frames, hhdm: u64) {
    // Cover every physical address the firmware reported, rounded up to 1 GiB.
    let max_phys = boot::memmap()
        .iter()
        .map(|e| e.base + e.length)
        .max()
        .expect("non-empty memory map")
        .div_ceil(GIB)
        * GIB;

    let flags = Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE;
    let gib_ok = supports_1gib_pages();

    let mut p = 0u64;
    while p < max_phys {
        let page_1g = p % GIB == 0 && p + GIB <= max_phys;
        let page_2m = p % MIB2 == 0 && p + MIB2 <= max_phys;
        if gib_ok && page_1g {
            let page = Page::<Size1GiB>::containing_address(VirtAddr::new(hhdm + p));
            let frame = PhysFrame::containing_address(PhysAddr::new(p));
            // SAFETY: identity-style HHDM entry into an inactive table; the
            // target frame is real physical memory and nothing aliases it
            // executably (NX is set).
            expect_mapped(unsafe { mapper.map_to(page, frame, flags, frames) });
            p += GIB;
        } else if page_2m {
            let page = Page::<Size2MiB>::containing_address(VirtAddr::new(hhdm + p));
            let frame = PhysFrame::containing_address(PhysAddr::new(p));
            // SAFETY: as above, 2 MiB granularity.
            expect_mapped(unsafe { mapper.map_to(page, frame, flags, frames) });
            p += MIB2;
        } else {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(hhdm + p));
            let frame = PhysFrame::containing_address(PhysAddr::new(p));
            // SAFETY: as above, 4 KiB granularity.
            expect_mapped(unsafe { mapper.map_to(page, frame, flags, frames) });
            p += KIB4;
        }
    }
}

/// Panics on a mapping failure, tolerating a page that is already mapped (the
/// kernel image can overlap the HHDM span harmlessly).
fn expect_mapped<S>(res: Result<MapperFlush<S>, MapToError<S>>)
where
    S: x86_64::structures::paging::PageSize + core::fmt::Debug,
{
    match res {
        Ok(flush) => flush.ignore(),
        Err(MapToError::PageAlreadyMapped(_)) => {}
        Err(e) => panic!("page mapping failed: {e:?}"),
    }
}

/// Physical address of the kernel PML4 (for cloning its higher half into new
/// user address spaces).
pub fn kernel_pml4_phys() -> u64 {
    KERNEL_PML4.load(Ordering::Acquire)
}

/// Acknowledges a TLB-shootdown IPI (incremented by the handler after flushing).
/// The full sender-side wait protocol lands with `munmap` freeing frames.
static TLB_ACKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Called by the TLB-shootdown IRQ after flushing, so a future sender can wait
/// for all CPUs to acknowledge before freeing the backing frames.
pub fn tlb_ack() {
    TLB_ACKS.fetch_add(1, Ordering::Release);
}

/// Loads the kernel page tables on the calling CPU (used by APs, which start on
/// the bootloader's tables and must adopt ours before touching kernel-only
/// mappings such as device MMIO).
pub fn activate() {
    let phys = KERNEL_PML4.load(Ordering::Acquire);
    let frame = PhysFrame::containing_address(PhysAddr::new(phys));
    // SAFETY: `frame` is the kernel PML4 built by `init`; it maps this code, the
    // HHDM, and all device MMIO, so the switch is seamless on any CPU.
    unsafe { Cr3::write(frame, Cr3Flags::empty()) };
}

/// Reconstructs an `OffsetPageTable` over the *currently active* PML4, so we
/// can add mappings after the initial switch (e.g. for device MMIO).
fn active_mapper(hhdm: u64) -> OffsetPageTable<'static> {
    let (frame, _) = Cr3::read();
    // SAFETY: CR3 holds our PML4; it is mapped through the HHDM and owned by
    // the kernel, so forming a mutable reference to it is sound in the
    // single-threaded bring-up path.
    unsafe {
        let pml4 = &mut *((hhdm + frame.start_address().as_u64()) as *mut PageTable);
        OffsetPageTable::new(pml4, VirtAddr::new(hhdm))
    }
}

/// Dedicated virtual window for uncacheable device MMIO, bump-allocated by
/// [`map_mmio`]. It is a canonical higher-half range distinct from both the HHDM
/// (which is cacheable and partly huge-page-mapped) and the kernel image, so UC
/// 4 KiB mappings can be laid down here without splitting any huge page.
const MMIO_WINDOW_BASE: u64 = 0xffff_fe00_0000_0000;
static MMIO_NEXT: AtomicU64 = AtomicU64::new(MMIO_WINDOW_BASE);

/// Maps a device MMIO region `phys_base..phys_base+size` as **uncacheable**,
/// writable, non-executable 4 KiB pages in the dedicated MMIO window, and
/// returns the virtual address of `phys_base`.
///
/// Device registers (APIC, I/O APIC, ...) must be uncacheable; mapping them in a
/// fresh window (rather than the HHDM) both guarantees UC and avoids having to
/// split the 1 GiB HHDM huge page that happens to cover the APIC physical range.
pub fn map_mmio(phys_base: u64, size: u64) -> u64 {
    let hhdm = phys::hhdm_offset();
    let mut mapper = active_mapper(hhdm);
    let mut frames = Frames;
    let flags = Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE | Flags::NO_CACHE;

    let start = phys_base & !(KIB4 - 1);
    let end = (phys_base + size).div_ceil(KIB4) * KIB4;
    let pages = (end - start) / KIB4;
    let va_base = MMIO_NEXT.fetch_add(pages * KIB4, Ordering::Relaxed);

    for i in 0..pages {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va_base + i * KIB4));
        let frame = PhysFrame::containing_address(PhysAddr::new(start + i * KIB4));
        // SAFETY: fresh window VA mapped to a device frame; no RAM is aliased
        // and the VA range is handed out uniquely by the bump allocator.
        match unsafe { mapper.map_to(page, frame, flags, &mut frames) } {
            Ok(flush) => flush.flush(),
            Err(e) => panic!("MMIO mapping failed: {e:?}"),
        }
    }
    va_base + (phys_base & (KIB4 - 1))
}

/// Whether the CPU supports 1 GiB pages (CPUID 8000_0001h EDX bit 26).
fn supports_1gib_pages() -> bool {
    // `__cpuid_count` is safe: it only reads CPU identification data.
    let leaf = __cpuid_count(0x8000_0001, 0);
    leaf.edx & (1 << 26) != 0
}
