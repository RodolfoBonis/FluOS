//! The kernel heap: a slab allocator for small objects, backed by the buddy
//! allocator for everything larger.
//!
//! The slab logic and its size classes live in the host-tested [`mm`] crate.
//! Here we feed it pages from the physical allocator (via the HHDM) and expose
//! it as the `#[global_allocator]`, so `alloc`-based collections work in the
//! kernel. Requests above [`mm::slab::MAX_SLAB_OBJECT`] skip the slab and take
//! naturally-aligned frame runs straight from the buddy.

use super::phys::{self, FRAME_SIZE};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use mm::slab::{PageSource, Slab};
use crate::sync::SpinLock;

/// Pages for the slab, drawn from the buddy allocator and addressed through the
/// HHDM.
struct BuddyPages;

// SAFETY: each page is a distinct 4 KiB-aligned frame, uniquely owned once
// handed to the slab (the slab never returns pages), and valid for the kernel's
// lifetime because the HHDM maps it permanently.
unsafe impl PageSource for BuddyPages {
    fn page_size(&self) -> usize {
        FRAME_SIZE as usize
    }

    fn alloc_page(&mut self) -> Option<NonNull<u8>> {
        let phys = phys::alloc_frame()?;
        NonNull::new(phys::phys_to_virt(phys) as *mut u8)
    }
}

static SLAB: SpinLock<Slab> = SpinLock::new(Slab::new(FRAME_SIZE as usize));

/// Number of frames a large (non-slab) allocation of this layout needs. The
/// buddy rounds this up to a power of two, giving a block aligned to at least
/// that many frames — enough to satisfy `align` as well as `size`.
fn large_frames(layout: Layout) -> usize {
    let for_size = (layout.size() as u64).div_ceil(FRAME_SIZE) as usize;
    let for_align = (layout.align() as u64).div_ceil(FRAME_SIZE) as usize;
    for_size.max(for_align).max(1)
}

struct KernelAllocator;

// SAFETY: `alloc` returns either a slab object sized/aligned for the layout or a
// frame run aligned to a power-of-two frame count >= the request, and `dealloc`
// routes each pointer back to the same source using the identical layout.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);
        let align = layout.align();

        if Slab::class_for(size, align).is_some() {
            return SLAB
                .lock()
                .alloc(size, align, &mut BuddyPages)
                .map_or(ptr::null_mut(), NonNull::as_ptr);
        }

        // Large allocation: a frame run straight from the buddy.
        match phys::alloc_frames(large_frames(layout)) {
            Some(phys) => phys::phys_to_virt(phys) as *mut u8,
            None => ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        let Some(ptr) = NonNull::new(p) else { return };
        let size = layout.size().max(1);
        let align = layout.align();

        if Slab::class_for(size, align).is_some() {
            // SAFETY: by the GlobalAlloc contract `ptr` came from `alloc` with
            // this same layout, hence from the matching slab class.
            unsafe { SLAB.lock().dealloc(ptr, size, align) };
            return;
        }

        let phys = p as u64 - phys::hhdm_offset();
        phys::free_frames(phys, large_frames(layout));
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

/// Exercises the heap right after bring-up so a broken allocator fails loudly
/// during boot instead of at some later, confusing allocation.
pub fn smoke_test() {
    use alloc::vec::Vec;

    let mut v: Vec<u64> = Vec::new();
    for i in 0..1024 {
        v.push(i * i);
    }
    let sum: u64 = v.iter().sum();
    assert_eq!(v.len(), 1024);
    assert_eq!(sum, (0..1024u64).map(|i| i * i).sum());

    // Force a large (multi-page) allocation through the buddy path.
    let big: Vec<u8> = alloc::vec![0xABu8; 16 * 1024];
    assert_eq!(big.iter().map(|&b| b as u64).sum::<u64>(), 0xAB * 16 * 1024);

    crate::log::info!("heap smoke test passed (slab + buddy paths)");
}
