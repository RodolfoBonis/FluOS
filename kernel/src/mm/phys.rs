//! Physical frame allocator: a buddy allocator bootstrapped from the Limine
//! memory map.
//!
//! The pure buddy logic lives in the host-tested [`mm`] crate; this module only
//! deals with the hardware realities the crate deliberately avoids: discovering
//! usable RAM, stealing a slice of it to hold the allocator's own metadata
//! (before any heap exists), and translating between physical frames and the
//! HHDM virtual addresses the kernel uses to touch them.
//!
//! Per-CPU frame caches (a later milestone) are expected to sit on top of this
//! global allocator and refill from it in batches; the buddy already keeps its
//! metadata external so those caches can be added without disturbing it.

use crate::boot;
use core::sync::atomic::{AtomicU64, Ordering};
use limine::memmap;
use mm::buddy::{Buddy, Node};
use crate::sync::SpinLock;

/// Page/frame size in bytes.
pub const FRAME_SIZE: u64 = 4096;

/// Largest block the buddy will coalesce: 2^18 frames = 1 GiB.
const MAX_ORDER: usize = 18;

/// HHDM offset, published once during [`init`] so frame↔pointer translation is
/// available crate-wide without threading it through every call.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// IRQ-safe: the timer tick path can allocate (runqueue growth), so taking
/// this lock must disable interrupts to avoid a same-CPU deadlock (C3).
static ALLOCATOR: SpinLock<Option<Buddy<'static>>> = SpinLock::new(None);

/// HHDM offset captured at init; valid after [`init`] has run.
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Relaxed)
}

/// Virtual (HHDM) pointer for a physical address.
pub fn phys_to_virt(phys: u64) -> u64 {
    phys + hhdm_offset()
}

/// Frame number (physical address / [`FRAME_SIZE`]) for a physical address.
fn frame_of(phys: u64) -> u64 {
    phys / FRAME_SIZE
}

/// Builds the frame allocator from the firmware memory map.
///
/// Steals a frame-aligned slice from the first usable region large enough to
/// hold the buddy's metadata, then releases every other usable frame into the
/// allocator. Must be called exactly once, before any frame is requested.
pub fn init(hhdm: u64) {
    HHDM_OFFSET.store(hhdm, Ordering::Relaxed);
    let entries = boot::memmap();

    // Span of physical frames to manage: from the lowest usable frame to the
    // highest. Holes (reserved/MMIO) inside the span simply never get freed.
    let usable = || entries.iter().filter(|e| e.type_ == memmap::MEMMAP_USABLE);
    let lowest = usable()
        .map(|e| frame_of(e.base))
        .min()
        .expect("no usable memory") as usize;
    let end_frame = usable()
        .map(|e| frame_of(e.base + e.length))
        .max()
        .expect("no usable memory") as usize;
    // Floor the managed base to 2^MAX_ORDER so a block's alignment relative to
    // the base is also its *absolute* physical alignment (required for huge
    // pages / DMA) — M1. Frames below the lowest usable one are simply never
    // released into the pool.
    let base_frame = lowest & !((1usize << MAX_ORDER) - 1);
    let frames = end_frame - base_frame;

    // Metadata layout: `frames` nodes (8 bytes each) followed by `frames` order
    // bytes, all carved from one stolen, frame-aligned run.
    let nodes_bytes = frames * core::mem::size_of::<Node>();
    let meta_bytes = Buddy::metadata_bytes(frames) as u64;
    let meta_frames = meta_bytes.div_ceil(FRAME_SIZE);

    let steal = usable()
        .find(|e| e.length >= meta_frames * FRAME_SIZE)
        .expect("no region large enough for allocator metadata");
    let steal_base = steal.base;
    let steal_frame = frame_of(steal_base) as usize;

    // SAFETY: the stolen run is usable RAM mapped by the HHDM, is excluded
    // below from the frames handed to the allocator, and lives for the kernel's
    // lifetime. `Node` and `u8` accept any bit pattern, so viewing the
    // (uninitialised) bytes as slices is sound; the buddy writes before it
    // reads. `base` is frame-aligned, satisfying `Node`'s alignment.
    let (nodes, order) = unsafe {
        let base = phys_to_virt(steal_base);
        let nodes = core::slice::from_raw_parts_mut(base as *mut Node, frames);
        let order = core::slice::from_raw_parts_mut((base + nodes_bytes as u64) as *mut u8, frames);
        (nodes, order)
    };

    let mut buddy = Buddy::new_empty(base_frame, frames, MAX_ORDER, nodes, order)
        .expect("buddy metadata slices sized correctly");

    // Release every usable frame except the ones backing the metadata.
    let meta_lo = steal_frame;
    let meta_hi = steal_frame + meta_frames as usize;
    for region in usable() {
        let lo = frame_of(region.base) as usize;
        let hi = frame_of(region.base + region.length) as usize;
        add_excluding(&mut buddy, lo, hi, meta_lo, meta_hi);
    }

    let free = buddy.free_frames();
    *ALLOCATOR.lock() = Some(buddy);
    crate::log::info!(
        "frame allocator: {} MiB free ({} frames), {} KiB metadata",
        free as u64 * FRAME_SIZE / (1024 * 1024),
        free,
        meta_bytes / 1024,
    );
}

/// Frees `[lo, hi)` to the buddy, skipping any overlap with the reserved
/// metadata range `[rlo, rhi)`.
fn add_excluding(buddy: &mut Buddy<'static>, lo: usize, hi: usize, rlo: usize, rhi: usize) {
    // Portion before the reserved range.
    let a_hi = hi.min(rlo);
    if lo < a_hi {
        buddy.add_frames(lo, a_hi - lo);
    }
    // Portion after the reserved range.
    let b_lo = lo.max(rhi);
    if b_lo < hi {
        buddy.add_frames(b_lo, hi - b_lo);
    }
}

/// Allocates one physical frame, returning its physical address.
pub fn alloc_frame() -> Option<u64> {
    alloc_frames(1)
}

/// Allocates `count` contiguous frames, returning the physical address of the
/// first. The block is at least `count` frames (rounded up to a power of two).
pub fn alloc_frames(count: usize) -> Option<u64> {
    let frame = ALLOCATOR.lock().as_mut()?.alloc_frames(count)?;
    Some(frame as u64 * FRAME_SIZE)
}

/// Allocates one frame and zeroes it. Page-table frames must be zeroed before
/// use, so the paging code always goes through here.
pub fn alloc_frame_zeroed() -> Option<u64> {
    let phys = alloc_frame()?;
    // SAFETY: the frame is freshly owned by this caller and mapped read-write
    // through the HHDM, so zeroing its 4 KiB is sound.
    unsafe {
        core::ptr::write_bytes(phys_to_virt(phys) as *mut u8, 0, FRAME_SIZE as usize);
    }
    Some(phys)
}

/// Frees `count` frames previously obtained from [`alloc_frames`] at `phys`.
pub fn free_frames(phys: u64, count: usize) {
    if let Some(buddy) = ALLOCATOR.lock().as_mut() {
        buddy.free_frames_at(frame_of(phys) as usize, count);
    }
}

/// `(free_frames, total_frames)` for diagnostics.
pub fn stats() -> (usize, usize) {
    ALLOCATOR
        .lock()
        .as_ref()
        .map_or((0, 0), |b| (b.free_frames(), b.total_frames()))
}
