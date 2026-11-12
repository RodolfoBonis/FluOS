//! Memory management: physical frames, paging, and the kernel heap.
//!
//! Bring-up order matters. The frame allocator comes first (it needs only the
//! firmware memory map). Paging builds on it to install the kernel's own page
//! tables. The heap is a `#[global_allocator]` that lazily pulls frames, so it
//! needs no explicit init beyond a smoke test once frames and paging are live.

pub mod fault;
pub mod heap;
pub mod paging;
pub mod phys;

/// Brings the whole memory subsystem online. Call once, early in boot.
pub fn init(hhdm: u64) {
    phys::init(hhdm);
    paging::init(hhdm);
    heap::smoke_test();
    phys::init_refcounts();

    let (free, total) = phys::stats();
    crate::log::info!(
        "mm online: {}/{} MiB physical free",
        free as u64 * phys::FRAME_SIZE / (1024 * 1024),
        total as u64 * phys::FRAME_SIZE / (1024 * 1024),
    );
}
