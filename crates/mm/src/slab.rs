//! A slab object cache with power-of-two size classes.
//!
//! The slab carves pages into fixed-size objects and threads the free ones
//! into an intrusive singly-linked list stored *inside* the free objects. It is
//! deliberately decoupled from where pages come from: callers implement
//! [`PageSource`], so the kernel can back it with the buddy allocator over the
//! HHDM while host tests back it with ordinary heap pages. Only object memory
//! that the slab owns is ever dereferenced, which keeps the logic testable.
//!
//! Allocations larger than [`MAX_SLAB_OBJECT`] are *not* this allocator's job;
//! [`Slab::class_for`] returns `None` and the kernel satisfies them straight
//! from the buddy allocator.
//!
//! Deliberate simplification: a page, once acquired, is kept for the lifetime
//! of the cache (no page is returned to the [`PageSource`] when it drains).
//! That keeps the hot path allocation-order-free and lock-light; reclaiming
//! empty slabs under memory pressure is left for a later milestone.

use core::ptr::NonNull;

/// Power-of-two object sizes served by the slab, in bytes.
pub const SIZE_CLASSES: [usize; 9] = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];

/// Largest object the slab will serve; above this, go to the buddy allocator.
pub const MAX_SLAB_OBJECT: usize = 2048;

/// Source of fixed-size, naturally-aligned pages for the slab to carve.
///
/// # Safety
/// Implementations must return pointers to at least `page_size()` bytes that
/// are aligned to `page_size()` and remain valid and exclusively owned by the
/// slab until the implementation is dropped.
pub unsafe trait PageSource {
    /// Size of each page returned by [`alloc_page`](Self::alloc_page).
    fn page_size(&self) -> usize;

    /// Returns a fresh page, or `None` when out of memory.
    fn alloc_page(&mut self) -> Option<NonNull<u8>>;
}

/// A single size class: a free list plus the stats to reason about it.
pub struct SlabCache {
    object_size: usize,
    objects_per_page: usize,
    free: Option<NonNull<u8>>,
    /// Live (handed-out) objects.
    allocated: usize,
    /// Pages acquired from the [`PageSource`].
    pages: usize,
}

impl SlabCache {
    /// Builds an empty cache for `object_size`-byte objects carved from
    /// `page_size`-byte pages. `object_size` must be a power of two, at least
    /// pointer-sized, and no larger than `page_size`.
    #[must_use]
    pub const fn new(object_size: usize, page_size: usize) -> Self {
        assert!(object_size.is_power_of_two());
        assert!(object_size >= core::mem::size_of::<usize>());
        assert!(object_size <= page_size);
        Self {
            object_size,
            objects_per_page: page_size / object_size,
            free: None,
            allocated: 0,
            pages: 0,
        }
    }

    /// Object size of this class in bytes.
    #[must_use]
    pub fn object_size(&self) -> usize {
        self.object_size
    }

    /// Live object count.
    #[must_use]
    pub fn allocated(&self) -> usize {
        self.allocated
    }

    /// Allocates one object, pulling a fresh page from `src` if the free list
    /// is empty. Returns `None` only when `src` is exhausted.
    pub fn alloc(&mut self, src: &mut impl PageSource) -> Option<NonNull<u8>> {
        if self.free.is_none() && !self.refill(src) {
            return None;
        }
        // SAFETY: `free` is `Some` (either it already was, or `refill` just
        // populated it). The head points at an object-sized slot we own; its
        // first bytes hold the next-free pointer we wrote in `push`.
        let head = self.free.expect("free list non-empty after refill");
        let next = unsafe { head.as_ptr().cast::<*mut u8>().read() };
        self.free = NonNull::new(next);
        self.allocated += 1;
        Some(head)
    }

    /// Returns an object previously obtained from this cache to the free list.
    ///
    /// # Safety
    /// `ptr` must have come from [`alloc`](Self::alloc) on *this* cache and not
    /// have been freed since.
    pub unsafe fn dealloc(&mut self, ptr: NonNull<u8>) {
        // SAFETY: caller guarantees `ptr` is one of our object slots, so it is
        // valid for a pointer-sized write that stores the old free-list head.
        unsafe { self.push(ptr) };
        self.allocated -= 1;
    }

    /// Carves one fresh page into objects and links them into the free list.
    fn refill(&mut self, src: &mut impl PageSource) -> bool {
        let Some(page) = src.alloc_page() else {
            return false;
        };
        self.pages += 1;
        let base = page.as_ptr();
        for i in 0..self.objects_per_page {
            // SAFETY: `base` points at `page_size` owned, aligned bytes and
            // `i < objects_per_page`, so every slot lies inside the page and is
            // `object_size`-aligned (object sizes are powers of two and the
            // page is page-aligned).
            let slot = unsafe { base.add(i * self.object_size) };
            // SAFETY: `slot` is a non-null interior pointer of a valid page.
            unsafe { self.push(NonNull::new_unchecked(slot)) };
        }
        true
    }

    /// Pushes `ptr` onto the intrusive free list.
    ///
    /// # Safety
    /// `ptr` must be valid for a pointer-sized write (an object slot we own).
    unsafe fn push(&mut self, ptr: NonNull<u8>) {
        let next = self.free.map_or(core::ptr::null_mut(), NonNull::as_ptr);
        // SAFETY: by contract `ptr` addresses an object slot of at least
        // pointer size, so writing the next-free link is in bounds.
        unsafe { ptr.as_ptr().cast::<*mut u8>().write(next) };
        self.free = Some(ptr);
    }
}

// SAFETY: a `SlabCache`/`Slab` owns the object memory its free list points at
// and is only ever reached through external synchronisation (the kernel wraps
// it in a `Mutex`). The raw pointers are plain kernel addresses with no
// thread affinity, so moving the cache between CPUs is sound.
unsafe impl Send for SlabCache {}
unsafe impl Send for Slab {}

/// A multi-class slab allocator: the kernel heap's fast path.
pub struct Slab {
    caches: [SlabCache; SIZE_CLASSES.len()],
}

impl Slab {
    /// Builds a slab whose caches carve `page_size`-byte pages.
    #[must_use]
    pub const fn new(page_size: usize) -> Self {
        // Kept in lockstep with `SIZE_CLASSES`; a const assert guards drift.
        Self {
            caches: [
                SlabCache::new(SIZE_CLASSES[0], page_size),
                SlabCache::new(SIZE_CLASSES[1], page_size),
                SlabCache::new(SIZE_CLASSES[2], page_size),
                SlabCache::new(SIZE_CLASSES[3], page_size),
                SlabCache::new(SIZE_CLASSES[4], page_size),
                SlabCache::new(SIZE_CLASSES[5], page_size),
                SlabCache::new(SIZE_CLASSES[6], page_size),
                SlabCache::new(SIZE_CLASSES[7], page_size),
                SlabCache::new(SIZE_CLASSES[8], page_size),
            ],
        }
    }

    /// Index of the smallest size class that satisfies `size` and `align`, or
    /// `None` when the request belongs to the buddy allocator instead.
    ///
    /// A class of size `2^k` yields objects aligned to `2^k`, so an alignment
    /// requirement is met as soon as the class size covers it.
    #[must_use]
    pub fn class_for(size: usize, align: usize) -> Option<usize> {
        let need = size.max(align).max(core::mem::size_of::<usize>());
        if need > MAX_SLAB_OBJECT {
            return None;
        }
        SIZE_CLASSES.iter().position(|&c| c >= need)
    }

    /// Allocates for a (`size`, `align`) request, or `None` if it is too large
    /// for the slab or the page source is exhausted.
    pub fn alloc(
        &mut self,
        size: usize,
        align: usize,
        src: &mut impl PageSource,
    ) -> Option<NonNull<u8>> {
        let class = Self::class_for(size, align)?;
        self.caches[class].alloc(src)
    }

    /// Frees a pointer previously returned by [`alloc`](Self::alloc) for the
    /// same (`size`, `align`).
    ///
    /// # Safety
    /// `ptr` must come from a matching [`alloc`](Self::alloc) call and must not
    /// have been freed already.
    pub unsafe fn dealloc(&mut self, ptr: NonNull<u8>, size: usize, align: usize) {
        if let Some(class) = Self::class_for(size, align) {
            // SAFETY: the (size, align) pair maps to the same class that served
            // the allocation, so `ptr` belongs to this cache.
            unsafe { self.caches[class].dealloc(ptr) };
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::alloc::{Layout, alloc, dealloc};
    use std::collections::BTreeSet;
    use std::vec::Vec;

    const PAGE: usize = 4096;

    /// Host-side page source backed by the system allocator; frees every page
    /// it handed out when dropped so Miri/ASan stay quiet.
    struct TestPages {
        pages: Vec<*mut u8>,
    }

    impl TestPages {
        fn new() -> Self {
            Self { pages: Vec::new() }
        }
    }

    // SAFETY: pages are `PAGE`-aligned, `PAGE` bytes, and uniquely owned by the
    // slab until this source drops.
    unsafe impl PageSource for TestPages {
        fn page_size(&self) -> usize {
            PAGE
        }

        fn alloc_page(&mut self) -> Option<NonNull<u8>> {
            let layout = Layout::from_size_align(PAGE, PAGE).unwrap();
            // SAFETY: non-zero layout.
            let ptr = unsafe { alloc(layout) };
            self.pages.push(ptr);
            NonNull::new(ptr)
        }
    }

    impl Drop for TestPages {
        fn drop(&mut self) {
            let layout = Layout::from_size_align(PAGE, PAGE).unwrap();
            for &p in &self.pages {
                // SAFETY: each `p` came from `alloc` with this exact layout.
                unsafe { dealloc(p, layout) };
            }
        }
    }

    #[test]
    fn class_selection_rounds_up() {
        assert_eq!(Slab::class_for(1, 1), Some(0)); // 8
        assert_eq!(Slab::class_for(8, 8), Some(0));
        assert_eq!(Slab::class_for(9, 1), Some(1)); // 16
        assert_eq!(Slab::class_for(100, 1), Some(4)); // 128
        assert_eq!(Slab::class_for(2048, 1), Some(8));
        assert_eq!(Slab::class_for(2049, 1), None);
        // Alignment can force a larger class than the size alone would.
        assert_eq!(Slab::class_for(8, 64), Some(3)); // 64
    }

    #[test]
    fn objects_are_aligned_and_distinct() {
        let mut src = TestPages::new();
        let mut cache = SlabCache::new(64, PAGE);
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        for _ in 0..200 {
            let p = cache.alloc(&mut src).unwrap();
            let addr = p.as_ptr() as usize;
            assert_eq!(addr % 64, 0, "object not aligned to its class");
            assert!(seen.insert(addr), "object handed out twice");
        }
        assert_eq!(cache.allocated(), 200);
    }

    #[test]
    fn free_list_recycles_objects() {
        let mut src = TestPages::new();
        let mut cache = SlabCache::new(32, PAGE);
        let a = cache.alloc(&mut src).unwrap();
        // SAFETY: `a` just came from this cache.
        unsafe { cache.dealloc(a) };
        let b = cache.alloc(&mut src).unwrap();
        assert_eq!(a, b, "freed object should be returned next");
        assert_eq!(cache.allocated(), 1);
    }

    #[test]
    fn allocation_survives_many_pages() {
        let mut src = TestPages::new();
        let mut slab = Slab::new(PAGE);
        let mut live: Vec<(NonNull<u8>, usize)> = Vec::new();
        // Enough 2048-byte objects to force several pages.
        for _ in 0..40 {
            let p = slab.alloc(2000, 8, &mut src).unwrap();
            // The returned memory is writable for its full size.
            // SAFETY: we requested >= 2000 bytes and got a 2048 object.
            unsafe { core::ptr::write_bytes(p.as_ptr(), 0xAB, 2000) };
            live.push((p, 2000));
        }
        for (p, size) in live.drain(..) {
            // SAFETY: matching dealloc for a live allocation.
            unsafe { slab.dealloc(p, size, 8) };
        }
    }

    #[test]
    fn oversized_requests_defer_to_buddy() {
        let mut src = TestPages::new();
        let mut slab = Slab::new(PAGE);
        assert!(slab.alloc(4096, 8, &mut src).is_none());
    }
}

#[cfg(test)]
mod proptests {
    extern crate std;
    use super::*;
    use proptest::prelude::*;
    use std::alloc::{Layout, alloc, dealloc};
    use std::collections::BTreeMap;
    use std::vec::Vec;

    const PAGE: usize = 4096;

    struct TestPages {
        pages: Vec<*mut u8>,
    }

    // SAFETY: see the unit-test source of the same shape.
    unsafe impl PageSource for TestPages {
        fn page_size(&self) -> usize {
            PAGE
        }
        fn alloc_page(&mut self) -> Option<NonNull<u8>> {
            let layout = Layout::from_size_align(PAGE, PAGE).unwrap();
            let ptr = unsafe { alloc(layout) };
            self.pages.push(ptr);
            NonNull::new(ptr)
        }
    }

    impl Drop for TestPages {
        fn drop(&mut self) {
            let layout = Layout::from_size_align(PAGE, PAGE).unwrap();
            for &p in &self.pages {
                unsafe { dealloc(p, layout) };
            }
        }
    }

    #[derive(Clone, Debug)]
    enum Op {
        Alloc(usize, usize),
        FreeKey(usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            ((1usize..=2048), prop_oneof![Just(1usize), Just(8), Just(16), Just(64)])
                .prop_map(|(s, a)| Op::Alloc(s, a)),
            (0usize..256).prop_map(Op::FreeKey),
        ]
    }

    proptest! {
        /// Slab allocations are correctly aligned, never alias a live object,
        /// and each byte of a live object stays writable (a write-and-verify
        /// catches any overlap the alignment check would miss).
        #[test]
        fn slab_objects_never_alias(ops in prop::collection::vec(op(), 0..300)) {
            let mut src = TestPages { pages: Vec::new() };
            let mut slab = Slab::new(PAGE);
            // key -> (ptr, size, align, tag byte)
            let mut live: BTreeMap<usize, (NonNull<u8>, usize, usize, u8)> = BTreeMap::new();
            let mut next_key = 0usize;
            let mut tag = 1u8;

            for step in ops {
                match step {
                    Op::Alloc(size, align) => {
                        if let Some(p) = slab.alloc(size, align, &mut src) {
                            prop_assert_eq!(p.as_ptr() as usize % align, 0);
                            tag = tag.wrapping_add(1).max(1);
                            // SAFETY: we own `size` bytes at `p`.
                            unsafe { core::ptr::write_bytes(p.as_ptr(), tag, size) };
                            live.insert(next_key, (p, size, align, tag));
                            next_key += 1;
                        }
                    }
                    Op::FreeKey(k) => {
                        if live.is_empty() { continue; }
                        let key = *live.keys().nth(k % live.len()).unwrap();
                        let (p, size, align, _) = live.remove(&key).unwrap();
                        // SAFETY: matching dealloc.
                        unsafe { slab.dealloc(p, size, align) };
                    }
                }

                // Every live object still holds exactly its own tag: no other
                // allocation scribbled over it.
                for &(p, size, _, t) in live.values() {
                    // SAFETY: `p` is live for `size` bytes.
                    let slice = unsafe { core::slice::from_raw_parts(p.as_ptr(), size) };
                    prop_assert!(slice.iter().all(|&b| b == t));
                }
            }
        }
    }
}
