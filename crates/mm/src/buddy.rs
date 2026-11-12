//! A binary buddy allocator over an abstract range of fixed-size frames.
//!
//! This is *pure logic*: it manipulates frame **indices** only and never
//! dereferences frame memory, so the whole allocator is unit- and
//! property-testable on the host with no hardware. All bookkeeping lives in
//! caller-provided metadata slices, which lets the kernel place that metadata
//! wherever convenient (for example, stolen from the first usable region
//! during early boot before the heap exists).
//!
//! The allocator works in orders: an order-`k` block spans `2^k` contiguous
//! frames and is aligned to `2^k`. Freeing a block merges it with its buddy
//! when the buddy is also free and of the same order, keeping fragmentation
//! low. Per-CPU frame caches (added in a later milestone) are expected to sit
//! *on top* of this global allocator, refilling from it in batches.

/// Sentinel for "no frame" in the intrusive free lists.
const NIL: u32 = u32::MAX;

/// Marks a frame that is not the head of a free block (allocated, or interior
/// to a larger block). No valid block order ever equals this.
const NOT_FREE_HEAD: u8 = u8::MAX;

/// Hard cap on the number of distinct orders. Order 31 already spans 2^31
/// frames (8 TiB at 4 KiB), far beyond any region we manage.
pub const MAX_ORDERS: usize = 32;

/// Per-frame bookkeeping slot for the allocator's intrusive free lists.
///
/// Callers allocate one slot per frame (see [`Buddy::new`]) but treat it as
/// opaque: build the backing storage with [`Node::EMPTY`] and let the
/// allocator own the contents.
#[derive(Clone, Copy)]
pub struct Node {
    next: u32,
    prev: u32,
}

impl Node {
    /// An unlinked slot, suitable for initialising the metadata array.
    pub const EMPTY: Self = Self { next: NIL, prev: NIL };
}

impl Default for Node {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Buddy allocator bound to externally-owned metadata slices.
///
/// Invariants maintained across every public call:
/// - a free block's head frame `i` has `order[i]` equal to its order and is
///   threaded into `heads[order[i]]`;
/// - every other frame has `order[i] == NOT_FREE_HEAD`;
/// - all free blocks are aligned to their order and lie fully within range.
pub struct Buddy<'a> {
    base_frame: usize,
    frames: usize,
    max_order: usize,
    nodes: &'a mut [Node],
    order: &'a mut [u8],
    heads: [u32; MAX_ORDERS],
    free_frames: usize,
}

impl<'a> Buddy<'a> {
    /// Metadata byte budget for a region of `frames` frames: one [`Node`]
    /// (8 bytes) and one order byte per frame. Callers sizing a static or
    /// stolen metadata arena use this to reserve storage up front.
    #[must_use]
    pub const fn metadata_bytes(frames: usize) -> usize {
        frames * (core::mem::size_of::<Node>() + 1)
    }

    /// Builds an allocator managing `frames` frames starting at `base_frame`.
    ///
    /// `nodes` and `order` must each have length `frames`. `max_order` bounds
    /// the largest block the allocator will coalesce into; it is clamped to a
    /// value that fits both the region and [`MAX_ORDERS`].
    ///
    /// Returns `None` if the slices are too short or the region is empty.
    pub fn new(
        base_frame: usize,
        frames: usize,
        max_order: usize,
        nodes: &'a mut [Node],
        order: &'a mut [u8],
    ) -> Option<Self> {
        let mut this = Self::new_empty(base_frame, frames, max_order, nodes, order)?;
        this.populate();
        Some(this)
    }

    /// Builds an allocator with *no* free frames: every frame starts allocated.
    ///
    /// Use this when the free regions are not contiguous (the kernel's real
    /// memory map has holes): construct empty, then hand each usable run to
    /// [`add_frames`](Self::add_frames). Slice-length and `max_order` rules
    /// match [`new`](Self::new).
    pub fn new_empty(
        base_frame: usize,
        frames: usize,
        max_order: usize,
        nodes: &'a mut [Node],
        order: &'a mut [u8],
    ) -> Option<Self> {
        if frames == 0 || nodes.len() < frames || order.len() < frames {
            return None;
        }
        // Clamp max_order so 2^max_order fits in a usize block count and the
        // order byte, and so the sentinel orders stay distinct.
        let max_order = max_order.min(MAX_ORDERS - 1).min(usize::BITS as usize - 2);

        for slot in order.iter_mut().take(frames) {
            *slot = NOT_FREE_HEAD;
        }

        Some(Self {
            base_frame,
            frames,
            max_order,
            nodes,
            order,
            heads: [NIL; MAX_ORDERS],
            free_frames: 0,
        })
    }

    /// Releases a contiguous run of `count` frames starting at `start_frame`
    /// into the free pool, decomposing it into naturally-aligned blocks and
    /// coalescing across already-free neighbours. The run must lie within the
    /// managed region and not overlap frames that are already free.
    pub fn add_frames(&mut self, start_frame: usize, count: usize) {
        let mut rel = start_frame
            .checked_sub(self.base_frame)
            .expect("region below allocator base");
        let end = rel + count;
        assert!(end <= self.frames, "region extends past allocator range");

        while rel < end {
            // Largest aligned power-of-two block that starts at `rel` and fits
            // in the remaining run (bounded by `max_order`).
            let mut k = self.max_order;
            loop {
                let size = 1usize << k;
                if k == 0 || (size <= end - rel && rel % size == 0) {
                    break;
                }
                k -= 1;
            }
            self.free_order(self.base_frame + rel, k);
            rel += 1usize << k;
        }
    }

    /// Greedily seeds the free lists with the largest aligned blocks that tile
    /// the region. Handles regions whose size is not a power of two.
    fn populate(&mut self) {
        let mut i = 0usize;
        while i < self.frames {
            let mut k = self.max_order;
            loop {
                let size = 1usize << k;
                if k == 0 || (size <= self.frames - i && i % size == 0) {
                    break;
                }
                k -= 1;
            }
            self.insert(i as u32, k as u8);
            self.free_frames += 1usize << k;
            i += 1usize << k;
        }
    }

    /// Total frames under management.
    #[must_use]
    pub fn total_frames(&self) -> usize {
        self.frames
    }

    /// Frames currently free (sum over all free blocks).
    #[must_use]
    pub fn free_frames(&self) -> usize {
        self.free_frames
    }

    /// Smallest order holding at least `count` frames.
    #[must_use]
    pub fn order_for(count: usize) -> usize {
        if count <= 1 {
            0
        } else {
            (usize::BITS - (count - 1).leading_zeros()) as usize
        }
    }

    /// Allocates an aligned block of `2^order` frames, returning its first
    /// frame number, or `None` when no block of that size can be formed.
    pub fn alloc_order(&mut self, order: usize) -> Option<usize> {
        if order > self.max_order {
            return None;
        }
        // Find the smallest available order >= the request.
        let mut j = order;
        while j <= self.max_order && self.heads[j] == NIL {
            j += 1;
        }
        if j > self.max_order {
            return None;
        }

        let block = self.pop(j);
        // Split down to the requested order, freeing the upper buddy each step.
        while j > order {
            j -= 1;
            let buddy = block + (1u32 << j);
            self.insert(buddy, j as u8);
        }
        self.order[block as usize] = NOT_FREE_HEAD;
        self.free_frames -= 1usize << order;
        Some(self.base_frame + block as usize)
    }

    /// Allocates at least `count` contiguous frames (rounded up to a power of
    /// two), returning the first frame number.
    pub fn alloc_frames(&mut self, count: usize) -> Option<usize> {
        self.alloc_order(Self::order_for(count))
    }

    /// Frees a block previously returned by [`alloc_order`](Self::alloc_order)
    /// with the same `order`. Coalesces with buddies where possible.
    ///
    /// # Panics
    /// Panics on obvious misuse (out-of-range frame, misaligned frame, or
    /// double free of a block that is already a free head), which indicates a
    /// kernel bug rather than a recoverable condition.
    pub fn free_order(&mut self, frame: usize, order: usize) {
        assert!(order <= self.max_order, "order {order} exceeds max");
        assert!(frame >= self.base_frame, "frame {frame} below region base");
        let mut idx = (frame - self.base_frame) as u32;
        assert!((idx as usize) < self.frames, "frame {frame} above region");
        assert!(
            idx % (1u32 << order) == 0,
            "frame {frame} not aligned to order {order}"
        );
        assert!(
            self.order[idx as usize] == NOT_FREE_HEAD,
            "double free at frame {frame}"
        );

        self.free_frames += 1usize << order;

        let mut k = order;
        while k < self.max_order {
            let buddy = idx ^ (1u32 << k);
            // The buddy block must lie fully within range and be free at the
            // same order for a merge to be legal.
            if (buddy as usize) + (1usize << k) > self.frames {
                break;
            }
            if self.order[buddy as usize] != k as u8 {
                break;
            }
            self.remove(buddy, k as u8);
            idx = idx.min(buddy);
            k += 1;
        }
        self.insert(idx, k as u8);
    }

    /// Frees a block allocated via [`alloc_frames`](Self::alloc_frames) with
    /// the same `count`.
    pub fn free_frames_at(&mut self, frame: usize, count: usize) {
        self.free_order(frame, Self::order_for(count));
    }

    // --- intrusive free-list plumbing -------------------------------------

    /// Links `idx` as a new free head of `order` at the front of its list.
    fn insert(&mut self, idx: u32, order: u8) {
        let head = self.heads[order as usize];
        self.nodes[idx as usize] = Node { next: head, prev: NIL };
        if head != NIL {
            self.nodes[head as usize].prev = idx;
        }
        self.heads[order as usize] = idx;
        self.order[idx as usize] = order;
    }

    /// Unlinks the free head `idx` of `order` from its list.
    fn remove(&mut self, idx: u32, order: u8) {
        let Node { next, prev } = self.nodes[idx as usize];
        if prev != NIL {
            self.nodes[prev as usize].next = next;
        } else {
            self.heads[order as usize] = next;
        }
        if next != NIL {
            self.nodes[next as usize].prev = prev;
        }
        self.order[idx as usize] = NOT_FREE_HEAD;
    }

    /// Pops the first free block of `order`, returning its head index.
    /// Caller must have checked the list is non-empty.
    fn pop(&mut self, order: usize) -> u32 {
        let idx = self.heads[order];
        debug_assert!(idx != NIL, "pop on empty order {order}");
        self.remove(idx, order as u8);
        idx
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Owns the metadata slices so tests can build a [`Buddy`] in one line.
    struct Arena {
        nodes: Vec<Node>,
        order: Vec<u8>,
    }

    impl Arena {
        fn new(frames: usize) -> Self {
            Self {
                nodes: vec![Node { next: NIL, prev: NIL }; frames],
                order: vec![0u8; frames],
            }
        }

        fn buddy(&mut self, base: usize, frames: usize, max_order: usize) -> Buddy<'_> {
            Buddy::new(base, frames, max_order, &mut self.nodes, &mut self.order).unwrap()
        }
    }

    #[test]
    fn order_for_rounds_up_to_power_of_two() {
        assert_eq!(Buddy::order_for(0), 0);
        assert_eq!(Buddy::order_for(1), 0);
        assert_eq!(Buddy::order_for(2), 1);
        assert_eq!(Buddy::order_for(3), 2);
        assert_eq!(Buddy::order_for(4), 2);
        assert_eq!(Buddy::order_for(5), 3);
        assert_eq!(Buddy::order_for(1024), 10);
    }

    #[test]
    fn full_region_is_free_initially() {
        let mut arena = Arena::new(1024);
        let b = arena.buddy(0, 1024, 10);
        assert_eq!(b.free_frames(), 1024);
        assert_eq!(b.total_frames(), 1024);
    }

    #[test]
    fn alloc_then_free_restores_all_frames() {
        let mut arena = Arena::new(1024);
        let mut b = arena.buddy(0, 1024, 10);
        let a = b.alloc_order(0).unwrap();
        assert_eq!(b.free_frames(), 1023);
        b.free_order(a, 0);
        assert_eq!(b.free_frames(), 1024);
        // The region fully coalesced back to a single top-order block.
        assert_eq!(b.alloc_order(10), Some(0));
    }

    #[test]
    fn allocations_do_not_overlap() {
        let mut arena = Arena::new(64);
        let mut b = arena.buddy(0, 64, 6);
        let mut spans: Vec<(usize, usize)> = Vec::new();
        // Carve the whole region into order-2 (4-frame) blocks.
        while let Some(f) = b.alloc_order(2) {
            spans.push((f, f + 4));
        }
        assert_eq!(spans.len(), 16);
        spans.sort_unstable();
        for pair in spans.windows(2) {
            assert!(pair[0].1 <= pair[1].0, "overlap: {:?} {:?}", pair[0], pair[1]);
        }
        assert_eq!(b.free_frames(), 0);
    }

    #[test]
    fn base_frame_offset_is_respected() {
        let mut arena = Arena::new(16);
        let mut b = arena.buddy(1000, 16, 4);
        let f = b.alloc_order(1).unwrap();
        assert!((1000..1016).contains(&f));
        b.free_order(f, 1);
        assert_eq!(b.free_frames(), 16);
    }

    #[test]
    fn non_power_of_two_region_tiles_exactly() {
        // 100 frames = 64 + 32 + 4.
        let mut arena = Arena::new(100);
        let b = arena.buddy(0, 100, 10);
        assert_eq!(b.free_frames(), 100);
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut arena = Arena::new(8);
        let mut b = arena.buddy(0, 8, 3);
        assert!(b.alloc_order(3).is_some());
        assert!(b.alloc_order(0).is_none());
    }

    #[test]
    fn empty_then_add_frames_matches_full_region() {
        // Build empty and hand it two disjoint runs with a hole between them.
        let mut arena = Arena::new(64);
        let mut b =
            Buddy::new_empty(0, 64, 6, &mut arena.nodes, &mut arena.order).unwrap();
        assert_eq!(b.free_frames(), 0);
        b.add_frames(0, 16);
        b.add_frames(32, 16); // leaves [16,32) permanently reserved
        assert_eq!(b.free_frames(), 32);
        // The reserved hole means no order-6 (64-frame) block can ever form.
        assert!(b.alloc_order(6).is_none());
        // Each run coalesced into a 16-frame (order-4) block; the free list is
        // LIFO, so the most recently added run comes back first.
        let got = b.alloc_order(4).unwrap();
        assert!(got == 0 || got == 32, "unexpected block {got}");
    }

    #[test]
    fn add_adjacent_runs_coalesce() {
        let mut arena = Arena::new(64);
        let mut b =
            Buddy::new_empty(0, 64, 6, &mut arena.nodes, &mut arena.order).unwrap();
        b.add_frames(0, 32);
        b.add_frames(32, 32);
        assert_eq!(b.free_frames(), 64);
        // Fully contiguous: the whole region coalesces into one order-6 block.
        assert_eq!(b.alloc_order(6), Some(0));
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_panics() {
        let mut arena = Arena::new(16);
        let mut b = arena.buddy(0, 16, 4);
        let f = b.alloc_order(0).unwrap();
        b.free_order(f, 0);
        b.free_order(f, 0);
    }
}

#[cfg(test)]
mod proptests {
    extern crate std;
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::vec;
    use std::vec::Vec;

    #[derive(Clone, Debug)]
    enum Op {
        Alloc(usize),
        FreeNth(usize),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0usize..=4).prop_map(Op::Alloc),
            (0usize..64).prop_map(Op::FreeNth),
        ]
    }

    proptest! {
        /// Model-based test: a reference set tracks every live allocation. The
        /// allocator must never hand out overlapping blocks, must conserve the
        /// total frame count, and must fully coalesce once everything is freed.
        #[test]
        fn buddy_never_overlaps_and_conserves(ops in prop::collection::vec(op_strategy(), 0..400)) {
            const FRAMES: usize = 256;
            const MAX_ORDER: usize = 8;
            let mut nodes = vec![Node { next: NIL, prev: NIL }; FRAMES];
            let mut order = vec![0u8; FRAMES];
            let mut b = Buddy::new(0, FRAMES, MAX_ORDER, &mut nodes, &mut order).unwrap();

            // Live allocations as (start, order).
            let mut live: Vec<(usize, usize)> = Vec::new();

            for op in ops {
                match op {
                    Op::Alloc(ord) => {
                        if let Some(start) = b.alloc_order(ord) {
                            // No overlap with any existing live allocation.
                            let end = start + (1 << ord);
                            for &(s, o) in &live {
                                let e = s + (1 << o);
                                prop_assert!(end <= s || e <= start,
                                    "overlap {:?} vs {:?}", (start, ord), (s, o));
                            }
                            live.push((start, ord));
                        }
                    }
                    Op::FreeNth(n) => {
                        if !live.is_empty() {
                            let i = n % live.len();
                            let (start, ord) = live.swap_remove(i);
                            b.free_order(start, ord);
                        }
                    }
                }

                // Conservation: free + allocated == total, at all times.
                let allocated: usize = live.iter().map(|&(_, o)| 1usize << o).sum();
                prop_assert_eq!(b.free_frames() + allocated, FRAMES);
            }

            // Drain and expect full coalescing back to the initial state.
            for (start, ord) in live.drain(..) {
                b.free_order(start, ord);
            }
            prop_assert_eq!(b.free_frames(), FRAMES);
            prop_assert_eq!(b.alloc_order(MAX_ORDER), Some(0));
        }

        /// Every frame handed out is within range and distinct.
        #[test]
        fn alloc_frames_are_in_range(reqs in prop::collection::vec(1usize..=16, 0..80)) {
            const FRAMES: usize = 128;
            let mut nodes = vec![Node { next: NIL, prev: NIL }; FRAMES];
            let mut order = vec![0u8; FRAMES];
            let mut b = Buddy::new(0, FRAMES, 7, &mut nodes, &mut order).unwrap();

            let mut seen: BTreeSet<usize> = BTreeSet::new();
            for count in reqs {
                if let Some(start) = b.alloc_frames(count) {
                    let n = 1usize << Buddy::order_for(count);
                    for f in start..start + n {
                        prop_assert!(f < FRAMES);
                        prop_assert!(seen.insert(f), "frame {} handed out twice", f);
                    }
                }
            }
        }
    }
}
