//! Per-frame reference counts for copy-on-write sharing and reclamation.
//!
//! A physical frame used by user memory can be shared by several address spaces
//! (a `fork` leaves parent and child pointing at the same frames until one
//! writes). To know when a frame may actually be returned to the buddy
//! allocator, each frame carries a reference count: [`incref`] when a new owner
//! starts sharing it, [`decref`] when one drops it. `decref` reports when the
//! count reaches zero so the caller frees the frame exactly once — never while a
//! peer still maps it (which would be a use-after-free once the frame is reused).
//!
//! This is the *pure logic* over a caller-provided counter slice, so it is
//! exercised on the host; the kernel backs it with a table sized to physical RAM.

use core::sync::atomic::{AtomicU16, Ordering};

/// A fixed table of per-frame reference counts, indexed by frame number.
pub struct RefCounts<'a> {
    counts: &'a [AtomicU16],
}

/// Saturating ceiling: a frame shared this many times stops counting up and is
/// then treated as permanently referenced (never auto-freed). With 4 KiB frames
/// this bound is far beyond any real sharing fan-out.
pub const REF_MAX: u16 = u16::MAX;

impl<'a> RefCounts<'a> {
    /// Wraps a counter slice (one entry per frame), all assumed zero initially.
    #[must_use]
    pub fn new(counts: &'a [AtomicU16]) -> Self {
        Self { counts }
    }

    /// Number of frames this table covers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// The current count for `frame` (0 if out of range).
    #[must_use]
    pub fn get(&self, frame: usize) -> u16 {
        self.counts.get(frame).map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Sets `frame`'s count to exactly `n` (used when a fresh frame is allocated,
    /// typically `set(frame, 1)`). Out-of-range frames are ignored.
    pub fn set(&self, frame: usize, n: u16) {
        if let Some(c) = self.counts.get(frame) {
            c.store(n, Ordering::Relaxed);
        }
    }

    /// Adds a reference to `frame` (another owner began sharing it). Saturates at
    /// [`REF_MAX`]. Out-of-range frames are ignored.
    pub fn incref(&self, frame: usize) {
        if let Some(c) = self.counts.get(frame) {
            // Saturating increment under contention.
            let mut cur = c.load(Ordering::Relaxed);
            loop {
                if cur >= REF_MAX {
                    return;
                }
                match c.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                    Ok(_) => return,
                    Err(actual) => cur = actual,
                }
            }
        }
    }

    /// Drops a reference to `frame`. Returns `true` if the count reached zero and
    /// the caller must now free the frame. A frame pinned at [`REF_MAX`] is never
    /// freed (returns `false`). Dropping a zero/out-of-range frame returns
    /// `false` (nothing to free — a double free is refused rather than acted on).
    #[must_use]
    pub fn decref(&self, frame: usize) -> bool {
        let Some(c) = self.counts.get(frame) else {
            return false;
        };
        let mut cur = c.load(Ordering::Relaxed);
        loop {
            if cur == 0 || cur >= REF_MAX {
                return false; // never-counted or pinned: do not free here
            }
            match c.compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return cur - 1 == 0,
                Err(actual) => cur = actual,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    fn table(n: usize) -> Vec<AtomicU16> {
        (0..n).map(|_| AtomicU16::new(0)).collect()
    }

    #[test]
    fn alloc_then_free_once() {
        let t = table(4);
        let rc = RefCounts::new(&t);
        rc.set(2, 1);
        assert_eq!(rc.get(2), 1);
        assert!(rc.decref(2), "last reference should free");
        assert_eq!(rc.get(2), 0);
    }

    #[test]
    fn shared_frame_frees_on_last_drop() {
        let t = table(8);
        let rc = RefCounts::new(&t);
        rc.set(5, 1); // allocated by the parent
        rc.incref(5); // fork: child now shares it (count 2)
        assert_eq!(rc.get(5), 2);
        assert!(!rc.decref(5), "one owner left; not freed");
        assert!(rc.decref(5), "last owner drops; free now");
    }

    #[test]
    fn decref_zero_is_refused() {
        let t = table(4);
        let rc = RefCounts::new(&t);
        assert!(!rc.decref(1), "never-counted frame must not report a free");
        assert_eq!(rc.get(1), 0);
    }

    #[test]
    fn out_of_range_is_ignored() {
        let t = table(2);
        let rc = RefCounts::new(&t);
        rc.set(99, 1);
        rc.incref(99);
        assert!(!rc.decref(99));
        assert_eq!(rc.get(99), 0);
    }

    #[test]
    fn pinned_frame_never_freed() {
        let t = table(2);
        let rc = RefCounts::new(&t);
        rc.set(0, REF_MAX);
        rc.incref(0); // saturates, stays pinned
        assert_eq!(rc.get(0), REF_MAX);
        assert!(!rc.decref(0), "pinned frame is never auto-freed");
        assert_eq!(rc.get(0), REF_MAX);
    }

    #[test]
    fn many_shares_then_drops() {
        let t = table(4);
        let rc = RefCounts::new(&t);
        rc.set(3, 1);
        for _ in 0..9 {
            rc.incref(3);
        }
        assert_eq!(rc.get(3), 10);
        for _ in 0..9 {
            assert!(!rc.decref(3));
        }
        assert!(rc.decref(3), "final drop frees");
    }
}
