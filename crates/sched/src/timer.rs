//! A timer queue backed by a binary min-heap keyed on expiry deadline.
//!
//! The scheduler uses this to drive sleep/wakeup and timeslice expiry: insert a
//! `(deadline, id)` and later ask for everything due at or before `now`. A heap
//! keeps `insert` and `pop` at O(log n) and the earliest deadline at O(1), which
//! is all a tickless timer needs to program the next LAPIC deadline.

use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::Reverse;

/// Identifier for a scheduled timer (usually the sleeping thread's tid).
pub type TimerId = u64;

/// A min-heap of pending timers.
#[derive(Default)]
pub struct TimerQueue {
    // `Reverse` turns the max-heap into a min-heap on the deadline, then id.
    heap: BinaryHeap<Reverse<(u64, TimerId)>>,
}

impl TimerQueue {
    #[must_use]
    pub const fn new() -> Self {
        Self { heap: BinaryHeap::new() }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Schedules `id` to fire at `deadline`.
    pub fn insert(&mut self, deadline: u64, id: TimerId) {
        self.heap.push(Reverse((deadline, id)));
    }

    /// The earliest pending deadline, used to program the next wakeup.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.heap.peek().map(|&Reverse((d, _))| d)
    }

    /// Pops up to `out.len()` timers due at or before `now` (deadline order)
    /// into `out`, returning how many. Allocation-free — safe in IRQ context.
    pub fn expire_into(&mut self, now: u64, out: &mut [TimerId]) -> usize {
        let mut count = 0;
        while count < out.len() {
            match self.heap.peek() {
                Some(&Reverse((deadline, _))) if deadline <= now => {
                    let Reverse((_, id)) = self.heap.pop().expect("peek just succeeded");
                    out[count] = id;
                    count += 1;
                }
                _ => break,
            }
        }
        count
    }

    /// Pops and returns every timer due at or before `now`, in deadline order.
    pub fn expire(&mut self, now: u64) -> Vec<TimerId> {
        let mut fired = Vec::new();
        while let Some(&Reverse((deadline, _))) = self.heap.peek() {
            if deadline > now {
                break;
            }
            let Reverse((_, id)) = self.heap.pop().expect("peek just succeeded");
            fired.push(id);
        }
        fired
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn empty_queue_has_no_deadline() {
        let mut q = TimerQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.next_deadline(), None);
        assert!(q.expire(1000).is_empty());
    }

    #[test]
    fn earliest_deadline_is_reported() {
        let mut q = TimerQueue::new();
        q.insert(50, 1);
        q.insert(10, 2);
        q.insert(30, 3);
        assert_eq!(q.next_deadline(), Some(10));
    }

    #[test]
    fn expire_returns_due_timers_in_order() {
        let mut q = TimerQueue::new();
        q.insert(50, 1);
        q.insert(10, 2);
        q.insert(30, 3);
        q.insert(100, 4);
        assert_eq!(q.expire(40), std::vec![2, 3]);
        assert_eq!(q.len(), 2);
        assert_eq!(q.next_deadline(), Some(50));
        assert_eq!(q.expire(1000), std::vec![1, 4]);
        assert!(q.is_empty());
    }

    #[test]
    fn expire_into_is_bounded_and_ordered() {
        let mut q = TimerQueue::new();
        for (d, id) in [(50, 1), (10, 2), (30, 3), (20, 4)] {
            q.insert(d, id);
        }
        let mut buf = [0u64; 2];
        // Only two slots: the two earliest due timers come out in order.
        assert_eq!(q.expire_into(100, &mut buf), 2);
        assert_eq!(buf, [2, 4]);
        // The rest remain for the next call.
        assert_eq!(q.expire_into(100, &mut buf), 2);
        assert_eq!(buf, [3, 1]);
        assert!(q.is_empty());
    }

    #[test]
    fn same_deadline_breaks_by_id() {
        let mut q = TimerQueue::new();
        q.insert(10, 7);
        q.insert(10, 3);
        assert_eq!(q.expire(10), std::vec![3, 7]);
    }
}
