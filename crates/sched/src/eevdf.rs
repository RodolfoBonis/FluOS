//! An EEVDF (Earliest Eligible Virtual Deadline First) runqueue.
//!
//! Each runnable entity carries a *weight* (derived from its nice level), a
//! *virtual runtime* that advances inversely to its weight as it runs, and a
//! *virtual deadline*. The queue's virtual time `V` is the weight-average of all
//! entities' vruntimes. An entity is **eligible** when its vruntime has not run
//! ahead of `V` (i.e. it has not already consumed more than its fair share); of
//! the eligible entities the scheduler runs the one with the earliest virtual
//! deadline, which bounds latency while keeping service proportional to weight.
//!
//! This is the pure logic only — no clocks, no CPUs — so it is exhaustively
//! host-tested. The kernel instantiates one queue per CPU.

use alloc::vec::Vec;

/// Weight of a nice-0 task; all weights are relative to this.
pub const WEIGHT_REF: u64 = 1024;

/// Base request size (in time units) used to set a task's deadline. Smaller
/// values tighten latency at the cost of more context switches.
pub const BASE_SLICE: u64 = 1024;

/// Fixed-point shift for virtual time. Vruntime increments are
/// `delta * WEIGHT_REF << SCALE_SHIFT / weight`; the shift preserves precision
/// so heavy tasks (large weight) still advance instead of truncating to zero.
const SCALE_SHIFT: u32 = 20;

/// Maximum lag (in fixed-point vruntime units) a joining task may carry, so a
/// long-sleeping, newly-woken, or migrated task cannot accrue unbounded credit
/// (or debt) relative to the queue's virtual time (H4). About eight reference
/// slices.
const MAX_LAG: u128 = (BASE_SLICE as u128) << (SCALE_SHIFT + 3);

/// Thread identifier the scheduler keys on.
pub type Tid = u64;

/// Linux's `sched_prio_to_weight` table for nice levels -20..=19.
const NICE_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, // -20..-16
    29154, 23254, 18705, 14949, 11916, // -15..-11
    9548, 7620, 6100, 4904, 3906, // -10..-6
    3121, 2501, 1991, 1586, 1277, // -5..-1
    1024, 820, 655, 526, 423, // 0..4
    335, 272, 215, 172, 137, // 5..9
    110, 87, 70, 56, 45, // 10..14
    36, 29, 23, 18, 15, // 15..19
];

/// Maps a nice value (-20..=19) to its scheduling weight.
#[must_use]
pub fn weight_from_nice(nice: i8) -> u64 {
    let idx = (nice.clamp(-20, 19) as i32 + 20) as usize;
    NICE_TO_WEIGHT[idx]
}

#[derive(Clone, Copy, Debug)]
struct Entity {
    tid: Tid,
    weight: u64,
    /// Virtual runtime in fixed-point units (see [`SCALE_SHIFT`]).
    vruntime: u128,
    /// Virtual deadline of the current request, same units as `vruntime`.
    deadline: u128,
}

impl Entity {
    /// Recomputes the virtual deadline for a fresh request: one base slice of
    /// virtual time ahead, scaled inversely to weight.
    fn renew_deadline(&mut self) {
        let request =
            ((u128::from(BASE_SLICE) * u128::from(WEIGHT_REF)) << SCALE_SHIFT) / u128::from(self.weight);
        self.deadline = self.vruntime + request;
    }
}

/// A single-CPU EEVDF runqueue.
#[derive(Default)]
pub struct Eevdf {
    entities: Vec<Entity>,
}

impl Eevdf {
    #[must_use]
    pub const fn new() -> Self {
        Self { entities: Vec::new() }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// Reserves capacity for `n` runnable entities so the common enqueue path
    /// (used from the timer IRQ) does not allocate.
    pub fn reserve(&mut self, n: usize) {
        self.entities.reserve(n);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    #[must_use]
    pub fn contains(&self, tid: Tid) -> bool {
        self.entities.iter().any(|e| e.tid == tid)
    }

    /// Virtual time `V`: the weight-average of all vruntimes (0 when empty).
    #[must_use]
    pub fn avg_vruntime(&self) -> u128 {
        let mut num: u128 = 0;
        let mut den: u128 = 0;
        for e in &self.entities {
            num += u128::from(e.weight) * e.vruntime;
            den += u128::from(e.weight);
        }
        if den == 0 { 0 } else { num / den }
    }

    /// Adds a task with the given weight. It joins at the current virtual time
    /// so it is immediately eligible without an unfair head start.
    pub fn insert(&mut self, tid: Tid, weight: u64) {
        debug_assert!(weight > 0, "weight must be positive");
        debug_assert!(!self.contains(tid), "tid already queued");
        let vruntime = self.avg_vruntime();
        let mut e = Entity { tid, weight, vruntime, deadline: 0 };
        e.renew_deadline();
        self.entities.push(e);
    }

    /// Adds a task carrying an explicit vruntime, used when the kernel removes a
    /// thread to run it (claiming it out of the queue) and later re-inserts it
    /// with the virtual time it accumulated while running, preserving fairness.
    pub fn insert_with(&mut self, tid: Tid, weight: u64, vruntime: u128) {
        debug_assert!(weight > 0, "weight must be positive");
        debug_assert!(!self.contains(tid), "tid already queued");
        let mut e = Entity { tid, weight, vruntime, deadline: 0 };
        e.renew_deadline();
        self.entities.push(e);
    }

    /// Adds a brand-new task placed at the queue's current virtual time `V`
    /// (zero lag), so it neither monopolises the CPU nor starves (H4).
    pub fn insert_at_v(&mut self, tid: Tid, weight: u64) {
        let v = self.avg_vruntime();
        self.insert_with(tid, weight, v);
    }

    /// Adds a returning task (woken from sleep, migrated, or re-queued after
    /// running) at its carried vruntime, clamped to `V ± MAX_LAG` so stale or
    /// foreign time bases cannot grant unbounded credit/debt (H4).
    pub fn insert_clamped(&mut self, tid: Tid, weight: u64, carried_vruntime: u128) {
        let v = self.avg_vruntime();
        let lo = v.saturating_sub(MAX_LAG);
        let hi = v.saturating_add(MAX_LAG);
        let placed = carried_vruntime.clamp(lo, hi);
        self.insert_with(tid, weight, placed);
    }

    /// Converts a real-time `delta` into the virtual-time it advances a task of
    /// `weight`, so the kernel can age a running (out-of-queue) thread the same
    /// way [`charge`](Self::charge) ages an in-queue one.
    #[must_use]
    pub fn vdelta(weight: u64, delta: u64) -> u128 {
        ((u128::from(delta) * u128::from(WEIGHT_REF)) << SCALE_SHIFT) / u128::from(weight)
    }

    /// Removes a task, returning `true` if it was queued.    /// Removes a task, returning `true` if it was queued.
    pub fn remove(&mut self, tid: Tid) -> bool {
        if let Some(i) = self.entities.iter().position(|e| e.tid == tid) {
            self.entities.swap_remove(i);
            true
        } else {
            false
        }
    }

    /// Picks the task to run next: the eligible entity with the earliest
    /// virtual deadline. Ties break by vruntime then tid for determinism.
    #[must_use]
    pub fn pick(&self) -> Option<Tid> {
        if self.entities.is_empty() {
            return None;
        }
        let v = self.avg_vruntime();

        let eligible = self.entities.iter().filter(|e| e.vruntime <= v);
        let best = eligible
            .min_by_key(|e| (e.deadline, e.vruntime, e.tid))
            // Integer rounding of `V` can (rarely) leave nobody eligible; fall
            // back to the globally earliest deadline so we always make progress.
            .or_else(|| self.entities.iter().min_by_key(|e| (e.deadline, e.vruntime, e.tid)));
        best.map(|e| e.tid)
    }

    /// Charges `delta` units of real runtime to `tid`, advancing its vruntime
    /// inversely to its weight and renewing its deadline.
    pub fn charge(&mut self, tid: Tid, delta: u64) {
        if let Some(e) = self.entities.iter_mut().find(|e| e.tid == tid) {
            let inc = ((u128::from(delta) * u128::from(WEIGHT_REF)) << SCALE_SHIFT) / u128::from(e.weight);
            e.vruntime += inc;
            e.renew_deadline();
        }
    }

    /// Detaches the task with the smallest fair share (lowest vruntime) for
    /// migration to another CPU. Used by work stealing so the victim keeps its
    /// most-serviced tasks and gives away the least-serviced.
    pub fn steal_one(&mut self) -> Option<(Tid, u64)> {
        let i = self
            .entities
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| (e.vruntime, e.tid))
            .map(|(i, _)| i)?;
        let e = self.entities.swap_remove(i);
        Some((e.tid, e.weight))
    }

    /// Current tids, for tests and diagnostics.
    #[must_use]
    pub fn tids(&self) -> Vec<Tid> {
        self.entities.iter().map(|e| e.tid).collect()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;

    /// Runs the queue for `rounds`, charging a fixed quantum each pick, and
    /// returns per-task accumulated service.
    fn simulate(weights: &[(Tid, u64)], rounds: usize, quantum: u64) -> BTreeMap<Tid, u64> {
        let mut q = Eevdf::new();
        for &(tid, w) in weights {
            q.insert(tid, w);
        }
        let mut service: BTreeMap<Tid, u64> = BTreeMap::new();
        for _ in 0..rounds {
            let tid = q.pick().expect("non-empty queue");
            *service.entry(tid).or_default() += quantum;
            q.charge(tid, quantum);
        }
        service
    }

    #[test]
    fn single_task_always_runs() {
        let mut q = Eevdf::new();
        q.insert(1, WEIGHT_REF);
        for _ in 0..100 {
            assert_eq!(q.pick(), Some(1));
            q.charge(1, 100);
        }
    }

    #[test]
    fn equal_weights_share_evenly() {
        let service = simulate(&[(1, WEIGHT_REF), (2, WEIGHT_REF), (3, WEIGHT_REF)], 9000, 100);
        let vals: Vec<u64> = service.values().copied().collect();
        let max = *vals.iter().max().unwrap();
        let min = *vals.iter().min().unwrap();
        // All three within 5% of each other.
        assert!((max - min) * 20 <= max, "unfair: {service:?}");
    }

    #[test]
    fn service_is_proportional_to_weight() {
        // Weights 1:2:4 should yield service ~1:2:4.
        let service = simulate(
            &[(1, WEIGHT_REF), (2, 2 * WEIGHT_REF), (3, 4 * WEIGHT_REF)],
            70_000,
            10,
        );
        let s1 = service[&1] as f64;
        let s2 = service[&2] as f64;
        let s3 = service[&3] as f64;
        assert!((s2 / s1 - 2.0).abs() < 0.15, "s2/s1 = {}", s2 / s1);
        assert!((s3 / s1 - 4.0).abs() < 0.3, "s3/s1 = {}", s3 / s1);
    }

    #[test]
    fn no_task_starves() {
        let service = simulate(&[(1, WEIGHT_REF), (2, 16 * WEIGHT_REF)], 10_000, 10);
        // Even the light task gets a meaningful slice of the CPU.
        assert!(service[&1] > 0, "light task starved");
    }

    #[test]
    fn insert_and_remove_track_membership() {
        let mut q = Eevdf::new();
        q.insert(5, WEIGHT_REF);
        q.insert(6, WEIGHT_REF);
        assert!(q.contains(5) && q.contains(6));
        assert_eq!(q.len(), 2);
        assert!(q.remove(5));
        assert!(!q.contains(5));
        assert!(!q.remove(5));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn steal_takes_least_serviced_task() {
        let mut q = Eevdf::new();
        q.insert(1, WEIGHT_REF);
        q.insert(2, WEIGHT_REF);
        // Advance task 1 a lot; task 2 (lower vruntime) should be stolen.
        q.charge(1, 10_000);
        let (tid, _) = q.steal_one().unwrap();
        assert_eq!(tid, 2);
    }

    #[test]
    fn new_task_joins_at_virtual_time() {
        // Task 1 runs alone for a while, pushing V up. A newcomer placed at V
        // must then SHARE fairly going forward — not monopolise (which placing
        // it at vruntime 0 would cause) nor be starved.
        let mut q = Eevdf::new();
        q.insert(1, WEIGHT_REF);
        for _ in 0..100 {
            q.charge(1, 1000);
        }
        q.insert_at_v(2, WEIGHT_REF);

        let mut s1 = 0u64;
        let mut s2 = 0u64;
        for _ in 0..4000 {
            let t = q.pick().unwrap();
            if t == 1 {
                s1 += 100;
            } else {
                s2 += 100;
            }
            q.charge(t, 100);
        }
        // Equal weights from a common V => roughly equal service.
        let (hi, lo) = (s1.max(s2), s1.min(s2));
        assert!(lo > 0 && (hi - lo) * 5 <= hi, "unfair after join: s1={s1} s2={s2}");
    }

    #[test]
    fn migrated_task_is_lag_clamped() {
        // A queue whose V is high (everyone has run a lot).
        let mut q = Eevdf::new();
        q.insert(1, WEIGHT_REF);
        q.insert(2, WEIGHT_REF);
        for _ in 0..500 {
            q.charge(1, 1000);
            q.charge(2, 1000);
        }
        let v = q.avg_vruntime();
        // Migrate in a task whose foreign vruntime is 0 (far behind): it would
        // otherwise monopolise. Clamped placement keeps it within MAX_LAG of V.
        q.insert_clamped(99, WEIGHT_REF, 0);
        // It is eligible but bounded: it cannot run forever. Simulate and check
        // the established tasks still get serviced.
        let mut got_99 = 0;
        let mut got_other = 0;
        for _ in 0..2000 {
            let t = q.pick().unwrap();
            if t == 99 {
                got_99 += 1;
            } else {
                got_other += 1;
            }
            q.charge(t, 100);
        }
        let _ = v;
        assert!(got_99 > 0, "migrated task never ran");
        assert!(got_other > 0, "migrated task starved the others");
    }

    #[test]
    fn nice_weights_match_linux_table() {
        assert_eq!(weight_from_nice(0), 1024);
        assert_eq!(weight_from_nice(-20), 88761);
        assert_eq!(weight_from_nice(19), 15);
        // Out-of-range clamps.
        assert_eq!(weight_from_nice(-50), 88761);
        assert_eq!(weight_from_nice(50), 15);
    }
}
