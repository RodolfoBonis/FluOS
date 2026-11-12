//! Work-stealing balance decisions.
//!
//! When a CPU runs dry it looks for the busiest peer and takes a batch of its
//! tasks. Keeping the policy here — pure functions over per-CPU load counts —
//! lets us test the balancing behaviour without any threads or locks.

use alloc::vec::Vec;

/// Finds the most-loaded CPU other than `thief` that has at least two tasks
/// (so stealing never empties a victim that was about to run something).
#[must_use]
pub fn find_victim(loads: &[usize], thief: usize) -> Option<usize> {
    loads
        .iter()
        .enumerate()
        .filter(|&(cpu, &load)| cpu != thief && load >= 2)
        .max_by_key(|&(_, &load)| load)
        .map(|(cpu, _)| cpu)
}

/// How many tasks to pull from a victim with `victim_load` runnable: half,
/// rounded down, so the two CPUs end up roughly balanced.
#[must_use]
pub fn steal_batch(victim_load: usize) -> usize {
    victim_load / 2
}

/// Full plan for an idle `thief`: `(victim, count)` to steal, or `None` when no
/// peer is worth stealing from.
#[must_use]
pub fn plan_steal(loads: &[usize], thief: usize) -> Option<(usize, usize)> {
    let victim = find_victim(loads, thief)?;
    let count = steal_batch(loads[victim]).max(1);
    Some((victim, count))
}

/// Applies a steal plan to a mutable load vector, returning the number moved.
/// Used by tests to check the policy drives the system toward balance.
pub fn apply_steal(loads: &mut [usize], thief: usize) -> usize {
    match plan_steal(loads, thief) {
        Some((victim, count)) => {
            let count = count.min(loads[victim].saturating_sub(1));
            loads[victim] -= count;
            loads[thief] += count;
            count
        }
        None => 0,
    }
}

/// Convenience: the balancing it would take for every empty CPU to steal once.
#[must_use]
pub fn balance_round(mut loads: Vec<usize>) -> Vec<usize> {
    let n = loads.len();
    for cpu in 0..n {
        if loads[cpu] == 0 {
            apply_steal(&mut loads, cpu);
        }
    }
    loads
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn picks_busiest_peer() {
        let loads = [0, 3, 5, 1];
        assert_eq!(find_victim(&loads, 0), Some(2));
    }

    #[test]
    fn ignores_peers_with_one_task() {
        let loads = [0, 1, 1, 1];
        assert_eq!(find_victim(&loads, 0), None);
    }

    #[test]
    fn steals_half() {
        assert_eq!(steal_batch(6), 3);
        assert_eq!(steal_batch(3), 1);
        assert_eq!(steal_batch(1), 0);
    }

    #[test]
    fn stealing_moves_toward_balance() {
        // One CPU has everything; the rest are idle.
        let mut loads = vec![8, 0, 0, 0];
        // Each idle CPU steals once.
        for cpu in 1..4 {
            apply_steal(&mut loads, cpu);
        }
        let max = *loads.iter().max().unwrap();
        let min = *loads.iter().min().unwrap();
        assert!(max - min <= 4, "still unbalanced: {loads:?}");
        assert_eq!(loads.iter().sum::<usize>(), 8, "tasks conserved");
    }

    #[test]
    fn no_victim_when_peers_have_at_most_one() {
        // Work stealing only fires for an idle thief; if no peer has >= 2 tasks
        // there is nothing to take.
        let loads = [0, 1, 1, 0];
        assert_eq!(plan_steal(&loads, 0), None);
    }

    #[test]
    fn steal_never_empties_a_victim() {
        let mut loads = [0, 2, 0, 0];
        let moved = apply_steal(&mut loads, 0);
        assert_eq!(moved, 1);
        assert_eq!(loads[1], 1, "victim kept at least one task");
    }

    #[test]
    fn repeated_rounds_converge() {
        let mut loads = vec![16, 0, 0, 0];
        for _ in 0..6 {
            loads = balance_round(loads);
        }
        let max = *loads.iter().max().unwrap();
        let min = *loads.iter().min().unwrap();
        assert!(max - min <= 2, "did not converge: {loads:?}");
        assert_eq!(loads.iter().sum::<usize>(), 16);
    }
}
