//! `sched` — the `no_std`, host-testable scheduler core for FluOS.
//!
//! It holds the *policy and data structures* of the kernel scheduler, free of
//! any clock, CPU, or lock, so the tricky parts can be exercised with ordinary
//! `cargo test`:
//!
//! - [`eevdf::Eevdf`] — a per-CPU EEVDF runqueue (weighted fair scheduling with
//!   bounded latency).
//! - [`steal`] — work-stealing balance decisions between per-CPU runqueues.
//! - [`timer::TimerQueue`] — a min-heap timer queue for sleep/wakeup and
//!   timeslice expiry.
//!
//! The kernel wires one [`eevdf::Eevdf`] and one [`timer::TimerQueue`] per CPU
//! and uses [`steal`] when a CPU goes idle.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod eevdf;
pub mod steal;
pub mod timer;

pub use eevdf::{Eevdf, Tid, WEIGHT_REF, weight_from_nice};
pub use timer::{TimerId, TimerQueue};
