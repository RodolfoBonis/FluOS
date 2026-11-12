//! `mm` — portable, host-testable memory-management primitives for FluOS.
//!
//! This crate holds the *pure logic* of the kernel's physical and heap
//! allocators so it can be exercised with ordinary `cargo test` (and
//! property tests) on the host, far away from any hardware. The kernel wires
//! these types to real memory; nothing here touches a register or a page
//! table.
//!
//! - [`buddy::Buddy`] — a binary buddy allocator over abstract frame indices.
//! - [`refcount::RefCounts`] — per-frame reference counts for CoW + reclamation.
//! - [`slab::Slab`] — a slab object cache with power-of-two size classes,
//!   fed by an abstract [`slab::PageSource`].
//!
//! The crate is `no_std` when built for the kernel target and pulls in `std`
//! only to host its own test harness.

#![cfg_attr(not(test), no_std)]

pub mod buddy;
pub mod refcount;
pub mod slab;
