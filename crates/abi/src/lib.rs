//! `abi` — the typed Linux x86_64 syscall ABI for FluOS.
//!
//! Syscall numbers ([`nr`]), errno values ([`errno`]), and the kernel structs
//! ([`types`]) musl and zsh pass across the syscall boundary. Keeping these in
//! one `no_std`, host-tested crate means the kernel and any userland helpers
//! agree on the exact layout, and the layouts are checked against the Linux ABI
//! with `cargo test -p abi`.

#![cfg_attr(not(test), no_std)]

pub mod errno;
pub mod nr;
pub mod types;

pub use errno::{Errno, SysResult};
