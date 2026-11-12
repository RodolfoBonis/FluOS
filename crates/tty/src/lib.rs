//! `tty` — a `no_std`, host-testable VT/xterm-256color terminal core.
//!
//! This crate turns a byte stream of text and escape sequences into a cell grid
//! the kernel's framebuffer console can render. It implements UTF-8 decoding,
//! C0 controls, CSI cursor motion / erase / scroll regions, SGR (16, 256, and
//! 24-bit truecolor plus bold/italic/underline/reverse), and the DEC private
//! modes for cursor visibility and the alternate screen. OSC strings (titles)
//! are parsed and ignored.
//!
//! It is deliberately free of any hardware or rendering concerns, so the whole
//! emulator is exercised on the host with `cargo test -p tty`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod cell;
pub mod color;
pub mod grid;
pub mod parser;

pub use cell::{Cell, Flags, Pen};
pub use color::{ANSI_16, Color, Rgb, resolve, resolve_indexed};
pub use grid::Grid;
pub use parser::Terminal;

#[cfg(test)]
mod tests;
