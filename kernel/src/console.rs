//! Framebuffer text console: renders the terminal grid with the Nerd Font atlas.
//!
//! The emulation lives in the host-tested [`tty`] crate; this module is the
//! renderer. It keeps a full-screen pixel back buffer in RAM, draws only the
//! cells the terminal marked damaged, and blits those cells to the (slow,
//! write-combining) framebuffer. Kernel log output is mirrored here via a sink
//! registered with [`crate::log`].

use crate::boot::Framebuffer;
use crate::font::{self, CELL_H, CELL_W};
use alloc::vec;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use tty::{Rgb, Terminal, resolve};

/// Default foreground/background, matching the splash theme.
const DEFAULT_FG: Rgb = Rgb::new(0xC0, 0xCA, 0xF5);
const DEFAULT_BG: Rgb = Rgb::new(0x1A, 0x1B, 0x26);

/// The framebuffer console.
pub struct Console {
    fb: *mut u32,
    fb_w: usize,
    fb_h: usize,
    /// Framebuffer stride in pixels (u32 units).
    stride: usize,
    back: Vec<u32>,
    term: Terminal,
    last_cursor: (usize, usize),
}

// SAFETY: the framebuffer pointer is a fixed MMIO/RAM address valid for the
// kernel's lifetime. The console is only ever reached behind the module `Mutex`
// and, in M2, from a single CPU, so sharing the raw pointer is sound.
unsafe impl Send for Console {}

impl Console {
    /// Builds a console filling `fb`, clearing it to the background color.
    pub fn new(fb: &Framebuffer) -> Self {
        let cols = (fb.width / CELL_W).max(1);
        let rows = (fb.height / CELL_H).max(1);
        let mut console = Self {
            fb: fb.addr,
            fb_w: fb.width,
            fb_h: fb.height,
            stride: fb.pitch / 4,
            back: vec![DEFAULT_BG.pack(); fb.width * fb.height],
            term: Terminal::new(rows, cols),
            last_cursor: (0, 0),
        };
        console.clear_screen();
        console
    }

    /// Paints the entire framebuffer with the background color.
    fn clear_screen(&mut self) {
        let bg = DEFAULT_BG.pack();
        for y in 0..self.fb_h {
            for x in 0..self.fb_w {
                // SAFETY: (x, y) is within the bootloader-reported framebuffer.
                unsafe { self.fb.add(y * self.stride + x).write_volatile(bg) };
            }
        }
    }

    /// Feeds bytes to the terminal and repaints the damaged cells.
    ///
    /// A bare line feed is expanded to CR+LF (the ONLCR output processing a
    /// cooked tty would do), so log lines that end in `\n` start at column 0
    /// instead of staircasing.
    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.term.advance(b'\r');
            }
            self.term.advance(b);
        }
        self.refresh();
    }

    /// Repaints every damaged cell, plus the old and new cursor cells so the
    /// block cursor tracks the caret.
    fn refresh(&mut self) {
        let cursor = self.term.grid().cursor();
        self.term.grid_mut().mark_dirty(self.last_cursor.0, self.last_cursor.1);
        self.term.grid_mut().mark_dirty(cursor.0, cursor.1);

        let rows = self.term.grid().rows();
        let cols = self.term.grid().cols();
        let show_cursor = self.term.cursor_visible();
        for row in 0..rows {
            for col in 0..cols {
                if self.term.grid().is_dirty(row, col) {
                    let is_cursor = show_cursor && (row, col) == cursor;
                    self.render_cell(row, col, is_cursor);
                }
            }
        }
        self.term.grid_mut().clear_damage();
        self.last_cursor = cursor;
    }

    /// Renders one cell into the back buffer and blits it to the framebuffer.
    fn render_cell(&mut self, row: usize, col: usize, is_cursor: bool) {
        let cell = *self.term.grid().cell(row, col);
        let mut fg = resolve(cell.fg, DEFAULT_FG);
        let mut bg = resolve(cell.bg, DEFAULT_BG);
        // Reverse video and the block cursor both swap fg/bg (XOR so a reversed
        // cell under the cursor swaps back).
        if cell.flags.reverse ^ is_cursor {
            core::mem::swap(&mut fg, &mut bg);
        }

        let glyph = font::glyph(cell.ch);
        let x0 = col * CELL_W;
        let y0 = row * CELL_H;
        let underline_row = CELL_H.saturating_sub(2);

        for py in 0..CELL_H {
            for px in 0..CELL_W {
                let mut a = match glyph {
                    Some(g) => g[py * CELL_W + px],
                    None => replacement_alpha(px, py),
                };
                // Fake bold: overstrike one pixel to the left for extra weight.
                if cell.flags.bold && px > 0 {
                    if let Some(g) = glyph {
                        a = a.max(g[py * CELL_W + (px - 1)]);
                    }
                }
                if cell.flags.underline && py == underline_row {
                    a = 0xFF;
                }
                let color = blend(fg, bg, a);
                self.back[(y0 + py) * self.fb_w + (x0 + px)] = color;
            }
        }

        // Blit the cell's pixels from the back buffer to the framebuffer.
        for py in 0..CELL_H {
            let dst = (y0 + py) * self.stride + x0;
            let src = (y0 + py) * self.fb_w + x0;
            for px in 0..CELL_W {
                // SAFETY: the cell lies within the framebuffer by construction
                // (cols/rows were derived from its dimensions).
                unsafe { self.fb.add(dst + px).write_volatile(self.back[src + px]) };
            }
        }
    }
}

/// Alpha-blends `fg` over `bg` by coverage `a` (0..=255), returning packed RGB.
fn blend(fg: Rgb, bg: Rgb, a: u8) -> u32 {
    let mix = |f: u8, b: u8| {
        let a = a as u16;
        ((f as u16 * a + b as u16 * (255 - a)) / 255) as u8
    };
    Rgb::new(mix(fg.r, bg.r), mix(fg.g, bg.g), mix(fg.b, bg.b)).pack()
}

/// Coverage for the replacement box drawn in place of a missing glyph: a hollow
/// rectangle one pixel inside the cell border.
fn replacement_alpha(px: usize, py: usize) -> u8 {
    let on_edge = px == 1 || px == CELL_W - 2 || py == 1 || py == CELL_H - 2;
    let inside = (1..CELL_W - 1).contains(&px) && (1..CELL_H - 1).contains(&py);
    if on_edge && inside { 0xC0 } else { 0 }
}

static CONSOLE: SpinLock<Option<Console>> = SpinLock::new(None);

/// Brings up the framebuffer console and mirrors kernel logs to it.
pub fn init(fb: &Framebuffer) {
    *CONSOLE.lock() = Some(Console::new(fb));
    crate::log::set_console_sink(Some(sink));
}

/// Writes a string (possibly containing escape sequences) to the console.
pub fn write_str(s: &str) {
    if let Some(console) = CONSOLE.lock().as_mut() {
        console.write(s.as_bytes());
    }
}

/// Log sink: a plain function pointer so `log` stays decoupled from the console.
fn sink(s: &str) {
    write_str(s);
}

/// Whether the console has been initialised (used to gate the demo/input loop).
#[allow(dead_code)] // used by the interactive input loop
pub fn is_ready() -> bool {
    CONSOLE.lock().is_some()
}
